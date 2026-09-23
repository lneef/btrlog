use std::cell::UnsafeCell;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::rc::Rc;

use super::ThreadUring;
use super::buffer::IoBuf;
use super::slot_storage::{IndexSlotId, IndexableSlotStorage};
use super::stream::{MessageConsumer, StreamId, StreamManager, StreamSendFuture, StreamState};
use super::uring::{IOEnterIntent, OpId};

#[inline]
fn io_error<T>(errno: i32) -> io::Result<T> {
    Err(io::Error::from_raw_os_error(errno))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SessionHealth {
    #[default]
    Healthy,
    Closed,
    Failed(i32),
}

impl SessionHealth {
    /// Positive errno reported to sends of an ended session.
    fn errno(self) -> Option<i32> {
        match self {
            Self::Healthy => None,
            Self::Closed => Some(libc::EPIPE),
            Self::Failed(err) => Some(-err),
        }
    }
}

pub(crate) struct Session {
    fd: OwnedFd,
    manager: StreamManager,
    health: SessionHealth,
    recv: Option<OpId>,
}

impl Session {
    fn new(fd: OwnedFd, client: bool) -> Self {
        Self {
            fd,
            manager: StreamManager::new(client),
            health: SessionHealth::Healthy,
            recv: None,
        }
    }

    fn ref_cnt(&self) -> usize {
        self.manager.ref_cnt() + self.recv.is_some() as usize
    }

    fn arm_recv(&mut self, io: &ThreadUring, slot: SessionId) {
        assert!(self.recv.is_none(), "recv armed twice");
        self.recv = Some(io.recv_multi(&self.fd, slot.slot()));
    }

    fn cancel_recv(&mut self, io: &ThreadUring) {
        if let Some(op) = self.recv {
            io.cancel_session_op(op);
        }
    }

    pub(crate) fn health(&self) -> SessionHealth {
        self.health
    }

    /// The first end of a session sticks.
    fn end(&mut self, health: SessionHealth) {
        if self.health == SessionHealth::Healthy {
            self.health = health;
        }
    }

    /// Fails the staged sends of an ended session once the kernel holds none.
    fn settle(&mut self) {
        if let Some(errno) = self.health.errno()
            && self.manager.state() != StreamState::Kernel
        {
            self.manager.fail_queued(-errno);
        }
        debug_assert!(
            self.health == SessionHealth::Healthy || self.manager.state() != StreamState::Queued,
            "staged sends outlive the session"
        );
    }

    pub(crate) fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// None once the session ended, its streams got their end notification.
    fn open_stream(&mut self) -> Option<StreamId> {
        if self.health != SessionHealth::Healthy {
            return None;
        }
        self.manager.open_stream()
    }

    fn close_stream(&mut self, id: StreamId) {
        self.manager.close_stream(id);
    }

    fn stage(
        &mut self,
        buf: IoBuf,
        id: StreamId,
    ) -> Result<(StreamSendFuture, bool), (i32, IoBuf)> {
        if let Some(errno) = self.health.errno() {
            return Err((errno, buf));
        }
        self.manager
            .stage(buf, id)
            .map_err(|buf| (libc::EBADF, buf))
    }

    /// True when sends are left to submit.
    fn reap(&mut self, res: io::Result<usize>) -> bool {
        let res = res.map_err(|e| -e.raw_os_error().expect("send completion without an errno"));
        if let Err(err) = res {
            self.end(SessionHealth::Failed(err));
        }
        let again = self.manager.reap(res);
        self.settle();
        again && self.health == SessionHealth::Healthy
    }

    /// None when no send is queued.
    fn prepare(&mut self) -> Option<*const libc::msghdr> {
        (self.manager.state() == StreamState::Queued).then(|| self.manager.prepare())
    }

    fn on_recv<C: MessageConsumer>(
        &mut self,
        res: io::Result<&[u8]>,
        slot: SessionId,
        consumer: &C,
    ) {
        let end = match res {
            Ok(data) if !data.is_empty() => return self.manager.on_data(data, slot, consumer),
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                log::warn!("recv buffers exhausted on session {:?}", slot);
                return;
            }
            Ok(_) => SessionHealth::Closed,
            Err(e) if e.raw_os_error() == Some(libc::ECANCELED) => SessionHealth::Closed,
            Err(e) => SessionHealth::Failed(-e.raw_os_error().unwrap_or(libc::EIO)),
        };
        self.recv = None;
        self.end(end);
        let err = match self.health {
            SessionHealth::Failed(err) => Some(io::Error::from_raw_os_error(-err)),
            _ => None,
        };
        self.manager.on_end(err, slot, consumer);
        self.settle();
    }
}

pub(crate) struct SessionManagerContext {
    pub(crate) socks: IndexableSlotStorage<Session>,
    accepted: Vec<SessionId>,
    queued: Vec<SessionId>,
}

impl SessionManagerContext {
    /// Frees the slot of a closed session no stream or kernel op refers to.
    fn release_if_unused(&mut self, slt: SessionId) {
        let unused = self.socks.index(slt.slot()).is_some_and(|session| {
            session.health() != SessionHealth::Healthy && session.ref_cnt() == 0
        });
        if unused {
            self.socks.put(slt.slot());
        }
    }
}

pub struct SessionManager<C: MessageConsumer> {
    io: ThreadUring,
    listener: Option<OwnedFd>,
    consumer: C,
    ctx: Rc<UnsafeCell<SessionManagerContext>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SessionId(IndexSlotId);

impl SessionId {
    fn slot(self) -> IndexSlotId {
        self.0
    }
}

impl From<IndexSlotId> for SessionId {
    fn from(slot: IndexSlotId) -> Self {
        Self(slot)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SessionAddr {
    session: SessionId,
    stream: StreamId,
}

impl SessionAddr {
    pub fn new(session: SessionId, stream: StreamId) -> Self {
        Self { session, stream }
    }

    pub fn session(&self) -> SessionId {
        self.session
    }

    pub fn stream(&self) -> StreamId {
        self.stream
    }
}

impl<C: MessageConsumer> SessionManager<C> {
    pub fn new(
        io: ThreadUring,
        listener: Option<impl Into<OwnedFd>>,
        slots: usize,
        consumer: C,
    ) -> Self {
        assert!(slots > 0, "session table needs at least one slot");
        let listener = listener.map(|fd| fd.into());
        let ctx = SessionManagerContext {
            socks: IndexableSlotStorage::new(slots),
            accepted: Vec::with_capacity(slots),
            queued: Vec::with_capacity(slots),
        };
        Self {
            io,
            listener,
            consumer,
            ctx: Rc::new(UnsafeCell::new(ctx)),
        }
    }

    pub fn start_accepting(&mut self) {
        self.io.accept_multi(
            self.listener
                .as_ref()
                .expect("A server needs to have a listener"),
        );
    }

    pub fn io(&self) -> &ThreadUring {
        &self.io
    }

    #[inline]
    pub(crate) fn access<R>(&self, f: impl FnOnce(&mut SessionManagerContext) -> R) -> R {
        f(unsafe { &mut *self.ctx.get() })
    }

    pub fn session_health(&self, slt: SessionId) -> Option<SessionHealth> {
        self.access(|ctx| Some(ctx.socks.index(slt.slot())?.health()))
    }

    pub fn open_stream(&self, slt: SessionId) -> Option<SessionAddr> {
        let stream = self.access(|ctx| ctx.socks.index_mut(slt.slot())?.open_stream())?;
        Some(SessionAddr::new(slt, stream))
    }

    pub fn close_stream(&mut self, addr: &SessionAddr) {
        self.access(|ctx| {
            ctx.socks
                .index_mut(addr.session.slot())
                .expect("close_stream on an unknown session")
                .close_stream(addr.stream);
            ctx.release_if_unused(addr.session);
        });
    }

    /// The recv ends with -ECANCELED, which closes the session.
    pub fn cancel_recv(&self, slt: SessionId) {
        self.access(|ctx| {
            if let Some(session) = ctx.socks.index_mut(slt.slot()) {
                session.cancel_recv(&self.io);
            }
        });
    }

    pub async fn put(&self, buf: IoBuf, addr: &SessionAddr) -> (io::Result<usize>, IoBuf) {
        let staged = self.access(|ctx| {
            let Some(session) = ctx.socks.index_mut(addr.session.slot()) else {
                return Err((libc::EBADF, buf));
            };
            let (fut, queue) = session.stage(buf, addr.stream)?;
            if queue {
                ctx.queued.push(addr.session);
            }
            Ok(fut)
        });
        match staged {
            Ok(fut) => fut.await,
            Err((errno, buf)) => (io_error(errno), buf),
        }
    }

    fn reap(&self, slt: SessionId, res: io::Result<usize>) {
        self.access(|ctx| {
            let Some(session) = ctx.socks.index_mut(slt.slot()) else {
                return;
            };
            if session.reap(res) {
                ctx.queued.push(slt);
            }
            if session.health() != SessionHealth::Healthy {
                session.cancel_recv(&self.io);
            }
            ctx.release_if_unused(slt);
        });
    }

    fn submit_streams(&self) {
        let mut queued = self.access(|ctx| std::mem::take(&mut ctx.queued));
        for slt in queued.drain(..) {
            self.access(|ctx| {
                let Some(session) = ctx.socks.index_mut(slt.slot()) else {
                    return;
                };
                if let Some(msg) = session.prepare() {
                    self.io.send_stream(&session.raw_fd(), slt.slot(), msg);
                }
            });
        }
        self.access(|ctx| {
            assert!(
                ctx.queued.is_empty(),
                "sessions queued during submission are dropped"
            );
            ctx.queued = queued;
        });
    }

    pub fn enter(&self, intent: IOEnterIntent) {
        self.submit_streams();
        self.io.enter(intent)
    }

    pub fn manage(&self) -> io::Result<usize> {
        let harvested = self.io.poll_completion(
            |res| match res {
                Ok(fd) => self.accept(fd),
                Err(e) => log::error!("accept ended: {}", e),
            },
            |slot, res| self.recv(slot.into(), res),
            |slot, res| self.reap(slot.into(), res),
        )?;
        let mut accepted = self.access(|ctx| std::mem::take(&mut ctx.accepted));
        for slot in accepted.drain(..) {
            self.access(|ctx| {
                ctx.socks
                    .index_mut(slot.slot())
                    .expect("accepted session vanished")
                    .arm_recv(&self.io, slot)
            });
        }
        self.access(|ctx| {
            assert!(
                ctx.accepted.is_empty(),
                "sessions accepted during rearm are dropped"
            );
            ctx.accepted = accepted;
        });
        Ok(harvested)
    }

    pub async fn connect(&self, addr: impl Into<SocketAddr>) -> io::Result<SessionId> {
        let fd = self.io.tcp_connect(addr).await?;
        let slot = self
            .access(|ctx| ctx.socks.get())
            .map(SessionId::from)
            .ok_or_else(|| io::Error::other("session table full"))?;
        let mut session = Session::new(fd, true);
        session.arm_recv(&self.io, slot);
        self.access(|ctx| ctx.socks.set(slot.slot(), session));
        Ok(slot)
    }

    fn accept(&self, fd: OwnedFd) {
        self.access(|ctx| {
            let Some(slot) = ctx.socks.get().map(SessionId::from) else {
                log::warn!("session table full, dropping connection");
                return;
            };
            ctx.socks.set(slot.slot(), Session::new(fd, false));
            ctx.accepted.push(slot);
        });
    }

    fn recv(&self, slot: SessionId, res: io::Result<&[u8]>) {
        self.access(|ctx| {
            let Some(session) = ctx.socks.index_mut(slot.slot()) else {
                log::debug!("recv completion for a closed session {:?}", slot);
                return;
            };
            session.on_recv(res, slot, &self.consumer);
            ctx.release_if_unused(slot);
        });
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::time::Duration;

    /// Records the end notification of every stream.
    #[derive(Default)]
    struct Ends(std::cell::RefCell<Vec<(StreamId, i32)>>);

    impl MessageConsumer for Ends {
        fn consume(&self, result: i32, addr: SessionAddr, buf: Option<&[u8]>) {
            if buf.is_none() {
                self.0.borrow_mut().push((addr.stream(), result));
            }
        }
    }

    fn ends(mgr: &SessionManager<Ends>) -> Vec<(StreamId, i32)> {
        mgr.consumer.0.borrow().clone()
    }

    fn staged_put(mgr: &SessionManager<Ends>, addr: &SessionAddr) -> impl Future<Output = (io::Result<usize>, IoBuf)> {
        let mut buf = crate::io::local_packet_buffer_pool().pop();
        buf.mark_used(4);
        mgr.put(buf, addr)
    }

    fn sessions<C: MessageConsumer>(mgr: &SessionManager<C>) -> Vec<SessionId> {
        mgr.access(|ctx| ctx.socks.ids().map(SessionId::from).collect())
    }

    fn drive<C: MessageConsumer>(mgr: &SessionManager<C>, mut done: impl FnMut() -> bool) {
        for _ in 0..10_000 {
            if done() {
                return;
            }
            mgr.enter(IOEnterIntent::Poll);
            mgr.manage().expect("manage failed");
            std::thread::sleep(Duration::from_micros(100));
        }
        panic!("timeout driving the session manager");
    }

    /// Drives completions without submitting staged sends.
    fn drive_recv<C: MessageConsumer>(mgr: &SessionManager<C>, mut done: impl FnMut() -> bool) {
        for _ in 0..10_000 {
            if done() {
                return;
            }
            mgr.io().enter(IOEnterIntent::Poll);
            mgr.manage().expect("manage failed");
            std::thread::sleep(Duration::from_micros(100));
        }
        panic!("timeout driving the session manager");
    }

    /// Server manager with one accepted session and its peer.
    fn accepted() -> (SessionManager<Ends>, SessionId, TcpStream) {
        let io = ThreadUring::new_with(|cfg| {
            cfg.sq_entries = 8;
            cfg.cq_entries = 8;
        })
        .expect("ring creation failed");
        let listener = io.tcp_listener(([127, 0, 0, 1], 0)).expect("listen failed");
        let addr = listener.local_addr().unwrap();
        let mut mgr = SessionManager::new(io, Some(listener), 2, Ends::default());
        mgr.start_accepting();
        let client = TcpStream::connect(addr).expect("connect failed");
        drive(&mgr, || sessions(&mgr).len() == 1);
        let slt = sessions(&mgr)[0];
        drive(&mgr, || {
            mgr.access(|ctx| ctx.socks.index(slt.slot()).unwrap().recv.is_some())
        });
        assert_eq!(mgr.session_health(slt), Some(SessionHealth::Healthy));
        (mgr, slt, client)
    }

    /// The peer ends the session while a send is staged but unsubmitted.
    fn staged_send_on_end(reset: bool, errno: i32) {
        let (mut mgr, slt, client) = accepted();
        let addr = mgr.open_stream(slt).expect("stream table full");
        {
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            let mut put = std::pin::pin!(staged_put(&mgr, &addr));
            assert!(put.as_mut().poll(&mut cx).is_pending(), "send staged");
            if reset {
                socket2::SockRef::from(&client)
                    .set_linger(Some(Duration::ZERO))
                    .unwrap();
            }
            drop(client);
            drive_recv(&mgr, || {
                mgr.session_health(slt) != Some(SessionHealth::Healthy)
            });
            let std::task::Poll::Ready((res, _buf)) = put.as_mut().poll(&mut cx) else {
                panic!("staged send outlives the session");
            };
            assert_eq!(res.unwrap_err().raw_os_error(), Some(errno));
        }
        assert_eq!(ends(&mgr), [(addr.stream(), -libc::ECONNRESET)]);
        assert!(mgr.open_stream(slt).is_none(), "stream opened on an ended session");
        assert_eq!(sessions(&mgr), [slt], "the open stream holds the session");
        mgr.close_stream(&addr);
        assert!(sessions(&mgr).is_empty());
        assert_eq!(mgr.session_health(slt), None);
    }

    #[test]
    fn test_closed_session_frees_its_slot() {
        let (mgr, slt, client) = accepted();
        drop(client);
        drive(&mgr, || sessions(&mgr).is_empty());
        assert_eq!(
            mgr.session_health(slt),
            None,
            "freed slot answers to a stale id"
        );
    }

    #[test]
    fn test_eof_fails_a_staged_send() {
        staged_send_on_end(false, libc::EPIPE);
    }

    #[test]
    fn test_reset_fails_a_staged_send() {
        staged_send_on_end(true, libc::ECONNRESET);
    }

    #[test]
    fn test_send_error_reaches_every_stream() {
        let (mut mgr, slt, _client) = accepted();
        let idle = mgr.open_stream(slt).expect("stream table full");
        let sending = mgr.open_stream(slt).expect("stream table full");
        let fd = mgr.access(|ctx| ctx.socks.index(slt.slot()).unwrap().raw_fd());
        assert_eq!(unsafe { libc::shutdown(fd, libc::SHUT_WR) }, 0);
        {
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            let mut put = std::pin::pin!(staged_put(&mgr, &sending));
            assert!(put.as_mut().poll(&mut cx).is_pending(), "send staged");
            drive(&mgr, || ends(&mgr).len() == 2);
            let std::task::Poll::Ready((res, _buf)) = put.as_mut().poll(&mut cx) else {
                panic!("failed send still pending");
            };
            assert_eq!(res.unwrap_err().raw_os_error(), Some(libc::EPIPE));
        }
        assert_eq!(mgr.session_health(slt), Some(SessionHealth::Failed(-libc::EPIPE)));
        let mut notified = ends(&mgr);
        notified.sort_by_key(|(id, _)| id.to_wire());
        assert_eq!(
            notified,
            [(idle.stream(), -libc::EPIPE), (sending.stream(), -libc::EPIPE)],
            "the send error ends every stream"
        );
        mgr.close_stream(&idle);
        assert_eq!(sessions(&mgr), [slt], "an open stream holds the session");
        mgr.close_stream(&sending);
        assert!(sessions(&mgr).is_empty());
    }
}
