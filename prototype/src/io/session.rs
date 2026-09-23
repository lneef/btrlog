use std::cell::UnsafeCell;
use std::io;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::rc::Rc;
use std::task::{Poll, Waker};

use super::ThreadUring;
use super::buffer::IoBuf;
use super::slot_storage::{IndexSlotId, IndexableSlotStorage};
use super::stream::{MessageConsumer, StreamId, StreamManager, StreamSendFuture};
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

/// Send counters of one `SessionManager` since the last `take_send_stats`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SendStats {
    /// messages staged for a send
    pub staged: u64,
    /// messages staged while their session had a sendmsg in flight
    pub behind: u64,
    /// completed sendmsgs
    pub sendmsgs: u64,
}

enum Staged {
    Sent(StreamSendFuture),
    /// The stream still holds a staged send.
    Busy(IoBuf),
    Failed(i32, IoBuf),
}

pub(crate) struct Session {
    fd: OwnedFd,
    peer: SocketAddr,
    manager: StreamManager,
    health: SessionHealth,
    /// the sendmsg the kernel holds
    send: Option<OpId>,
    recv: Option<OpId>,
}

impl Session {
    fn new(fd: OwnedFd, peer: SocketAddr, client: bool) -> Self {
        Self {
            fd,
            peer,
            manager: StreamManager::new(client),
            health: SessionHealth::Healthy,
            send: None,
            recv: None,
        }
    }

    fn ref_cnt(&self) -> usize {
        self.manager.ref_cnt() + self.send.is_some() as usize + self.recv.is_some() as usize
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
            && self.send.is_none()
        {
            self.manager.fail_queued(-errno);
        }
        debug_assert!(
            self.health == SessionHealth::Healthy || self.send.is_some() || self.manager.staged() == 0,
            "staged sends outlive the session"
        );
    }

    #[cfg(test)]
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.fd)
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

    /// Submits the send right away when no sendmsg is in flight.
    fn stage(
        &mut self,
        io: &ThreadUring,
        slot: SessionId,
        buf: IoBuf,
        id: StreamId,
        waker: &Waker,
    ) -> Staged {
        if let Some(errno) = self.health.errno() {
            return Staged::Failed(errno, buf);
        }
        if self.manager.wait_if_busy(id, waker) {
            return Staged::Busy(buf);
        }
        match self.manager.stage(buf, id) {
            Ok(fut) => {
                self.submit(io, slot);
                Staged::Sent(fut)
            }
            Err(buf) => Staged::Failed(libc::EBADF, buf),
        }
    }

    fn send_detached(
        &mut self,
        io: &ThreadUring,
        slot: SessionId,
        buf: IoBuf,
        id: StreamId,
    ) -> Result<(), (i32, IoBuf)> {
        if let Some(errno) = self.health.errno() {
            return Err((errno, buf));
        }
        if self.manager.is_busy(id) {
            return Err((libc::EBUSY, buf));
        }
        self.manager
            .stage_detached(buf, id)
            .map_err(|buf| (libc::EBADF, buf))?;
        self.submit(io, slot);
        Ok(())
    }

    /// Hands the staged sends to one sendmsg unless one is in flight.
    fn submit(&mut self, io: &ThreadUring, slot: SessionId) {
        if self.send.is_some() || self.manager.staged() == 0 || self.health != SessionHealth::Healthy {
            return;
        }
        let msg = self.manager.prepare();
        self.send = Some(io.send_stream(&self.fd, slot.slot(), msg));
    }

    /// Ends the sendmsg in flight, then submits what was staged meanwhile.
    fn reap(&mut self, io: &ThreadUring, slot: SessionId, res: io::Result<usize>) {
        assert!(self.send.take().is_some(), "send completion without a sendmsg in flight");
        let res = res.map_err(|e| -e.raw_os_error().expect("send completion without an errno"));
        if let Err(err) = res {
            self.end(SessionHealth::Failed(err));
        }
        self.manager.reap(res);
        self.settle();
        self.submit(io, slot);
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
    stats: SendStats,
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

impl SendStats {
    /// Prints the counters as one stderr line.
    pub fn print(&self, role: &str, id: usize) {
        let unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        eprintln!(
            "send-stats role={} id={} unix_ms={} staged={} behind={} sendmsgs={}",
            role, id, unix_ms, self.staged, self.behind, self.sendmsgs
        );
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
            stats: SendStats::default(),
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

    pub fn peer_addr(&self, slt: SessionId) -> Option<SocketAddr> {
        self.access(|ctx| Some(ctx.socks.index(slt.slot())?.peer))
    }

    pub fn open_stream(&self, slt: SessionId) -> Option<SessionAddr> {
        let stream = self.access(|ctx| ctx.socks.index_mut(slt.slot())?.open_stream())?;
        Some(SessionAddr::new(slt, stream))
    }

    pub fn close_stream(&self, addr: &SessionAddr) {
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

    /// Waits while the stream holds a staged send, then stages `buf` behind it.
    pub async fn put(&self, buf: IoBuf, addr: &SessionAddr) -> (io::Result<usize>, IoBuf) {
        let mut buf = Some(buf);
        let staged = std::future::poll_fn(|cx| {
            self.access(|ctx| {
                let taken = buf.take().expect("put polled after staging");
                let Some(session) = ctx.socks.index_mut(addr.session.slot()) else {
                    return Poll::Ready(Err((libc::EBADF, taken)));
                };
                let behind = session.send.is_some();
                match session.stage(&self.io, addr.session, taken, addr.stream, cx.waker()) {
                    Staged::Sent(fut) => {
                        ctx.stats.staged += 1;
                        ctx.stats.behind += behind as u64;
                        Poll::Ready(Ok(fut))
                    }
                    Staged::Failed(errno, buf) => Poll::Ready(Err((errno, buf))),
                    Staged::Busy(back) => {
                        buf = Some(back);
                        Poll::Pending
                    }
                }
            })
        })
        .await;
        match staged {
            Ok(fut) => fut.await,
            Err((errno, buf)) => (io_error(errno), buf),
        }
    }

    /// Stages `buf` without waiting for it. The buffer is dropped once the send ends.
    /// A failed send ends the session, which ends its streams.
    pub fn send(&self, buf: IoBuf, addr: &SessionAddr) -> Result<(), (io::Error, IoBuf)> {
        self.access(|ctx| {
            let Some(session) = ctx.socks.index_mut(addr.session.slot()) else {
                return Err((libc::EBADF, buf));
            };
            let behind = session.send.is_some();
            session.send_detached(&self.io, addr.session, buf, addr.stream)?;
            ctx.stats.staged += 1;
            ctx.stats.behind += behind as u64;
            Ok(())
        })
        .map_err(|(errno, buf)| (io::Error::from_raw_os_error(errno), buf))
    }

    /// True while the stream holds a staged send.
    pub fn take_send_stats(&self) -> SendStats {
        self.access(|ctx| std::mem::take(&mut ctx.stats))
    }

    pub fn stream_busy(&self, addr: &SessionAddr) -> bool {
        self.access(|ctx| {
            ctx.socks
                .index(addr.session.slot())
                .is_some_and(|session| session.manager.is_busy(addr.stream))
        })
    }

    fn reap(&self, slt: SessionId, res: io::Result<usize>) {
        self.access(|ctx| {
            let Some(session) = ctx.socks.index_mut(slt.slot()) else {
                return;
            };
            session.reap(&self.io, slt, res);
            ctx.stats.sendmsgs += 1;
            if session.health() != SessionHealth::Healthy {
                session.cancel_recv(&self.io);
            }
            ctx.release_if_unused(slt);
        });
    }

    pub fn enter(&self, intent: IOEnterIntent) {
        self.io.enter(intent)
    }

    /// Handles the session events collected by earlier enters. Returns their count.
    pub fn manage(&self) -> io::Result<usize> {
        let drained = self.io.drain_sessions(
            |res| match res {
                Ok(fd) => self.accept(fd),
                Err(e) => log::error!("accept ended: {}", e),
            },
            |slot, res| self.recv(slot.into(), res),
            |slot, res| self.reap(slot.into(), res),
        );
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
        Ok(drained)
    }

    pub async fn connect(&self, addr: impl Into<SocketAddr>) -> io::Result<SessionId> {
        let addr = addr.into();
        let fd = self.io.tcp_connect(addr).await?;
        let slot = self
            .access(|ctx| ctx.socks.get())
            .map(SessionId::from)
            .ok_or_else(|| io::Error::other("session table full"))?;
        let mut session = Session::new(fd, addr, true);
        session.arm_recv(&self.io, slot);
        self.access(|ctx| ctx.socks.set(slot.slot(), session));
        Ok(slot)
    }

    fn accept(&self, fd: OwnedFd) {
        let sock = socket2::SockRef::from(&fd);
        if let Err(e) = sock.set_tcp_nodelay(true) {
            log::warn!("TCP_NODELAY on an accepted connection failed: {}", e);
        }
        if let Err(e) = sock.set_tcp_congestion(b"bbr") {
            log::debug!("bbr unavailable, keeping the default congestion control: {}", e);
        }
        let peer = match sock.peer_addr().map(|a| a.as_socket()) {
            Ok(Some(peer)) => peer,
            Ok(None) | Err(_) => {
                log::warn!("accepted a connection without a peer address, dropping it");
                return;
            }
        };
        self.access(|ctx| {
            let Some(slot) = ctx.socks.get().map(SessionId::from) else {
                log::warn!("session table full, dropping connection");
                return;
            };
            ctx.socks.set(slot.slot(), Session::new(fd, peer, false));
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

    /// A put on a session the peer ended fails with the session's errno.
    fn put_on_ended_session(reset: bool, errno: i32) {
        let (mgr, slt, client) = accepted();
        let addr = mgr.open_stream(slt).expect("stream table full");
        if reset {
            socket2::SockRef::from(&client)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
        }
        drop(client);
        drive(&mgr, || mgr.session_health(slt) != Some(SessionHealth::Healthy));
        {
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            let mut put = std::pin::pin!(staged_put(&mgr, &addr));
            let std::task::Poll::Ready((res, _buf)) = put.as_mut().poll(&mut cx) else {
                panic!("put on an ended session is pending");
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

    fn read_exact(client: &mut TcpStream, len: usize) {
        use std::io::Read;
        let mut buf = vec![0u8; len];
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.read_exact(&mut buf).expect("peer read failed");
    }

    #[test]
    fn test_connect_opens_a_session() {
        let io = ThreadUring::new_with(|cfg| {
            cfg.sq_entries = 8;
            cfg.cq_entries = 8;
        })
        .expect("ring creation failed");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listen failed");
        let peer = listener.local_addr().unwrap();
        let mgr = SessionManager::new(io, None::<OwnedFd>, 2, Ends::default());
        let mut cx = std::task::Context::from_waker(Waker::noop());
        let mut connect = std::pin::pin!(mgr.connect(peer));
        let mut done = None;
        for _ in 0..10_000 {
            if let Poll::Ready(res) = connect.as_mut().poll(&mut cx) {
                done = Some(res);
                break;
            }
            mgr.enter(IOEnterIntent::Poll);
            std::thread::sleep(Duration::from_micros(100));
        }
        let slt = done.expect("connect never completed").expect("connect failed");
        listener.accept().expect("accept failed");
        assert_eq!(mgr.session_health(slt), Some(SessionHealth::Healthy));
        assert_eq!(mgr.peer_addr(slt), Some(peer));
    }

    fn packet() -> IoBuf {
        let mut buf = crate::io::local_packet_buffer_pool().pop();
        buf.mark_used(4);
        buf
    }

    #[test]
    fn test_detached_send_releases_its_buffer() {
        let (mgr, slt, mut client) = accepted();
        let addr = mgr.open_stream(slt).expect("stream table full");
        assert!(mgr.send(packet(), &addr).is_ok());
        assert!(mgr.stream_busy(&addr), "send staged");
        let (err, _buf) = mgr.send(packet(), &addr).expect_err("second send on a busy stream");
        assert_eq!(err.raw_os_error(), Some(libc::EBUSY));
        drive(&mgr, || !mgr.stream_busy(&addr));
        read_exact(&mut client, 4);
        mgr.close_stream(&addr);
        assert_eq!(mgr.session_health(slt), Some(SessionHealth::Healthy));
    }

    #[test]
    fn test_send_error_releases_detached_sends() {
        let (mgr, slt, _client) = accepted();
        let first = mgr.open_stream(slt).expect("stream table full");
        let second = mgr.open_stream(slt).expect("stream table full");
        let fd = mgr.access(|ctx| ctx.socks.index(slt.slot()).unwrap().raw_fd());
        assert_eq!(unsafe { libc::shutdown(fd, libc::SHUT_WR) }, 0);
        assert!(mgr.send(packet(), &first).is_ok());
        mgr.enter(IOEnterIntent::Poll);
        assert!(mgr.send(packet(), &second).is_ok(), "queued behind the send in the kernel");
        drive(&mgr, || ends(&mgr).len() == 2);
        assert!(!mgr.stream_busy(&first), "failed send in the kernel keeps its buffer");
        assert!(!mgr.stream_busy(&second), "failed queued send keeps its buffer");
        let (err, _buf) = mgr.send(packet(), &first).expect_err("send on a failed session");
        assert_eq!(err.raw_os_error(), Some(libc::EPIPE));
        mgr.close_stream(&first);
        mgr.close_stream(&second);
        assert!(sessions(&mgr).is_empty());
    }

    #[test]
    #[should_panic(expected = "closing a stream with a staged send")]
    fn test_close_of_a_busy_stream_panics() {
        let (mgr, slt, _client) = accepted();
        let addr = mgr.open_stream(slt).expect("stream table full");
        assert!(mgr.send(packet(), &addr).is_ok());
        mgr.close_stream(&addr);
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
    fn test_eof_fails_a_put() {
        put_on_ended_session(false, libc::EPIPE);
    }

    #[test]
    fn test_reset_fails_a_put() {
        put_on_ended_session(true, libc::ECONNRESET);
    }

    #[test]
    fn test_put_submits_without_manager_enter() {
        let (mgr, slt, mut client) = accepted();
        assert_eq!(mgr.peer_addr(slt), Some(client.local_addr().unwrap()));
        let addr = mgr.open_stream(slt).expect("stream table full");
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut put = std::pin::pin!(staged_put(&mgr, &addr));
        assert!(put.as_mut().poll(&mut cx).is_pending(), "send staged");
        let mut done = None;
        for _ in 0..10_000 {
            mgr.io().enter(IOEnterIntent::Poll);
            mgr.manage().expect("manage failed");
            if let std::task::Poll::Ready(res) = put.as_mut().poll(&mut cx) {
                done = Some(res);
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        let (res, _buf) = done.expect("put never completed");
        assert_eq!(res.unwrap(), 4);
        read_exact(&mut client, 4);
    }

    #[test]
    fn test_put_waits_on_a_busy_stream() {
        let (mgr, slt, mut client) = accepted();
        let addr = mgr.open_stream(slt).expect("stream table full");
        let woken = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        struct Flag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl std::task::Wake for Flag {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let waker = Waker::from(std::sync::Arc::new(Flag(woken.clone())));
        let mut cx = std::task::Context::from_waker(&waker);
        let mut first = std::pin::pin!(staged_put(&mgr, &addr));
        let mut second = std::pin::pin!(staged_put(&mgr, &addr));
        assert!(first.as_mut().poll(&mut cx).is_pending(), "first send staged");
        assert!(second.as_mut().poll(&mut cx).is_pending(), "second put waits");
        drive(&mgr, || {
            matches!(first.as_mut().poll(&mut cx), Poll::Ready((Ok(4), _)))
        });
        assert!(woken.load(std::sync::atomic::Ordering::SeqCst), "release wakes the waiter");
        drive(&mgr, || {
            matches!(second.as_mut().poll(&mut cx), Poll::Ready((Ok(4), _)))
        });
        read_exact(&mut client, 8);
    }

    #[test]
    fn test_send_error_reaches_every_stream() {
        let (mgr, slt, _client) = accepted();
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
