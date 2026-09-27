use std::cell::UnsafeCell;
use std::io;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::rc::Rc;
use std::task::{Poll, Waker};

use io_uring::Submitter;

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
    /// messages staged while their session had a send bundle in flight
    pub behind: u64,
    /// completed send bundles
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
    bgid: u16,
    /// the send bundle the kernel holds
    send: Option<OpId>,
    recv: Option<OpId>,
}

impl Session {
    fn new(
        fd: OwnedFd,
        peer: SocketAddr,
        client: bool,
        submitter: &Submitter,
        session: u16,
    ) -> Self {
        let bgid = session + 1; // 0 is multishot recv
        Self {
            fd,
            peer,
            manager: StreamManager::new(client, submitter, bgid),
            health: SessionHealth::Healthy,
            bgid,
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

    /// Submits the send right away when no send bundle is in flight.
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

    /// Hands the staged sends to one send bundle unless one is in flight.
    fn submit(&mut self, io: &ThreadUring, slot: SessionId) {
        if self.send.is_none() && self.manager.queued() > 0 {
            self.manager.flush();
            self.send = Some(io.send_bundle(&self.fd, slot.slot(), self.bgid));
        }
    }

    /// Ends the send bundle in flight, then submits what was staged meanwhile.
    fn reap(
        &mut self,
        io: &ThreadUring,
        slot: SessionId,
        res: io::Result<usize>,
        bid: Option<u16>,
    ) {
        assert!(
            self.send.take().is_some(),
            "send completion without a send bundle in flight"
        );
        let res = res.map_err(|e| -e.raw_os_error().expect("send completion without an errno"));
        if let Err(err) = res {
            self.end(SessionHealth::Failed(err));
        }
        self.manager.reap(res, bid);
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
    fn release_if_unused(&mut self, slt: SessionId, submitter: &Submitter) {
        let unused = self.socks.index(slt.slot()).is_some_and(|session| {
            session.health() != SessionHealth::Healthy && session.ref_cnt() == 0
        });
        if unused {
            let mut session = self.socks.put(slt.slot()).expect("unused session vanished");
            session.manager.unregister(submitter);
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

impl<C: MessageConsumer> Drop for SessionManager<C> {
    fn drop(&mut self) {
        let submitter = self.io.submitter();
        self.access(|ctx| {
            let ids: Vec<_> = ctx.socks.ids().collect();
            for id in ids {
                if let Some(mut session) = ctx.socks.put(id) {
                    session.manager.unregister(&submitter);
                }
            }
        });
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
            ctx.release_if_unused(addr.session, &self.io.submitter());
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

    fn reap(&self, slt: SessionId, res: io::Result<usize>, bid: Option<u16>) {
        self.access(|ctx| {
            let Some(session) = ctx.socks.index_mut(slt.slot()) else {
                return;
            };
            session.reap(&self.io, slt, res, bid);
            ctx.stats.sendmsgs += 1;
            if session.health() != SessionHealth::Healthy {
                session.cancel_recv(&self.io);
            }
            ctx.release_if_unused(slt, &self.io.submitter());
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
            |slot, res, bid| self.reap(slot.into(), res, bid),
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
        let mut session = Session::new(fd, addr, true, &self.io.submitter(), slot.0.idx() as u16);
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
            log::debug!(
                "bbr unavailable, keeping the default congestion control: {}",
                e
            );
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
            ctx.socks.set(
                slot.slot(),
                Session::new(fd, peer, false, &self.io().submitter(), slot.0.idx() as u16),
            );
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
            ctx.release_if_unused(slot, &self.io.submitter());
        });
    }
}
