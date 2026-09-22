use std::cell::UnsafeCell;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::rc::Rc;

use super::ThreadUring;
use super::buffer::IoBuf;
use super::slot_storage::{IndexSlotId, IndexableSlotStorage};
use super::stream::{MessageConsumer, STREAM_CLOSED, StreamId, StreamManager, StreamState};
use super::uring::IOEnterIntent;

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

pub(crate) struct Session {
    fd: OwnedFd,
    mux: StreamManager,
    health: SessionHealth,
}

impl Session {
    fn new(fd: OwnedFd, client: bool) -> Self {
        Self {
            fd,
            mux: StreamManager::new(client),
            health: SessionHealth::Healthy,
        }
    }

    pub(crate) fn health(&self) -> SessionHealth {
        self.health
    }

    pub(crate) fn fail(&mut self, err: i32) {
        if self.health == SessionHealth::Healthy {
            self.health = SessionHealth::Failed(err);
        }
        self.mux_mut().fail(err);
    }

    pub(crate) fn close(&mut self) {
        if self.health == SessionHealth::Healthy {
            self.health = SessionHealth::Closed;
        }
    }

    pub(crate) fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub(crate) fn mux_mut(&mut self) -> &mut StreamManager {
        &mut self.mux
    }
}

pub(crate) struct SessionManagerContext {
    pub(crate) socks: IndexableSlotStorage<Session>,
    accepted: Vec<SessionId>,
    queued: Vec<SessionId>,
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
        let stream = self.access(|ctx| ctx.socks.index_mut(slt.slot())?.mux_mut().open_stream())?;
        Some(SessionAddr::new(slt, stream))
    }

    pub fn close_stream(&mut self, addr: &SessionAddr) {
        self.access(|ctx| {
            ctx.socks
                .index_mut(addr.session.slot())
                .expect("close_stream on an unknown session")
                .mux_mut()
                .close_stream(addr.stream);
        });
    }

    pub async fn put(&self, buf: IoBuf, addr: &SessionAddr) -> (io::Result<usize>, IoBuf) {
        let session = unsafe { &mut *self.ctx.get() }
            .socks
            .index_mut(addr.session.slot());
        let session = match session {
            Some(session) => session,
            None => return (io_error(libc::EBADF), buf),
        };
        match session.health() {
            SessionHealth::Healthy => {}
            SessionHealth::Closed => return (io_error(libc::EPIPE), buf),
            SessionHealth::Failed(err) => return (io_error(-err), buf),
        }
        let (fut, queue) = match session.mux_mut().stage(buf, addr.stream) {
            Ok(staged) => staged,
            Err(buf) => return (io_error(libc::EBADF), buf),
        };
        if queue {
            self.access(|ctx| ctx.queued.push(addr.session));
        }
        fut.await
    }

    fn reap(&self, slt: SessionId, res: io::Result<usize>) {
        match res {
            Err(err) => {
                let errno = err
                    .raw_os_error()
                    .expect("send completion without an errno");
                assert!(errno > 0, "raw_os_error yields a positive errno");
                self.access(|ctx| {
                    let failed = ctx.socks.index_mut(slt.slot()).map(|s| {
                        s.fail(-errno);
                    });
                    assert!(failed.is_none());
                });
            }
            Ok(res) => {
                self.access(|ctx| {
                    let again = ctx
                        .socks
                        .index_mut(slt.slot())
                        .map(|s| s.mux_mut().reap(res));
                    match again {
                        Some(true) => ctx.queued.push(slt),
                        Some(false) => panic!("not implemented"),
                        None => {}
                    }
                });
            }
        }
    }

    fn submit_streams(&self) {
        let mut queued = self.access(|ctx| std::mem::take(&mut ctx.queued));
        for slt in queued.drain(..) {
            self.access(|ctx| {
                if let Some(session) = ctx.socks.index_mut(slt.slot()) {
                    if session.mux_mut().state() != StreamState::Queued {
                        return;
                    }
                    let fd = session.raw_fd();
                    let msg = session.mux_mut().prepare();
                    self.io.send_stream(&fd, slt.slot(), msg);
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
            let fd = self.access(|ctx| {
                ctx.socks
                    .index(slot.slot())
                    .expect("accepted session vanished")
                    .raw_fd()
            });
            self.io.recv_multi(&fd, slot.slot());
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
        self.io.recv_multi(&fd, slot.slot());
        self.access(|ctx| ctx.socks.set(slot.slot(), Session::new(fd, true)));
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
            match res {
                Ok(data) if !data.is_empty() => {
                    session.mux_mut().on_data(data, slot, &self.consumer)
                }
                Ok(_) => {
                    session.close();
                    session.mux_mut().on_end(None, slot, &self.consumer);
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    log::warn!("recv buffers exhausted on session {:?}", slot);
                }
                Err(e) => {
                    let err = -e.raw_os_error().unwrap_or(libc::EIO);
                    session.fail(err);
                    session.mux_mut().on_end(Some(e), slot, &self.consumer);
                }
            }
        });
    }
}
