use std::cell::UnsafeCell;
use std::io;
use std::marker::PhantomData;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::rc::Rc;

use super::ThreadUring;
use super::buffer::IoBuf;
use super::framing::{MessageConsumer, MessageFramer};
use super::send_stream::SendStreamState;
use super::slot_storage::{IndexSlotId, IndexableSlotStorage};
use super::uring::IOEnterIntent;

const DEFAULT_STREAM_SLOTS: usize = 32;

pub(crate) struct Session<C: MessageConsumer> {
    fd: OwnedFd,
    stream: SendStreamState,
    msg_framer: MessageFramer<C>,
}

impl<C: MessageConsumer> Session<C> {
    fn new(fd: OwnedFd, consumer: C) -> Self {
        Self {
            fd,
            stream: SendStreamState::new(DEFAULT_STREAM_SLOTS),
            msg_framer: MessageFramer::new(consumer),
        }
    }

    pub(crate) fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub(crate) fn stream_mut(&mut self) -> &mut SendStreamState {
        &mut self.stream
    }
}

pub(crate) struct SessionManagerContext<C: MessageConsumer> {
    pub(crate) socks: IndexableSlotStorage<Session<C>>,
    accepted: Vec<IndexSlotId>,
    queued: Vec<IndexSlotId>,
}

pub struct SessionManager<C: MessageConsumer> {
    io: ThreadUring,
    listener: OwnedFd,
    ctx: Rc<UnsafeCell<SessionManagerContext<C>>>,
}

impl<C: MessageConsumer> SessionManager<C> {
    pub fn new(io: ThreadUring, listener: impl Into<OwnedFd>, slots: usize) -> Self {
        let listener = listener.into();
        let ctx = SessionManagerContext {
            socks: IndexableSlotStorage::new(slots),
            accepted: Vec::with_capacity(slots),
            queued: Vec::with_capacity(slots),
        };
        Self {
            io,
            listener,
            ctx: Rc::new(UnsafeCell::new(ctx)),
        }
    }

    pub fn start_accepting(&mut self) {
        self.io.accept_multi(&self.listener);
    }

    pub fn io(&self) -> &ThreadUring {
        &self.io
    }

    #[inline]
    pub(crate) fn access<R>(&self, f: impl FnOnce(&mut SessionManagerContext<C>) -> R) -> R {
        f(unsafe { &mut *self.ctx.get() })
    }

    pub async fn put(&self, buf: IoBuf, slt: IndexSlotId) -> (io::Result<usize>, IoBuf) {
        let stream = unsafe { &mut *self.ctx.get() }
            .socks
            .index_mut(slt)
            .expect("put on an unknown session")
            .stream_mut();
        let (fut, queue) = stream.stage(buf).await;
        if queue {
            self.access(|ctx| ctx.queued.push(slt));
        }
        fut.await
    }

    fn reap(&self, slt: IndexSlotId, res: io::Result<usize>) {
        match res {
            Err(err) => {
                self.access(|ctx| {
                    ctx.socks
                        .index_mut(slt)
                        .map(|s| s.stream_mut().fail(err.raw_os_error().unwrap()));
                });
            }
            Ok(res) => {
                self.access(|ctx| {
                    let again = ctx.socks.index_mut(slt).map(|s| s.stream_mut().reap(res));
                    if again == Some(true) {
                        ctx.queued.push(slt);
                    }
                });
            }
        }
    }

    fn submit_streams(&self) {
        let mut queued = self.access(|ctx| std::mem::take(&mut ctx.queued));
        for slt in queued.drain(..) {
            self.access(|ctx| {
                if let Some(session) = ctx.socks.index_mut(slt) {
                    let fd = session.raw_fd();
                    let msg = session.stream_mut().prepare();
                    self.io.send_stream(&fd, slt, msg);
                }
            });
        }
        self.access(|ctx| ctx.queued = queued);
    }

    pub fn enter(&self, intent: IOEnterIntent) {
        self.submit_streams();
        self.io.enter(intent)
    }

    pub fn manage(&self, mut new_consumer: impl FnMut(IndexSlotId) -> C) -> io::Result<usize> {
        let harvested = self.io.poll_completion(
            |res| match res {
                Ok(fd) => self.accept(fd, &mut new_consumer),
                Err(e) => log::error!("accept ended: {}", e),
            },
            |slot, res| self.recv(slot, res),
            |slot, res| self.reap(slot, res),
        )?;
        let mut accepted = self.access(|ctx| std::mem::take(&mut ctx.accepted));
        for slot in accepted.drain(..) {
            let fd = self.access(|ctx| {
                ctx.socks
                    .index(slot)
                    .expect("accepted session vanished")
                    .raw_fd()
            });
            self.io.recv_multi(&fd, slot);
        }
        self.access(|ctx| ctx.accepted = accepted);
        Ok(harvested)
    }

    pub async fn connect(
        &self,
        addr: impl Into<SocketAddr>,
        new_consumer: impl FnOnce(IndexSlotId) -> C,
    ) -> io::Result<IndexSlotId> {
        let fd = self.io.tcp_connect(addr).await?;
        let slot = self
            .access(|ctx| ctx.socks.get())
            .ok_or_else(|| io::Error::other("session table full"))?;
        self.io.recv_multi(&fd, slot);
        self.access(|ctx| ctx.socks.set(slot, Session::new(fd, new_consumer(slot))));
        Ok(slot)
    }

    fn accept(&self, fd: OwnedFd, new_consumer: &mut impl FnMut(IndexSlotId) -> C) {
        self.access(|ctx| {
            let Some(slot) = ctx.socks.get() else {
                log::warn!("session table full, dropping connection");
                return;
            };
            ctx.socks.set(slot, Session::new(fd, new_consumer(slot)));
            ctx.accepted.push(slot);
        });
    }

    fn recv(&self, slot: IndexSlotId, res: io::Result<&[u8]>) {
        self.access(|ctx| {
            let session = ctx
                .socks
                .index_mut(slot)
                .expect("recv for an unknown session");
            match res {
                Ok(data) if !data.is_empty() => session.msg_framer.on_data(data),
                Ok(_) => {
                    session.msg_framer.on_end(None);
                    ctx.socks.put(slot);
                }
                // the buffer ring ran dry; the ring rearms the recv, the stream is intact
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    log::warn!("recv buffers exhausted on session {:?}", slot);
                }
                Err(e) => {
                    session.msg_framer.on_end(Some(e));
                    ctx.socks.put(slot);
                }
            }
        });
    }
}
