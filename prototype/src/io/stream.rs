use std::cell::{Cell, UnsafeCell};
use std::rc::Rc;
use std::task::Poll;
use std::task::Waker;
use std::{io, vec};

use io_uring::Submitter;

use super::buffer::IoBuf;
use super::framing::{MessageFramer, StreamConsumer};
use super::send_ring::SendRing;
use super::session::{SessionAddr, SessionId};
use super::slot_storage::{IndexSlotId, SMALL_SLOT_CAPACITY, SmallSlotStorage};
use crate::types::packet::PacketHeader;

const STREAM_COUNT: usize = SMALL_SLOT_CAPACITY;
pub const STREAM_CLOSED: i32 = -libc::ECONNRESET;

#[derive(Default)]
struct StreamContext {
    buf: Option<IoBuf>,
    waker: Option<Waker>,
    err: i32,
    woken: bool,
    /// no future owns the staged send
    detached: bool,
    /// puts waiting for the staged send to be released
    waiters: Vec<Waker>,
}

impl StreamContext {
    fn complete(&mut self) -> Option<Waker> {
        self.woken = true;
        self.waker.take()
    }

    /// Ends the staged send. A detached buffer goes back to its pool.
    fn finish(&mut self) -> Option<Waker> {
        if !self.detached {
            return self.complete();
        }
        self.detached = false;
        self.buf = None;
        self.err = 0;
        self.wake_waiters();
        None
    }

    fn wake_waiters(&mut self) {
        for waker in self.waiters.drain(..) {
            waker.wake();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StreamId(IndexSlotId);

impl StreamId {
    fn slot(self) -> IndexSlotId {
        self.0
    }

    /// Decodes `PacketHeader::stream_id`. None when the index names no slot.
    pub fn from_wire(id: u32) -> Option<Self> {
        let slot = IndexSlotId::from_bits(id);
        (slot.idx() < STREAM_COUNT as u32).then_some(Self(slot))
    }

    pub fn to_wire(self) -> u32 {
        self.0.bits()
    }
}

struct StreamSlotStore {
    slots: UnsafeCell<SmallSlotStorage<StreamContext>>,
}

impl StreamSlotStore {
    fn new() -> Self {
        Self {
            slots: UnsafeCell::new(SmallSlotStorage::new()),
        }
    }

    fn access<'a, R>(&'a self, f: impl FnOnce(&'a mut SmallSlotStorage<StreamContext>) -> R) -> R {
        unsafe { f(&mut *self.slots.get()) }
    }

    fn open_stream(&self) -> Option<StreamId> {
        self.access(|slots| {
            let idx = slots.get()?;
            slots.set(idx, Default::default());
            Some(StreamId(idx))
        })
    }

    fn stream_or_insert(
        &self,
        idx: StreamId,
        init: impl FnOnce() -> StreamContext,
    ) -> Option<&mut StreamContext> {
        self.access(|slots| slots.get_or_insert(idx.slot(), init))
    }

    fn slot_at_mut(&self, idx: StreamId) -> Option<&mut StreamContext> {
        self.access(|slots| slots.index_mut(idx.slot()))
    }

    fn slot_at(&self, idx: StreamId) -> Option<&StreamContext> {
        self.access(|slots| slots.index_mut(idx.slot()).map(|slot| &*slot))
    }

    fn stream_ids(&self) -> impl Iterator<Item = StreamId> + '_ {
        self.access(|slots| slots.ids().map(StreamId))
    }

    fn close_stream(&self, idx: StreamId) {
        let closed = self.access(|slots| slots.put(idx.slot()));
        closed.expect("close of an unopened stream").wake_waiters();
    }

    fn open_streams(&self) -> usize {
        self.access(|slots| slots.occupied())
    }

    fn release(&self, idx: StreamId) -> (Option<IoBuf>, io::Result<usize>) {
        let slot = self.slot_at_mut(idx).expect("release on a closed stream");
        // errors are stored as -errno
        assert!(slot.err <= 0, "error code stored with the wrong sign");
        let buf = slot.buf.take();
        slot.waker = None;
        slot.woken = false;
        let err = -slot.err;
        let sent = buf
            .as_ref()
            .expect("release without a staged send")
            .used_bytes();
        slot.err = 0;
        slot.wake_waiters();
        (
            buf,
            if err == 0 {
                Ok(sent)
            } else {
                Err(io::Error::from_raw_os_error(err))
            },
        )
    }
}

pub(crate) struct StreamSendFuture {
    idx: Cell<Option<StreamId>>,
    slots: Rc<StreamSlotStore>,
}

impl StreamSendFuture {
    fn new(idx: StreamId, slots: Rc<StreamSlotStore>) -> Self {
        Self {
            idx: Cell::new(Some(idx)),
            slots,
        }
    }
}

impl Future for StreamSendFuture {
    type Output = (io::Result<usize>, IoBuf);
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let idx = self.idx.get().expect("polled after completion");
        if !self
            .slots
            .slot_at(idx)
            .expect("poll on a closed stream")
            .woken
        {
            self.slots
                .slot_at_mut(idx)
                .expect("poll on a closed stream")
                .waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        self.idx.set(None);
        let (buf, err) = self.slots.release(idx);
        Poll::Ready((err, buf.expect("completed send without a buffer")))
    }
}

impl Drop for StreamSendFuture {
    fn drop(&mut self) {
        if let Some(idx) = self.idx.get() {
            assert!(
                std::thread::panicking() || self.slots.slot_at(idx).is_some_and(|slot| slot.woken),
                "send future dropped while the staged buffer is still in the send ring"
            );
            let _ = self.slots.release(idx);
        }
    }
}

/// Sink for the messages of every session of one `SessionManager`.
/// `consume` runs inside the completion loop and must not re-enter the manager.
/// A negative `result` without `buf` ends the stream. Its owner then calls `close_stream` once.
pub trait MessageConsumer {
    fn consume(&self, result: i32, addr: SessionAddr, buf: Option<&[u8]>);
}

/// Borrows the stream table of one session for the length of a framer callback.
struct StreamMultiplexer<'a, C> {
    slots: &'a StreamSlotStore,
    consumer: &'a C,
    session: SessionId,
    client: bool,
}

impl<'a, C: MessageConsumer> StreamMultiplexer<'a, C> {
    fn new(slots: &'a StreamSlotStore, consumer: &'a C, session: SessionId, client: bool) -> Self {
        Self {
            slots,
            consumer,
            session,
            client,
        }
    }
}

impl<C: MessageConsumer> StreamConsumer for StreamMultiplexer<'_, C> {
    fn on_message(&mut self, msg: &[u8]) {
        let header = PacketHeader::peek(msg)
            .expect("framed message shorter than the header")
            .expect("framer accepted an undecodable header");
        debug_assert_eq!(
            msg.len(),
            PacketHeader::WIRE_SIZE + header.fragment_len as usize
        );
        let Some(idx) = StreamId::from_wire(header.stream_id) else {
            log::warn!("Stream {} out of range", header.stream_id);
            return;
        };
        let open = if self.client {
            self.slots.slot_at(idx).is_some()
        } else {
            self.slots
                .stream_or_insert(idx, StreamContext::default)
                .is_some()
        };

        if open {
            let addr = SessionAddr::new(self.session, idx);
            self.consumer.consume(msg.len() as i32, addr, Some(msg));
        } else {
            log::warn!("Stream {} not active", header.stream_id);
        }
    }

    fn on_end(&mut self, err: Option<io::Error>) {
        let err = err.map_or(STREAM_CLOSED, |err| {
            -err.raw_os_error().unwrap_or(libc::EPROTO)
        });
        let mut ids = [StreamId::default(); STREAM_COUNT];
        let mut len = 0;
        for id in self.slots.stream_ids() {
            ids[len] = id;
            len += 1;
        }
        for &id in &ids[..len] {
            self.consumer
                .consume(err, SessionAddr::new(self.session, id), None);
        }
    }
}

pub struct StreamManager {
    stream_order: Box<[StreamId]>,
    slots: Rc<StreamSlotStore>,
    head: usize,
    tail: usize,
    ring: SendRing,
    client: bool,
    framer: MessageFramer,
}

impl StreamManager {
    const ENTRIES: usize = STREAM_COUNT * 2;
    const fn wrap(idx: usize) -> usize {
        (idx) % Self::ENTRIES
    }

    pub fn new(client: bool, submitter: &Submitter, bgid: u16) -> Self {
        let mut ring = SendRing::new(Self::ENTRIES as u16).expect("mapping the send ring failed");
        ring.register(submitter, bgid).expect("Registration failed");
        Self {
            stream_order: vec![StreamId::default(); Self::ENTRIES].into_boxed_slice(),
            slots: Rc::new(StreamSlotStore::new()),
            head: 0,
            tail: 0,
            ring,
            client,
            framer: MessageFramer::new(),
        }
    }

    pub fn ref_cnt(&self) -> usize {
        self.slots.open_streams()
    }

    pub fn open_stream(&mut self) -> Option<StreamId> {
        self.slots.open_stream()
    }

    pub fn close_stream(&mut self, idx: StreamId) {
        assert!(!self.is_busy(idx), "closing a stream with a staged send");
        self.slots.close_stream(idx);
    }

    /// True while the stream holds a staged send.
    pub(crate) fn is_busy(&self, idx: StreamId) -> bool {
        self.slots
            .slot_at(idx)
            .is_some_and(|slot| slot.buf.is_some())
    }

    /// True while the stream holds a staged send; `waker` runs once it is released.
    pub(crate) fn wait_if_busy(&mut self, idx: StreamId, waker: &Waker) -> bool {
        let Some(slot) = self.slots.slot_at_mut(idx) else {
            return false;
        };
        let busy = slot.buf.is_some();
        if busy {
            slot.waiters.push(waker.clone());
        }
        busy
    }

    pub(crate) fn on_data<C: MessageConsumer>(
        &mut self,
        data: &[u8],
        session: SessionId,
        consumer: &C,
    ) {
        let mut mux = StreamMultiplexer::new(&self.slots, consumer, session, self.client);
        self.framer.on_data(data, &mut mux);
    }

    pub(crate) fn on_end<C: MessageConsumer>(
        &mut self,
        err: Option<io::Error>,
        session: SessionId,
        consumer: &C,
    ) {
        let mut mux = StreamMultiplexer::new(&self.slots, consumer, session, self.client);
        self.framer.on_end(err, &mut mux);
    }

    pub(crate) fn stage(&mut self, buf: IoBuf, idx: StreamId) -> Result<StreamSendFuture, IoBuf> {
        self.stage_inner(buf, idx, false)?;
        Ok(StreamSendFuture::new(idx, self.slots.clone()))
    }

    /// Stages a send no future waits for. Its buffer is dropped once the send ends.
    pub(crate) fn stage_detached(&mut self, buf: IoBuf, idx: StreamId) -> Result<(), IoBuf> {
        self.stage_inner(buf, idx, true)
    }

    fn stage_inner(&mut self, buf: IoBuf, idx: StreamId, detached: bool) -> Result<(), IoBuf> {
        assert!(buf.used_bytes() > 0, "staging an empty send");
        assert!(Self::wrap(self.head + 1) != self.tail);
        let addr = unsafe { buf.type_erased_ptr() };
        let len = buf.used_bytes();

        let Some(slot) = self.slots.slot_at_mut(idx) else {
            return Err(buf);
        };
        assert!(slot.buf.is_none(), "stream already has a send in flight");
        slot.buf = Some(buf);
        slot.waker = None;
        slot.err = 0;
        slot.woken = false;
        slot.detached = detached;

        self.stream_order[self.head] = idx;
        self.ring.push(addr, len as u32);
        self.head = Self::wrap(self.head + 1);
        Ok(())
    }

    /// Fails every staged send. The caller guarantees the kernel holds none of them.
    pub fn fail_queued(&mut self, err: i32) {
        if self.queued() == 0 {
            return;
        }

        panic!("TODO: Failed with {}", err);
    }

    /// Ends the send bundle in flight. A failed one fails every staged send.
    pub fn reap(&mut self, res: Result<usize, i32>, bid: Option<u16>) {
        let mut sent = match res {
            Ok(sent) => sent,
            Err(err) => return self.fail_queued(err),
        };
        let mut bid = bid.unwrap() as usize;
        assert!(sent > 0, "send completed without transferring anything");
        assert!(self.tail == bid);
        while sent > 0 {
            let idx = self.stream_order[bid];
            let buf_size = self.slots.access(|inner| {
                inner
                    .index_mut(idx.0)
                    .expect("invalid index")
                    .buf
                    .as_ref()
                    .unwrap()
                    .used_bytes()
            });
            assert!(sent >= buf_size);
            let waker = self.slots.slot_at_mut(idx).expect("invalid index").finish();
            if let Some(waker) = waker {
                waker.wake();
            }
            sent -= buf_size;
            bid = Self::wrap(bid + 1);
        }
        self.ring
            .consume(Self::wrap(bid + Self::ENTRIES - self.tail) as u16);
        self.tail = bid;
    }

    pub(super) fn flush(&mut self) {
        self.ring.flush();
    }

    pub(super) fn unregister(&mut self, submitter: &Submitter) {
        if let Err(e) = self.ring.unregister(submitter) {
            log::error!("unregistering send ring failed: {}", e);
        }
    }

    pub(super) fn queued(&self) -> usize {
        Self::wrap(self.head + Self::ENTRIES - self.tail)
    }
}
