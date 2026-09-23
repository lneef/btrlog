use std::cell::{Cell, UnsafeCell};
use std::ffi::c_void;
use std::rc::Rc;
use std::task::Poll;
use std::task::Waker;
use std::{io, vec};

use self::StreamState::Kernel;

use super::buffer::IoBuf;
use super::framing::{MessageFramer, StreamConsumer};
use super::session::{SessionAddr, SessionId};
use super::slot_storage::{IndexSlotId, SMALL_SLOT_CAPACITY, SmallSlotStorage};
use crate::types::packet::PacketHeader;

const STREAM_COUNT: usize = SMALL_SLOT_CAPACITY;
pub const STREAM_CLOSED: i32 = -libc::ECONNRESET;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamState {
    Idle,
    Queued,
    Kernel,
}

#[derive(Default)]
struct StreamContext {
    buf: Option<IoBuf>,
    waker: Option<Waker>,
    err: i32,
    woken: bool,
    /// puts waiting for the staged send to be released
    waiters: Vec<Waker>,
}

impl StreamContext {
    fn complete(&mut self) -> Option<Waker> {
        self.woken = true;
        self.waker.take()
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
                "send future dropped while the staged buffer is still in the iovec"
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
    iovec: Box<[libc::iovec]>,
    stream_order: Box<[StreamId]>,
    slots: Rc<StreamSlotStore>,
    head: usize,
    msghdr: libc::msghdr,
    state: StreamState,
    client: bool,
    framer: MessageFramer,
}

impl StreamManager {
    pub fn new(client: bool) -> Self {
        Self {
            iovec: vec![Self::empty_iovec(); STREAM_COUNT].into_boxed_slice(),
            stream_order: vec![StreamId::default(); STREAM_COUNT].into_boxed_slice(),
            slots: Rc::new(StreamSlotStore::new()),
            head: 0,
            msghdr: unsafe { std::mem::zeroed() },
            state: StreamState::Idle,
            client,
            framer: MessageFramer::new(),
        }
    }

    pub fn state(&self) -> StreamState {
        self.state
    }

    const fn empty_iovec() -> libc::iovec {
        libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }
    }

    pub fn ref_cnt(&self) -> usize {
        self.slots.open_streams() + (self.state == Kernel) as usize
    }

    pub fn open_stream(&mut self) -> Option<StreamId> {
        self.slots.open_stream()
    }

    pub fn close_stream(&mut self, idx: StreamId) {
        self.slots.close_stream(idx);
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

    pub(crate) fn stage(
        &mut self,
        buf: IoBuf,
        idx: StreamId,
    ) -> Result<(StreamSendFuture, bool), IoBuf> {
        assert!(self.head < STREAM_COUNT, "iovec ring is full");
        assert!(buf.used_bytes() > 0, "staging an empty send");

        let iovec_item = libc::iovec {
            iov_base: unsafe { buf.type_erased_ptr() } as *mut c_void,
            iov_len: buf.used_bytes(),
        };

        let Some(slot) = self.slots.slot_at_mut(idx) else {
            return Err(buf);
        };
        assert!(slot.buf.is_none(), "stream already has a send in flight");
        slot.buf = Some(buf);
        slot.waker = None;
        slot.err = 0;
        slot.woken = false;

        self.stream_order[self.head] = idx;
        self.iovec[self.head] = iovec_item;
        self.head += 1;

        let queue = self.state == StreamState::Idle;
        if queue {
            self.state = StreamState::Queued;
        }
        Ok((StreamSendFuture::new(idx, self.slots.clone()), queue))
    }

    pub fn prepare(&mut self) -> *const libc::msghdr {
        assert!(
            self.state == StreamState::Queued && self.head > 0,
            "prepare without a queued send"
        );
        self.msghdr.msg_iov = self.iovec.as_mut_ptr();
        self.msghdr.msg_iovlen = self.head;
        self.state = StreamState::Kernel;
        &self.msghdr
    }

    /// Fails every staged send the kernel does not hold.
    pub fn fail_queued(&mut self, err: i32) {
        assert!(err < 0, "errors are stored as -errno");
        assert_ne!(
            self.state,
            StreamState::Kernel,
            "failing sends the kernel still reads"
        );
        for &idx in &self.stream_order[..self.head] {
            let waker = {
                let slot = self
                    .slots
                    .slot_at_mut(idx)
                    .expect("failed send on a closed stream");
                assert_eq!(slot.err, 0, "stream failed twice");
                slot.err = err;
                slot.complete()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
        self.head = 0;
        self.state = StreamState::Idle;
    }

    /// Ends the send in flight. True when sends are left to submit.
    pub fn reap(&mut self, res: Result<usize, i32>) -> bool {
        assert_eq!(self.state, StreamState::Kernel);
        let mut sent = match res {
            Ok(sent) => sent,
            Err(err) => {
                self.state = StreamState::Queued;
                self.fail_queued(err);
                return false;
            }
        };
        assert!(sent > 0, "send completed without transferring anything");
        let mut last = 0usize;
        for _ in 0..self.head {
            if self.iovec[last].iov_len > sent {
                self.iovec[last].iov_len -= sent;
                unsafe { self.iovec[last].iov_base = self.iovec[last].iov_base.add(sent) };
                break;
            }
            sent -= self.iovec[last].iov_len;
            let idx = self.stream_order[last];
            let waker = self
                .slots
                .slot_at_mut(idx)
                .expect("completed send on a closed stream")
                .complete();
            if let Some(waker) = waker {
                waker.wake();
            }
            last += 1;
        }
        self.stream_order.copy_within(last..self.head, 0);
        self.iovec.copy_within(last..self.head, 0);
        self.head -= last;
        self.state = if self.head > 0 {
            StreamState::Queued
        } else {
            StreamState::Idle
        };
        self.head > 0
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Tests

#[cfg(test)]
mod tests {
    use super::*;

    struct Rec(Rc<std::cell::RefCell<Vec<StreamId>>>);

    impl MessageConsumer for Rec {
        fn consume(&self, _result: i32, addr: SessionAddr, _buf: Option<&[u8]>) {
            self.0.borrow_mut().push(addr.stream());
        }
    }

    /// Multiplexer over `slots`, addressing streams on the default session.
    fn mux<'a, C: MessageConsumer>(
        slots: &'a StreamSlotStore,
        consumer: &'a C,
        client: bool,
    ) -> StreamMultiplexer<'a, C> {
        StreamMultiplexer::new(slots, consumer, SessionId::default(), client)
    }

    /// Wire form of a stream at `idx` in its `generation`.
    fn wire(idx: u16, generation: u16) -> u32 {
        StreamId(IndexSlotId::new(idx, generation)).to_wire()
    }

    /// Bodyless frame addressed to a wire stream id.
    fn frame(msg_id: u64, stream_id: u32) -> Vec<u8> {
        use crate::types::wire::auto::WireMessage as _;
        let hdr = PacketHeader {
            msg_id,
            reply_to: 0,
            stream_id,
            fragment_len: 0,
        };
        let mut scratch = [0u8; 64];
        let n = hdr.encode_into(&mut scratch).unwrap();
        assert_eq!(n, PacketHeader::WIRE_SIZE);
        scratch[..n].to_vec()
    }

    #[test]
    fn test_wire_id_roundtrip() {
        let mut mux = StreamManager::new(false);
        let id = mux.open_stream().unwrap();
        assert_eq!(StreamId::from_wire(id.to_wire()), Some(id));
        mux.close_stream(id);
        // the index comes back, the wire id does not
        let again = mux.open_stream().unwrap();
        assert_ne!(again.to_wire(), id.to_wire());
        assert_eq!(StreamId::from_wire(again.to_wire()), Some(again));
    }

    #[test]
    fn test_reopened_stream_starts_clean() {
        let mut mux = StreamManager::new(false);
        let stale = mux.open_stream().unwrap();
        mux.close_stream(stale);
        assert_eq!(mux.ref_cnt(), 0);
        let id = mux.open_stream().unwrap();
        assert_ne!(id, stale);
        assert_eq!(mux.ref_cnt(), 1);

        let mut buf = crate::io::local_packet_buffer_pool().pop();
        buf.mark_used(4);
        let buf = mux.stage(buf, stale).err().expect("staged on a closed stream");
        let (fut, queue) = mux.stage(buf, id).unwrap();
        assert!(queue);
        mux.prepare();
        assert!(!mux.reap(Ok(4)));
        assert_eq!(mux.state(), StreamState::Idle);

        let mut cx = std::task::Context::from_waker(Waker::noop());
        let Poll::Ready((res, _buf)) = std::pin::pin!(fut).poll(&mut cx) else {
            panic!("completed send still pending");
        };
        assert_eq!(res.unwrap(), 4);
        mux.close_stream(id);
        assert_eq!(mux.ref_cnt(), 0);
    }

    #[test]
    fn test_wire_index_out_of_range_is_rejected() {
        assert!(StreamId::from_wire(wire((STREAM_COUNT - 1) as u16, 1)).is_some());
        assert!(StreamId::from_wire(wire(STREAM_COUNT as u16, 1)).is_none());
        assert!(StreamId::from_wire(u32::MAX).is_none());

        let seen = Rc::new(std::cell::RefCell::new(Vec::new()));
        let slots = StreamSlotStore::new();
        let rec = Rec(seen.clone());
        mux(&slots, &rec, false).on_message(&frame(1, wire(STREAM_COUNT as u16, 1)));
        assert!(seen.borrow().is_empty());
        assert_eq!(slots.open_streams(), 0);
    }

    #[test]
    fn test_server_rejects_a_recycled_stream() {
        let seen = Rc::new(std::cell::RefCell::new(Vec::new()));
        let slots = StreamSlotStore::new();
        let rec = Rec(seen.clone());
        let mut mux = mux(&slots, &rec, false);
        let live = wire(3, 5);
        let stale = wire(3, 4);

        mux.on_message(&frame(42, live));
        assert_eq!(
            seen.borrow().as_slice(),
            [StreamId::from_wire(live).unwrap()]
        );
        // same index, the generation the peer used before we recycled it
        mux.on_message(&frame(42, stale));
        assert_eq!(seen.borrow().len(), 1, "stale generation delivered");
        // generation 0 never addresses a stream
        mux.on_message(&frame(42, wire(3, 0)));
        assert_eq!(seen.borrow().len(), 1, "unset generation delivered");
        // a stream carries more than one request
        mux.on_message(&frame(43, live));
        mux.on_message(&frame(44, live));
        assert_eq!(seen.borrow().len(), 3);
    }

    #[test]
    fn test_end_notifies_open_streams() {
        let seen = Rc::new(std::cell::RefCell::new(Vec::new()));
        let slots = StreamSlotStore::new();
        let rec = Rec(seen.clone());
        let mut mux = mux(&slots, &rec, false);
        let a = wire(3, 5);
        let b = wire(9, 2);
        mux.on_message(&frame(1, a));
        mux.on_message(&frame(2, b));
        assert_eq!(slots.open_streams(), 2);

        mux.on_end(None);
        assert_eq!(slots.open_streams(), 2, "the owner closes its streams");
        assert_eq!(seen.borrow().len(), 4);
        assert_eq!(
            seen.borrow()[2..],
            [
                StreamId::from_wire(a).unwrap(),
                StreamId::from_wire(b).unwrap()
            ]
        );
        slots.close_stream(StreamId::from_wire(a).unwrap());
        slots.close_stream(StreamId::from_wire(b).unwrap());
        assert_eq!(slots.open_streams(), 0);
    }

    #[test]
    fn test_end_notifies_a_sending_stream() {
        let seen = Rc::new(std::cell::RefCell::new(Vec::new()));
        let rec = Rec(seen.clone());
        let mut mux = StreamManager::new(false);
        let id = mux.open_stream().unwrap();
        let mut buf = crate::io::local_packet_buffer_pool().pop();
        buf.mark_used(4);
        let (_fut, _) = mux.stage(buf, id).unwrap();

        mux.on_end(None, SessionId::default(), &rec);
        assert_eq!(mux.slots.open_streams(), 1, "a staged send lost its stream");
        assert_eq!(seen.borrow().as_slice(), [id]);
        // the sender is woken, the caller closes once it has reaped the buffer
        mux.fail_queued(STREAM_CLOSED);
        assert_eq!(mux.slots.open_streams(), 1);
    }

    #[test]
    fn test_failed_send_wakes_every_staged_stream() {
        let mut mux = StreamManager::new(false);
        let ids = [mux.open_stream().unwrap(), mux.open_stream().unwrap()];
        let futs = ids.map(|id| {
            let mut buf = crate::io::local_packet_buffer_pool().pop();
            buf.mark_used(4);
            mux.stage(buf, id).unwrap().0
        });
        mux.prepare();
        assert_eq!(mux.ref_cnt(), 3, "two streams and the send in flight");
        assert!(!mux.reap(Err(-libc::ECONNRESET)));
        assert_eq!(mux.state(), StreamState::Idle);
        assert_eq!(mux.ref_cnt(), 2);
        let mut cx = std::task::Context::from_waker(Waker::noop());
        for fut in futs {
            let Poll::Ready((res, _buf)) = std::pin::pin!(fut).poll(&mut cx) else {
                panic!("failed send still pending");
            };
            assert_eq!(res.unwrap_err().raw_os_error(), Some(libc::ECONNRESET));
        }
    }

    #[test]
    fn test_open_stream_count() {
        let mut mux = StreamManager::new(false);
        assert_eq!(mux.slots.open_streams(), 0);
        let first = mux.open_stream().unwrap();
        mux.open_stream().unwrap();
        mux.open_stream().unwrap();
        assert_eq!(mux.slots.open_streams(), 3);
        mux.close_stream(first);
        assert_eq!(mux.slots.open_streams(), 2);
    }
}
