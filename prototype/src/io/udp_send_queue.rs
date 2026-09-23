//! Per-socket UDP send queue that coalesces sends with GSO (UDP_SEGMENT).
//!
//! `send_to` doesn't enqueue an SQE; it appends the buffer to the queue of
//! its destination. Right before the ring is entered (once per event loop
//! iteration, via a pre-submit hook) every destination queue is flushed:
//! runs of consecutive buffers with identical length become one sendmsg with
//! gso_size = that length, gathering the buffers with an iovec (no copy).
//! Everything else, including a queue holding a single buffer (the low-load
//! case), goes out as a plain send, exactly like `ThreadUring::send_to`.
//! One message per segment, no padding, no packing; receivers without GRO
//! see the same datagrams as without GSO.
//!
//! The futures resolve on completion of the send that carried their buffer
//! and hand the buffer back, so callers can reuse it for retries as before.
//! If the kernel rejects GSO (no checksum offload on the device, segment
//! larger than the path MTU, ...), GSO is turned off for this queue and the
//! affected buffers are sent again as plain sends.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::SocketAddr,
    ops::Range,
    os::fd::RawFd,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, Waker},
};

use io_uring::{opcode, types};
use smallvec::SmallVec;

use crate::runtime::rcwaker::RcWaker;

use super::{
    ThreadUring,
    buffer::IoBuf,
    udp_offload::{self, MAX_GSO_SEGMENTS, MAX_UDP_PAYLOAD, SendCmsgBuf},
    uring::{OpId, PreSubmitHook, UringContext},
};

////////////////////////////////////////////////////////////////////////////////
//  grouping

/// How many of the leading messages (by length, in queue order) go into the
/// next send: a run of identical lengths, at most `max_segments` of them and
/// at most `max_bytes` in total; 1 if GSO is off
pub fn next_group_len(mut lens: impl Iterator<Item = usize>, gso: bool, max_segments: usize, max_bytes: usize) -> usize {
    let Some(first) = lens.next() else { return 0 };
    if !gso || first == 0 || first > u16::MAX as usize {
        return 1;
    }
    let cap = max_segments.min(max_bytes / first).max(1);
    1 + lens.take(cap - 1).take_while(|&len| len == first).count()
}

/// Splits a destination's queue into sends, see `next_group_len`
pub fn plan_sends(lens: &[usize], gso: bool, max_segments: usize, max_bytes: usize) -> Vec<Range<usize>> {
    let mut res = Vec::new();
    let mut start = 0;
    while start < lens.len() {
        let n = next_group_len(lens[start..].iter().copied(), gso, max_segments, max_bytes);
        res.push(start..start + n);
        start += n;
    }
    res
}

/// FIFO queues per destination; only destinations with queued messages are
/// kept, so the linear search stays short
struct DestQueues<T> {
    queues: Vec<(SocketAddr, VecDeque<T>)>,
}

impl<T> DestQueues<T> {
    const fn new() -> Self {
        Self { queues: Vec::new() }
    }

    fn push(&mut self, to: SocketAddr, item: T) {
        match self.queues.iter_mut().find(|(addr, _)| *addr == to) {
            Some((_, queue)) => queue.push_back(item),
            None => self.queues.push((to, VecDeque::from([item]))),
        }
    }

    /// put items back in front of the queue, keeping their order
    fn push_front_all(&mut self, to: SocketAddr, items: impl DoubleEndedIterator<Item = T>) {
        let idx = match self.queues.iter().position(|(addr, _)| *addr == to) {
            Some(idx) => idx,
            None => {
                self.queues.push((to, VecDeque::new()));
                self.queues.len() - 1
            }
        };
        for item in items.rev() {
            self.queues[idx].1.push_front(item);
        }
    }

    fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    fn take(&mut self) -> Vec<(SocketAddr, VecDeque<T>)> {
        std::mem::take(&mut self.queues)
    }
}

////////////////////////////////////////////////////////////////////////////////
//  queue state

type EntryId = u32;
type BatchId = u32;
type Wakers = SmallVec<[Waker; MAX_GSO_SEGMENTS]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryState {
    Free,
    Queued,
    InFlight(BatchId),
    /// bytes sent or -errno
    Done(i32),
}

struct Entry {
    state: EntryState,
    buf: Option<IoBuf>,
    waker: Option<Waker>,
    /// the future was dropped; free the entry once the kernel is done with the buffer
    abandoned: bool,
}

/// one submitted send; boxed, since the SQE points into it until completion
struct InFlight {
    op: OpId,
    to: SocketAddr,
    entries: SmallVec<[EntryId; MAX_GSO_SEGMENTS]>,
    gso: bool,
    completed: bool,
    addr: socket2::SockAddr,
    iov: [libc::iovec; MAX_GSO_SEGMENTS],
    msg: libc::msghdr,
    cmsg: SendCmsgBuf,
}

struct QueueState {
    entries: Vec<Entry>,
    free_entries: Vec<EntryId>,
    queued: DestQueues<EntryId>,
    batches: Vec<Option<Box<InFlight>>>,
    free_batches: Vec<BatchId>,
    /// recycled batches, to not allocate per send
    spare: Vec<Box<InFlight>>,
    completed: usize,
}

impl QueueState {
    fn alloc_entry(&mut self, buf: IoBuf) -> EntryId {
        let entry = Entry {
            state: EntryState::Queued,
            buf: Some(buf),
            waker: None,
            abandoned: false,
        };
        match self.free_entries.pop() {
            Some(id) => {
                self.entries[id as usize] = entry;
                id
            }
            None => {
                self.entries.push(entry);
                (self.entries.len() - 1) as EntryId
            }
        }
    }

    fn free_entry(&mut self, id: EntryId) {
        let entry = &mut self.entries[id as usize];
        entry.state = EntryState::Free;
        entry.buf = None; // back to its pool
        entry.waker = None;
        self.free_entries.push(id);
    }

    fn alloc_batch(&mut self, batch: Box<InFlight>) -> BatchId {
        match self.free_batches.pop() {
            Some(id) => {
                self.batches[id as usize] = Some(batch);
                id
            }
            None => {
                self.batches.push(Some(batch));
                (self.batches.len() - 1) as BatchId
            }
        }
    }

    fn free_batch(&mut self, id: BatchId) -> Box<InFlight> {
        self.free_batches.push(id);
        self.batches[id as usize].take().expect("freeing unknown batch")
    }

    fn buf_len(&self, id: EntryId) -> usize {
        self.entries[id as usize].buf.as_ref().map(|b| b.used_bytes()).unwrap_or(0)
    }

    /// returns the waker to wake once the state isn't borrowed anymore
    fn finish_entry(&mut self, id: EntryId, result: i32) -> Option<Waker> {
        let entry = &mut self.entries[id as usize];
        if entry.abandoned {
            self.free_entry(id);
            return None;
        }
        entry.state = EntryState::Done(result);
        entry.waker.take()
    }
}

////////////////////////////////////////////////////////////////////////////////
//  queue

pub struct UdpSendQueue {
    fd: RawFd,
    io: ThreadUring,
    gso: Cell<bool>,
    state: RefCell<QueueState>,
}

impl UdpSendQueue {
    /// `gso`: coalesce equal-sized sends; if false, this only defers sends
    /// to the next ring enter
    pub fn new(fd: RawFd, io: &ThreadUring, gso: bool) -> Rc<Self> {
        let res = Rc::new(Self {
            fd,
            io: io.clone(),
            gso: Cell::new(gso),
            state: RefCell::new(QueueState {
                entries: Vec::new(),
                free_entries: Vec::new(),
                queued: DestQueues::new(),
                batches: Vec::new(),
                free_batches: Vec::new(),
                spare: Vec::new(),
                completed: 0,
            }),
        });
        let hook: Rc<dyn PreSubmitHook> = res.clone();
        io.register_presubmit_hook(Rc::downgrade(&hook));
        res
    }

    pub fn gso_active(&self) -> bool {
        self.gso.get()
    }

    /// queue `buf` (its used bytes) for `to`; it's sent on the next ring enter.
    /// Resolves once the send completed, returning the buffer like `ThreadUring::send_to`
    pub fn send_to(self: &Rc<Self>, to: SocketAddr, buf: IoBuf) -> QueuedSend {
        let mut state = self.state.borrow_mut();
        let id = state.alloc_entry(buf);
        state.queued.push(to, id);
        QueuedSend {
            queue: self.clone(),
            id,
            finished: false,
        }
    }

    /// distribute results of completed sends to their entries
    fn reap(&self, ctx: &mut UringContext) {
        let mut wakers = Wakers::new();
        self.reap_inner(ctx, &mut wakers);
        wakers.into_iter().for_each(Waker::wake);
    }

    fn reap_inner(&self, ctx: &mut UringContext, wakers: &mut Wakers) {
        let mut state = self.state.borrow_mut();
        if state.completed == 0 {
            return;
        }
        for batch_id in 0..state.batches.len() as BatchId {
            let (op, done) = match &state.batches[batch_id as usize] {
                Some(batch) => (batch.op, batch.completed),
                None => continue,
            };
            if !done {
                continue;
            }
            let result = match ctx.take_result(op, Waker::noop()) {
                Poll::Ready(((Ok(n), _), _)) => n,
                Poll::Ready(((Err(e), _), _)) => -e.raw_os_error().unwrap_or(libc::EIO),
                Poll::Pending => {
                    log::error!("send marked as completed is pending in uring");
                    continue;
                }
            };
            state.completed -= 1;
            let batch = state.free_batch(batch_id);
            self.on_batch_done(&mut state, &batch, result, wakers);
            state.spare.push(batch);
        }
    }

    fn on_batch_done(&self, state: &mut QueueState, batch: &InFlight, result: i32, wakers: &mut Wakers) {
        if result < 0 && batch.gso && Self::is_gso_error(-result) {
            // like quinn-udp: EIO means the device/driver can't do the checksum
            // offload GSO needs; fall back to plain sends for this socket and
            // resend the segments. Other GSO batches in flight may fail too,
            // but only the first one logs and counts.
            if self.gso.replace(false) {
                eprintln!(
                    "UDP GSO send of {} segments to {:?} failed ({}); falling back to plain sends on fd {}",
                    batch.entries.len(),
                    batch.to,
                    io::Error::from_raw_os_error(-result),
                    self.fd
                );
                udp_offload::record(|s| s.gso_fallbacks += 1);
            }
            for id in batch.entries.iter() {
                state.entries[*id as usize].state = EntryState::Queued;
            }
            state.queued.push_front_all(batch.to, batch.entries.iter().copied());
            return;
        }
        if result >= 0 {
            let _total: usize = batch.entries.iter().map(|id| state.buf_len(*id)).sum();
            debug_assert_eq!(_total, result as usize);
        }
        for id in batch.entries.iter() {
            let res = if result < 0 { result } else { state.buf_len(*id) as i32 };
            wakers.extend(state.finish_entry(*id, res));
        }
    }

    /// EIO: no checksum offload on the egress device (what quinn-udp handles);
    /// EINVAL/EMSGSIZE: gso_size + headers > path MTU, or segment limit;
    /// EOPNOTSUPP/ENOPROTOOPT: kernel without UDP_SEGMENT
    fn is_gso_error(errno: i32) -> bool {
        matches!(errno, libc::EIO | libc::EINVAL | libc::EOPNOTSUPP | libc::EMSGSIZE | libc::ENOPROTOOPT)
    }

    /// submit all queued messages; returns the number of enqueued SQEs
    fn flush(self: &Rc<Self>, ctx: &mut UringContext) -> usize {
        let mut state = self.state.borrow_mut();
        if state.queued.is_empty() {
            return 0;
        }
        let mut enqueued = 0;
        let mut stalled = false;
        for (to, mut queue) in state.queued.take() {
            while !stalled && !queue.is_empty() {
                let lens = queue.iter().map(|id| state.buf_len(*id));
                let n = next_group_len(lens, self.gso.get(), MAX_GSO_SEGMENTS, MAX_UDP_PAYLOAD);
                let group: SmallVec<[EntryId; MAX_GSO_SEGMENTS]> = queue.drain(..n).collect();
                match self.submit_group(ctx, &mut state, to, &group) {
                    Ok(()) => enqueued += 1,
                    Err(()) => {
                        // out of uring slots / SQ space; retry on the next enter
                        state.queued.push_front_all(to, group.into_iter());
                        stalled = true;
                    }
                }
            }
            if !queue.is_empty() {
                state.queued.push_front_all(to, queue.into_iter());
            }
        }
        enqueued
    }

    fn submit_group(
        self: &Rc<Self>,
        ctx: &mut UringContext,
        state: &mut QueueState,
        to: SocketAddr,
        group: &[EntryId],
    ) -> Result<(), ()> {
        debug_assert!(!group.is_empty() && group.len() <= MAX_GSO_SEGMENTS);
        let op = ctx.register_op().ok_or(())?;
        let gso = group.len() > 1;
        let mut batch = match state.spare.pop() {
            Some(batch) => batch,
            None => Box::new(InFlight {
                op,
                to,
                entries: SmallVec::new(),
                gso,
                completed: false,
                addr: socket2::SockAddr::from(to),
                iov: [libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                }; MAX_GSO_SEGMENTS],
                msg: unsafe { std::mem::zeroed() },
                cmsg: SendCmsgBuf::new(),
            }),
        };
        batch.op = op;
        batch.to = to;
        batch.entries.clear();
        batch.entries.extend_from_slice(group);
        batch.gso = gso;
        batch.completed = false;
        batch.addr = socket2::SockAddr::from(to);
        batch.msg = unsafe { std::mem::zeroed() };
        let sqe = if gso {
            let segment_size = state.buf_len(group[0]);
            for (iov, id) in batch.iov.iter_mut().zip(group.iter()) {
                let buf = state.entries[*id as usize].buf.as_ref().expect("queued entry without buffer");
                debug_assert_eq!(buf.used_bytes(), segment_size);
                *iov = libc::iovec {
                    iov_base: buf.ptr_mut() as *mut libc::c_void,
                    iov_len: buf.used_bytes(),
                };
            }
            let batch = &mut *batch;
            batch.msg.msg_name = batch.addr.as_ptr() as *mut libc::c_void; // not written by sendmsg
            batch.msg.msg_namelen = batch.addr.len();
            batch.msg.msg_iov = batch.iov.as_mut_ptr();
            batch.msg.msg_iovlen = group.len();
            batch.cmsg.attach_segment_size(&mut batch.msg, segment_size as u16);
            opcode::SendMsg::new(types::Fd(self.fd), &batch.msg as *const libc::msghdr).build()
        } else {
            // same as ThreadUring::send
            let buf = state.entries[group[0] as usize].buf.as_ref().expect("queued entry without buffer");
            opcode::Send::new(types::Fd(self.fd), buf.ptr(), buf.used_bytes() as u32)
                .dest_addr(batch.addr.as_ptr() as *const libc::sockaddr)
                .dest_addr_len(batch.addr.len())
                .build()
        };
        let batch_id = state.alloc_batch(batch);
        let _registered = ctx.register_waker(op, SendCompletionWaker::new_rc_waker(self, batch_id as u16));
        debug_assert!(_registered);
        if ctx.enqueue_retry_once(sqe.user_data(op.into_user_data())).is_err() {
            ctx.drop_registered_op(op);
            let batch = state.free_batch(batch_id);
            state.spare.push(batch);
            return Err(());
        }
        for id in group {
            state.entries[*id as usize].state = EntryState::InFlight(batch_id);
        }
        let segments = group.len() as u64;
        udp_offload::record(|s| {
            if gso {
                s.gso_sends += 1;
                s.gso_segments += segments;
                s.gso_max_segments = s.gso_max_segments.max(segments);
            } else {
                s.plain_sends += 1;
            }
        });
        Ok(())
    }

    fn on_send_completion(&self, batch_id: BatchId) {
        let mut wakers = Wakers::new();
        self.on_send_completion_inner(batch_id, &mut wakers);
        wakers.into_iter().for_each(Waker::wake);
    }

    fn on_send_completion_inner(&self, batch_id: BatchId, wakers: &mut Wakers) {
        let mut state = self.state.borrow_mut();
        let Some(batch) = state.batches[batch_id as usize].as_mut() else {
            log::error!("completion for unknown send batch {}", batch_id);
            return;
        };
        debug_assert!(!batch.completed);
        batch.completed = true;
        let entries = batch.entries.clone();
        state.completed += 1;
        // the futures reap the result (or the next flush does, if they're gone)
        for id in entries {
            wakers.extend(state.entries[id as usize].waker.take());
        }
    }
}

impl PreSubmitHook for UdpSendQueue {
    fn before_submit(self: Rc<Self>, ctx: &mut UringContext) -> usize {
        self.reap(ctx);
        let enqueued = self.flush(ctx);
        udp_offload::maybe_report_offload_stats();
        enqueued
    }
}

/// woken by the uring once the send in batch `tag` completed
struct SendCompletionWaker;
impl RcWaker for SendCompletionWaker {
    type Handler = UdpSendQueue;

    fn on_wake(handler: Rc<Self::Handler>, tag: u16) {
        handler.on_send_completion(tag as BatchId);
    }

    fn on_wake_by_ref(handler: &Rc<Self::Handler>, tag: u16) {
        handler.on_send_completion(tag as BatchId);
    }
}

////////////////////////////////////////////////////////////////////////////////
//  future

pub struct QueuedSend {
    queue: Rc<UdpSendQueue>,
    id: EntryId,
    finished: bool,
}

impl Future for QueuedSend {
    type Output = (io::Result<usize>, IoBuf);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let queue = self.queue.clone();
        let state = queue.state.borrow().entries[self.id as usize].state;
        if let EntryState::InFlight(_) = state {
            if queue.state.borrow().completed > 0 {
                queue.io.access(|ctx| queue.reap(ctx));
            }
        }
        let mut state = queue.state.borrow_mut();
        let entry = &mut state.entries[self.id as usize];
        match entry.state {
            EntryState::Done(result) => {
                let buf = entry.buf.take().expect("finished entry without buffer");
                state.free_entry(self.id);
                self.finished = true;
                let res = if result < 0 { Err(io::Error::from_raw_os_error(-result)) } else { Ok(result as usize) };
                Poll::Ready((res, buf))
            }
            EntryState::Queued | EntryState::InFlight(_) => {
                entry.waker = Some(cx.waker().clone());
                Poll::Pending
            }
            EntryState::Free => panic!("polled send {} after it finished", self.id),
        }
    }
}

impl Drop for QueuedSend {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut state = self.queue.state.borrow_mut();
        let entry = &mut state.entries[self.id as usize];
        match entry.state {
            // the buffer is (or will be) in use by the kernel; freed on completion
            EntryState::Queued | EntryState::InFlight(_) => {
                entry.abandoned = true;
                entry.waker = None;
            }
            EntryState::Done(_) => state.free_entry(self.id),
            EntryState::Free => {}
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
//  tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        io::{
            uring::IOEnterIntent,
            watermark::{PacketConsumer, RecvOptions, WatermarkRecv},
        },
        runtime::{Executor, ThreadRuntime, test_exec, test_rt},
    };
    use std::{os::fd::AsRawFd, time::Duration};

    #[test]
    fn groups_runs_of_equal_length() {
        let lens = [194, 194, 194, 80, 80, 194, 194, 50];
        assert_eq!(plan_sends(&lens, true, 64, MAX_UDP_PAYLOAD), vec![0..3, 3..5, 5..7, 7..8]);
        // a single message is a plain send
        assert_eq!(plan_sends(&[194], true, 64, MAX_UDP_PAYLOAD), vec![0..1]);
        assert_eq!(plan_sends(&[], true, 64, MAX_UDP_PAYLOAD), vec![]);
    }

    #[test]
    fn gso_off_sends_one_by_one() {
        let lens = [194, 194, 194];
        assert_eq!(plan_sends(&lens, false, 64, MAX_UDP_PAYLOAD), vec![0..1, 1..2, 2..3]);
    }

    #[test]
    fn caps_segments_and_bytes() {
        // segment cap
        let lens = vec![194; 150];
        assert_eq!(plan_sends(&lens, true, MAX_GSO_SEGMENTS, MAX_UDP_PAYLOAD), vec![0..64, 64..128, 128..150]);
        // byte cap: 8000 * 8 = 64000 <= 65507 < 8000 * 9
        let lens = vec![8000; 20];
        assert_eq!(plan_sends(&lens, true, MAX_GSO_SEGMENTS, MAX_UDP_PAYLOAD), vec![0..8, 8..16, 16..20]);
        // larger than half the byte cap -> one per send
        let lens = vec![40000; 2];
        assert_eq!(plan_sends(&lens, true, MAX_GSO_SEGMENTS, MAX_UDP_PAYLOAD), vec![0..1, 1..2]);
        // gso_size must fit the u16 cmsg
        assert_eq!(next_group_len([65536usize, 65536].into_iter(), true, 64, usize::MAX), 1);
    }

    #[test]
    fn splits_per_destination_in_order() {
        let (a, b): (SocketAddr, SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
        let mut queues = DestQueues::new();
        for (idx, to) in [a, b, a, a, b].into_iter().enumerate() {
            queues.push(to, idx);
        }
        let taken = queues.take();
        assert!(queues.is_empty());
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].0, a);
        assert_eq!(taken[0].1.iter().copied().collect::<Vec<_>>(), vec![0, 2, 3]);
        assert_eq!(taken[1].0, b);
        assert_eq!(taken[1].1.iter().copied().collect::<Vec<_>>(), vec![1, 4]);
        // requeueing keeps the order in front of newer messages
        queues.push(a, 9);
        queues.push_front_all(a, [2, 3].into_iter());
        assert_eq!(queues.take()[0].1.iter().copied().collect::<Vec<_>>(), vec![2, 3, 9]);
    }

    #[test]
    fn gso_failure_falls_back_to_plain_sends_once() {
        let io = ThreadUring::new(Default::default()).expect("error creating uring");
        let sock = io.udp_bind("127.0.4.51:8510".parse::<SocketAddr>().unwrap()).expect("error binding socket");
        let queue = UdpSendQueue::new(sock.as_raw_fd(), &io, true);
        let to: SocketAddr = "127.0.4.52:8511".parse().unwrap();
        let pool = crate::io::local_packet_buffer_pool();
        let before = udp_offload::thread_offload_stats().gso_fallbacks;
        let mut sends: Vec<_> = (0..4)
            .map(|_| {
                let mut buf = pool.pop();
                buf.mark_used(194);
                queue.send_to(to, buf)
            })
            .collect();
        // pretend the first three went out as one GSO send that failed with EIO,
        // and a concurrent GSO send of the fourth failed as well
        let mut state = queue.state.borrow_mut();
        let mut queued = state.queued.take();
        assert_eq!(queued.len(), 1);
        let ids: Vec<EntryId> = queued[0].1.drain(..).collect();
        let fake_batch = |entries: &[EntryId]| InFlight {
            op: OpId::default(),
            to,
            entries: SmallVec::from_slice(entries),
            gso: true,
            completed: true,
            addr: socket2::SockAddr::from(to),
            iov: [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; MAX_GSO_SEGMENTS],
            msg: unsafe { std::mem::zeroed() },
            cmsg: SendCmsgBuf::new(),
        };
        let mut wakers = Wakers::new();
        queue.on_batch_done(&mut state, &fake_batch(&ids[..3]), -libc::EIO, &mut wakers);
        assert!(!queue.gso_active());
        queue.on_batch_done(&mut state, &fake_batch(&ids[3..]), -libc::EIO, &mut wakers);
        // counted and logged once; all four requeued in order, not failed
        assert_eq!(udp_offload::thread_offload_stats().gso_fallbacks - before, 1);
        assert!(wakers.is_empty());
        let queued = state.queued.take();
        assert_eq!(queued[0].1.iter().copied().collect::<Vec<_>>(), vec![ids[3], ids[0], ids[1], ids[2]]);
        assert!(ids.iter().all(|id| state.entries[*id as usize].state == EntryState::Queued));
        // without GSO, the queue plans one plain send per message
        let lens: Vec<_> = ids.iter().map(|id| state.buf_len(*id)).collect();
        assert_eq!(plan_sends(&lens, queue.gso_active(), MAX_GSO_SEGMENTS, MAX_UDP_PAYLOAD).len(), 4);
        // a plain send failing with EIO is just an error
        queue.on_batch_done(&mut state, &InFlight { gso: false, ..fake_batch(&ids[..1]) }, -libc::EIO, &mut wakers);
        assert_eq!(state.entries[ids[0] as usize].state, EntryState::Done(-libc::EIO));
        drop(state);
        sends.clear(); // abandon the rest
    }

    /// counts messages; each message is `[len: u32][tag byte repeated]`
    struct CountingConsumer {
        from: SocketAddr,
        received: RefCell<Vec<Vec<u8>>>,
    }

    impl PacketConsumer for CountingConsumer {
        fn consume_raw(&self, result: i32, from: SocketAddr, buf: IoBuf, _id: OpId) {
            assert!(result > 0, "recv error {}", result);
            assert_eq!(from, self.from);
            self.received.borrow_mut().push(buf.as_slice()[..result as usize].to_vec());
        }
    }

    fn message(tag: u8, len: usize) -> Vec<u8> {
        let mut msg = vec![tag; len];
        udp_offload::write_frag_len(&mut msg, 0, len);
        msg
    }

    /// queued sends of equal size are coalesced into GSO sends, which a GRO
    /// receiver gets as coalesced buffers and splits again
    #[test]
    fn test_queued_gso_sends_to_gro_receiver() {
        let recv_addr: SocketAddr = "127.0.4.50:8500".parse().unwrap();
        let sender_addr: SocketAddr = "127.0.5.50:8501".parse().unwrap();
        // 70 x 194B (-> 64 + 6 segments), then 3 x 60B, then one 1000B message
        let mut messages: Vec<Vec<u8>> = (0..70).map(|i| message(i as u8, 194)).collect();
        messages.extend((0..3).map(|i| message(100 + i, 60)));
        messages.push(message(200, 1000));
        let expected = messages.clone();
        let barrier = &std::sync::Barrier::new(2);
        std::thread::scope(|s| {
            s.spawn(move || {
                let ring = ThreadUring::new(Default::default()).expect("error creating uring");
                let sock = ring.udp_bind(recv_addr).expect("error binding recv socket");
                let opts = RecvOptions {
                    framing: udp_offload::RecvFraming::LengthChecked { offset: 0 },
                    gro: true,
                };
                let consumer = CountingConsumer {
                    from: sender_addr,
                    received: RefCell::new(Vec::new()),
                };
                let watermark = WatermarkRecv::with_options(sock.as_raw_fd(), ring.clone(), 8, opts, consumer);
                barrier.wait();
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while watermark.consumer().received.borrow().len() < expected.len() && std::time::Instant::now() < deadline {
                    ring.enter(IOEnterIntent::Submit);
                    watermark.poll_completed();
                }
                let mut received = watermark.consumer().received.borrow().clone();
                received.sort();
                let mut expected = expected.clone();
                expected.sort();
                assert_eq!(received, expected);
                let stats = udp_offload::thread_offload_stats();
                assert!(stats.gro_multi_segment_recvs > 0, "no coalesced receive: {}", stats);
                assert_eq!(stats.frag_len_mismatches, 0, "{}", stats);
            });

            test_rt().with_executor(Default::default(), || async move {
                let io = test_exec().io().clone();
                let sock = io.udp_bind(sender_addr).expect("error binding sender socket");
                let queue = UdpSendQueue::new(sock.as_raw_fd(), &io, true);
                let bufpool = crate::io::local_packet_buffer_pool();
                barrier.wait();
                let before = udp_offload::thread_offload_stats();
                // queue everything before the first ring enter
                let sends = messages.iter().map(|msg| {
                    let mut buf = bufpool.pop();
                    buf.as_mut_slice()[..msg.len()].copy_from_slice(msg);
                    buf.mark_used(msg.len());
                    queue.send_to(recv_addr, buf)
                });
                let results = crate::runtime::future::join_all(sends).await;
                for ((res, buf), msg) in results.into_iter().zip(messages.iter()) {
                    assert_eq!(res.expect("send failed"), msg.len());
                    // buffers come back intact, e.g. for retries
                    assert_eq!(buf.as_slice(), msg.as_slice());
                }
                let stats = udp_offload::thread_offload_stats();
                assert_eq!(stats.gso_sends - before.gso_sends, 3, "{}", stats); // 64 + 6 + 3
                assert_eq!(stats.gso_segments - before.gso_segments, 73);
                assert_eq!(stats.gso_max_segments, 64);
                assert_eq!(stats.plain_sends - before.plain_sends, 1); // the 1000B one
                // at low load, a single queued send is a plain send
                // (to ourselves, the receiver already got everything it expects)
                let msg = message(250, 194);
                let mut buf = bufpool.pop();
                buf.as_mut_slice()[..msg.len()].copy_from_slice(&msg);
                buf.mark_used(msg.len());
                let (res, _buf) = queue.send_to(sender_addr, buf).await;
                assert_eq!(res.expect("send failed"), msg.len());
                let stats = udp_offload::thread_offload_stats();
                assert_eq!(stats.plain_sends - before.plain_sends, 2);
                assert_eq!(stats.gso_sends - before.gso_sends, 3);
            })
        });
    }
}
