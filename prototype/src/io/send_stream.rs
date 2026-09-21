use std::cell::{Cell, UnsafeCell};
use std::collections::VecDeque;
use std::ffi::c_void;
use std::rc::Rc;
use std::task::Poll;
use std::task::Waker;
use std::{io, vec};

use crate::runtime::waker_chain::WakerList;

use super::buffer::IoBuf;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamState {
    Idle,
    Queued,
    Kernel,
}

#[derive(Default)]
struct IoBufWakerContext {
    buf: Option<IoBuf>,
    waker: Option<Waker>,
    err: i32,
    woken: bool,
    generation: u32,
}

struct StreamSlotStore {
    slots: Box<[IoBufWakerContext]>,
    free: VecDeque<usize>,
    wakers: WakerList,
}

impl StreamSlotStore {
    fn new(len: usize) -> Self {
        Self {
            slots: (0..len).map(|_| IoBufWakerContext::default()).collect(),
            free: (0..len).collect(),
            wakers: WakerList::new(),
        }
    }

    fn get_slot(&mut self) -> Option<usize> {
        self.free.pop_front()
    }

    fn slot_at_mut(&mut self, idx: usize) -> &mut IoBufWakerContext {
        &mut self.slots[idx]
    }

    fn slot_at(&self, idx: usize) -> &IoBufWakerContext {
        &self.slots[idx]
    }

    fn free_slot(&mut self, idx: usize) {
        self.free.push_front(idx);
    }

    fn release(&mut self, idx: usize) -> (Option<IoBuf>, io::Result<usize>) {
        let slot = self.slot_at_mut(idx);
        let buf = slot.buf.take();
        slot.waker = None;
        slot.woken = false;
        let err = -slot.err;
        let sent = buf.as_ref().unwrap().used_bytes();
        slot.err = 0;
        slot.generation = slot.generation.wrapping_add(1);
        self.free_slot(idx);
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

pub(crate) struct SendStreamFuture {
    idx: Cell<Option<usize>>,
    generation: u32,
    slots: Rc<UnsafeCell<StreamSlotStore>>,
}

impl SendStreamFuture {
    fn new(idx: usize, generation: u32, slots: Rc<UnsafeCell<StreamSlotStore>>) -> Self {
        Self {
            idx: Cell::new(Some(idx)),
            generation,
            slots,
        }
    }

    fn access_state<R>(&self, f: impl FnOnce(&mut StreamSlotStore) -> R) -> R {
        unsafe { f(&mut *self.slots.get()) }
    }
}

impl Future for SendStreamFuture {
    type Output = (io::Result<usize>, IoBuf);
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let idx = self.idx.get().expect("polled after completion");
        let (ready, err) = self.access_state(|state| {
            debug_assert_eq!(state.slot_at(idx).generation, self.generation);
            if !state.slot_at(idx).woken {
                state.slot_at_mut(idx).waker = Some(cx.waker().clone());
                return (None, Ok(0));
            }
            self.idx.set(None);
            let res = state.release(idx);
            state.wakers.pop_wake_one();
            res
        });
        match ready {
            None => Poll::Pending,
            Some(buf) => Poll::Ready((err, buf)),
        }
    }
}

impl Drop for SendStreamFuture {
    fn drop(&mut self) {
        if let Some(idx) = self.idx.get() {
            self.access_state(|state| {
                let _ = state.release(idx);
            })
        }
    }
}

pub struct SendStreamState {
    iovec: Box<[libc::iovec]>,
    stream_order: Box<[(usize, u32)]>,
    slots: Rc<UnsafeCell<StreamSlotStore>>,
    head: usize,
    len: usize,
    msghdr: libc::msghdr,
    state: StreamState,
}

impl SendStreamState {
    pub fn new(len: usize) -> Self {
        Self {
            iovec: vec![Self::empty_iovec(); len].into_boxed_slice(),
            stream_order: vec![(0, 0); len].into_boxed_slice(),
            slots: Rc::new(UnsafeCell::new(StreamSlotStore::new(len))),
            head: 0,
            len,
            msghdr: unsafe { std::mem::zeroed() },
            state: StreamState::Idle,
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

    fn access_state<'a, R>(&'a self, f: impl FnOnce(&'a mut StreamSlotStore) -> R) -> R {
        unsafe { f(&mut *self.slots.get()) }
    }

    pub(crate) async fn stage(&mut self, buf: IoBuf) -> (SendStreamFuture, bool) {
        let idx = self.acquire_slot().await;
        assert!(self.head < self.len, "iovec ring is full");

        let iovec_item = libc::iovec {
            iov_base: unsafe { buf.type_erased_ptr() } as *mut c_void,
            iov_len: buf.used_bytes(),
        };

        let generation = self.access_state(|state| {
            let slot = state.slot_at_mut(idx);
            slot.buf = Some(buf);
            slot.waker = None;
            slot.err = 0;
            slot.woken = false;
            slot.generation
        });

        self.stream_order[self.head] = (idx, generation);
        self.iovec[self.head] = iovec_item;
        self.head += 1;

        let queue = self.state == StreamState::Idle;
        if queue {
            self.state = StreamState::Queued;
        }
        (
            SendStreamFuture::new(idx, generation, self.slots.clone()),
            queue,
        )
    }

    pub fn prepare(&mut self) -> *const libc::msghdr {
        assert!(self.state == StreamState::Queued && self.head > 0);
        self.msghdr.msg_iov = self.iovec.as_mut_ptr();
        self.msghdr.msg_iovlen = self.head;
        self.state = StreamState::Kernel;
        &self.msghdr
    }

    async fn acquire_slot(&mut self) -> usize {
        loop {
            if let Some(idx) = self.access_state(|state| state.get_slot()) {
                return idx;
            }
            let wakers = self.access_state(|state| &state.wakers);
            wakers.wait_for_ping().await;
        }
    }

    pub fn fail(&mut self, err: i32) -> bool {
        for &(idx, generation) in &self.stream_order[..self.head] {
            let waker = self.access_state(|state| {
                let slot = state.slot_at_mut(idx);
                if slot.generation != generation {
                    return None;
                }
                assert_eq!(slot.err, 0);
                slot.woken = true;
                slot.err = err;
                slot.waker.take()
            });
            if let Some(waker) = waker {
                waker.wake();
            }
        }
        self.head = 0;
        false
    }

    pub fn reap(&mut self, mut sent: usize) -> bool {
        assert_eq!(self.state, StreamState::Kernel);
        let mut last = 0usize;
        for _ in 0..self.head {
            if self.iovec[last].iov_len > sent {
                self.iovec[last].iov_len -= sent;
                unsafe { self.iovec[last].iov_base = self.iovec[last].iov_base.add(sent) };
                break;
            }
            sent -= self.iovec[last].iov_len;
            let (idx, generation) = self.stream_order[last];
            let waker = self.access_state(|state| {
                let slot = state.slot_at_mut(idx);
                if slot.generation != generation {
                    return None;
                }
                slot.woken = true;
                slot.waker.take()
            });
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
