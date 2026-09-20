use std::cell::{Cell, UnsafeCell};
use std::collections::VecDeque;
use std::ffi::c_void;
use std::rc::Rc;
use std::task::Poll;
use std::task::Waker;
use std::{io, vec};

use crate::runtime::waker_chain::WakerList;

use super::buffer::IoBuf;

#[derive(Default)]
struct IoBufWakerContext {
    buf: Option<IoBuf>,
    waker: Option<Waker>,
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
}

pub(crate) struct SendStreamFuture {
    polled_once: Cell<bool>,
    idx: usize,
    slots: Rc<UnsafeCell<StreamSlotStore>>,
}

impl SendStreamFuture {
    fn new(idx: usize, slots: Rc<UnsafeCell<StreamSlotStore>>) -> Self {
        Self {
            polled_once: Cell::new(false),
            idx,
            slots,
        }
    }

    fn access_state<R>(&self, f: impl FnOnce(&mut StreamSlotStore) -> R) -> R {
        unsafe { f(&mut *self.slots.get()) }
    }
}

impl Future for SendStreamFuture {
    type Output = IoBuf;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if !self.polled_once.get() {
            self.access_state(|state| {
                state.slots[self.idx].waker = Some(cx.waker().clone());
            });
            self.polled_once.set(true);
            Poll::Pending
        } else {
            let buf = self.access_state(|state| {
                let buf = state.slot_at_mut(self.idx).buf.take().unwrap();
                state.free_slot(self.idx);
                buf
            });
            self.access_state(|state| state.wakers.pop_wake_one());
            Poll::Ready(buf)
        }
    }
}

pub struct SendStreamState {
    iovec: Box<[libc::iovec]>,
    stream_order: Box<[usize]>,
    slots: Rc<UnsafeCell<StreamSlotStore>>,
    head: usize,
    len: usize,
}

impl SendStreamState {
    pub fn new(len: usize) -> Self {
        Self {
            iovec: vec![Self::empty_iovec(); len].into_boxed_slice(),
            stream_order: vec![0; len].into_boxed_slice(),
            slots: Rc::new(UnsafeCell::new(StreamSlotStore::new(len))),
            head: 0,
            len,
        }
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

    pub fn prepare_iovec(&mut self) -> (&mut [libc::iovec], usize) {
        (self.iovec.as_mut(), self.head)
    }

    pub async fn put(&mut self, buf: IoBuf) -> IoBuf {
        assert!(self.head < self.len, "iovec ring is full");

        let idx = self.acquire_slot().await;

        let iovec_item = libc::iovec {
            iov_base: unsafe { buf.type_erased_ptr() } as *mut c_void,
            iov_len: buf.used_bytes(),
        };

        self.access_state(|state| {
            *state.slot_at_mut(idx) = IoBufWakerContext {
                err: None,
                buf: Some(buf),
                waker: None,
            };
        });

        self.stream_order[self.head] = idx;
        self.iovec[self.head] = iovec_item;
        self.head += 1;

        SendStreamFuture::new(idx, self.slots.clone()).await
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

    pub fn reap(&mut self, ret: io::Result<usize>) {
        let mut sent = ret.unwrap();
        let mut last = 0usize;
        for _ in 0..self.head {
            if self.iovec[last].iov_len > sent {
                self.iovec[last].iov_len -= sent;
                unsafe { self.iovec[last].iov_base = self.iovec[last].iov_base.add(sent) };
                break;
            }
            sent -= self.iovec[last].iov_len;
            let waker = self.access_state(|state| {
                state
                    .slot_at(self.stream_order[last])
                    .waker
                    .clone()
                    .unwrap()
            });
            waker.wake();
            last += 1;
        }
        self.stream_order.copy_within(last..self.head, 0);
        self.iovec.copy_within(last..self.head, 0);
        self.head -= last;
    }
}
