use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU16, Ordering};

use io_uring::types::BufRingEntry;
use io_uring::{Submitter, opcode, squeue, types};

use super::buf_ring::BufId;

const ENTRY_SIZE: usize = std::mem::size_of::<BufRingEntry>();
const MAX_ENTRIES: u16 = 1 << 15;

////////////////////////////////////////////////////////////////////////////////
//  Provided buffer ring for send bundles

/// Outgoing byte queue of one socket. Entries point into buffers the caller keeps alive
/// until `consume` retires them. The bid of an entry is its ring position.
pub struct SendRing {
    map: *mut u8,
    map_len: usize,
    entries: u16,
    /// oldest entry the kernel has not consumed
    head: u16,
    tail: u16,
    /// tail last stored to the shared ring
    published: u16,
    bgid: Option<u16>,
}

impl SendRing {
    pub fn new(entries: u16) -> io::Result<Self> {
        assert!(entries.is_power_of_two() && entries <= MAX_ENTRIES);
        use libc::{MAP_ANONYMOUS, MAP_POPULATE, MAP_PRIVATE, PROT_READ, PROT_WRITE};
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let map_len = (entries as usize * ENTRY_SIZE).next_multiple_of(page_size);
        // SAFETY: anonymous mapping, no file, no fixed address
        let map = unsafe { libc::mmap(std::ptr::null_mut(), map_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0) };
        if map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            map: map as *mut u8,
            map_len,
            entries,
            head: 0,
            tail: 0,
            published: 0,
            bgid: None,
        })
    }

    pub fn register(&mut self, sub: &Submitter, bgid: u16) -> io::Result<()> {
        assert!(self.bgid.is_none());
        // SAFETY: the mapping outlives the registration, Drop asserts unregistered
        unsafe { sub.register_buf_ring_with_flags(self.ring_ptr() as u64, self.entries, bgid, 0)? };
        self.bgid = Some(bgid);
        Ok(())
    }

    pub fn unregister(&mut self, sub: &Submitter) -> io::Result<()> {
        let bgid = self.bgid.expect("unregister of an unregistered send ring");
        sub.unregister_buf_ring(bgid)?;
        self.bgid = None;
        Ok(())
    }

    /// Queues `len` bytes at `addr` behind the staged entries.
    pub fn push(&mut self, addr: *const u8, len: u32) -> BufId {
        assert!(self.staged() < self.entries as usize, "send ring is full");
        assert!(len > 0, "queueing an empty send");
        let bid = self.tail & (self.entries - 1);
        // SAFETY: bid < entries, ring memory is owned by self
        let entry = unsafe { &mut *self.ring_ptr().add(bid as usize) };
        entry.set_addr(addr as u64);
        entry.set_len(len);
        entry.set_bid(bid);
        self.tail = self.tail.wrapping_add(1);
        BufId(bid)
    }

    /// Publishes all pending entries to the kernel. No-op without pending entries.
    pub fn flush(&mut self) {
        if self.tail == self.published {
            return;
        }
        // SAFETY: ring_ptr() is the initialized page-aligned ring base
        let tail = unsafe { AtomicU16::from_ptr(BufRingEntry::tail(self.ring_ptr()) as *mut u16) };
        tail.store(self.tail, Ordering::Release);
        self.published = self.tail;
    }

    /// Retires the `n` oldest entries once the kernel has consumed them.
    pub fn consume(&mut self, n: u16) {
        assert!(n <= self.published.wrapping_sub(self.head), "consumed unpublished entries");
        self.head = self.head.wrapping_add(n);
    }

    /// Entries pushed and not yet consumed, published or not.
    pub fn staged(&self) -> usize {
        self.tail.wrapping_sub(self.head) as usize
    }

    /// Bid of the oldest staged entry.
    pub fn head(&self) -> BufId {
        BufId(self.head & (self.entries - 1))
    }

    pub fn send_bundle(&self, fd: RawFd) -> squeue::Entry {
        let bgid = self.bgid.expect("send bundle on an unregistered send ring");
        opcode::SendBundle::new(types::Fd(fd), bgid)
            .flags(libc::MSG_NOSIGNAL)
            .build()
    }

    pub fn bgid(&self) -> Option<u16> {
        self.bgid
    }

    pub fn entries(&self) -> u16 {
        self.entries
    }

    fn ring_ptr(&self) -> *mut BufRingEntry {
        self.map as *mut BufRingEntry
    }
}

impl Drop for SendRing {
    fn drop(&mut self) {
        debug_assert!(self.bgid.is_none(), "SendRing dropped while registered");
        // SAFETY: map/map_len originate from mmap in new()
        let res = unsafe { libc::munmap(self.map as *mut libc::c_void, self.map_len) };
        if res < 0 {
            panic!("munmap failed {}", io::Error::last_os_error());
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_tail(ring: &SendRing) -> u16 {
        unsafe { *BufRingEntry::tail(ring.ring_ptr()) }
    }

    fn entry(ring: &SendRing, idx: usize) -> &BufRingEntry {
        unsafe { &*ring.ring_ptr().add(idx) }
    }

    #[test]
    fn test_push_flush() {
        let data = [0u8; 16];
        let mut ring = SendRing::new(8).unwrap();
        assert_eq!(ring.push(data.as_ptr(), 4), BufId(0));
        assert_eq!(ring.push(data[4..].as_ptr(), 12), BufId(1));
        assert_eq!(ring.staged(), 2);
        assert_eq!(shared_tail(&ring), 0);
        ring.flush();
        assert_eq!(shared_tail(&ring), 2);
        let e = entry(&ring, 1);
        assert_eq!((e.bid(), e.len(), e.addr()), (1, 12, data[4..].as_ptr() as u64));
    }

    #[test]
    fn test_consume_wraparound() {
        let data = [0u8; 1];
        let mut ring = SendRing::new(8).unwrap();
        for _ in 0..8 {
            ring.push(data.as_ptr(), 1);
        }
        ring.flush();
        ring.consume(5);
        assert_eq!((ring.staged(), ring.head()), (3, BufId(5)));
        assert_eq!(ring.push(data.as_ptr(), 1), BufId(0));
        ring.head = u16::MAX;
        ring.tail = u16::MAX;
        ring.published = u16::MAX;
        assert_eq!(ring.push(data.as_ptr(), 1), BufId(7));
        assert_eq!(ring.push(data.as_ptr(), 1), BufId(0));
        ring.flush();
        assert_eq!(shared_tail(&ring), 1);
        ring.consume(2);
        assert_eq!(ring.staged(), 0);
    }

    #[test]
    #[should_panic(expected = "send ring is full")]
    fn test_push_past_capacity_panics() {
        let data = [0u8; 1];
        let mut ring = SendRing::new(8).unwrap();
        for _ in 0..9 {
            ring.push(data.as_ptr(), 1);
        }
    }

    #[test]
    #[should_panic(expected = "consumed unpublished entries")]
    fn test_consume_unpublished_panics() {
        let data = [0u8; 1];
        let mut ring = SendRing::new(8).unwrap();
        ring.push(data.as_ptr(), 1);
        ring.consume(1);
    }

    // requires io_uring; blocked in the sandbox
    #[test]
    fn test_register_send_bundle() {
        use io_uring::{IoUring, cqueue};
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::AsRawFd;

        let mut uring = IoUring::new(8).unwrap();
        let mut ring = SendRing::new(8).unwrap();
        ring.register(&uring.submitter(), 3).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tx = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut rx, _) = listener.accept().unwrap();
        ring.push(b"ping".as_ptr(), 4);
        ring.push(b"pong".as_ptr(), 4);
        ring.flush();

        let sqe = ring.send_bundle(tx.as_raw_fd()).user_data(42);
        unsafe { uring.submission().push(&sqe).unwrap() };
        uring.submit_and_wait(1).unwrap();

        let cqe = uring.completion().next().unwrap();
        assert_eq!((cqe.user_data(), cqe.result()), (42, 8));
        assert_eq!(cqueue::buffer_select(cqe.flags()), Some(0));
        ring.consume(2);
        let mut got = [0u8; 8];
        rx.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"pingpong");

        ring.unregister(&uring.submitter()).unwrap();
    }
}
