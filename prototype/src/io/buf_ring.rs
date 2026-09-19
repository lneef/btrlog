use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU16, Ordering};

use io_uring::types::BufRingEntry;
use io_uring::{Submitter, cqueue, opcode, squeue, types};

pub const BUF_SIZE: usize = 2048 + 64;

const ENTRY_SIZE: usize = std::mem::size_of::<BufRingEntry>();
const MAX_ENTRIES: u16 = 1 << 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufId(pub u16);

/// Buffer handed back by a multishot recv CQE. Must be released exactly once.
#[derive(Clone, Copy, Debug)]
pub struct RecvBuf {
    pub bid: BufId,
    pub len: usize,
}

////////////////////////////////////////////////////////////////////////////////
//  Provided buffer ring

/// Every bid is in exactly one of: pool, ring, user code.
pub struct BufRing {
    map: *mut u8,
    map_len: usize,
    storage_offset: usize,
    entries: u16,
    tail: u16,
    bgid: u16,
    registered: bool,
    pool: Vec<u16>,
}

impl BufRing {
    pub fn new(bgid: u16, entries: u16) -> io::Result<Self> {
        assert!(entries.is_power_of_two() && entries <= MAX_ENTRIES);
        use libc::{MAP_ANONYMOUS, MAP_POPULATE, MAP_PRIVATE, PROT_READ, PROT_WRITE};
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let storage_offset = (entries as usize * ENTRY_SIZE).next_multiple_of(page_size);
        let map_len = storage_offset + entries as usize * BUF_SIZE;
        // SAFETY: anonymous mapping, no file, no fixed address
        let map = unsafe { libc::mmap(std::ptr::null_mut(), map_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0) };
        if map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            map: map as *mut u8,
            map_len,
            storage_offset,
            entries,
            tail: 0,
            bgid,
            registered: false,
            pool: (0..entries).rev().collect(),
        })
    }

    pub fn register(&mut self, sub: &Submitter) -> io::Result<()> {
        assert!(!self.registered);
        // SAFETY: the mapping outlives the registration, Drop asserts unregistered
        unsafe { sub.register_buf_ring_with_flags(self.ring_ptr() as u64, self.entries, self.bgid, 0)? };
        self.registered = true;
        Ok(())
    }

    pub fn unregister(&mut self, sub: &Submitter) -> io::Result<()> {
        assert!(self.registered);
        sub.unregister_buf_ring(self.bgid)?;
        self.registered = false;
        Ok(())
    }

    /// Moves up to `n` pooled buffers into the ring. Returns the count moved.
    pub fn promote(&mut self, n: usize) -> usize {
        let n = n.min(self.pool.len());
        for _ in 0..n {
            let bid = self.pool.pop().expect("pool empty");
            self.push_entry(bid);
        }
        n
    }

    /// Returns a buffer received from the kernel into the ring.
    pub fn release(&mut self, bid: BufId) {
        self.push_entry(bid.0);
    }

    /// Publishes all pending entries to the kernel.
    pub fn flush(&mut self) {
        // SAFETY: ring_ptr() is the initialized page-aligned ring base
        let tail = unsafe { AtomicU16::from_ptr(BufRingEntry::tail(self.ring_ptr()) as *mut u16) };
        tail.store(self.tail, Ordering::Release);
    }

    /// Buffer handed over by `cqe`, independent of the result value.
    pub fn resolve(&self, cqe: &cqueue::Entry) -> Option<RecvBuf> {
        cqueue::buffer_select(cqe.flags()).map(|bid| {
            let len = cqe.result().max(0) as usize;
            debug_assert!(len <= BUF_SIZE);
            RecvBuf { bid: BufId(bid), len }
        })
    }

    pub fn data(&self, buf: RecvBuf) -> &[u8] {
        assert!(buf.len <= BUF_SIZE);
        // SAFETY: buf_ptr() asserts the bid, len is within the buffer
        unsafe { std::slice::from_raw_parts(self.buf_ptr(buf.bid.0), buf.len) }
    }

    pub fn recv_multi(&self, fd: RawFd) -> squeue::Entry {
        opcode::RecvMulti::new(types::Fd(fd), self.bgid).build()
    }

    pub fn bgid(&self) -> u16 {
        self.bgid
    }

    pub fn entries(&self) -> u16 {
        self.entries
    }

    pub fn pooled(&self) -> usize {
        self.pool.len()
    }

    fn push_entry(&mut self, bid: u16) {
        let idx = (self.tail & (self.entries - 1)) as usize;
        let addr = self.buf_ptr(bid) as u64;
        // SAFETY: idx < entries, ring memory is owned by self
        let entry = unsafe { &mut *self.ring_ptr().add(idx) };
        entry.set_addr(addr);
        entry.set_len(BUF_SIZE as u32);
        entry.set_bid(bid);
        self.tail = self.tail.wrapping_add(1);
    }

    fn ring_ptr(&self) -> *mut BufRingEntry {
        self.map as *mut BufRingEntry
    }

    fn buf_ptr(&self, bid: u16) -> *mut u8 {
        assert!(bid < self.entries);
        // SAFETY: offset stays within the mapping
        unsafe { self.map.add(self.storage_offset + bid as usize * BUF_SIZE) }
    }
}

impl Drop for BufRing {
    fn drop(&mut self) {
        debug_assert!(!self.registered, "BufRing dropped while registered");
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

    fn shared_tail(ring: &BufRing) -> u16 {
        unsafe { *BufRingEntry::tail(ring.ring_ptr()) }
    }

    fn entry(ring: &BufRing, idx: usize) -> &BufRingEntry {
        unsafe { &*ring.ring_ptr().add(idx) }
    }

    #[test]
    fn test_layout() {
        let ring = BufRing::new(7, 8).unwrap();
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert_eq!(ring.pooled(), 8);
        assert_eq!(ring.ring_ptr() as usize % page, 0);
        assert_eq!(ring.buf_ptr(0) as usize % 64, 0);
        for i in 1..8 {
            assert_eq!(ring.buf_ptr(i) as usize - ring.buf_ptr(i - 1) as usize, BUF_SIZE);
        }
    }

    #[test]
    fn test_promote_flush() {
        let mut ring = BufRing::new(7, 8).unwrap();
        assert_eq!(ring.promote(3), 3);
        assert_eq!(ring.pooled(), 5);
        assert_eq!(shared_tail(&ring), 0);
        ring.flush();
        assert_eq!(shared_tail(&ring), 3);
        for i in 0..3u16 {
            let e = entry(&ring, i as usize);
            assert_eq!(e.bid(), i);
            assert_eq!(e.len(), BUF_SIZE as u32);
            assert_eq!(e.addr(), ring.buf_ptr(i) as u64);
        }
    }

    #[test]
    fn test_release() {
        let mut ring = BufRing::new(7, 8).unwrap();
        ring.promote(3);
        ring.flush();
        ring.release(BufId(1));
        assert_eq!(shared_tail(&ring), 3);
        ring.flush();
        assert_eq!(shared_tail(&ring), 4);
        assert_eq!(entry(&ring, 3).bid(), 1);
    }

    #[test]
    fn test_wraparound() {
        let mut ring = BufRing::new(7, 8).unwrap();
        assert_eq!(ring.promote(usize::MAX), 8);
        assert_eq!(ring.promote(1), 0);
        for bid in 0..8u16 {
            ring.release(BufId(bid));
        }
        ring.flush();
        assert_eq!(shared_tail(&ring), 16);
        assert_eq!(entry(&ring, 5).bid(), 5);
        ring.tail = u16::MAX;
        ring.release(BufId(2));
        ring.flush();
        assert_eq!(shared_tail(&ring), 0);
        assert_eq!(entry(&ring, 7).bid(), 2);
    }

    #[test]
    fn test_data() {
        let mut ring = BufRing::new(7, 8).unwrap();
        let buf = RecvBuf { bid: BufId(3), len: 5 };
        unsafe { ring.buf_ptr(3).copy_from_nonoverlapping(b"hello".as_ptr(), 5) };
        assert_eq!(ring.data(buf), b"hello");
        ring.release(buf.bid);
        ring.flush();
    }

    // requires io_uring; blocked in the sandbox
    #[test]
    fn test_register_recv() {
        use io_uring::IoUring;
        use std::net::UdpSocket;
        use std::os::fd::AsRawFd;

        let mut ring = IoUring::new(8).unwrap();
        let mut bufs = BufRing::new(0, 16).unwrap();
        bufs.register(&ring.submitter()).unwrap();
        bufs.promote(16);
        bufs.flush();

        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sqe = bufs.recv_multi(rx.as_raw_fd()).user_data(42);
        unsafe { ring.submission().push(&sqe).unwrap() };
        ring.submit().unwrap();
        tx.send_to(b"ping", rx.local_addr().unwrap()).unwrap();
        ring.submit_and_wait(1).unwrap();

        let cqe = ring.completion().next().unwrap();
        assert_eq!(cqe.user_data(), 42);
        assert!(cqueue::more(cqe.flags()));
        let buf = bufs.resolve(&cqe).unwrap();
        assert_eq!(bufs.data(buf), b"ping");
        bufs.release(buf.bid);
        bufs.flush();

        bufs.unregister(&ring.submitter()).unwrap();
    }
}
