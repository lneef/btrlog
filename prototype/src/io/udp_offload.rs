//! UDP segmentation offload (GSO, `UDP_SEGMENT`) on send and receive offload
//! (GRO, `UDP_GRO`) on receive.
//!
//! Wire format: one application message per datagram, as without offload.
//! Messages start with a header that carries the message's total encoded
//! length as little-endian u32 at a fixed offset (`PacketHeader::frag_len`).
//!
//! Send: `udp_send_queue::UdpSendQueue` (used by server and client) gathers
//! runs of equal-sized messages to one destination into one sendmsg with an
//! UDP_SEGMENT cmsg (`ThreadUring::send_to_gso` does the same for a single
//! buffer); the kernel (or NIC) cuts it into one datagram per segment.
//!
//! Receive: with UDP_GRO the kernel may coalesce datagrams of the same flow
//! into one buffer and reports the original datagram size (gso_size) via
//! cmsg; all datagrams but the last have exactly that size. Since every
//! datagram is one message, cutting the buffer at gso_size recovers the
//! messages (`Segments`). `frag_len` is only a consistency check
//! (`frag_len_matches`), not the source of truth: a mismatch is counted and
//! the datagram is still delivered as is. `WatermarkRecv` hands every
//! segment to the consumer separately, so consumers never see a coalesced buffer.
//!
//! Partial messages: unlike TCP, there is no per-socket leftover. UDP keeps
//! datagram boundaries, GRO only merges whole datagrams, and messages never
//! span datagrams. A message can only be incomplete if the receive buffer was
//! too small (MSG_TRUNC), and then the kernel discarded the tail, so there is
//! nothing to stitch it to later. Receive buffers are 64KiB, which fits any
//! UDP datagram and the default GRO aggregate limit (gro_max_size = 64KiB).

use std::{ops::Range, os::fd::RawFd};

////////////////////////////////////////////////////////////////////////////////
//  framing

/// How received datagrams map to application messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvFraming {
    /// every datagram is one message
    Datagram,
    /// every datagram is one message whose header carries its total length
    /// as little-endian u32 at `offset`; the length is checked, and
    /// mismatches are counted (`OffloadStats::frag_len_mismatches`)
    LengthChecked { offset: usize },
}

#[inline]
pub fn read_frag_len(msg: &[u8], offset: usize) -> Option<usize> {
    let field = msg.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(field.try_into().unwrap()) as usize)
}

#[inline]
pub fn write_frag_len(msg: &mut [u8], offset: usize, len: usize) {
    debug_assert!(len <= u32::MAX as usize);
    msg[offset..offset + 4].copy_from_slice(&(len as u32).to_le_bytes());
}

/// whether a datagram's length field agrees with its length
#[inline]
pub fn frag_len_matches(datagram: &[u8], framing: RecvFraming) -> bool {
    match framing {
        RecvFraming::Datagram => true,
        RecvFraming::LengthChecked { offset } => read_frag_len(datagram, offset) == Some(datagram.len()),
    }
}

/// The datagrams in a received buffer of `len` bytes: consecutive
/// `segment_size` byte ranges, the last one possibly shorter
pub struct Segments {
    len: usize,
    segment_size: usize,
    start: usize,
}

impl Segments {
    /// `segment_size`: GRO segment size, or None if the buffer is a single datagram
    pub fn new(len: usize, segment_size: Option<usize>) -> Self {
        let segment_size = match segment_size {
            Some(size) if size > 0 => size,
            _ => len.max(1),
        };
        Self { len, segment_size, start: 0 }
    }

    pub fn count(len: usize, segment_size: Option<usize>) -> usize {
        match segment_size {
            Some(size) if size > 0 => len.div_ceil(size),
            _ => 1,
        }
    }
}

impl Iterator for Segments {
    type Item = Range<usize>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.start >= self.len {
            return None;
        }
        let end = (self.start + self.segment_size).min(self.len);
        let res = self.start..end;
        self.start = end;
        Some(res)
    }
}

////////////////////////////////////////////////////////////////////////////////
//  receive offload (GRO)

/// room for the UDP_GRO cmsg (CMSG_SPACE(sizeof(int)) = 24 bytes)
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(super) struct RecvCmsgBuf(pub [u8; 64]);

impl RecvCmsgBuf {
    pub(super) const fn new() -> Self {
        Self([0u8; 64])
    }
}

pub fn enable_udp_gro(fd: RawFd) -> std::io::Result<()> {
    setsockopt_int(fd, libc::SOL_UDP, libc::UDP_GRO, 1)
}

fn setsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> std::io::Result<()> {
    let res = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if res < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

/// returns the GRO segment size from a completed recvmsg's control data
///
/// SAFETY: `msg` must be a msghdr filled in by the kernel whose msg_control
/// (if non-null) points to msg_controllen valid bytes
pub(super) unsafe fn gro_segment_size(msg: &libc::msghdr) -> Option<usize> {
    if msg.msg_control.is_null() {
        return None;
    }
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == libc::UDP_GRO {
                let size = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int);
                return if size > 0 { Some(size as usize) } else { None };
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

////////////////////////////////////////////////////////////////////////////////
//  segmentation offload (GSO)

/// upper bound of segments per sendmsg. The kernel's UDP_MAX_SEGMENTS was 64
/// when UDP GSO was added (4.18) and raised to 128 in 6.9 (so 6.14 allows 128);
/// sends above the limit fail with EINVAL. 64 is safe on every GSO kernel.
pub const MAX_GSO_SEGMENTS: usize = 64;
/// 65535 - IPv4 header - UDP header
pub const MAX_UDP_PAYLOAD: usize = 65507;

/// room for the UDP_SEGMENT cmsg (CMSG_SPACE(sizeof(u16)) = 24 bytes)
#[repr(C, align(8))]
pub(super) struct SendCmsgBuf([u8; 32]);

impl SendCmsgBuf {
    pub(super) const fn new() -> Self {
        Self([0u8; 32])
    }

    /// point `msg`'s control data at this buffer, holding an UDP_SEGMENT
    /// cmsg that tells the kernel to cut the payload into `segment_size` datagrams
    pub(super) fn attach_segment_size(&mut self, msg: &mut libc::msghdr, segment_size: u16) {
        msg.msg_control = self.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = self.0.len();
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(msg);
            debug_assert!(!cmsg.is_null());
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = libc::UDP_SEGMENT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut u16, segment_size);
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize;
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
//  per-thread counters, to see whether coalescing happens

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OffloadStats {
    pub gso_sends: u64,
    pub gso_segments: u64,
    pub gso_max_segments: u64,
    pub plain_sends: u64,
    pub gso_fallbacks: u64,
    pub recvs: u64,
    pub recv_segments: u64,
    pub gro_multi_segment_recvs: u64,
    pub frag_len_mismatches: u64,
}

impl OffloadStats {
    const ZERO: Self = Self {
        gso_sends: 0,
        gso_segments: 0,
        gso_max_segments: 0,
        plain_sends: 0,
        gso_fallbacks: 0,
        recvs: 0,
        recv_segments: 0,
        gro_multi_segment_recvs: 0,
        frag_len_mismatches: 0,
    };

    fn avg(sum: u64, n: u64) -> f64 {
        if n == 0 { 0.0 } else { sum as f64 / n as f64 }
    }

    /// counters since `earlier`; the max stays the running max
    fn since(&self, earlier: &Self) -> Self {
        Self {
            gso_sends: self.gso_sends - earlier.gso_sends,
            gso_segments: self.gso_segments - earlier.gso_segments,
            gso_max_segments: self.gso_max_segments,
            plain_sends: self.plain_sends - earlier.plain_sends,
            gso_fallbacks: self.gso_fallbacks - earlier.gso_fallbacks,
            recvs: self.recvs - earlier.recvs,
            recv_segments: self.recv_segments - earlier.recv_segments,
            gro_multi_segment_recvs: self.gro_multi_segment_recvs - earlier.gro_multi_segment_recvs,
            frag_len_mismatches: self.frag_len_mismatches - earlier.frag_len_mismatches,
        }
    }
}

impl std::fmt::Display for OffloadStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(:gso-sends {} :gso-segments-avg {:.2} :gso-segments-max {} :plain-sends {} :gso-fallbacks {} :recvs {} :recv-segments-avg {:.2} :gro-multi-segment-recvs {} :frag-len-mismatches {})",
            self.gso_sends,
            Self::avg(self.gso_segments, self.gso_sends),
            self.gso_max_segments,
            self.plain_sends,
            self.gso_fallbacks,
            self.recvs,
            Self::avg(self.recv_segments, self.recvs),
            self.gro_multi_segment_recvs,
            self.frag_len_mismatches,
        )
    }
}

struct StatsState {
    stats: OffloadStats,
    /// only report on threads that use GSO or GRO
    enabled: bool,
    interval: Option<std::time::Duration>,
    last_report: Option<(std::time::Instant, OffloadStats)>,
}

thread_local! {
    static STATS: std::cell::RefCell<StatsState> = const {
        std::cell::RefCell::new(StatsState {
            stats: OffloadStats::ZERO,
            enabled: false,
            interval: None,
            last_report: None,
        })
    };
}

#[inline]
pub(super) fn record<F: FnOnce(&mut OffloadStats)>(f: F) {
    STATS.with(|s| f(&mut s.borrow_mut().stats))
}

pub fn thread_offload_stats() -> OffloadStats {
    STATS.with(|s| s.borrow().stats)
}

/// mark this thread as using GSO/GRO so the totals get printed; `interval_ms`
/// > 0 also prints the counters of the last interval to stderr periodically
pub fn enable_offload_stats(interval_ms: u64) {
    STATS.with(|s| {
        let mut s = s.borrow_mut();
        s.enabled = true;
        if interval_ms > 0 {
            s.interval = Some(std::time::Duration::from_millis(interval_ms));
        }
    })
}

/// periodic report; only reads a thread local when disabled
#[inline]
pub(super) fn maybe_report_offload_stats() {
    STATS.with(|s| {
        let mut s = s.borrow_mut();
        let Some(interval) = s.interval else { return };
        let now = std::time::Instant::now();
        let stats = s.stats;
        match s.last_report {
            None => s.last_report = Some((now, stats)),
            Some((last, earlier)) if now.duration_since(last) >= interval => {
                let thread = std::thread::current().id();
                eprintln!("[udp-offload {:?} interval] {}", thread, stats.since(&earlier));
                s.last_report = Some((now, stats));
            }
            Some(_) => {}
        }
    })
}

/// print this thread's totals, e.g. at shutdown
pub fn print_offload_stats(label: &str) {
    STATS.with(|s| {
        let s = s.borrow();
        if s.enabled {
            eprintln!("[udp-offload {} {:?} total] {}", label, std::thread::current().id(), s.stats);
        }
    })
}

////////////////////////////////////////////////////////////////////////////////
//  tests

#[cfg(test)]
mod tests {
    use super::*;

    const OFFSET: usize = 2;
    const FRAMING: RecvFraming = RecvFraming::LengthChecked { offset: OFFSET };

    /// message with a 2 byte tag, the length field, and `fill` bytes of payload
    fn framed(tag: u8, fill: usize) -> Vec<u8> {
        let mut msg = vec![tag; OFFSET + 4 + fill];
        let len = msg.len();
        write_frag_len(&mut msg, OFFSET, len);
        msg
    }

    fn split(data: &[u8], segment_size: Option<usize>) -> Vec<&[u8]> {
        Segments::new(data.len(), segment_size).map(|r| &data[r]).collect()
    }

    #[test]
    fn single_datagram() {
        let msg = framed(1, 10);
        assert_eq!(split(&msg, None), vec![msg.as_slice()]);
        assert_eq!(Segments::count(msg.len(), None), 1);
        // a segment size at least the buffer length is a single datagram, too
        assert_eq!(split(&msg, Some(1000)), vec![msg.as_slice()]);
        assert!(frag_len_matches(&msg, FRAMING));
    }

    #[test]
    fn gro_buffer_of_equal_segments() {
        let msgs: Vec<_> = (0..5).map(|i| framed(i, 188)).collect();
        let data = msgs.concat();
        let segments = split(&data, Some(194));
        assert_eq!(segments, msgs.iter().map(|m| m.as_slice()).collect::<Vec<_>>());
        assert_eq!(Segments::count(data.len(), Some(194)), 5);
        assert!(segments.iter().all(|s| frag_len_matches(s, FRAMING)));
    }

    #[test]
    fn gro_buffer_with_short_last_segment() {
        let seg = 32;
        let msgs = [framed(1, seg - 6), framed(2, seg - 6), framed(3, seg - 6), framed(4, 5)];
        let data = msgs.concat();
        assert_eq!(data.len(), 3 * seg + 11);
        assert_eq!(split(&data, Some(seg)), msgs.iter().map(|m| m.as_slice()).collect::<Vec<_>>());
        assert_eq!(Segments::count(data.len(), Some(seg)), 4);
    }

    #[test]
    fn frag_len_mismatches() {
        let mut msg = framed(1, 10);
        // length field disagrees with the datagram
        write_frag_len(&mut msg, OFFSET, 15);
        assert!(!frag_len_matches(&msg, FRAMING));
        // too short to carry the field
        assert!(!frag_len_matches(&msg[..OFFSET + 3], FRAMING));
        // truncated datagram (MSG_TRUNC)
        let msg = framed(1, 10);
        assert!(!frag_len_matches(&msg[..msg.len() - 1], FRAMING));
        // unchecked framing accepts anything
        assert!(frag_len_matches(&msg[..3], RecvFraming::Datagram));
    }
}
