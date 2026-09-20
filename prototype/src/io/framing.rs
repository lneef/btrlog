use std::io;

use super::buffer::IoBuf;
use super::uring::RecvConsumer;
use super::{MAX_PACKET_SIZE, ThreadBuffers, local_packet_buffer_pool};
use crate::types::packet::PacketHeader;
use crate::types::wire::auto::WireMessage as _;

/// Framed messages of one stream.
pub trait MessageConsumer: 'static {
    /// `msg` is one framed message, header and body, valid during the call only.
    /// It points into the recv buffer, or into scratch for a frame spanning fragments.
    fn on_message(&mut self, msg: &[u8]);
    /// The stream ended: recv error, malformed frame or `None` for a clean close.
    fn on_end(&mut self, err: Option<io::Error>);
}

/// Frame spanning fragments, reassembled in a pool buffer.
struct Partial {
    buf: IoBuf,
    filled: usize,
}

/// Cuts multishot recv fragments into framed messages. Copies only frames spanning fragments.
pub struct MessageFramer<C> {
    pool: ThreadBuffers,
    partial: Option<Partial>,
    /// the stream ended; ignore the rest
    dead: bool,
    consumer: C,
}

impl<C: MessageConsumer> MessageFramer<C> {
    pub fn new(consumer: C) -> Self {
        Self {
            pool: local_packet_buffer_pool(),
            partial: None,
            dead: false,
            consumer,
        }
    }

    /// Total frame length, `None` for a truncated header.
    fn frame_len(bytes: &[u8]) -> Option<io::Result<usize>> {
        if bytes.len() < PacketHeader::WIRE_SIZE {
            return None;
        }
        let len = match PacketHeader::decode_from(&bytes[..PacketHeader::WIRE_SIZE]) {
            Ok((hdr, _)) => PacketHeader::WIRE_SIZE + hdr.fragment_len as usize,
            Err(e) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
        };
        if len > MAX_PACKET_SIZE {
            return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds the maximum packet size")));
        }
        Some(Ok(len))
    }

    /// Appends to the partial message; the header first, then the exact body length.
    /// Returns the unconsumed rest.
    fn fill_partial<'a>(&mut self, data: &'a [u8]) -> io::Result<&'a [u8]> {
        let partial = self.partial.as_mut().expect("no partial message");
        let need = match Self::frame_len(&partial.buf.as_slice()[..partial.filled]) {
            None => PacketHeader::WIRE_SIZE,
            Some(len) => len?,
        };
        let n = (need - partial.filled).min(data.len());
        partial.buf.as_mut_slice()[partial.filled..partial.filled + n].copy_from_slice(&data[..n]);
        partial.filled += n;
        if let Some(len) = Self::frame_len(&partial.buf.as_slice()[..partial.filled]) {
            let len = len?;
            if partial.filled == len {
                // scratch returns to the pool after the call
                let partial = self.partial.take().unwrap();
                self.consumer.on_message(&partial.buf.as_slice()[..len]);
            }
        }
        Ok(&data[n..])
    }

    fn feed(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            if self.partial.is_some() {
                data = self.fill_partial(data)?;
                continue;
            }
            match Self::frame_len(data).transpose()? {
                Some(len) if len <= data.len() => {
                    self.consumer.on_message(&data[..len]);
                    data = &data[len..];
                }
                _ => {
                    let buf = self.pool.pop();
                    debug_assert!(buf.capacity() >= MAX_PACKET_SIZE);
                    self.partial = Some(Partial { buf, filled: 0 });
                }
            }
        }
        Ok(())
    }
}

impl<C: MessageConsumer> RecvConsumer for MessageFramer<C> {
    fn on_data(&mut self, data: &[u8]) {
        if self.dead {
            return;
        }
        if let Err(e) = self.feed(data) {
            self.dead = true;
            self.partial = None;
            self.consumer.on_end(Some(e));
        }
    }

    fn on_end(&mut self, err: Option<io::Error>) {
        if self.dead {
            return;
        }
        self.dead = true;
        let err = match (err, self.partial.take()) {
            (Some(e), _) => Some(e),
            (None, Some(_)) => Some(io::Error::new(io::ErrorKind::UnexpectedEof, "stream closed inside a message")),
            (None, None) => None,
        };
        self.consumer.on_end(err);
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct Record {
        msgs: Vec<Vec<u8>>,
        /// address of each delivered message
        ptrs: Vec<*const u8>,
        end: Option<Option<io::Error>>,
    }

    impl Record {
        fn within(&self, idx: usize, fragment: &[u8]) -> bool {
            let range = fragment.as_ptr_range();
            range.contains(&self.ptrs[idx])
        }
    }

    struct Rec(Rc<RefCell<Record>>);

    impl MessageConsumer for Rec {
        fn on_message(&mut self, msg: &[u8]) {
            let mut rec = self.0.borrow_mut();
            rec.msgs.push(msg.to_vec());
            rec.ptrs.push(msg.as_ptr());
        }
        fn on_end(&mut self, err: Option<io::Error>) {
            assert!(self.0.borrow_mut().end.replace(err).is_none(), "on_end called twice");
        }
    }

    fn framer() -> (MessageFramer<Rec>, Rc<RefCell<Record>>) {
        let record = Rc::new(RefCell::new(Record::default()));
        (MessageFramer::new(Rec(record.clone())), record)
    }

    fn frame(msg_id: u64, body: &[u8]) -> Vec<u8> {
        let hdr = PacketHeader {
            msg_id,
            reply_to: 7,
            fragment_len: body.len() as u32,
        };
        let mut scratch = [0u8; 64];
        assert_eq!(hdr.encode_into(&mut scratch).unwrap(), PacketHeader::WIRE_SIZE);
        [&scratch[..PacketHeader::WIRE_SIZE], body].concat()
    }

    #[test]
    fn test_whole_frames() {
        let (mut f, rec) = framer();
        let a = frame(1, b"alpha");
        let b = frame(2, b"");
        f.on_data(&a);
        let two = [b.clone(), a.clone()].concat();
        f.on_data(&two);
        assert_eq!(rec.borrow().msgs, [a.clone(), b, a]);
        assert!(rec.borrow().within(1, &two) && rec.borrow().within(2, &two), "contiguous frames are not copied");
        f.on_end(None);
        assert!(rec.borrow().end.as_ref().unwrap().is_none());
    }

    #[test]
    fn test_split_frames() {
        let (mut f, rec) = framer();
        let a = frame(1, b"split across fragments");
        let b = frame(2, b"second");
        let c = frame(3, b"third");
        // header cut, body cut, then tail of a + all of b + head of c
        f.on_data(&a[..5]);
        f.on_data(&a[5..PacketHeader::WIRE_SIZE + 3]);
        assert!(rec.borrow().msgs.is_empty());
        let mut rest = a[PacketHeader::WIRE_SIZE + 3..].to_vec();
        rest.extend_from_slice(&b);
        rest.extend_from_slice(&c[..PacketHeader::WIRE_SIZE]);
        f.on_data(&rest);
        assert_eq!(rec.borrow().msgs, [a, b]);
        assert!(!rec.borrow().within(0, &rest), "spanning frame comes from scratch");
        assert!(rec.borrow().within(1, &rest), "following frame comes from the fragment");
        f.on_data(&c[PacketHeader::WIRE_SIZE..]);
        assert_eq!(rec.borrow().msgs[2], c);
        assert!(f.partial.is_none(), "scratch space returned");
    }

    #[test]
    fn test_byte_by_byte() {
        let (mut f, rec) = framer();
        let a = frame(1, b"one byte at a time");
        for byte in a.iter() {
            f.on_data(std::slice::from_ref(byte));
        }
        assert_eq!(rec.borrow().msgs, [a]);
    }

    #[test]
    fn test_oversized_frame_ends_stream() {
        let (mut f, rec) = framer();
        let mut hdr = frame(1, b"");
        hdr[PacketHeader::WIRE_SIZE - 4..].copy_from_slice(&(MAX_PACKET_SIZE as u32).to_le_bytes());
        f.on_data(&hdr[..4]);
        f.on_data(&hdr[4..]);
        assert_eq!(rec.borrow().end.as_ref().unwrap().as_ref().unwrap().kind(), io::ErrorKind::InvalidData);
        // the stream is dead: nothing else gets through
        f.on_data(&frame(2, b"late"));
        f.on_end(None);
        assert!(rec.borrow().msgs.is_empty());
    }

    #[test]
    fn test_eof_inside_message() {
        let (mut f, rec) = framer();
        let a = frame(1, b"unfinished");
        f.on_data(&a[..a.len() - 1]);
        f.on_end(None);
        assert_eq!(rec.borrow().end.as_ref().unwrap().as_ref().unwrap().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_recv_error_passes_through() {
        let (mut f, rec) = framer();
        f.on_end(Some(io::Error::from_raw_os_error(libc::ECONNRESET)));
        assert_eq!(rec.borrow().end.as_ref().unwrap().as_ref().unwrap().raw_os_error(), Some(libc::ECONNRESET));
    }
}
