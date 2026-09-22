use std::io;

use super::buffer::IoBuf;
use super::{MAX_PACKET_SIZE, ThreadBuffers, local_packet_buffer_pool};
use crate::types::packet::PacketHeader;

pub trait StreamConsumer {
    fn on_message(&mut self, msg: &[u8]);
    fn on_end(&mut self, err: Option<io::Error>);
}

struct Partial {
    buf: IoBuf,
    filled: usize,
}

pub struct MessageFramer {
    pool: ThreadBuffers,
    partial: Option<Partial>,
    dead: bool,
}

impl MessageFramer {
    pub fn new() -> Self {
        Self {
            pool: local_packet_buffer_pool(),
            partial: None,
            dead: false,
        }
    }

    fn frame_len(bytes: &[u8]) -> Option<io::Result<usize>> {
        let len = match PacketHeader::peek(bytes)? {
            Ok(hdr) => PacketHeader::WIRE_SIZE + hdr.fragment_len as usize,
            Err(e) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
        };
        if len > MAX_PACKET_SIZE {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame exceeds the maximum packet size",
            )));
        }
        Some(Ok(len))
    }

    fn fill_partial<'a, C: StreamConsumer>(
        &mut self,
        data: &'a [u8],
        consumer: &mut C,
    ) -> io::Result<&'a [u8]> {
        let partial = self.partial.as_mut().expect("no partial message");
        let need = match Self::frame_len(&partial.buf.as_slice()[..partial.filled]) {
            None => PacketHeader::WIRE_SIZE,
            Some(len) => len?,
        };
        assert!(
            partial.filled < need,
            "a complete frame was left in the scratch buffer"
        );
        let n = (need - partial.filled).min(data.len());
        partial.buf.as_mut_slice()[partial.filled..partial.filled + n].copy_from_slice(&data[..n]);
        partial.filled += n;
        if let Some(len) = Self::frame_len(&partial.buf.as_slice()[..partial.filled]) {
            let len = len?;
            if partial.filled == len {
                // scratch returns to the pool after the call
                let partial = self.partial.take().unwrap();
                consumer.on_message(&partial.buf.as_slice()[..len]);
            }
        }
        Ok(&data[n..])
    }

    fn feed<C: StreamConsumer>(&mut self, mut data: &[u8], consumer: &mut C) -> io::Result<()> {
        while !data.is_empty() {
            if self.partial.is_some() {
                let pending = data.len();
                data = self.fill_partial(data, consumer)?;
                assert!(data.len() < pending, "framer consumed no input");
                continue;
            }
            match Self::frame_len(data).transpose()? {
                Some(len) if len <= data.len() => {
                    consumer.on_message(&data[..len]);
                    data = &data[len..];
                }
                _ => {
                    let buf = self.pool.pop();
                    assert!(
                        buf.capacity() >= MAX_PACKET_SIZE,
                        "packet pool hands out buffers below the maximum frame size"
                    );
                    self.partial = Some(Partial { buf, filled: 0 });
                }
            }
        }
        Ok(())
    }

    pub fn on_data<C: StreamConsumer>(&mut self, data: &[u8], consumer: &mut C) {
        if self.dead {
            return;
        }
        if let Err(e) = self.feed(data, consumer) {
            self.dead = true;
            self.partial = None;
            consumer.on_end(Some(e));
        }
    }

    pub fn on_end<C: StreamConsumer>(&mut self, err: Option<io::Error>, consumer: &mut C) {
        if self.dead {
            return;
        }
        self.dead = true;
        let err = match (err, self.partial.take()) {
            (Some(e), _) => Some(e),
            (None, Some(_)) => Some(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream closed inside a message",
            )),
            (None, None) => None,
        };
        consumer.on_end(err);
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::wire::auto::WireMessage as _;
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

    impl StreamConsumer for Rec {
        fn on_message(&mut self, msg: &[u8]) {
            let mut rec = self.0.borrow_mut();
            rec.msgs.push(msg.to_vec());
            rec.ptrs.push(msg.as_ptr());
        }
        fn on_end(&mut self, err: Option<io::Error>) {
            assert!(
                self.0.borrow_mut().end.replace(err).is_none(),
                "on_end called twice"
            );
        }
    }

    fn framer() -> (MessageFramer, Rec, Rc<RefCell<Record>>) {
        let record = Rc::new(RefCell::new(Record::default()));
        (MessageFramer::new(), Rec(record.clone()), record)
    }

    fn frame(msg_id: u64, body: &[u8]) -> Vec<u8> {
        let hdr = PacketHeader {
            msg_id,
            reply_to: 7,
            stream_id: 0,
            fragment_len: body.len() as u32,
        };
        let mut scratch = [0u8; 64];
        assert_eq!(
            hdr.encode_into(&mut scratch).unwrap(),
            PacketHeader::WIRE_SIZE
        );
        [&scratch[..PacketHeader::WIRE_SIZE], body].concat()
    }

    #[test]
    fn test_whole_frames() {
        let (mut f, mut c, rec) = framer();
        let a = frame(1, b"alpha");
        let b = frame(2, b"");
        f.on_data(&a, &mut c);
        let two = [b.clone(), a.clone()].concat();
        f.on_data(&two, &mut c);
        assert_eq!(rec.borrow().msgs, [a.clone(), b, a]);
        assert!(
            rec.borrow().within(1, &two) && rec.borrow().within(2, &two),
            "contiguous frames are not copied"
        );
        f.on_end(None, &mut c);
        assert!(rec.borrow().end.as_ref().unwrap().is_none());
    }

    #[test]
    fn test_split_frames() {
        let (mut f, mut c, rec) = framer();
        let a = frame(1, b"split across fragments");
        let b = frame(2, b"second");
        let c_frame = frame(3, b"third");
        // header cut, body cut, then tail of a + all of b + head of c
        f.on_data(&a[..5], &mut c);
        f.on_data(&a[5..PacketHeader::WIRE_SIZE + 3], &mut c);
        assert!(rec.borrow().msgs.is_empty());
        let mut rest = a[PacketHeader::WIRE_SIZE + 3..].to_vec();
        rest.extend_from_slice(&b);
        rest.extend_from_slice(&c_frame[..PacketHeader::WIRE_SIZE]);
        f.on_data(&rest, &mut c);
        assert_eq!(rec.borrow().msgs, [a, b]);
        assert!(
            !rec.borrow().within(0, &rest),
            "spanning frame comes from scratch"
        );
        assert!(
            rec.borrow().within(1, &rest),
            "following frame comes from the fragment"
        );
        f.on_data(&c_frame[PacketHeader::WIRE_SIZE..], &mut c);
        assert_eq!(rec.borrow().msgs[2], c_frame);
        assert!(f.partial.is_none(), "scratch space returned");
    }

    #[test]
    fn test_byte_by_byte() {
        let (mut f, mut c, rec) = framer();
        let a = frame(1, b"one byte at a time");
        for byte in a.iter() {
            f.on_data(std::slice::from_ref(byte), &mut c);
        }
        assert_eq!(rec.borrow().msgs, [a]);
    }

    #[test]
    fn test_oversized_frame_ends_stream() {
        let (mut f, mut c, rec) = framer();
        let mut hdr = frame(1, b"");
        hdr[PacketHeader::WIRE_SIZE - 4..].copy_from_slice(&(MAX_PACKET_SIZE as u32).to_le_bytes());
        f.on_data(&hdr[..4], &mut c);
        f.on_data(&hdr[4..], &mut c);
        assert_eq!(
            rec.borrow().end.as_ref().unwrap().as_ref().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        // the stream is dead: nothing else gets through
        f.on_data(&frame(2, b"late"), &mut c);
        f.on_end(None, &mut c);
        assert!(rec.borrow().msgs.is_empty());
    }

    #[test]
    fn test_eof_inside_message() {
        let (mut f, mut c, rec) = framer();
        let a = frame(1, b"unfinished");
        f.on_data(&a[..a.len() - 1], &mut c);
        f.on_end(None, &mut c);
        assert_eq!(
            rec.borrow().end.as_ref().unwrap().as_ref().unwrap().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn test_recv_error_passes_through() {
        let (mut f, mut c, rec) = framer();
        f.on_end(Some(io::Error::from_raw_os_error(libc::ECONNRESET)), &mut c);
        assert_eq!(
            rec.borrow()
                .end
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .raw_os_error(),
            Some(libc::ECONNRESET)
        );
    }
}
