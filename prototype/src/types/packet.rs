use super::{message::*, wire::EncodeError, wire::auto::*};
use crate::io::udp_offload::{RecvFraming, write_frag_len};

// Messages that aren't sent as part of a persistent connection
// additionally need an id to correlate requests with responses.
// The 'reply_to' field is used to for load balancing & sending
// packets to the correct port <-> thread immediately.
// 'frag_len' is the length of the whole encoded packet. Receivers split
// GRO-coalesced buffers by the GRO segment size and use it as a
// consistency check; see io::udp_offload. It is filled in by
// `FramedPacket::encode_framed`.
#[derive(Encode, Decode)]
#[apply(on_wire)]
pub struct PacketHeader {
    pub msg_id: u64,
    pub reply_to: u16,
    pub frag_len: u32,
}

impl PacketHeader {
    /// byte offset of `frag_len` in an encoded packet (fixint encoding, header first)
    pub const FRAG_LEN_OFFSET: usize = size_of::<u64>() + size_of::<u16>();
    /// receive framing for sockets carrying request/response packets
    pub const FRAMING: RecvFraming = RecvFraming::LengthChecked {
        offset: Self::FRAG_LEN_OFFSET,
    };

    pub fn new(msg_id: u64, reply_to: u16) -> Self {
        Self {
            msg_id,
            reply_to,
            frag_len: 0,
        }
    }
}

#[derive(Encode, Decode)]
#[apply(on_wire)]
pub struct RequestPacket {
    pub header: PacketHeader,
    pub request: JournalRequest,
}

#[derive(Encode, Decode)]
#[apply(on_wire)]
pub struct ResponsePacket {
    pub header: PacketHeader,
    pub request: JournalResponse,
}

/// packets starting with a `PacketHeader`
pub trait FramedPacket: WireMessage<()> {
    /// encode, then patch the encoded length into the header's `frag_len`
    fn encode_framed(self, dst: &mut [u8]) -> Result<usize, EncodeError> {
        let len = self.encode_into(dst)?;
        write_frag_len(dst, PacketHeader::FRAG_LEN_OFFSET, len);
        Ok(len)
    }
}
impl FramedPacket for RequestPacket {}
impl FramedPacket for ResponsePacket {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::udp_offload::{Segments, frag_len_matches, read_frag_len};

    fn request(msg_id: u64) -> RequestPacket {
        RequestPacket {
            header: PacketHeader::new(msg_id, 4269),
            request: JournalRequest::Heartbeat,
        }
    }

    #[test]
    fn frag_len_is_patched_at_offset() {
        let mut buf = [0u8; 256];
        let len = request(7).encode_framed(&mut buf).unwrap();
        assert_eq!(read_frag_len(&buf, PacketHeader::FRAG_LEN_OFFSET), Some(len));
        let (decoded, decoded_len) = RequestPacket::decode_from(&buf[..len]).unwrap();
        assert_eq!(decoded_len, len);
        assert_eq!(decoded.header.frag_len as usize, len);
        assert_eq!(decoded.header.msg_id, 7);
        assert_eq!(decoded.header.reply_to, 4269);
        // same layout for responses
        let resp = ResponsePacket {
            header: PacketHeader::new(8, 1),
            request: JournalResponse::Heartbeat,
        };
        let len = resp.encode_framed(&mut buf).unwrap();
        let (decoded, _) = ResponsePacket::decode_from(&buf[..len]).unwrap();
        assert_eq!(decoded.header.frag_len as usize, len);
    }

    #[test]
    fn coalesced_packets_split_by_segment_size() {
        // equal-sized packets back to back, as a GRO receive delivers them
        let mut data = vec![0u8; 1024];
        let mut pos = 0;
        let mut size = 0;
        for id in 0..5 {
            size = request(id).encode_framed(&mut data[pos..]).unwrap();
            pos += size;
        }
        data.truncate(pos);
        let ids: Vec<_> = Segments::new(data.len(), Some(size))
            .map(|r| {
                assert!(frag_len_matches(&data[r.clone()], PacketHeader::FRAMING));
                RequestPacket::decode_from(&data[r]).unwrap().0.header.msg_id
            })
            .collect();
        assert_eq!(ids, vec![0, 1, 2, 3, 4]);
    }
}
