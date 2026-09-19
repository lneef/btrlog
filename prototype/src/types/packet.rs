use super::{message::*, wire::auto::*, wire::EncodeError};

// Messages that aren't sent as part of a persistent connection
// additionally need an id to correlate requests with responses.
// The 'reply_to' field is used to for load balancing & sending
// packets to the correct port <-> thread immediately.
#[derive(Encode, Decode)]
#[apply(on_wire)]
pub struct PacketHeader {
    pub msg_id: u64,
    pub reply_to: u16,
    // body bytes following the header
    pub fragment_len: u32,
}

impl PacketHeader {
    // fixint encoding: u64 + u16 + u32
    pub const WIRE_SIZE: usize = 8 + 2 + 4;
}

// header at dst[..WIRE_SIZE], body after it, fragment_len = body bytes
fn encode_framed<B: WireMessage<()>>(mut header: PacketHeader, body: B, dst: &mut [u8]) -> Result<usize, EncodeError> {
    let body_len = body.encode_into(&mut dst[PacketHeader::WIRE_SIZE..])?;
    header.fragment_len = body_len as u32;
    // header writes exactly WIRE_SIZE bytes at the front
    let hdr_len = header.encode_into(dst)?;
    debug_assert_eq!(hdr_len, PacketHeader::WIRE_SIZE);
    Ok(PacketHeader::WIRE_SIZE + body_len)
}

#[derive(Encode, Decode)]
#[apply(on_wire)]
pub struct RequestPacket {
    pub header: PacketHeader,
    pub request: JournalRequest,
}

impl RequestPacket {
    pub fn encode_framed(self, dst: &mut [u8]) -> Result<usize, EncodeError> {
        encode_framed(self.header, self.request, dst)
    }
}

#[derive(Encode, Decode)]
#[apply(on_wire)]
pub struct ResponsePacket {
    pub header: PacketHeader,
    pub request: JournalResponse,
}

impl ResponsePacket {
    pub fn encode_framed(self, dst: &mut [u8]) -> Result<usize, EncodeError> {
        encode_framed(self.header, self.request, dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dst::RandomDST as _, types::id::JournalId};

    #[test]
    fn header_wire_size() {
        let mut buf = [0u8; 64];
        let hdr = PacketHeader {
            msg_id: 0x0102030405060708,
            reply_to: 9,
            fragment_len: 10,
        };
        let n = hdr.encode_into(&mut buf).unwrap();
        assert_eq!(n, PacketHeader::WIRE_SIZE);
    }

    #[test]
    fn framed_encoding_matches_struct_encoding() {
        let body = JournalRequest::FetchMeta(JournalMetadataRequest { id: JournalId::dst_random().into() });
        let header = PacketHeader {
            msg_id: 42,
            reply_to: 7,
            fragment_len: 0,
        };
        let mut framed = [0u8; RequestPacket::WIRE_SIZE_BOUND];
        let n = RequestPacket {
            header: header.clone(),
            request: body.clone(),
        }
        .encode_framed(&mut framed)
        .unwrap();
        // whole-struct encoding with the filled length is byte-identical
        let mut plain = [0u8; RequestPacket::WIRE_SIZE_BOUND];
        let filled = PacketHeader {
            fragment_len: (n - PacketHeader::WIRE_SIZE) as u32,
            ..header
        };
        let m = RequestPacket {
            header: filled.clone(),
            request: body.clone(),
        }
        .encode_into(&mut plain)
        .unwrap();
        assert_eq!(n, m);
        assert_eq!(&framed[..n], &plain[..m]);
        // decode yields the filled header
        let (decoded, bytes) = RequestPacket::decode_from(&framed[..n]).unwrap();
        assert_eq!(bytes, n);
        assert_eq!(decoded.header, filled);
        assert_eq!(decoded.request, body);
        assert_eq!(bytes, PacketHeader::WIRE_SIZE + decoded.header.fragment_len as usize);
    }
}
