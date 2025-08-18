use bytes::BytesMut;

use crate::api::TpktError;

pub const HEADER_LENGTH: usize = 4;
pub const TPKT_MAGIC_START_NUMBER: u8 = 0x03u8;
pub const MAX_PACKET_LENGTH: usize = 2usize.pow(16) - 1;
pub const MAX_PAYLOAD_LENGTH: usize = MAX_PACKET_LENGTH - HEADER_LENGTH;

pub struct TpktSerialiser {}

impl TpktSerialiser {
    pub fn new() -> Self {
        Self {}
    }

    pub fn serialise(&self, data: &[u8]) -> Result<BytesMut, TpktError> {
        if data.len() > MAX_PAYLOAD_LENGTH {
            return Err(TpktError::ProtocolError(format!("TPKT user data must be less than or equal to {} but was {}", MAX_PAYLOAD_LENGTH, data.len())));
        }
        let packet_length = ((data.len() + HEADER_LENGTH) as u16).to_be_bytes();
        let mut send_buffer = BytesMut::with_capacity(4 + data.len());
        send_buffer.extend_from_slice(&[0x03u8, 0x00u8]);
        send_buffer.extend_from_slice(&packet_length);
        send_buffer.extend_from_slice(&data);
        Ok(send_buffer)
    }
}
