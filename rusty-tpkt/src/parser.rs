use std::array::TryFromSliceError;

use bytes::BytesMut;

use crate::api::TpktError;

pub const HEADER_LENGTH: usize = 4;
pub const TKPT_MAGIC_START_NUMBER: u8 = 0x03u8;
pub const MAX_PACKET_LENGTH: usize = 2usize.pow(16) - 1;
pub const MAX_PAYLOAD_LENGTH: usize = MAX_PACKET_LENGTH - HEADER_LENGTH;

pub enum TkptParserResult {
    InProgress,
    Data(Vec<u8>),
}

pub struct TkptParser {}

impl TkptParser {
    pub fn new() -> Self {
        Self {}
    }

    pub fn parse(&self, data: &mut BytesMut) -> Result<TkptParserResult, TpktError> {
        let packet_length_value = match data.len() {
            0 => return Ok(TkptParserResult::InProgress),
            x if x > 0 && data[0] != TKPT_MAGIC_START_NUMBER => {
                return Err(TpktError::ProtocolError(format!("Invalid Header. Expected 0x03 but was {:#04x}", x).into()));
            }
            // Ignore the version field and just straight to the length.
            x if x > 3 => u16::from_be_bytes(data[2..4].try_into().map_err(|e: TryFromSliceError| TpktError::InternalError(format!("Failed to parse data: {:?}", e.to_string()).into()))?),
            _ => return Ok(TkptParserResult::InProgress),
        } as usize;

        if data.len() < packet_length_value {
            return Ok(TkptParserResult::InProgress);
        }
        let _remove_header = data.split_to(HEADER_LENGTH);
        return Ok(TkptParserResult::Data(data.split_to(packet_length_value - HEADER_LENGTH).to_vec()));
    }
}
