use crate::{
    error::CotpError,
    packet::
        payload::TransportProtocolDataUnit
    , serialiser::packet_cr::serialise_connection_request,
};

pub struct TransportProtocolDataUnitSerialiser {}

impl TransportProtocolDataUnitSerialiser {
    pub fn new() -> Self {
        TransportProtocolDataUnitSerialiser {}
    }

    pub fn serialise(&mut self, data: &TransportProtocolDataUnit) -> Result<Vec<u8>, CotpError> {
        match data {
            TransportProtocolDataUnit::CR(x) => serialise_connection_request(&x),
            // (_, CONNECTION_CONFIRM_CODE, _) => parse_create_confirm(credit, &data[2..(header_length + 1)], &data[(header_length + 1)..]),
            // (DISCONNECT_REQUEST_CODE, _, _) => parse_disconnect_request(&data[2..(header_length + 1)], &data[(header_length + 1)..]),
            // (DATA_TRANSFER_CODE, _, _) => parse_data_transfer(&data[2..(header_length + 1)], &data[(header_length + 1)..]),
            // (TPDU_ERROR_CODE, _, _) => parse_tpdu_error(&data[2..(header_length + 1)]),
            _ => return Err(CotpError::ProtocolError(format!("Unsupported tpdu: {:?}", data).into())),
        }
    }
}
