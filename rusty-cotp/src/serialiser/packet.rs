use crate::{
    api::CotpError,
    packet::payload::TransportProtocolDataUnit,
    serialiser::{packet_cc::serialise_connection_confirm, packet_cr::serialise_connection_request, packet_dt::serialise_data_transfer},
};

pub(crate) fn serialise(data: &TransportProtocolDataUnit) -> Result<Vec<u8>, CotpError> {
    match data {
        TransportProtocolDataUnit::CR(x) => serialise_connection_request(&x),
        TransportProtocolDataUnit::CC(x) => serialise_connection_confirm(&x),
        TransportProtocolDataUnit::DT(x) => serialise_data_transfer(&x),
        _ => return Err(CotpError::ProtocolError(format!("Unsupported tpdu: {:?}", data).into())),
    }
}
