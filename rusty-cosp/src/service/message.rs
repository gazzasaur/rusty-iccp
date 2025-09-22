use rusty_cotp::{CotpReader, CotpRecvResult};

use crate::{CospError, message::CospMessage, packet::pdu::SessionPduList};

pub(crate) const MIN_PAYLOAD_SIZE: usize = 64; // This is mainly here to protect algorithms.
pub(crate) const MAX_PAYLOAD_SIZE: usize = 65510; // Technically the maximum is 65528 but it seems to be an issue with some frameworks. Leaving buffer with this one.

pub(crate) async fn receive_message(reader: &mut impl CotpReader) -> Result<CospMessage, CospError> {
    let data = match reader.recv().await? {
        CotpRecvResult::Closed => return Err(CospError::ProtocolError("The transport connection was closed before the conection could be established.".into())),
        CotpRecvResult::Data(data) => data,
    };
    CospMessage::from_spdu_list(SessionPduList::deserialise(&data)?)
}
