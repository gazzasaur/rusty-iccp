use crate::{MmsError, pdu::{initiaterequest::InitiateRequestPdu, initiateresponse::InitiateResponsePdu, types::ConfirmedMmsPduType}};

#[repr(u8)]
pub(crate) enum MmsPduType {
    ConfirmedRequestPduType(ConfirmedMmsPdu) = 0,
    ConfirmedResponsePduType = 1,
    ConfirmedErrorPduType = 2,

    UnconfirmedPduType = 3,

    RejectPduType = 4,
    CancelRequestPduType = 5,
    CancelResponsePduType = 6,
    CancelErrorPduType = 7,

    InitiateRequestPduType(InitiateRequestPdu) = 8,
    InitiateResponsePduType(InitiateResponsePdu) = 9,
    InitiateErrorPduType = 10,

    ConcludeRequestPduType = 11,
    ConcludeResponsePduType = 12,
    ConcludeErrorPduType = 13,
}

pub(crate) struct ConfirmedMmsPdu {
    pub(crate) invocation_id: i32,
    pub(crate) payload: ConfirmedMmsPduType,
}

pub(crate) fn expect_value<T>(pdu: &str, field: &str, value: Option<T>) -> Result<T, MmsError> {
    value.ok_or_else(|| MmsError::ProtocolError(format!("MMS Payload '{}' must container the field '{}' but was not found.", pdu, field)))
}
