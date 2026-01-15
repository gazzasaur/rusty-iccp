use crate::pdu::{initiaterequest::InitiateRequestPdu, initiateresponse::InitiateResponsePdu, readrequest::ReadRequestPdu};

pub(crate) mod initiateresponse;
pub(crate) mod initiaterequest;
pub(crate) mod common;
pub(crate) mod readrequest;
pub(crate) mod confirmedrequest;
pub(crate) mod confirmedresponse;
pub(crate) mod readresponse;

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

#[repr(u8)]
pub(crate) enum ConfirmedMmsPduType {
    ReadRequestPduType(ReadRequestPdu) = 1,
}
