use crate::packet::parameter::CotpParameter;

pub const DISCONNECT_REQUEST_CODE: u8 = 0x80u8;

#[derive(Debug, PartialEq)]
pub struct DisconnectRequest {
    source_reference: u16,
    destination_reference: u16,
    reason: DisconnectReason,
    parameters: Vec<CotpParameter>,
    user_data: Vec<u8>,
}

impl DisconnectRequest {
    pub fn new(source_reference: u16, destination_reference: u16, reason: DisconnectReason, parameters: Vec<CotpParameter>, user_data: &[u8]) -> Self {
        Self {
            source_reference,
            destination_reference,
            reason,
            parameters,
            user_data: user_data.into(),
        }
    }

    pub fn source_reference(&self) -> u16 {
        self.source_reference
    }

    pub fn destination_reference(&self) -> u16 {
        self.destination_reference
    }

    pub fn reason(&self) -> &DisconnectReason {
        &self.reason
    }

    pub fn parameters(&self) -> &[CotpParameter] {
        &self.parameters
    }

    pub fn user_data(&self) -> &[u8] {
        &self.user_data
    }
}

#[derive(Debug, PartialEq)]
pub enum DisconnectReason {
    ReasonNotSpecified,
    CongestionAtTsap,
    NotAttachedToTsap,
    AddressUnknown,

    NormalDisconnect,
    CongestionAtConnectionRequestTime,
    ConnectionNegotiationFailed,
    DuplicateSourceReferenceDetected,
    MismatchedEeferences,
    ProtocolError,
    NotUsed134,
    ReferenceOverflow,
    ConnectionRequestRefused,
    NotUsed137,
    HeaderOrParameterLengthInvalid,

    Unkown(u8),
}

impl From<u8> for DisconnectReason {
    fn from(value: u8) -> Self {
        match value {
            0 => DisconnectReason::ReasonNotSpecified,
            1 => DisconnectReason::CongestionAtTsap,
            2 => DisconnectReason::NotAttachedToTsap,
            3 => DisconnectReason::AddressUnknown,
            128 => DisconnectReason::NormalDisconnect,
            129 => DisconnectReason::CongestionAtConnectionRequestTime,
            130 => DisconnectReason::ConnectionNegotiationFailed,
            131 => DisconnectReason::DuplicateSourceReferenceDetected,
            132 => DisconnectReason::MismatchedEeferences,
            133 => DisconnectReason::ProtocolError,
            134 => DisconnectReason::NotUsed134,
            135 => DisconnectReason::ReferenceOverflow,
            136 => DisconnectReason::ConnectionRequestRefused,
            137 => DisconnectReason::NotUsed137,
            138 => DisconnectReason::HeaderOrParameterLengthInvalid,
            x => DisconnectReason::Unkown(x),
        }
    }
}
