use crate::packet::parameters::CotpParameter;

pub const TPDU_ERROR_CODE: u8 = 0x70u8;

#[derive(Debug, PartialEq)]
pub struct TpduError {
    destination_reference: u16,
    reason: RejectCause,
    parameters: Vec<CotpParameter>,
}

impl TpduError {
    pub fn new(destination_reference: u16, reason: RejectCause, parameters: Vec<CotpParameter>) -> Self {
        Self { destination_reference, reason, parameters }
    }

    pub fn destination_reference(&self) -> u16 {
        self.destination_reference
    }

    pub fn reason(&self) -> &RejectCause {
        &self.reason
    }

    pub fn parameters(&self) -> &[CotpParameter] {
        &self.parameters
    }
}

#[derive(Debug, PartialEq)]
pub enum RejectCause {
    ReasonNotSpecified,
    InvalidParameterCode,
    InvalidTpduType,
    InvalidParameterValue,
    Unkown(u8),
}

impl From<u8> for RejectCause {
    fn from(value: u8) -> Self {
        match value {
            0 => RejectCause::ReasonNotSpecified,
            1 => RejectCause::InvalidParameterCode,
            2 => RejectCause::InvalidTpduType,
            3 => RejectCause::InvalidParameterValue,
            x => RejectCause::Unkown(x),
        }
    }
}
