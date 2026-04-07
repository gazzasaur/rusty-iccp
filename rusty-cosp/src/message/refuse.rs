use crate::{
    ReasonCode,
    api::CospError,
    packet::parameters::{EnclosureField, SessionPduParameter},
};

pub(crate) struct RefuseMessage {
    has_more_data: bool,
    reason_code: Option<ReasonCode>,
}

impl RefuseMessage {
    pub(crate) fn new(has_more_data: bool, reason_code: Option<ReasonCode>) -> Self {
        Self { has_more_data, reason_code }
    }

    pub(crate) fn reason_code(&self) -> Option<&ReasonCode> {
        self.reason_code.as_ref()
    }

    pub(crate) fn has_more_data(&self) -> bool {
        self.has_more_data
    }

    pub(crate) fn from_parameters(parameters: &[SessionPduParameter]) -> Result<Self, CospError> {
        let mut reason_code = None;
        let mut enclosure = None;

        // Not minding about order or duplicates.
        for parameter in parameters {
            match parameter {
                SessionPduParameter::EnclosureParameter(field) => enclosure = Some(*field),
                SessionPduParameter::ReasonCodeParameter(reason_code_data) => reason_code = Some(reason_code_data.clone()),
                _ => (), // Ignore everything else.
            };
        }

        Ok(RefuseMessage { reason_code, has_more_data: !enclosure.unwrap_or_else(|| EnclosureField(2)).end() })
    }
}
