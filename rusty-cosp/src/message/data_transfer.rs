use crate::{
    api::CospError,
    packet::parameters::{EnclosureField, SessionPduParameter},
};

pub(crate) struct DataTransferMessage {
    enclosure: Option<EnclosureField>,
    user_information: Vec<u8>,
}

impl DataTransferMessage {
    pub(crate) fn enclosure(&self) -> Option<EnclosureField> {
        self.enclosure
    }

    pub(crate) fn take_user_information(self) -> Vec<u8> {
        self.user_information
    }

    pub(crate) fn from_parameters(parameters: &[SessionPduParameter], user_information: Vec<u8>) -> Result<Self, CospError> {
        let mut enclosure = None;

        // Not minding about order or duplicates.
        for parameter in parameters {
            match parameter {
                SessionPduParameter::Enclosure(field) => enclosure = Some(*field),
                _ => (), // Ignore everything else.
            };
        }

        Ok(DataTransferMessage { enclosure, user_information })
    }
}
