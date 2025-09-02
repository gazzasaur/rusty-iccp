use crate::{
    api::IsoSpError,
    packet::parameters::{EnclosureField, SessionPduParameter},
};

pub(crate) struct DataTransferMessage {
    enclosure: Option<EnclosureField>,
}

impl DataTransferMessage {
    pub(crate) fn enclosure(&self) -> Option<EnclosureField> {
        self.enclosure
    }

    pub(crate) fn from_parameters(parameters: &[SessionPduParameter]) -> Result<Self, IsoSpError> {
        let mut enclosure = None;

        // Not minding about order or duplicates.
        for parameter in parameters {
            match parameter {
                SessionPduParameter::Enclosure(field) => enclosure = Some(*field),
                _ => (), // Ignore everything else.
            };
        }

        Ok(DataTransferMessage { enclosure })
    }
}
