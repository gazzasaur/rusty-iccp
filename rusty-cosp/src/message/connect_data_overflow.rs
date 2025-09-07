use crate::{
    api::CospError,
    packet::parameters::{EnclosureField, SessionPduParameter},
};

pub(crate) struct ConnectDataOverflowMessage {
    has_more_data: bool,
    user_data: Option<Vec<u8>>,
}

impl ConnectDataOverflowMessage {
    pub(crate) fn user_data(&self) -> Option<&Vec<u8>> {
        self.user_data.as_ref()
    }

    pub(crate) fn has_more_data(&self) -> bool {
        self.has_more_data
    }

    pub(crate) fn from_parameters(parameters: &[SessionPduParameter]) -> Result<Self, CospError> {
        let mut user_data = None;
        let mut enclosure = None;

        // Not minding about order or duplicates.
        for parameter in parameters {
            match parameter {
                SessionPduParameter::EnclosureParameter(field) => enclosure = Some(*field),
                SessionPduParameter::UserDataParameter(data) => user_data = Some(data.clone()),
                _ => (), // Ignore everything else.
            };
        }

        Ok(ConnectDataOverflowMessage {
            user_data,
            has_more_data: !enclosure.unwrap_or_else(|| EnclosureField(2)).end(),
        })
    }
}
