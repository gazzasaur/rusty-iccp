use crate::{
    api::CospError,
    common::TsduMaximumSize,
    packet::parameters::{EnclosureField, SessionPduParameter, SessionUserRequirementsField},
};

pub(crate) struct AcceptMessage {
    has_more_data: bool,
    user_data: Option<Vec<u8>>,
    maximum_size_to_responder: TsduMaximumSize,
}

impl AcceptMessage {
    pub(crate) fn new(has_more_data: bool, maximum_size_to_responder: TsduMaximumSize, user_data: Option<Vec<u8>>) -> Self {
        Self { has_more_data, user_data, maximum_size_to_responder }
    }
    
    pub(crate) fn user_data(&self) -> Option<&Vec<u8>> {
        self.user_data.as_ref()
    }

    pub(crate) fn maximum_size_to_responder(&self) -> &TsduMaximumSize {
        &self.maximum_size_to_responder
    }

    pub(crate) fn has_more_data(&self) -> bool {
        self.has_more_data
    }

    pub(crate) fn from_parameters(parameters: &[SessionPduParameter]) -> Result<Self, CospError> {
        let mut user_data = None;
        let mut enclosure = None;
        let mut version_number = None;
        let mut maximum_size_to_responder = TsduMaximumSize::Unlimited;
        let mut session_user_requirements = SessionUserRequirementsField::default();

        // Not minding about order or duplicates.
        for parameter in parameters {
            match parameter {
                SessionPduParameter::ConnectAcceptItemParameter(sub_pdus) => {
                    for sub_pdu in sub_pdus {
                        match sub_pdu {
                            SessionPduParameter::VersionNumberParameter(supported_versions) => version_number = Some(supported_versions),
                            SessionPduParameter::TsduMaximumSizeParameter(tsdu_maximum_size) => maximum_size_to_responder = TsduMaximumSize::Size(tsdu_maximum_size.to_responder()),
                            _ => (), // Ignore everything else.
                        }
                    }
                }
                SessionPduParameter::SessionUserRequirementsParameter(field) => session_user_requirements = *field,
                SessionPduParameter::EnclosureParameter(field) => enclosure = Some(*field),
                SessionPduParameter::UserDataParameter(data) => user_data = Some(data.clone()),
                _ => (), // Ignore everything else.
            };
        }
        match version_number {
            Some(version) if version.version2() => (),
            Some(version) if version.version1() => return Err(CospError::ProtocolError("Only version 2 is supported but version 1 was requested by the server on accept.".into())),
            Some(_) => return Err(CospError::ProtocolError("Only version 2 is supported but not was requested by the server on accept.".into())),
            None => return Err(CospError::ProtocolError("Only version 2 is supported but version 1 was implied by the server on accept.".into())),
        }
        if session_user_requirements.0 != 2 {
            return Err(CospError::ProtocolError(format!("Only full duplex mode functional unit is supported in accept but got: {:?}", session_user_requirements)));
        }

        Ok(AcceptMessage {
            user_data,
            maximum_size_to_responder,
            has_more_data: !enclosure.unwrap_or_else(|| EnclosureField(2)).end(),
        })
    }
}
