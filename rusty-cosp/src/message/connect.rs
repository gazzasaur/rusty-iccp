use crate::{
    api::CospError,
    common::TsduMaximumSize,
    packet::parameters::{DataOverflowField, SessionPduParameter, SessionUserRequirementsField},
};

pub(crate) struct ConnectMessage {
    user_data: Option<Vec<u8>>,
    data_overflow: Option<DataOverflowField>,
    maximum_size_to_initiator: TsduMaximumSize,
}

impl ConnectMessage {
    pub(crate) fn user_data(&self) -> Option<&Vec<u8>> {
        self.user_data.as_ref()
    }

    pub(crate) fn data_overflow(&self) -> Option<&DataOverflowField> {
        self.data_overflow.as_ref()
    }

    pub(crate) fn maximum_size_to_initiator(&self) -> &TsduMaximumSize {
        &self.maximum_size_to_initiator
    }

    pub(crate) fn from_parameters(parameters: &[SessionPduParameter]) -> Result<Self, CospError> {
        let mut user_data = None;
        let mut data_overflow = None;
        let mut extended_user_data = None;
        let mut version_number = None;
        let mut maximum_size_to_initiator = TsduMaximumSize::Unlimited;
        let mut session_user_requirements = SessionUserRequirementsField::default();

        // Not minding about order or duplicates.
        for parameter in parameters {
            match parameter {
                SessionPduParameter::ConnectAcceptItemParameter(session_pdu_sub_parameters) => {
                    for sub_parameters in session_pdu_sub_parameters {
                        match sub_parameters {
                            // We don't really care about protocol options. We are not going to support extended concatentation.
                            SessionPduParameter::VersionNumberParameter(value) => version_number = Some(value),
                            SessionPduParameter::TsduMaximumSizeParameter(value) => {
                                if value.to_initiator() != 0 {
                                    maximum_size_to_initiator = TsduMaximumSize::Size(value.to_initiator()) // Ignore the responder as that is us.
                                }
                            }
                            _ => (), // Ignore everything else.
                        }
                    }
                }
                SessionPduParameter::SessionUserRequirementsParameter(field) => session_user_requirements = *field,
                SessionPduParameter::UserDataParameter(data) => user_data = Some(data),
                SessionPduParameter::DataOverflowParameter(field) if field.more_data() => data_overflow = Some(*field), // Ignore it if there is no more data.
                SessionPduParameter::ExtendedUserDataParameter(data) => extended_user_data = Some(data),
                _ => (), // Ignore everything else.
            };
        }
        match version_number {
            Some(version) if version.version2() => (),
            _ => return Err(CospError::ProtocolError("Only version 2 is supported but version 1 was requested by the client.".into())),
        }
        if !session_user_requirements.full_duplex() {
            return Err(CospError::ProtocolError(format!("Full duplex mode is not supported by peer.")));
        }
        if extended_user_data.is_none() && data_overflow.is_some() {
            return Err(CospError::ProtocolError(format!("An overflow parameter was found but no data was provided.")));
        }
        let user_data = match (user_data, extended_user_data) {
            (None, None) => None,
            (None, Some(data)) => Some(data.clone()),
            (Some(data), None) => Some(data.clone()),
            (Some(_), Some(_)) => return Err(CospError::ProtocolError(format!("User Data and Overflow data was detected. Cannot continue to connect."))),
        };

        Ok(ConnectMessage {
            user_data,
            data_overflow,
            maximum_size_to_initiator,
        })
    }
}
