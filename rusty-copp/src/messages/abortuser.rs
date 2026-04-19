use der_parser::der::{Class, Header, Tag};

use crate::{
    CoppError, PresentationContextIdentifier, UserData,
    error::protocol_error,
    messages::parsers::process_presentation_context_identifier_list,
};

#[derive(Debug)]
pub(crate) struct AbortUserMessage {
    presentation_contexts: Option<Vec<PresentationContextIdentifier>>,
    user_data: Option<UserData>,
}

impl AbortUserMessage {
    pub(crate) fn new(presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> Self {
        Self { presentation_contexts, user_data }
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<AbortUserMessage, CoppError> {
        let mut user_data = None;
        let mut context_definition_list = None;

        // This destructively processes the payload directly into the accept message in a single pass. No retrun is required.
        der_parser::ber::parse_ber_set_of_v(|data| {
            let (abort_message_remainder, object) = der_parser::ber::parse_ber_any(data)?;

            match object.header.raw_tag() {
                Some(&[160]) => context_definition_list = Some(process_presentation_context_identifier_list(object.data)?),
                Some(&[97]) => user_data = Some(UserData::parse(object)?),
                _ => (),
            };
            Ok((abort_message_remainder, 0))
        })(&data)
        .map_err(|e| protocol_error("sd", e))?;

        Ok(AbortUserMessage { presentation_contexts: context_definition_list, user_data })
    }

    pub(crate) fn to_error(self) -> CoppError {
        CoppError::UserAborted(self.presentation_contexts, self.user_data)
    }

    pub(crate) fn serialise(&self) -> Result<Vec<u8>, CoppError> {
        let user_data = match &self.user_data {
            Some(user_data) => Some(user_data.to_ber()),
            None => None,
        };

        Ok(der_parser::ber::BerObject::from_header_and_content(
            Header::new(Class::ContextSpecific, true, Tag::from(0), der_parser::ber::Length::Definite(0)),
            der_parser::ber::BerObjectContent::Sequence(
                vec![
                    // Context Definition List
                    match &self.presentation_contexts {
                        Some(contexts) => Some(der_parser::ber::BerObject::from_header_and_content(
                            Header::new(Class::ContextSpecific, true, Tag::from(0), der_parser::ber::Length::Definite(0)),
                            der_parser::ber::BerObjectContent::Sequence(
                                contexts
                                    .iter()
                                    .map(|context| {
                                        der_parser::ber::BerObject::from_seq(
                                            vec![
                                                Some(der_parser::ber::BerObject::from_header_and_content(
                                                    Header::new(Class::ContextSpecific, false, Tag::from(0), der_parser::ber::Length::Definite(0)),
                                                    der_parser::ber::BerObjectContent::Integer(&context.identifier),
                                                )),
                                                Some(der_parser::ber::BerObject::from_header_and_content(
                                                    Header::new(Class::ContextSpecific, false, Tag::from(1), der_parser::ber::Length::Definite(0)),
                                                    der_parser::ber::BerObjectContent::OID(context.transfer_syntax_name.clone()),
                                                )),
                                            ]
                                            .into_iter()
                                            .filter_map(|f| f)
                                            .collect(),
                                        )
                                    })
                                    .collect(),
                            ),
                        )),
                        None => todo!(),
                    },
                    // User Data
                    user_data,
                ]
                .into_iter()
                .filter_map(|i| i)
                .collect(),
            ),
        )
        .to_vec()
        .map_err(|e| CoppError::InternalError(e.to_string()))?)
    }
}
