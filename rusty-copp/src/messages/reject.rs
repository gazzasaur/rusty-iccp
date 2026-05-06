use der_parser::{
    ber::BitStringObject,
    der::{Class, Header, Tag},
};

use crate::{
    CoppError, PresentationContextResultType, ProviderReason, UserData,
    error::protocol_error,
    messages::parsers::{PresentationMode, Protocol, process_octetstring, process_presentation_context_result_list, process_protocol},
};

#[derive(Debug)]
pub(crate) struct RejectMessage {
    protocol: Option<Protocol>,
    presentation_mode: Option<PresentationMode>,
    responding_presentation_selector: Option<Vec<u8>>,
    context_definition_result_list: PresentationContextResultType,
    provider_reason: Option<ProviderReason>,
    user_data: Option<UserData>,
}

impl RejectMessage {
    pub(crate) fn new(
        protocol: Option<Protocol>,
        responding_presentation_selector: Option<Vec<u8>>,
        context_definition_result_list: PresentationContextResultType,
        provider_reason: Option<ProviderReason>,
        user_data: Option<UserData>,
    ) -> Self {
        Self { protocol, presentation_mode: Some(PresentationMode::Normal), responding_presentation_selector, context_definition_result_list, provider_reason, user_data }
    }

    pub(crate) fn to_error(self) -> CoppError {
        CoppError::Rejected(self.provider_reason, self.context_definition_result_list, self.user_data)
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<RejectMessage, CoppError> {
        let mut context_definition_list = None;
        let mut reject_message = RejectMessage {
            protocol: None,
            presentation_mode: None,
            responding_presentation_selector: None,
            context_definition_result_list: PresentationContextResultType::ContextDefinitionList(vec![]),
            provider_reason: None,
            user_data: None,
        };

        // This destructively processes the payload directly into the accept message in a single pass. No retrun is required.
        der_parser::ber::parse_ber_sequence_of_v(|data| {
            let (reject_message_remainder, object) = der_parser::ber::parse_ber_any(data)?;

            let (_, reject_message_parameter) = match object.header.raw_tag() {
                Some(&[128]) => {
                    reject_message.protocol = process_protocol(object)?;
                    (&[] as &[u8], 0)
                },
                Some(&[131]) => {
                    reject_message.responding_presentation_selector = process_octetstring(object)?;
                    (&[] as &[u8], 0)
                },
                Some(&[165]) => {
                    context_definition_list = Some(process_presentation_context_result_list(object.data)?);
                    (&[] as &[u8], 0)
                },
                Some(&[97]) => {
                    reject_message.user_data = Some(UserData::parse(object)?);
                    (&[] as &[u8], 0)
                },
                _ => (&[] as &[u8], 0),
            };
            Ok((reject_message_remainder, reject_message_parameter))
        })(&data)
        .map_err(|e| protocol_error("sd", e))?;

        Ok(reject_message)
    }

    pub(crate) fn serialise(&self) -> Result<Vec<u8>, CoppError> {
        if matches!(self.presentation_mode, Some(PresentationMode::X410)) || matches!(self.presentation_mode, Some(PresentationMode::Unknown)) {
            return Err(CoppError::InternalError(format!("Unsupported mode: {:?}", self.presentation_mode)));
        }
        let provider_reason: Option<Vec<u8>> = match &self.provider_reason {
            Some(value) => Some(value.into()),
            None => None,
        };
        let user_data = match &self.user_data {
            Some(user_data) => Some(user_data.to_ber()),
            None => None,
        };

        Ok(der_parser::ber::BerObject::from_seq(
            vec![
                // Protocol
                match self.protocol.as_ref() {
                    Some(&Protocol::Version1) => Some(der_parser::ber::BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, false, Tag::from(0), der_parser::ber::Length::Definite(0)),
                        der_parser::ber::BerObjectContent::BitString(6, BitStringObject { data: &[1] }),
                    )),
                    Some(Protocol::Unknown(x)) => return Err(CoppError::InternalError(format!("Unknown protocol version: {:?}", x))),
                    None => None,
                },
                // Calling Presentation Selector
                match self.responding_presentation_selector.as_ref() {
                    Some(x) => {
                        Some(der_parser::ber::BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(3), der_parser::ber::Length::Definite(0)), der_parser::ber::BerObjectContent::OctetString(x.as_slice())))
                    }
                    None => None,
                },
                // Context Definition List
                match &self.context_definition_result_list {
                    PresentationContextResultType::ContextDefinitionList(contexts) => Some(der_parser::ber::BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(5), der_parser::ber::Length::Definite(0)),
                        der_parser::ber::BerObjectContent::Sequence(
                            contexts
                                .iter()
                                .map(|context| {
                                    der_parser::ber::BerObject::from_seq(
                                        vec![
                                            Some(der_parser::ber::BerObject::from_header_and_content(
                                                Header::new(Class::ContextSpecific, false, Tag::from(0), der_parser::ber::Length::Definite(0)),
                                                der_parser::ber::BerObjectContent::Integer(context.result.clone().into()),
                                            )),
                                            match &context.transfer_syntax_name {
                                                Some(transfer_syntax_name) => Some(der_parser::ber::BerObject::from_header_and_content(
                                                    Header::new(Class::ContextSpecific, false, Tag::from(1), der_parser::ber::Length::Definite(0)),
                                                    der_parser::ber::BerObjectContent::OID(transfer_syntax_name.clone()),
                                                )),
                                                None => None,
                                            },
                                            match &context.provider_reason {
                                                Some(provider_reason) => Some(der_parser::ber::BerObject::from_header_and_content(
                                                    Header::new(Class::ContextSpecific, false, Tag::from(2), der_parser::ber::Length::Definite(0)),
                                                    der_parser::ber::BerObjectContent::Integer(provider_reason.clone().into()),
                                                )),
                                                None => None,
                                            },
                                        ]
                                        .into_iter()
                                        .filter_map(|f| f)
                                        .collect(),
                                    )
                                })
                                .collect(),
                        ),
                    )),
                },
                // Presentation Requirements
                provider_reason
                    .as_ref()
                    .map(|x| der_parser::ber::BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(10), der_parser::ber::Length::Definite(0)), der_parser::ber::BerObjectContent::Integer(x.as_slice()))),
                // User Data
                user_data,
            ]
            .into_iter()
            .filter_map(|i| i)
            .collect(),
        )
        .to_vec()
        .map_err(|e| CoppError::InternalError(e.to_string()))?)
    }
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use crate::{PresentationContextResult, PresentationContextResultCause};

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_parse_reject() -> Result<(), anyhow::Error> {
        let subject = RejectMessage::new(
            Some(Protocol::Version1),
            Some(vec![0x04]),
            PresentationContextResultType::ContextDefinitionList(vec![PresentationContextResult { result: PresentationContextResultCause::Acceptance, transfer_syntax_name: None, provider_reason: None }]),
            None,
            None,
        );
        let data = subject.serialise()?;
        let result = RejectMessage::parse(data)?;
        assert_eq!(result.responding_presentation_selector, Some(vec![4u8]));

        Ok(())
    }
}
