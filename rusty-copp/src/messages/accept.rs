use der_parser::{
    ber::{BitStringObject, parse_ber_graphicstring, parse_ber_tagged_implicit_g},
    der::{Class, Header, Tag},
};

use crate::{
    CoppError, PresentationContextResultType, UserData,
    error::protocol_error,
    messages::parsers::{PresentationMode, Protocol, process_constructed_data, process_octetstring, process_presentation_context_result_list, process_protocol},
};

#[derive(Debug)]
pub(crate) struct AcceptMessage {
    protocol: Option<Protocol>,
    presentation_mode: Option<PresentationMode>,
    responding_presentation_selector: Option<Vec<u8>>,
    context_definition_result_list: PresentationContextResultType,
    user_data: Option<UserData>,
}

impl AcceptMessage {
    pub(crate) fn new(protocol: Option<Protocol>, responding_presentation_selector: Option<Vec<u8>>, context_definition_result_list: PresentationContextResultType, user_data: Option<UserData>) -> Self {
        Self {
            protocol,
            presentation_mode: Some(PresentationMode::Normal),
            responding_presentation_selector,
            context_definition_result_list,
            user_data,
        }
    }

    pub(crate) fn user_data(self) -> Option<UserData> {
        self.user_data
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<AcceptMessage, CoppError> {
        let mut context_definition_list = None;
        let mut accept_message = AcceptMessage {
            protocol: None,
            presentation_mode: None,
            responding_presentation_selector: None,
            context_definition_result_list: PresentationContextResultType::ContextDefinitionList(vec![]),
            user_data: None,
        };

        // This destructively processes the payload directly into the accept message in a single pass. No retrun is required.
        der_parser::ber::parse_ber_set_of_v(|data| {
            let (accept_message_remainder, object) = der_parser::ber::parse_ber_any(data)?;

            let (_, accept_message_parameter) = match object.header.raw_tag() {
                Some(&[160]) => {
                    let (_, presentation_mode) = parse_ber_tagged_implicit_g(Tag::from(0), |rem, header, size| {
                        let (_, value) = der_parser::ber::parse_ber_content(Tag::Integer)(rem, &header, size)?;
                        header.assert_class(Class::ContextSpecific)?;
                        header.assert_primitive()?;
                        Ok((&[], PresentationMode::from(value.as_slice()?)))
                    })(object.data)?;
                    accept_message.presentation_mode = Some(presentation_mode);
                    (&[] as &[u8], 0)
                }
                Some(&[162]) => {
                    // This is technically a sequence. But we are going to be relaxed. The standard also says to ignore unknown tags, which can complicate processing. So we treat this as a set.
                    for npm_object in process_constructed_data(object.data)? {
                        match npm_object.header.raw_tag() {
                            Some(&[128]) => accept_message.protocol = process_protocol(npm_object)?,
                            Some(&[131]) => accept_message.responding_presentation_selector = process_octetstring(npm_object)?,
                            Some(&[165]) => {
                                context_definition_list = Some(process_presentation_context_result_list(npm_object.data)?);
                            }
                            Some(&[97]) => accept_message.user_data = Some(UserData::parse(npm_object)?),
                            _ => (),
                        };
                    }

                    (&[] as &[u8], 0)
                }
                _ => (&[] as &[u8], 0),
            };
            Ok((accept_message_remainder, accept_message_parameter))
        })(&data)
        .map_err(|e| protocol_error("sd", e))?;

        Ok(accept_message)
    }

    // TODO Support for default context
    pub(crate) fn serialise(&self) -> Result<Vec<u8>, CoppError> {
        if matches!(self.presentation_mode, Some(PresentationMode::X410)) || matches!(self.presentation_mode, Some(PresentationMode::Unknown)) {
            return Err(CoppError::InternalError(format!("Unsupported mode: {:?}", self.presentation_mode)));
        }
        let user_data = match &self.user_data {
            Some(user_data) => Some(user_data.to_ber()),
            None => None,
        };

        Ok(der_parser::ber::BerObject::from_set(vec![
            // Version defaults to 1, omitting.
            // Normal Mode
            der_parser::ber::BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, true, Tag::from(0), der_parser::ber::Length::Definite(0)),
                der_parser::ber::BerObjectContent::Set(vec![der_parser::ber::BerObject::from_header_and_content(
                    Header::new(Class::ContextSpecific, false, Tag::from(0), der_parser::ber::Length::Definite(0)),
                    der_parser::ber::BerObjectContent::Integer(&[1]),
                )]),
            ),
            // Normal Mode Parameters
            der_parser::ber::BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, true, Tag::from(2), der_parser::ber::Length::Definite(0)),
                der_parser::ber::BerObjectContent::Sequence(
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
                            Some(x) => Some(der_parser::ber::BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, false, Tag::from(3), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::OctetString(x.as_slice()),
                            )),
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
                        Some(der_parser::ber::BerObject::from_header_and_content(
                            Header::new(Class::ContextSpecific, false, Tag::from(8), der_parser::ber::Length::Definite(0)),
                            der_parser::ber::BerObjectContent::BitString(6, BitStringObject { data: &[0] }),
                        )),
                        // User Data
                        user_data,
                    ]
                    .into_iter()
                    .filter_map(|i| i)
                    .collect(),
                ),
            ),
        ])
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
    async fn it_should_parse_accept() -> Result<(), anyhow::Error> {
        let subject = AcceptMessage::new(
            Some(Protocol::Version1),
            Some(vec![0x04]),
            PresentationContextResultType::ContextDefinitionList(vec![PresentationContextResult {
                result: PresentationContextResultCause::Acceptance,
                transfer_syntax_name: None,
                provider_reason: None,
            }]),
            None,
        );
        let data = subject.serialise()?;
        let result = AcceptMessage::parse(data)?;
        assert_eq!(result.responding_presentation_selector, Some(vec![4u8]));

        Ok(())
    }
}
