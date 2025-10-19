use der_parser::{
    ber::{BitStringObject, parse_ber_tagged_implicit_g},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    CoppError, PresentationContextResultType,
    error::protocol_error,
    messages::parsers::{PresentationMode, Protocol, process_constructed_data, process_octetstring, process_presentation_context_list, process_protocol},
};

#[derive(Debug)]
pub(crate) struct DataTransferMessage {
    user_data: Vec<u8>,
}

impl DataTransferMessage {
    pub(crate) fn new(user_data: Vec<u8>) -> Self {
        Self { user_data }
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<DataTransferMessage, CoppError> {
        let mut user_data = None;

        // This destructively processes the payload directly into the accept message in a single pass. No retrun is required.
        der_parser::ber::parse_ber_set_of_v(|data| {
            let (data_transfer_message_remainder, object) = der_parser::ber::parse_ber_any(data)?;

            let (_, data_transfer_message_remainder) = match object.header.raw_tag() {
                Some(&[161]) => {
                    let (_, user_data_bytes) = parse_ber_tagged_implicit_g(Tag::from(1), |rem, header, size| Ok((&[], rem.to_vec())))(object.data)?;
                    user_data = Some(user_data_bytes);
                    (&[] as &[u8], 0)
                }

                _ => (&[] as &[u8], 0),
            };
            warn!("here2");
            Ok((&[] as &[u8], 0))
        })(&data)
        .map_err(|e| protocol_error("sd", e))?;

        Ok(accept_message)
    }

    // TODO Support for default context
    pub(crate) fn serialise(&self) -> Result<Vec<u8>, CoppError> {
        if matches!(self.presentation_mode, Some(PresentationMode::X410)) || matches!(self.presentation_mode, Some(PresentationMode::Unknown)) {
            return Err(CoppError::InternalError(format!("Unsupported mode: {:?}", self.presentation_mode)));
        }
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
                        match self.user_data.as_ref() {
                            Some(x) => Some(der_parser::ber::BerObject::from_header_and_content(
                                Header::new(Class::Application, false, Tag::from(1), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::OctetString(x.as_slice()),
                            )),
                            None => None,
                        },
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
        let subject = DataTransferMessage::new(
            None,
        );
        let data = subject.serialise()?;
        let result = DataTransferMessage::parse(data)?;
        assert_eq!(result.responding_presentation_selector(), Some(&vec![4u8]));

        Ok(())
    }
}
