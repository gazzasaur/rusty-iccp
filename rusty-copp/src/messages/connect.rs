use der_parser::{
    ber::{BitStringObject, parse_ber_tagged_implicit_g},
    der::{Class, Header, Tag},
};

use crate::{
    error::protocol_error, messages::{parsers::{process_constructed_data, process_octetstring, process_presentation_context_list, process_protocol, PresentationMode, Protocol}, user_data::UserData}, CoppError, PresentationContextType
};

#[derive(Debug)]
pub(crate) struct ConnectMessage {
    protocol: Option<Protocol>,
    presentation_mode: Option<PresentationMode>,
    calling_presentation_selector: Option<Vec<u8>>,
    called_presentation_selector: Option<Vec<u8>>,
    context_definition_list: PresentationContextType,
    user_data: Option<UserData>,
}

impl ConnectMessage {
    pub(crate) fn new(protocol: Option<Protocol>, calling_presentation_selector: Option<Vec<u8>>, called_presentation_selector: Option<Vec<u8>>, context_definition_list: PresentationContextType, user_data: Option<UserData>) -> Self {
        Self {
            protocol,
            presentation_mode: Some(PresentationMode::Normal),
            calling_presentation_selector,
            called_presentation_selector,
            context_definition_list,
            user_data,
        }
    }

    pub(crate) fn protocol(&self) -> Option<&Protocol> {
        self.protocol.as_ref()
    }

    pub(crate) fn presentation_mode(&self) -> Option<&PresentationMode> {
        self.presentation_mode.as_ref()
    }

    pub(crate) fn calling_presentation_selector(&self) -> Option<&Vec<u8>> {
        self.calling_presentation_selector.as_ref()
    }

    pub(crate) fn called_presentation_selector(&self) -> Option<&Vec<u8>> {
        self.called_presentation_selector.as_ref()
    }

    pub(crate) fn context_definition_list(&self) -> &PresentationContextType {
        &self.context_definition_list
    }

    pub(crate) fn user_data_mut(&mut self) -> &mut Option<UserData> {
        &mut self.user_data
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<ConnectMessage, CoppError> {
        let mut context_definition_list = None;
        let mut connection_message = ConnectMessage {
            protocol: None,
            presentation_mode: None,
            calling_presentation_selector: None,
            called_presentation_selector: None,
            context_definition_list: PresentationContextType::ContextDefinitionList(vec![]),
            user_data: None,
        };

        // This destructively processes the payload directly into the connect message in a single pass. No retrun is required.
        der_parser::ber::parse_ber_set_of_v(|data| {
            let (connect_message_remainder, object) = der_parser::ber::parse_ber_any(data)?;

            let (_, connect_message_parameter) = match object.header.raw_tag() {
                Some(&[160]) => {
                    let (_, presentation_mode) = parse_ber_tagged_implicit_g(Tag::from(0), |rem, header, size| {
                        let (_, value) = der_parser::ber::parse_ber_content(Tag::Integer)(rem, &header, size)?;
                        header.assert_class(Class::ContextSpecific)?;
                        header.assert_primitive()?;
                        Ok((&[], PresentationMode::from(value.as_slice()?)))
                    })(object.data)?;
                    connection_message.presentation_mode = Some(presentation_mode);
                    (&[] as &[u8], 0)
                }
                Some(&[162]) => {
                    // This is technically a sequence. But we are going to be relaxed. The standard also says to ignore unknown tags, which can complicate processing. So we treat this as a set.
                    for npm_object in process_constructed_data(object.data)? {
                        match npm_object.header.raw_tag() {
                            Some(&[128]) => connection_message.protocol = process_protocol(npm_object)?,
                            Some(&[129]) => connection_message.calling_presentation_selector = process_octetstring(npm_object)?,
                            Some(&[130]) => connection_message.called_presentation_selector = process_octetstring(npm_object)?,
                            Some(&[164]) => {
                                context_definition_list = Some(process_presentation_context_list(npm_object.data)?);
                            }
                            _ => (),
                        };
                    }

                    (&[] as &[u8], 0)
                }
                _ => (&[] as &[u8], 0),
            };
            Ok((connect_message_remainder, connect_message_parameter))
        })(&data)
        .map_err(|e| protocol_error("sd", e))?;

        Ok(connection_message)
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
                        match self.calling_presentation_selector.as_ref() {
                            Some(x) => Some(der_parser::ber::BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, false, Tag::from(1), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::OctetString(x.as_slice()),
                            )),
                            None => None,
                        },
                        // Called Presentation Selector
                        match self.called_presentation_selector.as_ref() {
                            Some(x) => Some(der_parser::ber::BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, false, Tag::from(2), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::OctetString(x.as_slice()),
                            )),
                            None => None,
                        },
                        // Context Definition List
                        match &self.context_definition_list {
                            PresentationContextType::ContextDefinitionList(contexts) => Some(der_parser::ber::BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(4), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(
                                    contexts
                                        .iter()
                                        .map(|context| {
                                            der_parser::ber::BerObject::from_seq(vec![
                                                der_parser::ber::BerObject::from_obj(der_parser::ber::BerObjectContent::Integer(context.indentifier.as_slice())),
                                                der_parser::ber::BerObject::from_obj(der_parser::ber::BerObjectContent::OID(context.abstract_syntax_name.clone())),
                                                der_parser::ber::BerObject::from_seq(
                                                    context
                                                        .transfer_syntax_name_list
                                                        .iter()
                                                        .map(|transfer| der_parser::ber::BerObject::from_obj(der_parser::ber::BerObjectContent::OID(transfer.clone())))
                                                        .collect(),
                                                ),
                                            ])
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
                            Some(x) => Some(x.to_ber()),
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
    use der_parser::Oid;
    use tracing_test::traced_test;

    use crate::PresentationContext;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_parse_connect() -> Result<(), anyhow::Error> {
        let subject = ConnectMessage::new(
            Some(Protocol::Version1),
            Some(vec![0x03]),
            Some(vec![0x04]),
            PresentationContextType::ContextDefinitionList(vec![
                PresentationContext {
                    indentifier: vec![1],
                    abstract_syntax_name: Oid::from(&[2, 2, 1, 0, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?,
                    transfer_syntax_name_list: vec![Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?],
                },
                PresentationContext {
                    indentifier: vec![1],
                    abstract_syntax_name: Oid::from(&[2, 2, 1, 0, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?,
                    transfer_syntax_name_list: vec![Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?],
                },
            ]),
            None,
        );
        let data = subject.serialise()?;
        let result = ConnectMessage::parse(data)?;

        assert_eq!(result.calling_presentation_selector(), Some(&vec![3u8]));
        assert_eq!(result.called_presentation_selector(), Some(&vec![4u8]));
        Ok(())
    }
}
