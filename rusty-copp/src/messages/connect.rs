use der_parser::{
    ber::{BerObjectContent, BitStringObject, parse_ber_sequence_of_v, parse_ber_tagged_implicit_g},
    der::{Class, Header, Tag},
    error::BerError,
};
use tracing::warn;

use crate::{
    CoppError, PresentationContext,
    error::protocol_error,
    messages::parsers::{ConnectMessageParameter, FunctionalUnit, NormalModeParameter, PresentationMode, Protocol, process_called_selector_or_skip, process_calling_selector_or_skip, process_protocol_or_skip, process_unknown_and_skip},
};

#[derive(Debug)]
pub(crate) struct ConnectMessage {
    protocol: Option<Protocol>,
    calling_presentation_selector: Option<Vec<u8>>,
    called_presentation_selector: Option<Vec<u8>>,
    context_definition_list: Option<Vec<PresentationContext>>,
    user_data: Option<Vec<u8>>,
}

impl ConnectMessage {
    pub(crate) fn new(
        protocol: Option<Protocol>,
        calling_presentation_selector: Option<Vec<u8>>,
        called_presentation_selector: Option<Vec<u8>>,
        context_definition_list: Option<Vec<PresentationContext>>,
        user_data: Option<Vec<u8>>,
    ) -> Self {
        Self {
            protocol,
            calling_presentation_selector,
            called_presentation_selector,
            context_definition_list,
            user_data,
        }
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<ConnectMessage, CoppError> {
        warn!("{:?}", data);

        let mut connection_message = ConnectMessage {
            protocol: None,
            calling_presentation_selector: None,
            called_presentation_selector: None,
            context_definition_list: None,
            user_data: None,
        };

        let a = der_parser::ber::parse_ber_set_of_v(|data| {
            let (connect_message_remainder, object) = der_parser::ber::parse_ber_any(data)?;

            let (_, connect_message_parameter) = match object.header.raw_tag() {
                Some(&[160]) => parse_ber_tagged_implicit_g(Tag::from(0), |rem, header, size| {
                    let (_, value) = der_parser::ber::parse_ber_content(Tag::Integer)(rem, &header, size)?;
                    header.assert_class(Class::ContextSpecific)?;
                    header.assert_primitive()?;
                    Ok((&[], ConnectMessageParameter::Mode(PresentationMode::from(value.as_slice()?))))
                })(object.data)?,
                Some(&[162]) => {
                    let mut normal_mode_parameters: Vec<NormalModeParameter> = vec![];
                    let remaining_normal_mode_data = object.data;
                    let (remaining_normal_mode_data, npm_object) = der_parser::ber::parse_ber_any(remaining_normal_mode_data)?;

                    let (remaining_normal_mode_data, npm_object, res) = process_protocol_or_skip(remaining_normal_mode_data, npm_object)?;
                    connection_message.protocol = res;

                    let (remaining_normal_mode_data, npm_object, res) = process_calling_selector_or_skip(remaining_normal_mode_data, npm_object)?;
                    connection_message.calling_presentation_selector = res;

                    let (remaining_normal_mode_data, npm_object, res) = process_called_selector_or_skip(remaining_normal_mode_data, npm_object)?;
                    connection_message.called_presentation_selector = res;

                    let (remaining_normal_mode_data, npm_object) = if let Some(&[164]) = npm_object.header.raw_tag() {
                        let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::Sequence)(npm_object.data, &npm_object.header, npm_object.data.len())?;
                        if let BerObjectContent::Sequence(presentation_contexts) = inner_object {
                            for presentation_context in presentation_contexts {
                                if let BerObjectContent::Sequence(inner_presentation_context) = presentation_context.content {
                                    let mut inner_presentation_context_iter = inner_presentation_context.iter();

                                    let identifier = match inner_presentation_context_iter.next() {
                                        Some(identifier) => identifier,
                                        None => break,
                                    };

                                    warn!("{:?}", inner_presentation_context);
                                }
                            }
                        };
                        der_parser::ber::parse_ber_any(remaining_normal_mode_data)?
                    } else {
                        (remaining_normal_mode_data, npm_object)
                    };
                    warn!("{:?}", "ther");

                    if let Some(&[136]) = npm_object.header.raw_tag() {
                        let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::BitString)(npm_object.data, &npm_object.header, npm_object.data.len())?;
                        if let BerObjectContent::BitString(_, value) = inner_object {
                            normal_mode_parameters.push(NormalModeParameter::FunctionalUnits(
                                vec![
                                    if value.is_set(0) { Some(FunctionalUnit::ContextManagement) } else { None },
                                    if value.is_set(1) { Some(FunctionalUnit::Restoration) } else { None },
                                ]
                                .into_iter()
                                .filter_map(|i| i)
                                .collect(),
                            ));
                        };
                    };

                    warn!("++++++ {:?}", normal_mode_parameters);

                    // This is a sequence, we will try to parse it in order. Need to use any to determine if there is a parsing error or just a parameter missing
                    // let (remaining_normal_mode_parameters_data, param) = der_parser::ber::parse_ber_tagged_implicit_g(Tag::from(0), |rem, header, size| {
                    //     let (_, protocol_field) = parse_ber_content(Tag::BitString)(rem, &header, size)?;
                    //     match protocol_field.as_bitstring()?.is_set(0) {
                    //         true => Ok((&[], NormalModeParameter::Protocol(NormalModeParameterProtocol::Version1))),
                    //         false => Ok((&[], NormalModeParameter::Protocol(NormalModeParameterProtocol::Unknown))),
                    //     }
                    // })(remaining_normal_mode_parameters_data).map(|(rem, res)| {
                    //     (rem, Some(res))
                    // }).unwrap_or_else(|_| (remaining_normal_mode_parameters_data, None));
                    // if let Some(value) = param {
                    //     normal_mode_parameters.push(value);
                    // };

                    // warn!("{:?}", remaining_normal_mode_parameters_data);

                    (remaining_normal_mode_data, ConnectMessageParameter::NormalModeParameters(normal_mode_parameters))

                    // let mut nomral_mode_parameters = vec![];

                    // // Presentation Requirements
                    // let (rem, parameter) = parse_ber_tagged_implicit_g(Tag::from(8), |rem, header, size| {
                    //     let (remaining, value) = der_parser::ber::parse_ber_content(Tag::BitString)(rem, &header, size)?;
                    //     header.assert_class(Class::ContextSpecific)?;
                    //     header.assert_primitive()?;
                    //     Ok((remaining, value))
                    // })(object.data)?;
                    // // parse_ber_tagged_implicit(Tag::from(1), |rem, header, size| {
                    // //     let (remaining, value) = der_parser::ber::parse_ber_content(Tag::OctetString)(rem, header, size)?;
                    // //     header.assert_class(Class::ContextSpecific)?;
                    // //     header.assert_primitive()?;
                    // //     Ok((remaining, value))
                    // // })(object.data)?;

                    // // parse_ber_tagged_implicit(Tag::from(2), |rem, header, size| {
                    // //     let (_, value) = der_parser::ber::parse_ber_content(Tag::Sequence)(rem, header, size)?;
                    // //     warn!("{:?}", value);
                    // //     Ok((&[], value))
                    // // })(object.data)?;

                    // (rem, ConnectMessageParameter::NormalModeParameters(nomral_mode_parameters))
                }
                _ => (connect_message_remainder, ConnectMessageParameter::Unknown),
            };
            Ok((connect_message_remainder, connect_message_parameter))
        })(&data)
        .map_err(|e| protocol_error("sd", e))?;

        warn!("{:?}", a);
        warn!("{:?}", connection_message);

        // let (_, ber) = der_parser::parse_ber(data.as_slice()).map_err(|e| protocol_error("", e))?;

        // match ber.header.raw_tag() {
        //     Some(x) if x.len() == 1 && x[0] == 49 => (),
        //     Some(x) => return Err(CoppError::ProtocolError(format!("Cannot parse payload. Expecting Connect PPDU with a tag of 49 but got: {:?}", x))),
        //     _ => return Err(CoppError::ProtocolError("Cannot parse payload. Not tag detected on root element of Connect PPDU.".into())),
        // }
        // let outer_payload = match ber.content {
        //     der_parser::ber::BerObjectContent::Set(ber_objects) => ber_objects,
        //     _ => return Err(CoppError::ProtocolError(format!("Cannot parse payload. Expected Set but found {:?}", ber.content))),
        // };

        // let mut mode: Option<u8> = None;
        // let mut version: Option<u8> = None; // TODO default to 1
        // let mut normal_mode_parameters: Option<u8> = None;
        // for parameter in outer_payload {
        //     match parameter.header.raw_tag() {
        //         Some(&[160]) => {
        //             warn!("{:?}", parameter)
        //         },
        //         Some(x) => warn!("Unsupported tag in outer body of connection: {:?}", x),
        //         _ => return Err(CoppError::ProtocolError(format!("No tag was detected in outer payload of connect message"))),
        //     }

        //     // der_parser::ber::parse_ber_tagged_implicit(Tag::from(160))

        //     // match parameter.header.raw_tag() {
        //     //     Some(&[160]) => match &parameter.content {
        //     //         der_parser::ber::BerObjectContent::Unknown(mode_objects) => {
        //     //             println!("{:?}", parameter);
        //     //             let b = parse_ber_implicit(mode_objects.data, 0, parse_ber_content(Tag::Set));
        //     //             println!("{:?}", b);

        //     //             // warn!("{:?}", parse_ber(mode_objects.data).map_err(|e| protocol_error("", e))?);
        //     //             // for mode_object in mode_objects {
        //     //             //     match mode_object.header.raw_tag() {
        //     //             //         x => return Err(CoppError::ProtocolError(format!("Unexpected tag on mode parameter {:?}", x))),
        //     //             //     }
        //     //             // }
        //     //         }
        //     //         x => return Err(CoppError::ProtocolError(format!("Unexpected context in mode {:?}", x))),
        //     //     },
        //     //     Some(x) => warn!("Unsupported tag in outer body of connection: {:?}", x),
        //     //     _ => return Err(CoppError::ProtocolError(format!("No tag was detected in outer payload of connect message"))),
        //     // }
        // }

        todo!("finish");
    }

    // TODO Default Context
    pub(crate) fn serialise(&self) -> Result<Vec<u8>, CoppError> {
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
                            Some(contexts) => Some(der_parser::ber::BerObject::from_header_and_content(
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
                            None => None,
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
    use std::{ops::Range, time::Duration};

    use der_parser::Oid;
    use rusty_cosp::{TcpCospInitiator, TcpCospListener, TcpCospReader, TcpCospResponder, TcpCospWriter};
    use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    use tokio::join;
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_parse_connect() -> Result<(), anyhow::Error> {
        let subject = ConnectMessage::new(
            Some(Protocol::Version1),
            Some(vec![0x03]),
            Some(vec![0x04]),
            Some(vec![
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
        let _result = ConnectMessage::parse(data)?;
        Ok(())
    }
}
