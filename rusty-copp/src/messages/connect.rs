use std::any::Any;

use der_parser::{
    ber::{parse_ber_content, parse_ber_implicit, BitStringObject, Length},
    der::{parse_der_container, Class, Header, Tag}, parse_ber,
};
use tracing::warn;

use crate::{CoppError, PresentationContext, error::protocol_error};

pub(crate) struct ConnectMessage {
    calling_presentation_selector: Option<Vec<u8>>,
    called_presentation_selector: Option<Vec<u8>>,
    context_definition_list: Option<Vec<PresentationContext>>,
    user_data: Option<Vec<u8>>,
}

impl ConnectMessage {
    pub(crate) fn new(calling_presentation_selector: Option<Vec<u8>>, called_presentation_selector: Option<Vec<u8>>, context_definition_list: Option<Vec<PresentationContext>>, user_data: Option<Vec<u8>>) -> Self {
        Self {
            calling_presentation_selector,
            called_presentation_selector,
            context_definition_list,
            user_data,
        }
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<ConnectMessage, CoppError> {
        let (_, ber) = der_parser::parse_ber(data.as_slice()).map_err(|e| protocol_error("", e))?;

        match ber.header.raw_tag() {
            Some(x) if x.len() == 1 && x[0] == 49 => (),
            Some(x) => return Err(CoppError::ProtocolError(format!("Cannot parse payload. Expecting Connect PPDU with a tag of 49 but got: {:?}", x))),
            _ => return Err(CoppError::ProtocolError("Cannot parse payload. Not tag detected on root element of Connect PPDU.".into())),
        }
        let outer_payload = match ber.content {
            der_parser::ber::BerObjectContent::Set(ber_objects) => ber_objects,
            _ => return Err(CoppError::ProtocolError(format!("Cannot parse payload. Expected Set but found {:?}", ber.content))),
        };

        let mut mode: Option<u8> = None;
        let mut version: Option<u8> = None; // TODO default to 1
        let mut normal_mode_parameters: Option<u8> = None;
        for parameter in outer_payload {
            match parameter.header.raw_tag() {
                Some(&[160]) => match &parameter.content {
                    der_parser::ber::BerObjectContent::Unknown(mode_objects) => {
                        println!("{:?}", parameter);
                            let b = parse_ber_implicit(
        mode_objects.data,
        0,
        parse_ber_content(Tag::Set),
    );
    println!("{:?}", b);

                        // warn!("{:?}", parse_ber(mode_objects.data).map_err(|e| protocol_error("", e))?);
                        // for mode_object in mode_objects {
                        //     match mode_object.header.raw_tag() {
                        //         x => return Err(CoppError::ProtocolError(format!("Unexpected tag on mode parameter {:?}", x))),
                        //     }
                        // }
                    }
                    x => return Err(CoppError::ProtocolError(format!("Unexpected context in mode {:?}", x))),
                },
                Some(x) => warn!("Unsupported tag in outer body of connection: {:?}", x),
                _ => return Err(CoppError::ProtocolError(format!("No tag was detected in outer payload of connect message"))),
            }
        }

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
        let subject = ConnectMessage::new(None, None, None, None);
        let data = subject.serialise()?;
        let _result = ConnectMessage::parse(data)?;
        Ok(())
    }
}
