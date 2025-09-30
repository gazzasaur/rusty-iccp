use std::marker::PhantomData;

use der_parser::{
    Oid,
    ber::BitStringObject,
    der::{Class, Header, Tag},
};
use rusty_cosp::{CospConnection, CospInitiator, CospListener, CospReader, CospResponder, CospWriter};

use crate::{CoppConnection, CoppConnectionInformation, CoppError, CoppInitiator, CoppListener, CoppReader, CoppRecvResult, CoppResponder, CoppWriter, PresentationContext};

pub struct RustyCoppInitiator<T: CospInitiator, R: CospReader, W: CospWriter> {
    cosp_initiator: T,
    cosp_reader: PhantomData<R>,
    cosp_writer: PhantomData<W>,
    options: CoppConnectionInformation,
    presentation_contexts: Option<Vec<PresentationContext>>,
}

impl<T: CospInitiator, R: CospReader, W: CospWriter> RustyCoppInitiator<T, R, W> {
    pub fn new(cosp_initiator: impl CospInitiator, options: CoppConnectionInformation, presentation_contexts: Option<Vec<PresentationContext>>) -> RustyCoppInitiator<impl CospInitiator, impl CospReader, impl CospWriter> {
        RustyCoppInitiator {
            cosp_initiator,
            cosp_reader: PhantomData::<R>,
            cosp_writer: PhantomData::<W>,
            presentation_contexts,
            options,
        }
    }
}

impl<T: CospInitiator, R: CospReader, W: CospWriter> CoppInitiator for RustyCoppInitiator<T, R, W> {
    async fn initiate(self, user_data: Option<Vec<u8>>) -> Result<(impl CoppConnection, Option<Vec<u8>>), CoppError> {
        let cosp_initiator = self.cosp_initiator;

        let data = der_parser::ber::BerObject::from_set(vec![
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
                        match self.options.calling_presentation_selector.as_ref() {
                            Some(x) => Some(der_parser::ber::BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, false, Tag::from(1), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::OctetString(x.as_slice()),
                            )),
                            None => None,
                        },
                        // Called Presentation Selector
                        match self.options.called_presentation_selector.as_ref() {
                            Some(x) => Some(der_parser::ber::BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, false, Tag::from(2), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::OctetString(x.as_slice()),
                            )),
                            None => None,
                        },
                        // Context Definition List
                        match &self.presentation_contexts {
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
                        match user_data.as_ref() {
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
        .map_err(|e| CoppError::InternalError(e.to_string()))?;
        let (cosp_connection, _) = cosp_initiator.initiate(Some(data)).await?;
        let (cosp_reader, cosp_writer) = cosp_connection.split().await?;
        Ok((RustyCoppConnection::new(cosp_reader, cosp_writer), None))
    }
}

pub struct RustyCoppListener<T: CospResponder, R: CospReader, W: CospWriter> {
    cosp_responder: T,
    user_data: Option<Vec<u8>>,
    cosp_reader: PhantomData<R>,
    cosp_writer: PhantomData<W>,
}

impl<T: CospResponder, R: CospReader, W: CospWriter> RustyCoppListener<T, R, W> {
    pub async fn new(cosp_listener: impl CospListener) -> Result<(RustyCoppListener<impl CospResponder, impl CospReader, impl CospWriter>, CoppConnectionInformation), CoppError> {
        let (cosp_responder, _, user_data) = cosp_listener.responder().await?;
        Ok((
            RustyCoppListener {
                cosp_responder,
                cosp_reader: PhantomData::<R>,
                cosp_writer: PhantomData::<W>,
                user_data,
            },
            CoppConnectionInformation::default(),
        ))
    }
}

impl<T: CospResponder, R: CospReader, W: CospWriter> CoppListener for RustyCoppListener<T, R, W> {
    async fn responder(self) -> Result<(impl CoppResponder, CoppConnectionInformation, Option<Vec<u8>>), CoppError> {
        Ok((RustyCoppResponder::<T, R, W>::new(self.cosp_responder), CoppConnectionInformation::default(), None))
    }
}

pub struct RustyCoppResponder<T: CospResponder, R: CospReader, W: CospWriter> {
    cosp_responder: T,
    cosp_reader: PhantomData<R>,
    cosp_writer: PhantomData<W>,
}

impl<T: CospResponder, R: CospReader, W: CospWriter> RustyCoppResponder<T, R, W> {
    fn new(cosp_responder: T) -> RustyCoppResponder<impl CospResponder, impl CospReader, impl CospWriter> {
        RustyCoppResponder {
            cosp_responder,
            cosp_reader: PhantomData::<R>,
            cosp_writer: PhantomData::<W>,
        }
    }
}

impl<T: CospResponder, R: CospReader, W: CospWriter> CoppResponder for RustyCoppResponder<T, R, W> {
    async fn accept(self, _accept_data: Option<&[u8]>) -> Result<impl CoppConnection, CoppError> {
        let (cosp_reader, cosp_writer) = self.cosp_responder.accept(None).await?.split().await?;
        Ok(RustyCoppConnection::new(cosp_reader, cosp_writer))
    }
}

pub struct RustyCoppConnection<R: CospReader, W: CospWriter> {
    cosp_reader: R,
    cosp_writer: W,
}

impl<R: CospReader, W: CospWriter> RustyCoppConnection<R, W> {
    fn new(cosp_reader: R, cosp_writer: W) -> RustyCoppConnection<impl CospReader, impl CospWriter> {
        RustyCoppConnection { cosp_reader, cosp_writer }
    }
}

impl<R: CospReader, W: CospWriter> CoppConnection for RustyCoppConnection<R, W> {
    async fn split(self) -> Result<(impl CoppReader, impl CoppWriter), CoppError> {
        Ok((RustyCoppReader::new(self.cosp_reader), RustyCoppWriter::new(self.cosp_writer)))
    }
}

pub struct RustyCoppReader<R: CospReader> {
    cosp_reader: R,
}

impl<R: CospReader> RustyCoppReader<R> {
    fn new(cosp_reader: R) -> RustyCoppReader<impl CospReader> {
        RustyCoppReader { cosp_reader }
    }
}

impl<R: CospReader> CoppReader for RustyCoppReader<R> {
    async fn recv(&mut self) -> Result<CoppRecvResult, CoppError> {
        Ok(CoppRecvResult::Closed)
    }
}

pub struct RustyCoppWriter<W: CospWriter> {
    cosp_writer: W,
}

impl<W: CospWriter> RustyCoppWriter<W> {
    fn new(cosp_writer: W) -> RustyCoppWriter<impl CospWriter> {
        RustyCoppWriter { cosp_writer }
    }
}

impl<W: CospWriter> CoppWriter for RustyCoppWriter<W> {
    async fn send(&mut self, _data: &[u8]) -> Result<(), CoppError> {
        todo!()
    }

    async fn continue_send(&mut self) -> Result<(), CoppError> {
        todo!()
    }
}
