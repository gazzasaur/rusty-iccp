use std::marker::PhantomData;

use der_parser::Oid;
use rusty_cosp::{CospConnection, CospInitiator, CospListener, CospReader, CospResponder, CospWriter};

use crate::{
    CoppConnection, CoppConnectionInformation, CoppError, CoppInitiator, CoppListener, CoppReader, CoppRecvResult, CoppResponder, CoppWriter, PresentationContextResult, PresentationContextResultCause, PresentationContextResultType, PresentationContextType, UserData, messages::{accept::AcceptMessage, connect::ConnectMessage}
};

pub struct RustyCoppInitiator<T: CospInitiator, R: CospReader, W: CospWriter> {
    cosp_initiator: T,
    cosp_reader: PhantomData<R>,
    cosp_writer: PhantomData<W>,
    options: CoppConnectionInformation,
}

impl<T: CospInitiator, R: CospReader, W: CospWriter> RustyCoppInitiator<T, R, W> {
    pub fn new(cosp_initiator: impl CospInitiator, options: CoppConnectionInformation) -> RustyCoppInitiator<impl CospInitiator, impl CospReader, impl CospWriter> {
        RustyCoppInitiator {
            cosp_initiator,
            cosp_reader: PhantomData::<R>,
            cosp_writer: PhantomData::<W>,
            options,
        }
    }
}

impl<T: CospInitiator, R: CospReader, W: CospWriter> CoppInitiator for RustyCoppInitiator<T, R, W> {
    async fn initiate(self, presentation_contexts: PresentationContextType, user_data: Option<UserData>) -> Result<(impl CoppConnection, Option<UserData>), CoppError> {
        let cosp_initiator = self.cosp_initiator;

        let connect_message = ConnectMessage::new(None, self.options.calling_presentation_selector, self.options.called_presentation_selector, presentation_contexts, user_data);
        let data = connect_message.serialise()?;

        let (cosp_connection, accept_data) = cosp_initiator.initiate(Some(data)).await?;
        let accept_message = match accept_data {
            Some(data) => AcceptMessage::parse(data)?,
            None => return Err(CoppError::ProtocolError("No accept message data was received fromt he remote host.".to_string())),
        };

        let (cosp_reader, cosp_writer) = cosp_connection.split().await?;
        Ok((RustyCoppConnection::new(cosp_reader, cosp_writer), accept_message.user_data()))
    }
}

pub struct RustyCoppListener<T: CospResponder, R: CospReader, W: CospWriter> {
    cosp_responder: T,
    user_data: Option<UserData>,
    cosp_reader: PhantomData<R>,
    cosp_writer: PhantomData<W>,
    connection_information: CoppConnectionInformation,
}

impl<T: CospResponder, R: CospReader, W: CospWriter> RustyCoppListener<T, R, W> {
    pub async fn new(cosp_listener: impl CospListener) -> Result<(RustyCoppListener<impl CospResponder, impl CospReader, impl CospWriter>, CoppConnectionInformation), CoppError> {
        let (cosp_responder, _, user_data) = cosp_listener.responder().await?;

        let mut connect_message = match user_data {
            Some(user_data) => ConnectMessage::parse(&user_data)?,
            None => return Err(CoppError::ProtocolError("No presentation connection data received.".to_string())),
        };

        let presentation_user_data = connect_message.user_data_mut().take();
        let copp_information = CoppConnectionInformation {
            calling_presentation_selector: connect_message.calling_presentation_selector().cloned(),
            called_presentation_selector: connect_message.called_presentation_selector().cloned(),
            presentation_context: connect_message.context_definition_list().clone(),
        };

        Ok((
            RustyCoppListener {
                cosp_responder,
                cosp_reader: PhantomData::<R>,
                cosp_writer: PhantomData::<W>,
                user_data: presentation_user_data,
                connection_information: copp_information.clone(),
                // resultant_contexts: None,
            },
            copp_information,
        ))
    }

    // pub fn with_context(&mut self, resultant_contexts: Option<PresentationContextResultType>) {
    //     self.resultant_contexts = resultant_contexts;
    // }
}

impl<T: CospResponder, R: CospReader, W: CospWriter> CoppListener for RustyCoppListener<T, R, W> {
    async fn responder(self) -> Result<(impl CoppResponder, Option<UserData>), CoppError> {
        Ok((RustyCoppResponder::<T, R, W>::new(self.cosp_responder, self.connection_information), self.user_data))
    }
}

pub struct RustyCoppResponder<T: CospResponder, R: CospReader, W: CospWriter> {
    cosp_responder: T,
    cosp_reader: PhantomData<R>,
    cosp_writer: PhantomData<W>,
    connection_information: CoppConnectionInformation,
}

impl<T: CospResponder, R: CospReader, W: CospWriter> RustyCoppResponder<T, R, W> {
    fn new(cosp_responder: T, connection_information: CoppConnectionInformation) -> RustyCoppResponder<impl CospResponder, impl CospReader, impl CospWriter> {
        RustyCoppResponder {
            cosp_responder,
            cosp_reader: PhantomData::<R>,
            cosp_writer: PhantomData::<W>,
            connection_information,
        }
    }
}

impl<T: CospResponder, R: CospReader, W: CospWriter> CoppResponder for RustyCoppResponder<T, R, W> {
    async fn accept(self, accept_data: Option<UserData>) -> Result<impl CoppConnection, CoppError> {
        let contexts = PresentationContextResultType::ContextDefinitionList(vec![
            PresentationContextResult {
                result: PresentationContextResultCause::Acceptance,
                transfer_syntax_name: Some(Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?),
                provider_reason: None,
            },
            PresentationContextResult {
                result: PresentationContextResultCause::Acceptance,
                transfer_syntax_name: Some(Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?),
                provider_reason: None,
            },
        ]);

        let responder = self.cosp_responder;
        let accept_message = AcceptMessage::new(None, self.connection_information.called_presentation_selector, contexts, accept_data);
        let accept_message_data = Some(accept_message.serialise()?);
        let (cosp_reader, cosp_writer) = responder.accept(accept_message_data).await?.split().await?;
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
        match self.cosp_reader.recv().await? {
            rusty_cosp::CospRecvResult::Closed => return Ok(CoppRecvResult::Closed),
            rusty_cosp::CospRecvResult::Data(items) => Ok(CoppRecvResult::Data(UserData::parse_raw(&items).map_err(|e| CoppError::ProtocolError(e.to_string()))?)),
        }
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
    async fn send(&mut self, user_data: &UserData) -> Result<(), CoppError> {
        self.cosp_writer
            .send(user_data.to_ber().to_vec().map_err(|e| CoppError::ProtocolError(e.to_string()))?.as_slice())
            .await
            .map_err(|e| CoppError::ProtocolStackError(e))
    }

    async fn continue_send(&mut self) -> Result<(), CoppError> {
        Ok(self.cosp_writer.continue_send().await?)
    }
}
