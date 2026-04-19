use std::{collections::VecDeque, marker::PhantomData};

use der_parser::Oid;
use rusty_cosp::{CospAcceptor, CospConnection, CospError, CospInitiator, CospReader, CospRecvResult, CospResponder, CospWriter, ReasonCode};

use crate::{
    CoppConnection, CoppConnectionInformation, CoppError, CoppInitiator, CoppListener, CoppReader, CoppRecvResult, CoppResponder, CoppWriter, EventIdentifier, PresentationContextIdentifier, PresentationContextResult, PresentationContextResultCause, PresentationContextResultType, PresentationContextType, ProviderReason, UserData, messages::{abortprovider::AbortProviderMessage, abortuser::AbortUserMessage, accept::AcceptMessage, connect::ConnectMessage, reject::RejectMessage}
};

pub struct RustyCoppInitiator<T: CospInitiator, R: CospReader, W: CospWriter> {
    cosp_initiator: T,
    cosp_reader: PhantomData<R>,
    cosp_writer: PhantomData<W>,
    options: CoppConnectionInformation,
}

impl<T: CospInitiator, R: CospReader, W: CospWriter> RustyCoppInitiator<T, R, W> {
    pub fn new(cosp_initiator: impl CospInitiator, options: CoppConnectionInformation) -> RustyCoppInitiator<impl CospInitiator, impl CospReader, impl CospWriter> {
        RustyCoppInitiator { cosp_initiator, cosp_reader: PhantomData::<R>, cosp_writer: PhantomData::<W>, options }
    }
}

impl<T: CospInitiator, R: CospReader, W: CospWriter> CoppInitiator for RustyCoppInitiator<T, R, W> {
    async fn initiate(self, presentation_contexts: PresentationContextType, user_data: Option<UserData>) -> Result<(impl CoppConnection, Option<UserData>), CoppError> {
        let cosp_initiator = self.cosp_initiator;

        let connect_message = ConnectMessage::new(None, self.options.calling_presentation_selector, self.options.called_presentation_selector, presentation_contexts, user_data);
        let data = connect_message.serialise()?;

        let (cosp_connection, accept_data) = match cosp_initiator.initiate(Some(data)).await {
            Ok(x) => x,
            Err(CospError::Refused(_user_data)) => todo!(),
            Err(CospError::Aborted(_user_data)) => todo!(),
            Err(e) => Err(e)?,
        };
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
    presentation_context: PresentationContextType,
    connection_information: CoppConnectionInformation,
}

impl<T: CospResponder, R: CospReader, W: CospWriter> RustyCoppListener<T, R, W> {
    pub async fn new(cosp_listener: impl CospAcceptor) -> Result<(RustyCoppListener<impl CospResponder, impl CospReader, impl CospWriter>, CoppConnectionInformation), CoppError> {
        let (cosp_responder, user_data) = cosp_listener.accept().await?;

        let mut connect_message = match user_data {
            Some(user_data) => ConnectMessage::parse(&user_data)?,
            None => return Err(CoppError::ProtocolError("No presentation connection data received.".to_string())),
        };

        let presentation_user_data = connect_message.user_data_mut().take();
        let presentation_context = connect_message.context_definition_list();
        let copp_information = CoppConnectionInformation { calling_presentation_selector: connect_message.calling_presentation_selector().cloned(), called_presentation_selector: connect_message.called_presentation_selector().cloned() };

        Ok((
            RustyCoppListener {
                cosp_responder,
                cosp_reader: PhantomData::<R>,
                cosp_writer: PhantomData::<W>,
                user_data: presentation_user_data,
                connection_information: copp_information.clone(),
                presentation_context: presentation_context.clone(),
                // resultant_contexts: None,
            },
            copp_information,
        ))
    }
}

impl<T: CospResponder, R: CospReader, W: CospWriter> CoppListener for RustyCoppListener<T, R, W> {
    async fn accept(self) -> Result<(impl CoppResponder, PresentationContextType, Option<UserData>), CoppError> {
        Ok((RustyCoppResponder::<T, R, W>::new(self.cosp_responder, self.connection_information), self.presentation_context, self.user_data))
    }
    
    async fn reject(self, context_definition_result_list: PresentationContextResultType, provider_reason: Option<ProviderReason>, user_data: Option<UserData>) -> Result<(), CoppError> {
        let responder = self.connection_information.called_presentation_selector;
        self.cosp_responder.refuse(Some(ReasonCode::RejectionByCalledSsUserWithData(RejectMessage::new(None, responder, context_definition_result_list, provider_reason, user_data).serialise()?))).await?;
        Ok(())
    }

    async fn user_abort(self, presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> Result<(), CoppError> {
        self.cosp_responder.abort(Some(AbortUserMessage::new(presentation_contexts, user_data).serialise()?)).await?;
        Ok(())
    }
    
    async fn provider_abort(self, provider_reason: Option<ProviderReason>, event_identifier: Option<EventIdentifier>) -> Result<(), CoppError> {
        self.cosp_responder.abort(Some(AbortProviderMessage::new(provider_reason, event_identifier).serialise()?)).await?;
        Ok(())
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
        RustyCoppResponder { cosp_responder, cosp_reader: PhantomData::<R>, cosp_writer: PhantomData::<W>, connection_information }
    }
}

impl<T: CospResponder, R: CospReader, W: CospWriter> CoppResponder for RustyCoppResponder<T, R, W> {
    async fn complete_connection(self, accept_data: Option<UserData>) -> Result<impl CoppConnection, CoppError> {
        let contexts = PresentationContextResultType::ContextDefinitionList(vec![
            PresentationContextResult { result: PresentationContextResultCause::Acceptance, transfer_syntax_name: Some(Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?), provider_reason: None },
            PresentationContextResult { result: PresentationContextResultCause::Acceptance, transfer_syntax_name: Some(Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?), provider_reason: None },
        ]);

        let responder = self.cosp_responder;
        let accept_message = AcceptMessage::new(None, self.connection_information.called_presentation_selector, contexts, accept_data);
        let accept_message_data = Some(accept_message.serialise()?);
        let (cosp_reader, cosp_writer) = responder.complete_connection(accept_message_data).await?.split().await?;
        Ok(RustyCoppConnection::new(cosp_reader, cosp_writer))
    }
    
    async fn reject(self, context_definition_result_list: PresentationContextResultType, provider_reason: Option<ProviderReason>, user_data: Option<UserData>) -> Result<(), CoppError> {
        let responder = self.connection_information.called_presentation_selector;
        self.cosp_responder.refuse(Some(ReasonCode::RejectionByCalledSsUserWithData(RejectMessage::new(None, responder, context_definition_result_list, provider_reason, user_data).serialise()?))).await?;
        Ok(())
    }

    async fn user_abort(self, presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> Result<(), CoppError> {
        self.cosp_responder.abort(Some(AbortUserMessage::new(presentation_contexts, user_data).serialise()?)).await?;
        Ok(())
    }
    
    async fn provider_abort(self, provider_reason: Option<ProviderReason>, event_identifier: Option<EventIdentifier>) -> Result<(), CoppError> {
        self.cosp_responder.abort(Some(AbortProviderMessage::new(provider_reason, event_identifier).serialise()?)).await?;
        Ok(())
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
        let message = match self.cosp_reader.recv().await {
            Ok(x) => x,
            Err(CospError::Refused(None)) => return Err(CoppError::ProtocolError("Refused message received after the connection was established.".into())),
            Err(CospError::Refused(Some(ReasonCode::RejectionByCalledSsUserWithData(user_data)))) => return Err(RejectMessage::parse(user_data)?.to_error()),
            Err(CospError::Aborted(None)) => return Err(CoppError::ProviderAborted(None, None)),
            Err(CospError::Aborted(Some(user_data))) => {
                match user_data.get(0) {
                    Some(160) => return Err(AbortUserMessage::parse(user_data)?.to_error()),
                    Some(30) => return Err(AbortProviderMessage::parse(user_data)?.to_error()),
                    Some(x) => return Err(CoppError::ProtocolError(format!("COPP abort expected does not match a supported header: {x}"))),
                    None => return Err(CoppError::ProtocolError("COPP abort expected but no data was received.".into())),
                }
            },
            Result::Err(e) => Err(e)?,
        };

        match message {
            CospRecvResult::Finish(_) => todo!(),
            CospRecvResult::Disconnect(_) => todo!(),
            CospRecvResult::Closed => return Ok(CoppRecvResult::Closed),
            CospRecvResult::Data(items) => Ok(CoppRecvResult::Data(UserData::parse_raw(&items).map_err(|e| CoppError::ProtocolError(e.to_string()))?)),
        }
    }
}

pub struct RustyCoppWriter<W: CospWriter> {
    cosp_writer: W,
    buffer: VecDeque<Vec<u8>>,
}

impl<W: CospWriter> RustyCoppWriter<W> {
    fn new(cosp_writer: W) -> RustyCoppWriter<impl CospWriter> {
        RustyCoppWriter { cosp_writer, buffer: VecDeque::new() }
    }
}

impl<W: CospWriter> CoppWriter for RustyCoppWriter<W> {
    async fn send(&mut self, user_data: &mut VecDeque<UserData>) -> Result<(), CoppError> {
        while let Some(user_data_item) = user_data.pop_front() {
            self.buffer.push_back(user_data_item.to_ber().to_vec().map_err(|e| CoppError::ProtocolError(e.to_string()))?);
        }

        while !self.buffer.is_empty() {
            self.cosp_writer.send(&mut self.buffer).await?;
        }

        // Perform one more to ensure lower levels are also flushed even if this layer is complete.
        self.cosp_writer.send(&mut self.buffer).await?;
        Ok(())
    }

    async fn abort_user(self, presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> Result<(), CoppError> {
        self.cosp_writer.abort(Some(AbortUserMessage::new(presentation_contexts, user_data).serialise()?)).await?;
        Ok(())
    }
}
