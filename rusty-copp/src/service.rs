use std::marker::PhantomData;

use rusty_cosp::{CospConnection, CospInitiator, CospListener, CospReader, CospResponder, CospWriter};

use crate::{
    messages::{accept::AcceptMessage, connect::ConnectMessage}, CoppConnection, CoppConnectionInformation, CoppContext, CoppError, CoppInitiator, CoppListener, CoppReader, CoppRecvResult, CoppResponder, CoppWriter, PresentationContextResult, PresentationContextResultCause, PresentationContextResultType, PresentationContextType
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
    async fn initiate(self, presentation_contexts: PresentationContextType, user_data: Option<Vec<u8>>) -> Result<(impl CoppConnection, Option<Vec<u8>>), CoppError> {
        let cosp_initiator = self.cosp_initiator;

        let connect_message = ConnectMessage::new(
            None,
            self.options.calling_presentation_selector,
            self.options.called_presentation_selector,
            presentation_contexts,
            user_data,
        );
        let data = connect_message.serialise()?;

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
    connection_information: CoppConnectionInformation,
    resultant_contexts: Option<PresentationContextResultType>,
}

impl<T: CospResponder, R: CospReader, W: CospWriter> RustyCoppListener<T, R, W> {
    pub async fn new(cosp_listener: impl CospListener) -> Result<(RustyCoppListener<impl CospResponder, impl CospReader, impl CospWriter>, CoppConnectionInformation), CoppError> {
        let (cosp_responder, _, user_data) = cosp_listener.responder().await?;

        let mut connect_message = match user_data {
            Some(user_data) => ConnectMessage::parse(user_data)?,
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
                resultant_contexts: None,
            },
            copp_information,
        ))
    }
}

impl<T: CospResponder, R: CospReader, W: CospWriter> CoppListener for RustyCoppListener<T, R, W> {
    async fn responder(self) -> Result<(impl CoppContext, Option<Vec<u8>>), CoppError> {
        Ok((RustyCoppContext::<T, R, W>::new(self.cosp_responder, self.connection_information, self.resultant_contexts), self.user_data))
    }
}

pub struct RustyCoppContext<T: CospResponder, R: CospReader, W: CospWriter> {
}

impl<T: CospResponder, R: CospReader, W: CospWriter> CoppContext for RustyCoppContext<T, R, W> {
    async fn responder(self) -> Result<(impl CoppContext, Option<Vec<u8>>), CoppError> {
        Ok((RustyCoppResponder::<T, R, W>::new(self.cosp_responder, self.connection_information, self.resultant_contexts), self.user_data))
    }
}

pub struct RustyCoppResponder<T: CospResponder, R: CospReader, W: CospWriter> {
    cosp_responder: T,
    cosp_reader: PhantomData<R>,
    cosp_writer: PhantomData<W>,
    connection_information: CoppConnectionInformation,
    resultant_contexts: Option<PresentationContextResultType>,
}

impl<T: CospResponder, R: CospReader, W: CospWriter> RustyCoppResponder<T, R, W> {
    fn new(cosp_responder: T, connection_information: CoppConnectionInformation, resultant_contexts: Option<PresentationContextResultType>) -> RustyCoppResponder<impl CospResponder, impl CospReader, impl CospWriter> {
        RustyCoppResponder {
            cosp_responder,
            cosp_reader: PhantomData::<R>,
            cosp_writer: PhantomData::<W>,
            connection_information,
            resultant_contexts,
        }
    }
}

impl<T: CospResponder, R: CospReader, W: CospWriter> CoppResponder for RustyCoppResponder<T, R, W> {
    async fn accept(self, accept_data: Option<Vec<u8>>) -> Result<impl CoppConnection, CoppError> {
        let (cosp_reader, cosp_writer) = self.cosp_responder.accept(None).await?.split().await?;
        // let result = match self.connection_information.presentation_context {
        //     PresentationContextType::ContextDefinitionList(presentation_contexts) => presentation_contexts.into_iter().map(|context| {
        //         PresentationContextResult {
        //             result: PresentationContextResultCause::Acceptance,
        //             transfer_syntax_name: None,
        //             provider_reason: None,
        //         }
        //     }),
        // };

        let accept_message = AcceptMessage::new(None, self.connection_information.called_presentation_selector, PresentationContextResultType::ContextDefinitionList(vec![]), accept_data);

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
