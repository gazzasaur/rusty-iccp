use std::collections::VecDeque;

use rusty_cotp::{CotpConnection, CotpReader, CotpRecvResult, CotpWriter};

use crate::{
    message::{parameters::TsduMaximumSize, CospMessage}, packet::{
        parameters::{EnclosureField, SessionPduParameter},
        pdu::SessionPduList,
    }, service::{
        accept::{receive_accept_with_all_user_data, send_accept},
        connect::{send_connect_reqeust, SendConnectionRequestResult},
        message::{receive_message, MAX_PAYLOAD_SIZE, MIN_PAYLOAD_SIZE},
        overflow::{receive_connect_data_overflow, receive_overflow_accept, send_connect_data_overflow, send_overflow_accept},
    }, CospConnection, CospConnectionInformation, CospError, CospInitiator, CospListener, CospReader, CospRecvResult, CospResponder, CospWriter
};

pub(crate) mod accept;
pub(crate) mod connect;
pub(crate) mod message;
pub(crate) mod overflow;

pub struct TcpCospInitiator<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    options: CospConnectionInformation,
}

impl<R: CotpReader, W: CotpWriter> TcpCospInitiator<R, W> {
    pub async fn new(cotp_connection: impl CotpConnection, options: CospConnectionInformation) -> Result<TcpCospInitiator<impl CotpReader, impl CotpWriter>, CospError> {
        let (cotp_reader, cotp_writer) = cotp_connection.split().await?;
        Ok(TcpCospInitiator { cotp_reader, cotp_writer, options })
    }
}

impl<R: CotpReader, W: CotpWriter> CospInitiator for TcpCospInitiator<R, W> {
    // TODO Also need to handle refuse which will just generically error at the moment.
    async fn initiate(self, user_data: Option<Vec<u8>>) -> Result<(impl CospConnection, Option<Vec<u8>>), CospError> {
        let (mut cotp_reader, mut cotp_writer) = (self.cotp_reader, self.cotp_writer);

        let send_connect_result = send_connect_reqeust(&mut cotp_writer, self.options, user_data.as_deref()).await?;

        let accept_message = match (send_connect_result, user_data) {
            (SendConnectionRequestResult::Complete, _) => receive_accept_with_all_user_data(&mut cotp_reader).await?,
            (SendConnectionRequestResult::Overflow(sent_data), Some(user_data)) => {
                let overflow_accept = receive_overflow_accept(&mut cotp_reader).await?;
                send_connect_data_overflow(&mut cotp_writer, *overflow_accept.maximum_size_to_responder(), &user_data[sent_data..]).await?;
                receive_accept_with_all_user_data(&mut cotp_reader).await?
            }
            (SendConnectionRequestResult::Overflow(_), None) => return Err(CospError::InternalError("User data was sent even though user data was not provided.".into())),
        };

        Ok((TcpCospConnection::new(cotp_reader, cotp_writer, *accept_message.maximum_size_to_responder()), accept_message.user_data().map(|data| data.clone())))
    }
}

pub struct TcpCospConnector<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
}

impl<R: CotpReader, W: CotpWriter> TcpCospConnector<R, W> {
    pub async fn new(cotp_connection: impl CotpConnection) -> Result<TcpCospConnector<impl CotpReader, impl CotpWriter>, CospError> {
        let (cotp_reader, cotp_writer) = cotp_connection.split().await?;
        Ok(TcpCospConnector { cotp_reader, cotp_writer })
    }
}

impl<R: CotpReader, W: CotpWriter> CospListener for TcpCospConnector<R, W> {
    async fn responder(self) -> Result<(impl CospResponder, CospConnectionInformation, Option<Vec<u8>>), CospError> {
        let mut cotp_reader = self.cotp_reader;
        let mut cotp_writer = self.cotp_writer;

        let connect_request = match receive_message(&mut cotp_reader).await? {
            CospMessage::CN(connect_message) => connect_message,
            message => return Err(CospError::ProtocolError(format!("Expecting a connect message, but got {}", <CospMessage as Into<&'static str>>::into(message)))),
        };

        let maximum_size_to_initiator = connect_request.maximum_size_to_initiator();
        let has_more_data = match &connect_request.data_overflow() {
            Some(overflow) => overflow.more_data(),
            None => false,
        };

        let mut user_data = VecDeque::new();
        let has_user_data = connect_request.user_data().is_some() || connect_request.data_overflow().is_some();
        if let Some(request_user_data) = connect_request.user_data() {
            user_data.extend(request_user_data);
        }

        if has_more_data {
            send_overflow_accept(&mut cotp_writer, &maximum_size_to_initiator).await?;
            user_data.extend(receive_connect_data_overflow(&mut cotp_reader).await?);
        }

        let user_data = match has_user_data {
            true => Some(user_data.drain(..).collect()),
            false => None,
        };
        Ok((
            TcpCospResponder::<R, W>::new(cotp_reader, cotp_writer, *maximum_size_to_initiator),
            CospConnectionInformation {
                tsdu_maximum_size: if let TsduMaximumSize::Size(x) = maximum_size_to_initiator { Some(*x) } else { None },
                called_session_selector: connect_request.called_session_selector().map(|x| x.clone()),
                calling_session_selector: connect_request.calling_session_selector().map(|x| x.clone()),
            },
            user_data,
        ))
    }
}

pub struct TcpCospResponder<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    maximum_size_to_initiator: TsduMaximumSize,
}

impl<R: CotpReader, W: CotpWriter> TcpCospResponder<R, W> {
    fn new(cotp_reader: impl CotpReader, cotp_writer: impl CotpWriter, maximum_size_to_initiator: TsduMaximumSize) -> TcpCospResponder<impl CotpReader, impl CotpWriter> {
        TcpCospResponder {
            cotp_reader,
            cotp_writer,
            maximum_size_to_initiator,
        }
    }
}

impl<R: CotpReader, W: CotpWriter> CospResponder for TcpCospResponder<R, W> {
    async fn accept(self, accept_data: Option<&[u8]>) -> Result<impl CospConnection, CospError> {
        let cotp_reader = self.cotp_reader;
        let mut cotp_writer = self.cotp_writer;

        send_accept(&mut cotp_writer, &self.maximum_size_to_initiator, accept_data).await?;
        Ok(TcpCospConnection::new(cotp_reader, cotp_writer, self.maximum_size_to_initiator))
    }
}

pub struct TcpCospConnection<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    remote_max_size: TsduMaximumSize,
}

impl<R: CotpReader, W: CotpWriter> TcpCospConnection<R, W> {
    fn new(cotp_reader: R, cotp_writer: W, remote_max_size: TsduMaximumSize) -> TcpCospConnection<impl CotpReader, impl CotpWriter> {
        TcpCospConnection { cotp_reader, cotp_writer, remote_max_size }
    }
}

impl<R: CotpReader, W: CotpWriter> CospConnection for TcpCospConnection<R, W> {
    async fn split(self) -> Result<(impl CospReader, impl CospWriter), CospError> {
        Ok((
            TcpCospReader {
                cotp_reader: self.cotp_reader,
                buffer: VecDeque::new(),
            },
            TcpCospWriter {
                cotp_writer: self.cotp_writer,
                remote_max_size: self.remote_max_size,
            },
        ))
    }
}

pub struct TcpCospReader<R: CotpReader> {
    cotp_reader: R,
    buffer: VecDeque<u8>,
}

impl<R: CotpReader> CospReader for TcpCospReader<R> {
    async fn recv(&mut self) -> Result<CospRecvResult, CospError> {
        loop {
            let receive_result = self.cotp_reader.recv().await?;
            let data = match receive_result {
                CotpRecvResult::Closed => return Ok(CospRecvResult::Closed),
                CotpRecvResult::Data(data) => data,
            };

            let received_message = CospMessage::from_spdu_list(SessionPduList::deserialise(&data)?)?;
            let data_transfer_message = match received_message {
                CospMessage::DT(message) => message,
                _ => todo!(),
            };

            let enclosure = data_transfer_message.enclosure();
            self.buffer.extend(data_transfer_message.take_user_information());
            match enclosure {
                Some(x) if x.end() => return Ok(CospRecvResult::Data(self.buffer.drain(..).collect())),
                None => return Ok(CospRecvResult::Data(self.buffer.drain(..).collect())),
                Some(_) => (),
            }
        }
    }
}

pub struct TcpCospWriter<W: CotpWriter> {
    cotp_writer: W,
    remote_max_size: TsduMaximumSize,
}

impl<W: CotpWriter> CospWriter for TcpCospWriter<W> {
    async fn send(&mut self, data: &[u8]) -> Result<(), CospError> {
        const HEADER_LENGTH_WITHOUT_ENCLOSURE: usize = 4; // GT + DT

        match self.remote_max_size {
            TsduMaximumSize::Size(x) if data.len() < MAX_PAYLOAD_SIZE && data.len() + HEADER_LENGTH_WITHOUT_ENCLOSURE < x as usize => {
                let payload = SessionPduList::new(vec![SessionPduParameter::GiveTokens(), SessionPduParameter::DataTransfer(vec![])], data.to_vec()).serialise()?;
                self.cotp_writer.send(&payload).await?;
            }
            TsduMaximumSize::Unlimited => {
                let payload = SessionPduList::new(vec![SessionPduParameter::GiveTokens(), SessionPduParameter::DataTransfer(vec![])], data.to_vec()).serialise()?;
                self.cotp_writer.send(&payload).await?;
            }
            TsduMaximumSize::Size(x) => {
                let mut cursor: usize = 0;
                let payload_length = usize::max(MIN_PAYLOAD_SIZE, usize::min(MAX_PAYLOAD_SIZE, x as usize));

                while cursor < data.len() {
                    let start = cursor;
                    cursor = match cursor + payload_length as usize {
                        cursor if cursor > data.len() => data.len(),
                        cursor => cursor,
                    };
                    let enclosure = EnclosureField(if start == 0 { 1 } else { 0 } + if cursor == data.len() { 2 } else { 0 });
                    let payload = SessionPduList::new(
                        vec![SessionPduParameter::GiveTokens(), SessionPduParameter::DataTransfer(vec![SessionPduParameter::EnclosureParameter(enclosure)])],
                        data[start..cursor].to_vec(),
                    )
                    .serialise()?;
                    self.cotp_writer.send(&payload).await?;
                }
            }
        }
        Ok(())
    }

    async fn continue_send(&mut self) -> Result<(), CospError> {
        Ok(())
    }
}
