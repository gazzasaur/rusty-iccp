use std::collections::VecDeque;

use rusty_cotp::{CotpConnection, CotpReader, CotpWriter};
use rusty_tpkt::ProtocolInformation;

use crate::{
    CospAcceptor, CospConnection, CospConnectionParameters, CospError, CospInitiator, CospProtocolInformation, CospReader, CospRecvResult, CospResponder, CospWriter,
    message::{CospMessage, parameters::TsduMaximumSize},
    packet::{
        parameters::{EnclosureField, SessionPduParameter},
        pdu::SessionPduList,
    },
    service::{
        accept::{receive_accept_with_all_user_data, send_accept},
        connect::{SendConnectionRequestResult, send_connect_reqeust},
        message::{MAX_PAYLOAD_SIZE, MIN_PAYLOAD_SIZE, receive_message},
        overflow::{receive_connect_data_overflow, receive_overflow_accept, send_connect_data_overflow, send_overflow_accept},
    },
};

pub(crate) mod accept;
pub(crate) mod connect;
pub(crate) mod message;
pub(crate) mod overflow;

pub struct TcpCospInitiator<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    options: CospProtocolInformation,
    connection_options: CospConnectionParameters,
    protocol_information_list: Vec<Box<dyn ProtocolInformation>>,
}

impl<R: CotpReader, W: CotpWriter> TcpCospInitiator<R, W> {
    pub async fn new(cotp_connection: impl CotpConnection, options: CospProtocolInformation, connection_options: CospConnectionParameters) -> Result<TcpCospInitiator<impl CotpReader, impl CotpWriter>, CospError> {
        let mut protocol_information_list = cotp_connection.get_protocol_infomation_list().clone();
        let (cotp_reader, cotp_writer) = cotp_connection.split().await?;
        protocol_information_list.push(Box::new(options.clone()));
        Ok(TcpCospInitiator { cotp_reader, cotp_writer, options, connection_options, protocol_information_list })
    }
}

impl<R: CotpReader, W: CotpWriter> CospInitiator for TcpCospInitiator<R, W> {
    // TODO Also need to handle refuse which will just generically error at the moment.
    async fn initiate(self, user_data: Option<Vec<u8>>) -> Result<(impl CospConnection, Option<Vec<u8>>), CospError> {
        let (mut cotp_reader, mut cotp_writer) = (self.cotp_reader, self.cotp_writer);

        let send_connect_result = send_connect_reqeust(&mut cotp_writer, self.options, self.connection_options, user_data.as_deref()).await?;

        let accept_message = match (send_connect_result, user_data) {
            (SendConnectionRequestResult::Complete, _) => receive_accept_with_all_user_data(&mut cotp_reader).await?,
            (SendConnectionRequestResult::Overflow(sent_data), Some(user_data)) => {
                let overflow_accept = receive_overflow_accept(&mut cotp_reader).await?;
                send_connect_data_overflow(&mut cotp_writer, *overflow_accept.maximum_size_to_responder(), &user_data[sent_data..]).await?;
                receive_accept_with_all_user_data(&mut cotp_reader).await?
            }
            (SendConnectionRequestResult::Overflow(_), None) => return Err(CospError::InternalError("User data was sent even though user data was not provided.".into())),
        };

        Ok((TcpCospConnection::new(cotp_reader, cotp_writer, *accept_message.maximum_size_to_responder(), self.protocol_information_list), accept_message.user_data().map(|data| data.clone())))
    }
}

pub struct TcpCospAcceptor<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    user_data: Option<Vec<u8>>,
    cosp_connection_parameters: CospConnectionParameters,
    protocol_information_list: Vec<Box<dyn ProtocolInformation>>,
}

impl<R: CotpReader, W: CotpWriter> TcpCospAcceptor<R, W> {
    pub async fn new(cotp_connection: impl CotpConnection) -> Result<(TcpCospAcceptor<impl CotpReader, impl CotpWriter>, CospProtocolInformation), CospError> {
        let mut protocol_information_list = cotp_connection.get_protocol_infomation_list().clone();
        let (mut cotp_reader, mut cotp_writer) = cotp_connection.split().await?;

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
        let cosp_connection_information = CospProtocolInformation::new(connect_request.calling_session_selector().map(|x| x.clone()), connect_request.called_session_selector().map(|x| x.clone()));
        protocol_information_list.push(Box::new(cosp_connection_information.clone()));
        Ok((
            TcpCospAcceptor {
                cotp_reader,
                cotp_writer,
                user_data,
                protocol_information_list: protocol_information_list,
                cosp_connection_parameters: CospConnectionParameters { tsdu_maximum_size: if let TsduMaximumSize::Size(x) = maximum_size_to_initiator { Some(*x) } else { None } },
            },
            cosp_connection_information,
        ))
    }
}

impl<R: CotpReader, W: CotpWriter> CospAcceptor for TcpCospAcceptor<R, W> {
    async fn accept(self) -> Result<(impl CospResponder, Option<Vec<u8>>), CospError> {
        let cotp_reader = self.cotp_reader;
        let cotp_writer = self.cotp_writer;

        let maximum_size_to_initiator = match self.cosp_connection_parameters.tsdu_maximum_size {
            Some(x) => TsduMaximumSize::Size(x),
            None => TsduMaximumSize::Unlimited,
        };

        Ok((TcpCospResponder::<R, W>::new(cotp_reader, cotp_writer, maximum_size_to_initiator, self.protocol_information_list), self.user_data))
    }
}

pub struct TcpCospResponder<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    maximum_size_to_initiator: TsduMaximumSize,
    protocol_information_list: Vec<Box<dyn ProtocolInformation>>,
}

impl<R: CotpReader, W: CotpWriter> TcpCospResponder<R, W> {
    fn new(cotp_reader: impl CotpReader, cotp_writer: impl CotpWriter, maximum_size_to_initiator: TsduMaximumSize, protocol_information_list: Vec<Box<dyn ProtocolInformation>>) -> TcpCospResponder<impl CotpReader, impl CotpWriter> {
        TcpCospResponder { cotp_reader, cotp_writer, maximum_size_to_initiator, protocol_information_list }
    }
}

impl<R: CotpReader, W: CotpWriter> CospResponder for TcpCospResponder<R, W> {
    async fn complete_connection(self, accept_data: Option<Vec<u8>>) -> Result<impl CospConnection, CospError> {
        let cotp_reader = self.cotp_reader;
        let mut cotp_writer = self.cotp_writer;

        send_accept(&mut cotp_writer, &self.maximum_size_to_initiator, accept_data).await?;
        Ok(TcpCospConnection::new(cotp_reader, cotp_writer, self.maximum_size_to_initiator, self.protocol_information_list))
    }
}

pub struct TcpCospConnection<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    remote_max_size: TsduMaximumSize,
    protocol_information_list: Vec<Box<dyn ProtocolInformation>>
}

impl<R: CotpReader, W: CotpWriter> TcpCospConnection<R, W> {
    fn new(cotp_reader: R, cotp_writer: W, remote_max_size: TsduMaximumSize, protocol_information_list: Vec<Box<dyn ProtocolInformation>>) -> TcpCospConnection<impl CotpReader, impl CotpWriter> {
        TcpCospConnection { cotp_reader, cotp_writer, remote_max_size, protocol_information_list }
    }
}

impl<R: CotpReader, W: CotpWriter> CospConnection for TcpCospConnection<R, W> {
    fn get_protocol_infomation_list(&self) -> &Vec<Box<dyn ProtocolInformation>> {
        &self.protocol_information_list
    }

    async fn split(self) -> Result<(impl CospReader, impl CospWriter), CospError> {
        Ok((TcpCospReader { cotp_reader: self.cotp_reader, buffer: VecDeque::new() }, TcpCospWriter { buffer: VecDeque::new(), cotp_writer: self.cotp_writer, remote_max_size: self.remote_max_size }))
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
                None => return Ok(CospRecvResult::Closed),
                Some(data) => data,
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
    buffer: VecDeque<Vec<u8>>,
    remote_max_size: TsduMaximumSize,
}

impl<W: CotpWriter> CospWriter for TcpCospWriter<W> {
    async fn send(&mut self, input: &mut VecDeque<Vec<u8>>) -> Result<(), CospError> {
        const HEADER_LENGTH_WITHOUT_ENCLOSURE: usize = 4; // GT + DT

        while let Some(data_item) = input.pop_front() {
            match self.remote_max_size {
                TsduMaximumSize::Size(x) if data_item.len() < MAX_PAYLOAD_SIZE && data_item.len() + HEADER_LENGTH_WITHOUT_ENCLOSURE < x as usize => {
                    let payload = SessionPduList::new(vec![SessionPduParameter::GiveTokens(), SessionPduParameter::DataTransfer(vec![])], data_item).serialise()?;
                    self.buffer.push_back(payload);
                }
                TsduMaximumSize::Unlimited => {
                    let payload = SessionPduList::new(vec![SessionPduParameter::GiveTokens(), SessionPduParameter::DataTransfer(vec![])], data_item).serialise()?;
                    self.buffer.push_back(payload);
                }
                TsduMaximumSize::Size(x) => {
                    let mut cursor: usize = 0;
                    let payload_length = usize::max(MIN_PAYLOAD_SIZE, usize::min(MAX_PAYLOAD_SIZE, x as usize));

                    while cursor < data_item.len() {
                        let start = cursor;
                        cursor = match cursor + payload_length as usize {
                            cursor if cursor > data_item.len() => data_item.len(),
                            cursor => cursor,
                        };
                        let enclosure = EnclosureField(if start == 0 { 1 } else { 0 } + if cursor == data_item.len() { 2 } else { 0 });
                        let payload =
                            SessionPduList::new(vec![SessionPduParameter::GiveTokens(), SessionPduParameter::DataTransfer(vec![SessionPduParameter::EnclosureParameter(enclosure)])], data_item[start..cursor].to_vec()).serialise()?;
                        self.buffer.push_back(payload);
                    }
                }
            }
        }

        while !self.buffer.is_empty() {
            self.cotp_writer.send(&mut self.buffer).await?;
        }

        // Perform one more to ensure lower levels are also flushed even if this layer is complete.
        self.cotp_writer.send(&mut self.buffer).await?;
        Ok(())
    }
}
