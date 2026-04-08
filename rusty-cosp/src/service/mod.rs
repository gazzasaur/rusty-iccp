use std::collections::VecDeque;

use rusty_cotp::{CotpConnection, CotpReader, CotpWriter};
use rusty_tpkt::ProtocolInformation;

use crate::{
    CospAcceptor, CospConnection, CospConnectionParameters, CospError, CospInitiator, CospProtocolInformation, CospReader, CospRecvResult, CospResponder, CospWriter, ReasonCode,
    abort::{receive_abort_with_all_user_data, send_abort},
    disconnect::{receive_disconnect_with_all_user_data, send_disconnect},
    finish::{receive_finish_with_all_user_data, send_finish},
    message::{CospMessage, accept::AcceptMessage, overflow_accept::OverflowAcceptMessage, parameters::TsduMaximumSize},
    packet::{
        parameters::{EnclosureField, SessionPduParameter},
        pdu::SessionPduList,
    },
    refuse::{receive_refuse_with_all_user_data, send_refuse},
    service::{
        accept::{receive_accept_with_all_user_data, send_accept},
        connect::{SendConnectionRequestResult, send_connect_reqeust},
        message::{MAX_PAYLOAD_SIZE, MIN_PAYLOAD_SIZE, receive_message},
        overflow::{receive_connect_data_overflow, send_connect_data_overflow, send_overflow_accept},
    },
};

pub(crate) mod abort;
pub(crate) mod accept;
pub(crate) mod connect;
pub(crate) mod disconnect;
pub(crate) mod finish;
pub(crate) mod message;
pub(crate) mod overflow;
pub(crate) mod refuse;

/// A concrete implementation of an initiator.
pub struct RustyCospInitiator<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    options: CospProtocolInformation,
    connection_options: CospConnectionParameters,
    protocol_information_list: Vec<Box<dyn ProtocolInformation>>,
}

impl<R: CotpReader, W: CotpWriter> RustyCospInitiator<R, W> {
    /// Construct the initiator with options. This does not perform signalling.
    pub async fn new(cotp_connection: impl CotpConnection, options: CospProtocolInformation, connection_options: CospConnectionParameters) -> Result<RustyCospInitiator<impl CotpReader, impl CotpWriter>, CospError> {
        let mut protocol_information_list = cotp_connection.get_protocol_infomation_list().clone();
        let (cotp_reader, cotp_writer) = cotp_connection.split().await?;
        protocol_information_list.push(Box::new(options.clone()));
        Ok(RustyCospInitiator { cotp_reader, cotp_writer, options, connection_options, protocol_information_list })
    }
}

impl<R: CotpReader, W: CotpWriter> CospInitiator for RustyCospInitiator<R, W> {
    async fn initiate(self, user_data: Option<Vec<u8>>) -> Result<(impl CospConnection, Option<Vec<u8>>), CospError> {
        let (mut cotp_reader, mut cotp_writer) = (self.cotp_reader, self.cotp_writer);

        let send_connect_result = send_connect_reqeust(&mut cotp_writer, self.options, user_data.as_deref()).await?;

        let accept_message = match (send_connect_result, user_data) {
            (SendConnectionRequestResult::Complete, _) => receive_accept_or_refuse_or_abort_with_all_user_data(&mut cotp_reader, &self.connection_options).await?,
            (SendConnectionRequestResult::Overflow(sent_data), Some(user_data)) => {
                let overflow_accept = receive_overflow_accept_or_refuse_or_abort_with_all_user_data(&mut cotp_reader, &self.connection_options).await?;
                send_connect_data_overflow(&mut cotp_writer, *overflow_accept.maximum_size_to_responder(), &user_data[sent_data..]).await?;
                receive_accept_or_refuse_or_abort_with_all_user_data(&mut cotp_reader, &self.connection_options).await?
            }
            (SendConnectionRequestResult::Overflow(_), None) => return Err(CospError::InternalError("User data was sent even though user data was not provided.".into())),
        };

        Ok((RustyCospConnection::new(cotp_reader, cotp_writer, *accept_message.maximum_size_to_responder(), self.connection_options, self.protocol_information_list), accept_message.user_data().map(|data| data.clone())))
    }
}

async fn receive_accept_or_refuse_or_abort_with_all_user_data(cotp_reader: &mut impl CotpReader, connection_options: &CospConnectionParameters) -> Result<AcceptMessage, CospError> {
    let message = receive_message(cotp_reader).await?;
    match message {
        CospMessage::AC(accept_message) => Ok(receive_accept_with_all_user_data(cotp_reader, accept_message, connection_options).await?),
        CospMessage::RF(refuse_message) => Err(CospError::Refused(receive_refuse_with_all_user_data(cotp_reader, refuse_message, connection_options).await?.reason_code().cloned())),
        CospMessage::AB(abort_message) => Err(CospError::Aborted(receive_abort_with_all_user_data(cotp_reader, abort_message, connection_options).await?.user_data().cloned())),
        _ => Err(CospError::InternalError(format!("Expected accept or reject but got {}.", <CospMessage as Into<&'static str>>::into(message)))),
    }
}

async fn receive_overflow_accept_or_refuse_or_abort_with_all_user_data(cotp_reader: &mut impl CotpReader, connection_options: &CospConnectionParameters) -> Result<OverflowAcceptMessage, CospError> {
    let message = receive_message(cotp_reader).await?;
    match message {
        CospMessage::OA(overflow_accept_message) => Ok(overflow_accept_message),
        CospMessage::RF(refuse_message) => Err(CospError::Refused(receive_refuse_with_all_user_data(cotp_reader, refuse_message, connection_options).await?.reason_code().cloned())),
        CospMessage::AB(abort_message) => Err(CospError::Aborted(receive_abort_with_all_user_data(cotp_reader, abort_message, connection_options).await?.user_data().cloned())),
        _ => Err(CospError::InternalError(format!("Expected accept or reject but got {}.", <CospMessage as Into<&'static str>>::into(message)))),
    }
}

/// Concrete implementation of the acceptor.
pub struct RustyCospAcceptor<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    user_data: Option<Vec<u8>>,
    tsdu_maximum_size: TsduMaximumSize,
    cosp_connection_parameters: CospConnectionParameters,
    protocol_information_list: Vec<Box<dyn ProtocolInformation>>,
}

impl<R: CotpReader, W: CotpWriter> RustyCospAcceptor<R, W> {
    /// Creates and acceptor and receives the initial connect payload.
    pub async fn new(cotp_connection: impl CotpConnection, connection_parameters: CospConnectionParameters) -> Result<(RustyCospAcceptor<impl CotpReader, impl CotpWriter>, CospProtocolInformation), CospError> {
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
            user_data.extend(receive_connect_data_overflow(&mut cotp_reader, &connection_parameters).await?);
        }

        let user_data = match has_user_data {
            true => Some(user_data.drain(..).collect()),
            false => None,
        };
        let cosp_protocol_information = CospProtocolInformation::new(connect_request.calling_session_selector().map(|x| x.clone()), connect_request.called_session_selector().map(|x| x.clone()));
        protocol_information_list.push(Box::new(cosp_protocol_information.clone()));
        Ok((
            RustyCospAcceptor { cotp_reader, cotp_writer, user_data, tsdu_maximum_size: *maximum_size_to_initiator, protocol_information_list: protocol_information_list, cosp_connection_parameters: connection_parameters },
            cosp_protocol_information,
        ))
    }
}

impl<R: CotpReader, W: CotpWriter> CospAcceptor for RustyCospAcceptor<R, W> {
    async fn accept(self) -> Result<(impl CospResponder, Option<Vec<u8>>), CospError> {
        let cotp_reader = self.cotp_reader;
        let cotp_writer = self.cotp_writer;

        Ok((RustyCospResponder::<R, W>::new(cotp_reader, cotp_writer, self.tsdu_maximum_size, self.cosp_connection_parameters, self.protocol_information_list), self.user_data))
    }

    async fn refuse(self, reason_code: Option<ReasonCode>) -> Result<(), CospError> {
        let mut cotp_writer = self.cotp_writer;
        send_refuse(&mut cotp_writer, self.tsdu_maximum_size, reason_code.as_ref()).await
    }

    async fn abort(mut self, user_data: Option<Vec<u8>>) -> Result<(), CospError> {
        send_abort(&mut self.cotp_writer, self.tsdu_maximum_size, user_data).await?;
        Ok(())
    }
}

/// A concrete implementation of the responder.
/// This allows data to be singalled back to the initiator during the connect phase.
pub struct RustyCospResponder<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    maximum_size_to_initiator: TsduMaximumSize,
    connection_options: CospConnectionParameters,
    protocol_information_list: Vec<Box<dyn ProtocolInformation>>,
}

impl<R: CotpReader, W: CotpWriter> RustyCospResponder<R, W> {
    fn new(
        cotp_reader: impl CotpReader,
        cotp_writer: impl CotpWriter,
        maximum_size_to_initiator: TsduMaximumSize,
        connection_options: CospConnectionParameters,
        protocol_information_list: Vec<Box<dyn ProtocolInformation>>,
    ) -> RustyCospResponder<impl CotpReader, impl CotpWriter> {
        RustyCospResponder { cotp_reader, cotp_writer, maximum_size_to_initiator, connection_options, protocol_information_list }
    }
}

impl<R: CotpReader, W: CotpWriter> CospResponder for RustyCospResponder<R, W> {
    async fn complete_connection(self, accept_data: Option<Vec<u8>>) -> Result<impl CospConnection, CospError> {
        let cotp_reader = self.cotp_reader;
        let mut cotp_writer = self.cotp_writer;

        send_accept(&mut cotp_writer, &self.maximum_size_to_initiator, accept_data).await?;
        Ok(RustyCospConnection::new(cotp_reader, cotp_writer, self.maximum_size_to_initiator, self.connection_options, self.protocol_information_list))
    }

    async fn abort(mut self, user_data: Option<Vec<u8>>) -> Result<(), CospError> {
        send_abort(&mut self.cotp_writer, self.maximum_size_to_initiator, user_data).await?;
        Ok(())
    }
}

/// A concrete COSP connection.
pub struct RustyCospConnection<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    remote_max_size: TsduMaximumSize,
    connection_options: CospConnectionParameters,
    protocol_information_list: Vec<Box<dyn ProtocolInformation>>,
}

impl<R: CotpReader, W: CotpWriter> RustyCospConnection<R, W> {
    fn new(
        cotp_reader: R,
        cotp_writer: W,
        remote_max_size: TsduMaximumSize,
        connection_options: CospConnectionParameters,
        protocol_information_list: Vec<Box<dyn ProtocolInformation>>,
    ) -> RustyCospConnection<impl CotpReader, impl CotpWriter> {
        RustyCospConnection { cotp_reader, cotp_writer, remote_max_size, connection_options, protocol_information_list }
    }
}

impl<R: CotpReader, W: CotpWriter> CospConnection for RustyCospConnection<R, W> {
    fn get_protocol_infomation_list(&self) -> &Vec<Box<dyn ProtocolInformation>> {
        &self.protocol_information_list
    }

    async fn split(self) -> Result<(impl CospReader, impl CospWriter), CospError> {
        Ok((
            RustyCospReader { cotp_reader: self.cotp_reader, buffer: VecDeque::new(), connection_options: self.connection_options },
            RustyCospWriter { buffer: VecDeque::new(), cotp_writer: self.cotp_writer, remote_max_size: self.remote_max_size },
        ))
    }
}

/// A concrete COSP reader.
pub struct RustyCospReader<R: CotpReader> {
    cotp_reader: R,
    buffer: VecDeque<u8>,
    connection_options: CospConnectionParameters,
}

impl<R: CotpReader> CospReader for RustyCospReader<R> {
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
                CospMessage::FN(message) => {
                    let finish_message = receive_finish_with_all_user_data(&mut self.cotp_reader, message, &self.connection_options).await?;
                    return Ok(CospRecvResult::Finish(finish_message.user_data().cloned()));
                }
                CospMessage::DN(message) => {
                    let disconnect_message = receive_disconnect_with_all_user_data(&mut self.cotp_reader, message).await?;
                    return Ok(CospRecvResult::Disconnect(disconnect_message.user_data().cloned()));
                }
                CospMessage::AB(message) => {
                    let abort_message = receive_abort_with_all_user_data(&mut self.cotp_reader, message, &self.connection_options).await?;
                    return Err(CospError::Aborted(abort_message.user_data().cloned()));
                }
                message => return Err(CospError::ProtocolError(format!("Expected payload of type Data Transfer, Finish, Disconnect or Abort but found {}", <CospMessage as Into<&'static str>>::into(message)))),
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

/// A concrete COSP writer.
pub struct RustyCospWriter<W: CotpWriter> {
    cotp_writer: W,
    buffer: VecDeque<Vec<u8>>,
    remote_max_size: TsduMaximumSize,
}

impl<W: CotpWriter> CospWriter for RustyCospWriter<W> {
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

    async fn finish(mut self, user_data: Option<Vec<u8>>) -> Result<(), CospError> {
        send_finish(&mut self.cotp_writer, self.remote_max_size, user_data).await?;
        Ok(())
    }

    async fn disconnect(mut self, user_data: Option<Vec<u8>>) -> Result<(), CospError> {
        send_disconnect(&mut self.cotp_writer, self.remote_max_size, user_data).await?;
        Ok(())
    }

    async fn abort(mut self, user_data: Option<Vec<u8>>) -> Result<(), CospError> {
        send_abort(&mut self.cotp_writer, self.remote_max_size, user_data).await?;
        Ok(())
    }
}
