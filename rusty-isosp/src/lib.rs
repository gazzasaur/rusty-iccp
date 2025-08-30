use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use rusty_cotp::{
    api::{CotpConnectOptions, CotpConnection, CotpReader, CotpServer, CotpService, CotpWriter},
    service::{TcpCotpConnection, TcpCotpReader, TcpCotpServer, TcpCotpService, TcpCotpWriter},
};
use tracing::trace;

use crate::{
    api::{IsoSpAcceptor, IsoSpConnection, IsoSpError, IsoSpReader, IsoSpRecvResult, IsoSpServer, IsoSpService, IsoSpWriter},
    packet::session_pdu::{Enclosure, SessionPdu, SessionPduList, SessionPduParameter, TsduMaximumSizeSelected},
    service::{IcpIsoStateMachine, receive_accept, receive_connect_data_overflow, receive_connection_request, receive_overflow_accept, send_accept, send_connect_data_overflow, send_connect_reqeust, send_overflow_accept},
};

pub mod api;
pub mod packet;
pub mod service;

pub struct TcpIsoSpService {}

impl IsoSpService<SocketAddr> for TcpIsoSpService {
    async fn create_server<'a>(address: SocketAddr) -> Result<impl 'a + IsoSpServer<SocketAddr>, IsoSpError> {
        Ok(TcpIsoSpServer::new(address).await?)
    }

    // TODO Also need to handle refuse which will just generically error at the moment.
    async fn connect<'a>(address: SocketAddr, connect_data: Option<&[u8]>, options: CotpConnectOptions<'a>) -> Result<impl 'a + IsoSpConnection<SocketAddr>, IsoSpError> {
        let cotp_connection = TcpCotpService::connect(address, options).await?;
        let (mut cotp_reader, mut cotp_writer) = TcpCotpConnection::split(cotp_connection).await?;

        let send_connect_result = send_connect_reqeust(&mut cotp_writer, connect_data).await?;

        let maximum_size_to_responder = match (send_connect_result, connect_data) {
            (service::SendConnectionRequestResult::Complete, _) => receive_accept(&mut cotp_reader).await?.maximum_size_to_responder,
            (service::SendConnectionRequestResult::Overflow(sent_data), Some(user_data)) => {
                let overflow_accept = receive_overflow_accept(&mut cotp_reader).await?;
                send_connect_data_overflow(&mut cotp_writer, &user_data[sent_data..]).await?;
                overflow_accept.maximum_size_to_responder // This is all we really care about here. The rest is check in the receive method.
            }
            (service::SendConnectionRequestResult::Overflow(_), None) => return Err(IsoSpError::InternalError("User data was sent event though user data was not provided.".into())),
        };

        Ok(TcpIsoSpConnection::new(cotp_reader, cotp_writer, maximum_size_to_responder))
    }
}

pub struct TcpIsoSpServer {
    cotp_server: TcpCotpServer,
}

impl TcpIsoSpServer {
    pub async fn new(address: SocketAddr) -> Result<Self, IsoSpError> {
        Ok(Self {
            cotp_server: TcpCotpServer::new(address).await?,
        })
    }
}

impl IsoSpServer<SocketAddr> for TcpIsoSpServer {
    async fn accept<'a>(&self) -> Result<impl 'a + IsoSpAcceptor<SocketAddr>, IsoSpError> {
        Ok(TcpIsoSpAcceptor::new(self.cotp_server.accept().await?))
    }
}

pub struct TcpIsoSpAcceptor {
    cotp_connection: TcpCotpConnection,
}

impl TcpIsoSpAcceptor {
    pub fn new(cotp_connection: TcpCotpConnection) -> Self {
        Self { cotp_connection }
    }
}

impl IsoSpAcceptor<SocketAddr> for TcpIsoSpAcceptor {
    async fn accept<'a>(self, accept_data: Option<&[u8]>) -> Result<(impl 'a + IsoSpConnection<SocketAddr>, Option<Vec<u8>>), IsoSpError> {
        let (mut cotp_reader, mut cotp_writer) = self.cotp_connection.split().await?;

        let connect_request = receive_connection_request(&mut cotp_reader).await?;
        let maximum_size_to_initiator = connect_request.maximum_size_to_initiator;
        let has_more_data = match &connect_request.data_overflow {
            Some(overflow) => overflow.more_data(),
            None => false,
        };

        let mut user_data = VecDeque::new();
        let has_user_data = connect_request.user_data.is_some() || connect_request.data_overflow.is_some();
        if let Some(request_user_data) = connect_request.user_data {
            user_data.extend(request_user_data);
        }

        if has_more_data {
            send_overflow_accept(&mut cotp_writer, &maximum_size_to_initiator).await?;
            user_data.extend(receive_connect_data_overflow(&mut cotp_reader).await?);
        }
        send_accept(&mut cotp_writer, &maximum_size_to_initiator, accept_data).await?;

        let user_data = match has_user_data {
            true => Some(user_data.drain(..).collect()),
            false => None,
        };
        Ok((TcpIsoSpConnection::new(cotp_reader, cotp_writer, maximum_size_to_initiator), user_data))
    }
}

pub struct TcpIsoSpConnection {
    _state_machine: Arc<RwLock<IcpIsoStateMachine>>,
    cotp_reader: TcpCotpReader,
    cotp_writer: TcpCotpWriter,
    _remote_max_size: TsduMaximumSizeSelected,
}

impl TcpIsoSpConnection {
    pub fn new(cotp_reader: TcpCotpReader, cotp_writer: TcpCotpWriter, remote_max_size: TsduMaximumSizeSelected) -> Self {
        Self {
            _state_machine: Arc::new(RwLock::new(IcpIsoStateMachine::default())),
            cotp_reader,
            cotp_writer,
            _remote_max_size: remote_max_size,
        }
    }
}

impl IsoSpConnection<SocketAddr> for TcpIsoSpConnection {
    async fn split<'a>(self) -> Result<(impl 'a + IsoSpReader<SocketAddr> + Send, impl 'a + IsoSpWriter<SocketAddr> + Send), IsoSpError> {
        Ok((
            TcpIsoSpReader {
                cotp_reader: self.cotp_reader,
                buffer: VecDeque::new(),
            },
            TcpIsoSpWriter { cotp_writer: self.cotp_writer },
        ))
    }
}

pub struct TcpIsoSpReader {
    cotp_reader: TcpCotpReader,
    buffer: VecDeque<u8>,
}

impl IsoSpReader<SocketAddr> for TcpIsoSpReader {
    async fn recv(&mut self) -> Result<IsoSpRecvResult, IsoSpError> {
        loop {
            let data = match self.cotp_reader.recv().await? {
                rusty_cotp::api::CotpRecvResult::Closed => return Ok(IsoSpRecvResult::Closed),
                rusty_cotp::api::CotpRecvResult::Data(data) => data,
            };

            let mut pdus = SessionPduList::deserialise(TsduMaximumSizeSelected::Unlimited, &data)
                .map_err(|e| IsoSpError::ProtocolError(format!("Failed to parse message: {}", e).to_string()))?
                .0;

            while let Some(session_pdu) = pdus.pop() {
                let (enclosure, user_data) = match session_pdu {
                    SessionPdu::Finish(_session_pdu_parameters) => todo!(),
                    SessionPdu::Disconnect(_session_pdu_parameters) => todo!(),
                    SessionPdu::Abort(_session_pdu_parameters) => todo!(),
                    SessionPdu::DataTransfer(session_pdu_parameters) => {
                        let mut relevant_pdus: Vec<SessionPduParameter> = session_pdu_parameters
                            .into_iter()
                            .filter(|x| matches!(x, SessionPduParameter::EnclosureItem(_)) || matches!(x, SessionPduParameter::UserData(_)))
                            .collect();

                        match (relevant_pdus.pop(), relevant_pdus.pop()) {
                            (Some(SessionPduParameter::EnclosureItem(enclosure)), Some(SessionPduParameter::UserData(user_data))) => (enclosure, user_data),
                            (Some(SessionPduParameter::UserData(user_data)), _) => (Enclosure(0x02), user_data),
                            x => {
                                let message = "Failed to parse Data Transfer";
                                trace!("{} - Got: {:?}", message, x);
                                return Err(IsoSpError::ProtocolError(message.into()));
                            }
                        }
                    }
                    SessionPdu::GiveTokens(_) => continue,
                    SessionPdu::Unknown(_, _items) => todo!(),
                    _ => return Err(IsoSpError::ProtocolError("An unexpected payload was received.".into())),
                };

                self.buffer.extend(user_data);
                if !enclosure.end() {
                    continue;
                }
            }

            return Ok(IsoSpRecvResult::Data(data));
        }
    }
}

pub struct TcpIsoSpWriter {
    cotp_writer: TcpCotpWriter,
}

impl IsoSpWriter<SocketAddr> for TcpIsoSpWriter {
    async fn send(&mut self, data: &[u8]) -> Result<(), IsoSpError> {
        // TODO Segmentation
        let payload = SessionPduList(vec![SessionPdu::GiveTokens(vec![]), SessionPdu::DataTransfer(vec![SessionPduParameter::UserData(data.to_vec())])]).serialise()?;
        self.cotp_writer.send(&payload).await?;
        Ok(())
    }

    async fn continue_send(&mut self) -> Result<(), IsoSpError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::join;
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_negotiate_a_version_2_unlimited_size_connection() -> Result<(), anyhow::Error> {
        let address = "127.0.0.1:10002".parse()?;
        let server = TcpIsoSpService::create_server(address).await?;

        let (client_result, acceptor_result) = join!(TcpIsoSpService::connect(address, None, CotpConnectOptions::default()), async {
            let acceptor = server.accept().await?;
            acceptor.accept(None).await
        });
        let client_connection = client_result?;
        let (server_connection, _connect_data) = acceptor_result?;

        let (_client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, _server_writer) = server_connection.split().await?;

        client_writer.send("Hello".as_bytes()).await?;
        match server_reader.recv().await? {
            IsoSpRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            IsoSpRecvResult::Data(data) => assert_eq!(hex::encode(data), "01000107c10548656c6c6f"),
        }

        Ok(())
    }
}
