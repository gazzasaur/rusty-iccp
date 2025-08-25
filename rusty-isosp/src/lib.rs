use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use rusty_cotp::{
    api::{CotpConnection, CotpReader, CotpServer, CotpService, CotpWriter},
    service::{TcpCotpConnection, TcpCotpReader, TcpCotpServer, TcpCotpService, TcpCotpWriter},
};

use crate::{
    api::{IsoSpAcceptor, IsoSpConnection, IsoSpError, IsoSpReader, IsoSpRecvResult, IsoSpServer, IsoSpService, IsoSpWriter},
    packet::session_pdu::{self, ProtocolOptions, SessionPdu, SessionPduList, SessionPduParameter, SessionPduSubParameter, SessionUserRequirements, SupportedVersions, TsduMaximumSizeSelected},
    service::{IcpIsoStateMachine, receive_overflow_accept, send_connect_reqeust, send_connection_overflow_data},
};

pub mod api;
pub mod packet;
pub mod service;

pub struct TcpIsoSpService {}

impl IsoSpService<SocketAddr> for TcpIsoSpService {
    async fn create_server<'a>(address: SocketAddr) -> Result<impl 'a + IsoSpServer<SocketAddr>, IsoSpError> {
        Ok(TcpIsoSpServer::new(address).await?)
    }

    async fn connect<'a>(address: SocketAddr, connect_data: Option<&[u8]>) -> Result<impl 'a + IsoSpConnection<SocketAddr>, IsoSpError> {
        let cotp_connection = TcpCotpService::connect(address).await?;
        let (mut cotp_reader, mut cotp_writer) = TcpCotpConnection::split(cotp_connection).await?;

        let send_connect_result = send_connect_reqeust(&mut cotp_writer, connect_data).await?;

        match (send_connect_result, connect_data) {
            (service::SendConnectionRequestResult::Complete, _) => receive_accept(&mut cotp_reader).await?,
            (service::SendConnectionRequestResult::Overflow(sent_data), Some(user_data)) => {
                let oa = receive_overflow_accept(&mut cotp_reader).await?;
                send_connection_overflow_data(&mut cotp_writer, &user_data[sent_data..]).await?;
                oa
            }
            (service::SendConnectionRequestResult::Overflow(_), None) => return Err(IsoSpError::InternalError("User data was sent event though user data was not provided.".into())),
        };

        let data = match cotp_reader.recv().await? {
            rusty_cotp::api::CotpRecvResult::Closed => return Err(IsoSpError::ProtocolError("The connection was closed before the negotiation could complete.".into())),
            rusty_cotp::api::CotpRecvResult::Data(data) => data,
        };
        let pdus = SessionPduList::deserialise(TsduMaximumSizeSelected::Unlimited, &data)?;

        if pdus.0.len() == 0 {
            return Err(IsoSpError::ProtocolError("Error: Did not receive any data on connect.".into()));
        } else if pdus.0.len() > 1 {
            return Err(IsoSpError::ProtocolError("Error: Received more than one payload on a Class 1 event.".into()));
        }

        // TODO Follow the validation rules.
        let connect_pdu = match &pdus.0[0] {
            SessionPdu::Accept(session_pdu_parameters) => session_pdu_parameters,
            SessionPdu::Refuse(session_pdu_parameters) => return Err(IsoSpError::ProtocolError("The peer rejected the session request. They may be incompatible.".into())),
            SessionPdu::Unknown(..) => return Err(IsoSpError::ProtocolError("The peer did not return a recognised response.".into())),
            _ => return Err(IsoSpError::ProtocolError("The peer returned an unexpected response.".into())),
        };

        Ok(TcpIsoSpConnection::new(cotp_reader, cotp_writer))
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
    async fn accept<'a>(self, accept_data: &[u8]) -> Result<impl 'a + IsoSpConnection<SocketAddr>, IsoSpError> {
        // TODO check if we are compatible
        let (mut cotp_reader, mut cotp_writer) = self.cotp_connection.split().await?;

        cotp_reader.recv().await?;

        let data = SessionPduList(vec![SessionPdu::Accept(vec![
            SessionPduParameter::ConnectAcceptItem(vec![
                SessionPduSubParameter::ProtocolOptionsParameter(ProtocolOptions(2)), // Only set the duplex functionall unit
                SessionPduSubParameter::VersionNumberParameter(SupportedVersions(2)), // Version 2 only
            ]),
            SessionPduParameter::SessionUserRequirementsItem(SessionUserRequirements(2)), // Full Duplex only
        ])])
        .serialise()?;

        cotp_writer.send(data.as_slice()).await?;

        Ok(TcpIsoSpConnection::new(cotp_reader, cotp_writer))
    }
}

pub struct TcpIsoSpConnection {
    state_machine: Arc<RwLock<IcpIsoStateMachine>>,
    cotp_reader: TcpCotpReader,
    cotp_writer: TcpCotpWriter,
}

impl TcpIsoSpConnection {
    pub fn new(cotp_reader: TcpCotpReader, cotp_writer: TcpCotpWriter) -> Self {
        Self {
            state_machine: Arc::new(RwLock::new(IcpIsoStateMachine::default())),
            cotp_reader,
            cotp_writer,
        }
    }
}

impl IsoSpConnection<SocketAddr> for TcpIsoSpConnection {
    async fn split<'a>(self) -> Result<(impl 'a + IsoSpReader<SocketAddr> + Send, impl 'a + IsoSpWriter<SocketAddr> + Send), IsoSpError> {
        Ok((TcpIsoSpReader { cotp_reader: self.cotp_reader }, TcpIsoSpWriter { cotp_writer: self.cotp_writer }))
    }
}

pub struct TcpIsoSpReader {
    cotp_reader: TcpCotpReader,
}

impl IsoSpReader<SocketAddr> for TcpIsoSpReader {
    async fn recv(&mut self) -> Result<IsoSpRecvResult, IsoSpError> {
        loop {
            let data = match self.cotp_reader.recv().await? {
                rusty_cotp::api::CotpRecvResult::Closed => return Ok(IsoSpRecvResult::Closed),
                rusty_cotp::api::CotpRecvResult::Data(data) => data,
            };

            let mut pdus = SessionPduList::deserialise(TsduMaximumSizeSelected::Unlimited, &data)
                .map_err(|e| IsoSpError::ProtocolError("Failed to parse message.".to_string()))?
                .0;

            match (pdus.pop()) {
                Some(x) => match x {
                    SessionPdu::Finish(session_pdu_parameters) => todo!(),
                    SessionPdu::Disconnect(session_pdu_parameters) => todo!(),
                    SessionPdu::Abort(session_pdu_parameters) => todo!(),
                    SessionPdu::DataTransfer(session_pdu_parameters) => todo!(),
                    SessionPdu::GiveTokens(session_pdu_parameters) => todo!(),
                    SessionPdu::Unknown(_, items) => todo!(),
                    _ => return Err(IsoSpError::ProtocolError("An unexpected payload was received.".into())),
                },
                None => continue,
            };

            // println!("{:?}", pdus);
            // for pdus
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
        let payload = SessionPduList(vec![SessionPdu::DataTransfer(vec![])]).serialise()?;
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

        let (client_result, acceptor_result) = join!(TcpIsoSpService::connect(address, None), async {
            let acceptor = server.accept().await?;
            acceptor.accept(&[]).await
        });
        let client_connection = client_result?;
        let server_connection = acceptor_result?;

        let (client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, server_writer) = server_connection.split().await?;

        client_writer.send("Hello".as_bytes()).await?;
        match server_reader.recv().await? {
            IsoSpRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            IsoSpRecvResult::Data(data) => assert_eq!(data, "Hello".as_bytes().to_vec()),
        }

        Ok(())
    }
}
