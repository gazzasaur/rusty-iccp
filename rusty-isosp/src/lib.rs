use std::net::SocketAddr;

use rusty_cotp::{
    api::{CotpConnection, CotpReader, CotpServer, CotpService, CotpWriter},
    service::{TcpCotpConnection, TcpCotpReader, TcpCotpServer, TcpCotpService, TcpCotpWriter},
};

use crate::{
    api::{IsoSpAcceptor, IsoSpConnection, IsoSpError, IsoSpReader, IsoSpRecvResult, IsoSpServer, IsoSpService, IsoSpWriter},
    packet::session_pdu::{ProtocolOptions, SessionPdu, SessionPduList, SessionPduParameter, SessionPduSubParameter, SessionUserRequirements, SupportedVersions},
};

pub mod api;
pub mod packet;

pub struct TcpIsoSpService {}

impl IsoSpService<SocketAddr> for TcpIsoSpService {
    async fn create_server<'a>(address: SocketAddr) -> Result<impl 'a + IsoSpServer<SocketAddr>, IsoSpError> {
        Ok(TcpIsoSpServer::new(address).await?)
    }

    async fn connect<'a>(address: SocketAddr, connect_data: &[u8]) -> Result<impl 'a + IsoSpConnection<SocketAddr>, IsoSpError> {
        let cotp_connection = TcpCotpService::connect(address).await?;
        let (cotp_reader, mut cotp_writer) = TcpCotpConnection::split(cotp_connection).await?;

        let data = SessionPduList(vec![SessionPdu::Connect(vec![
            SessionPduParameter::ConnectAcceptItem(vec![
                SessionPduSubParameter::ProtocolOptionsParameter(ProtocolOptions(2)), // Only set the duplex functionall unit
                SessionPduSubParameter::VersionNumberParameter(SupportedVersions(2)), // Version 2 only
            ]),
            SessionPduParameter::SessionUserRequirementsItem(SessionUserRequirements(2)), // Full Duplex only
        ])])
        .serialise()?;

        cotp_writer.send(data.as_slice()).await?;

        // TODO Negotiation goes here.
        Ok(TcpIsoSpConnection::new(TcpCotpService::connect(address).await?))
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
    async fn accept<'a>(acceptpr: Self, accept_data: &[u8]) -> Result<impl 'a + IsoSpConnection<SocketAddr>, IsoSpError> {
        // TODO Negotiation goes here.
        Ok(TcpIsoSpConnection::new(acceptpr.cotp_connection))
    }
}

pub struct TcpIsoSpConnection {
    cotp_connection: TcpCotpConnection,
}

impl TcpIsoSpConnection {
    pub fn new(cotp_connection: TcpCotpConnection) -> Self {
        Self { cotp_connection }
    }
}

impl IsoSpConnection<SocketAddr> for TcpIsoSpConnection {
    async fn split<'a>(connection: Self) -> Result<(impl 'a + IsoSpReader<SocketAddr> + Send, impl 'a + IsoSpWriter<SocketAddr> + Send), IsoSpError> {
        let (reader, writer) = TcpCotpConnection::split(connection.cotp_connection).await?;
        Ok((TcpIsoSpReader { cotp_reader: reader }, TcpIsoSpWriter { cotp_writer: writer }))
    }
}

pub struct TcpIsoSpReader {
    cotp_reader: TcpCotpReader,
}

impl IsoSpReader<SocketAddr> for TcpIsoSpReader {
    async fn recv(&mut self) -> Result<IsoSpRecvResult, IsoSpError> {
        Ok(IsoSpRecvResult::Closed)
    }
}

pub struct TcpIsoSpWriter {
    cotp_writer: TcpCotpWriter,
}

impl IsoSpWriter<SocketAddr> for TcpIsoSpWriter {
    async fn send(&mut self, data: &[u8]) -> Result<(), IsoSpError> {
        Ok(())
    }

    async fn continue_send(&mut self) -> Result<(), IsoSpError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
