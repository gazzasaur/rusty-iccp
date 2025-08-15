use std::net::SocketAddr;

use rusty_tpkt::{TcpTpktConnection, TcpTpktServer, TcpTpktService, TpktConnection, TpktRecvResult, TpktServer, TpktService};

use crate::{
    api::{CotpConnection, CotpError, CotpServer, CotpService},
    packet::{
        connection_confirm::ConnectionConfirm,
        connection_request::ConnectionRequest,
        parameter::{ConnectionClass, CotpParameter, TpduSize},
        payload::TransportProtocolDataUnit,
    },
    parser::packet::TransportProtocolDataUnitParser,
    serialiser::packet::TransportProtocolDataUnitSerialiser,
};

pub struct TcpCotpService {}

impl CotpService<SocketAddr> for TcpCotpService {
    async fn create_server<'a>(address: SocketAddr) -> Result<impl 'a + CotpServer<SocketAddr>, CotpError> {
        Ok(TcpCotpServer::new(address).await?)
    }

    async fn connect<'a>(address: SocketAddr) -> Result<impl 'a + CotpConnection<SocketAddr>, CotpError> {
        TcpCotpConnection::initiate(TcpTpktService::connect(address).await?).await
    }
}

struct TcpCotpServer {
    listener: TcpTpktServer,
}

impl TcpCotpServer {
    pub async fn new(address: SocketAddr) -> Result<TcpCotpServer, CotpError> {
        Ok(TcpCotpServer {
            listener: TcpTpktServer::new(address).await?,
        })
    }
}

impl CotpServer<SocketAddr> for TcpCotpServer {
    async fn accept<'a>(&self) -> Result<impl 'a + CotpConnection<SocketAddr>, CotpError> {
        TcpCotpConnection::receive(self.listener.accept().await?).await
    }
}

struct TcpCotpConnection {
    buffer: Vec<u8>,
    source_reference: u16,
    max_payload_size: usize,
    destination_reference: u16,
    connection: TcpTpktConnection,
    parser: TransportProtocolDataUnitParser,
    serialiser: TransportProtocolDataUnitSerialiser,
}

impl TcpCotpConnection {
    pub async fn initiate(mut connection: TcpTpktConnection) -> Result<Self, CotpError> {
        let source_reference: u16 = rand::random();
        let parser = TransportProtocolDataUnitParser::new();
        let serialiser = TransportProtocolDataUnitSerialiser::new();

        TcpCotpConnection::send_connection_request(&mut connection, &serialiser, source_reference).await?;
        let connection_confirm = TcpCotpConnection::receive_connection_confirm(&mut connection, &parser).await?;
        let (_, max_payload_size) = TcpCotpConnection::calculate_remote_size_payload(connection_confirm.parameters()).await?;
        let destination_reference = connection_confirm.destination_reference(); // I do not really care if it is 0.

        Ok(TcpCotpConnection {
            parser,
            serialiser,
            connection,
            source_reference,
            max_payload_size,
            buffer: Vec::new(),
            destination_reference,
        })
    }

    pub async fn receive(mut connection: TcpTpktConnection) -> Result<Self, CotpError> {
        let destination_reference: u16 = rand::random();
        let parser = TransportProtocolDataUnitParser::new();
        let serialiser = TransportProtocolDataUnitSerialiser::new();

        let connection_request = TcpCotpConnection::receive_connection_request(&mut connection, &parser).await?;
        let (max_payload_indicator, max_payload_size) = TcpCotpConnection::calculate_remote_size_payload(connection_request.parameters()).await?;
        TcpCotpConnection::verify_class_compatibility(&connection_request).await?;
        let source_reference = connection_request.source_reference();
        TcpCotpConnection::send_connection_confirm(&mut connection, &serialiser, source_reference, destination_reference, max_payload_indicator).await?;

        Ok(TcpCotpConnection {
            parser,
            serialiser,
            connection,
            source_reference,
            max_payload_size,
            buffer: Vec::new(),
            destination_reference,
        })
    }

    async fn send_connection_request(connection: &mut TcpTpktConnection, serialiser: &TransportProtocolDataUnitSerialiser, source_reference: u16) -> Result<(), CotpError> {
        let payload = serialiser.serialise(&TransportProtocolDataUnit::CR(ConnectionRequest::new(
            0,
            source_reference,
            0,
            ConnectionClass::Class0,
            vec![],
            vec![CotpParameter::TpduLengthParameter(TpduSize::Size1024)],
            &[],
        )))?;
        Ok(connection.send(&payload.as_slice()).await?)
    }

    async fn send_connection_confirm(connection: &mut TcpTpktConnection, serialiser: &TransportProtocolDataUnitSerialiser, source_reference: u16, destination_reference: u16, size: TpduSize) -> Result<(), CotpError> {
        let payload = serialiser.serialise(&TransportProtocolDataUnit::CC(ConnectionConfirm::new(
            0,
            source_reference,
            destination_reference,
            ConnectionClass::Class0,
            vec![],
            vec![CotpParameter::TpduLengthParameter(size)],
            &[],
        )))?;
        Ok(connection.send(&payload.as_slice()).await?)
    }

    async fn receive_connection_confirm(connection: &mut TcpTpktConnection, parser: &TransportProtocolDataUnitParser) -> Result<ConnectionConfirm, CotpError> {
        let data = match connection.recv().await {
            Ok(TpktRecvResult::Data(x)) => x,
            Ok(TpktRecvResult::Closed) => return Err(CotpError::ProtocolError("The connection was closed before the COTP handshake was complete.".into())),
            Err(e) => return Err(e.into()),
        };
        return Ok(match parser.parse(data.as_slice())? {
            TransportProtocolDataUnit::CC(x) if x.preferred_class() != &ConnectionClass::Class0 => return Err(CotpError::ProtocolError("Remote failed to select COTP Class 0.".into())),
            TransportProtocolDataUnit::CC(x) => x,
            TransportProtocolDataUnit::CR(_) => return Err(CotpError::ProtocolError("Expected connection confirmed on handshake but got a connection request".into())),
            TransportProtocolDataUnit::DR(_) => return Err(CotpError::ProtocolError("Expected connection confirmed on handshake but got a disconnect reqeust".into())),
            TransportProtocolDataUnit::DT(_) => return Err(CotpError::ProtocolError("Expected connection confirmed on handshake but got a data transfer".into())),
            TransportProtocolDataUnit::ER(_) => return Err(CotpError::ProtocolError("Expected connection confirmed on handshake but got a error response".into())),
        });
    }

    async fn receive_connection_request(connection: &mut TcpTpktConnection, parser: &TransportProtocolDataUnitParser) -> Result<ConnectionRequest, CotpError> {
        let data = match connection.recv().await {
            Ok(TpktRecvResult::Data(x)) => x,
            Ok(TpktRecvResult::Closed) => return Err(CotpError::ProtocolError("The connection was closed before the COTP handshake was complete.".into())),
            Err(e) => return Err(e.into()),
        };
        return Ok(match parser.parse(data.as_slice())? {
            TransportProtocolDataUnit::CR(x) => x,
            TransportProtocolDataUnit::CC(_) => return Err(CotpError::ProtocolError("Expected connection request on handshake but got a connextion confirm".into())),
            TransportProtocolDataUnit::DR(_) => return Err(CotpError::ProtocolError("Expected connection request on handshake but got a disconnect reqeust".into())),
            TransportProtocolDataUnit::DT(_) => return Err(CotpError::ProtocolError("Expected connection request on handshake but got a data transfer".into())),
            TransportProtocolDataUnit::ER(_) => return Err(CotpError::ProtocolError("Expected connection request on handshake but got a error response".into())),
        });
    }

    async fn calculate_remote_size_payload(parameters: &[CotpParameter]) -> Result<(TpduSize, usize), CotpError> {
        let parameter: &TpduSize = parameters
            .iter()
            .filter_map(|p| match p {
                CotpParameter::TpduLengthParameter(x) => Some(x),
                _ => None,
            })
            .last()
            .unwrap_or(&TpduSize::Size128);

        Ok(match parameter {
            TpduSize::Size8192 => return Err(CotpError::ProtocolError("The remote side selected an 8192 bytes COTP payload but Class 0 support a maximum for 2048 bytes.".into())),
            TpduSize::Size4096 => return Err(CotpError::ProtocolError("The remote side selected an 4096 bytes COTP payload but Class 0 support a maximum for 2048 bytes.".into())),
            TpduSize::Unknown(x) => return Err(CotpError::ProtocolError(format!("The requested TPDU size is unknown {:?}.", x).into())),
            TpduSize::Size128 => (TpduSize::Size128, 128),
            TpduSize::Size256 => (TpduSize::Size256, 256),
            TpduSize::Size512 => (TpduSize::Size512, 512),
            TpduSize::Size1024 => (TpduSize::Size1024, 1024),
            TpduSize::Size2048 => (TpduSize::Size2048, 2048),
        })
    }

    async fn verify_class_compatibility(connection_request: &ConnectionRequest) -> Result<(), CotpError> {
        let empty_set = Vec::new();
        let class_parameters = connection_request
            .parameters()
            .iter()
            .filter_map(|p| match p {
                CotpParameter::AlternativeClassParameter(x) => Some(x),
                _ => None,
            })
            .last()
            .unwrap_or(&empty_set);

        // Verify we can downgrade to Class 0
        match connection_request.preferred_class() {
            ConnectionClass::Class0 => (),
            ConnectionClass::Class1 => (),
            ConnectionClass::Class2 if class_parameters.contains(&&ConnectionClass::Class0) => (),
            ConnectionClass::Class3 if class_parameters.contains(&&ConnectionClass::Class0) => (),
            ConnectionClass::Class3 if class_parameters.contains(&&ConnectionClass::Class1) => (),
            ConnectionClass::Class4 if class_parameters.contains(&&ConnectionClass::Class0) => (),
            ConnectionClass::Class4 if class_parameters.contains(&&ConnectionClass::Class1) => (),
            _ => {
                return Err(CotpError::ProtocolError(format!(
                    "Cannot downgrade connection request to Class 0 {:?} - {:?}",
                    connection_request.preferred_class(),
                    class_parameters
                )));
            }
        };
        Ok(())
    }
}

impl CotpConnection<SocketAddr> for TcpCotpConnection {
    // async fn recv(&mut self) -> Result<crate::api::CotpRecvResult, CotpError> {
    //     let data = self.connection.recv().await?;
    // }

    // async fn send(&mut self, data: &[u8]) -> Result<(), CotpError> {}
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ops::Range;
    use tokio::join;
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn perform_handshake() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let subject = TcpCotpService::create_server(test_address).await?;

        let (accept_result, connect_result) = join!(subject.accept(), TcpCotpService::connect(test_address));
        let server_connection = accept_result?;
        let client_connection = connect_result?;

        Ok(())
    }
}
