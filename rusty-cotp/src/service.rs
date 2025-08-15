use std::net::SocketAddr;

use rusty_tpkt::{TcpTpktConnection, TcpTpktServer, TcpTpktService, TpktConnection, TpktRecvResult, TpktServer, TpktService};

use crate::{
    api::{CotpConnection, CotpError, CotpServer, CotpService},
    packet::{
        connection_request::ConnectionRequest,
        parameter::{ConnectionClass, CotpParameter},
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
    connection: TcpTpktConnection,
}

impl TcpCotpConnection {
    pub async fn initiate(mut connection: TcpTpktConnection) -> Result<Self, CotpError> {
        let source_reference: u16 = rand::random();
        let serialiser = TransportProtocolDataUnitSerialiser::new();
        connection
            .send(
                serialiser
                    .serialise(&TransportProtocolDataUnit::CR(ConnectionRequest::new(
                        0,
                        source_reference,
                        0,
                        ConnectionClass::Class0,
                        vec![],
                        vec![CotpParameter::TpduLengthParameter(crate::packet::parameter::TpduSize::Size1024)],
                        &[],
                    )))?
                    .as_slice(),
            )
            .await?;
        Ok(TcpCotpConnection { connection, buffer: Vec::new() })
    }

    pub async fn receive(mut connection: TcpTpktConnection) -> Result<Self, CotpError> {
        let destination_reference: u16 = rand::random();
        let parser = TransportProtocolDataUnitParser::new();

        // CC must be a single packet.
        let payload = match connection.recv().await? {
            TpktRecvResult::Data(data) => parser.parse(data.as_slice()),
            TpktRecvResult::Closed => return Err(CotpError::ProtocolError("The connection is closed.".into())),
        }?;
        let connection_request = match payload {
            TransportProtocolDataUnit::CR(connection_request) => connection_request,
            _ => return Err(CotpError::ProtocolError(format!("Unexpected payload on session establishment: {:?}", payload))),
        };
        // The standards says if there are multiple of the same parameter we must use the last.
        let empty_vector = Vec::new();
        let class_parameters: Vec<&ConnectionClass> = connection_request
            .parameters()
            .iter()
            .filter_map(|p| match p {
                CotpParameter::AlternativeClassParameter(items) => Some(items),
                _ => None,
            })
            .last()
            .unwrap_or(&empty_vector)
            .iter()
            .collect();

        // Verofy we can downgrade to Class 0
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

        Ok(TcpCotpConnection { connection, buffer: Vec::new() })
    }
}

impl CotpConnection<SocketAddr> for TcpCotpConnection {
    async fn recv(&mut self) -> Result<crate::api::CotpRecvResult, CotpError> {
        let data = self.connection.recv().await?;
        todo!()
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), CotpError> {
        todo!()
    }

    //     async fn recv(&mut self) -> Result<CotpRecvResult, CotpError> {
    //         loop {
    //             let buffer = &mut self.receive_buffer;
    //             match self.parser.parse(buffer) {
    //                 Ok(CotpParserResult::Data(x)) => return Ok(CotpRecvResult::Data(x)),
    //                 Ok(CotpParserResult::InProgress) => (),
    //                 Err(x) => return Err(x),
    //             };
    //             if self.stream.read_buf(buffer).await? == 0 {
    //                 return Ok(CotpRecvResult::Closed);
    //             };
    //             match self.parser.parse(buffer) {
    //                 Ok(CotpParserResult::Data(x)) => return Ok(CotpRecvResult::Data(x)),
    //                 Ok(CotpParserResult::InProgress) => (),
    //                 Err(x) => return Err(x),
    //             }
    //         }
    //     }

    //     async fn send(&mut self, data: &[u8]) -> Result<(), CotpError> {
    //         if data.len() > MAX_PAYLOAD_LENGTH {
    //             return Err(CotpError::ProtocolError(format!("Cotp user data must be less than or equal to {} but was {}", MAX_PAYLOAD_LENGTH, data.len())));
    //         }
    //         let packet_length = ((data.len() + HEADER_LENGTH) as u16).to_be_bytes();
    //         self.stream.write_all(&[0x03u8, 0x00u8]).await?;
    //         self.stream.write_all(&packet_length).await?;
    //         Ok(self.stream.write_all(data).await?)
    //     }
}
