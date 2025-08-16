use std::net::SocketAddr;

use bytes::BytesMut;
use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktService, TcpTpktWriter, TpktConnection, TpktReader, TpktRecvResult, TpktServer, TpktService, TpktWriter};

use crate::{
    api::{CotpConnection, CotpError, CotpReader, CotpRecvResult, CotpServer, CotpService, CotpWriter},
    packet::{
        connection_confirm::ConnectionConfirm,
        connection_request::ConnectionRequest,
        data_transfer::DataTransfer,
        parameter::{ConnectionClass, CotpParameter, TpduSize},
        payload::TransportProtocolDataUnit,
    },
    parser::packet::TransportProtocolDataUnitParser,
    serialiser::packet::TransportProtocolDataUnitSerialiser,
};

pub struct TcpCotpService {}

impl CotpService<SocketAddr> for TcpCotpService {
    #[allow(refining_impl_trait)]
    async fn create_server<'a>(address: SocketAddr) -> Result<TcpCotpServer, CotpError> {
        Ok(TcpCotpServer::new(address).await?)
    }

    #[allow(refining_impl_trait)]
    async fn connect<'a>(address: SocketAddr) -> Result<TcpCotpConnection, CotpError> {
        TcpCotpConnection::initiate(TcpTpktService::connect(address).await?).await
    }
}

pub struct TcpCotpServer {
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
    #[allow(refining_impl_trait)]
    async fn accept<'a>(&self) -> Result<TcpCotpConnection, CotpError> {
        TcpCotpConnection::receive(self.listener.accept().await?).await
    }
}

pub struct TcpCotpConnection {
    reader: TcpTpktReader,
    writer: TcpTpktWriter,

    max_payload_size: usize,
    parser: TransportProtocolDataUnitParser,
    serialiser: TransportProtocolDataUnitSerialiser,
}

impl TcpCotpConnection {
    pub async fn initiate(connection: TcpTpktConnection) -> Result<Self, CotpError> {
        let source_reference: u16 = rand::random();
        let parser = TransportProtocolDataUnitParser::new();
        let serialiser = TransportProtocolDataUnitSerialiser::new();
        let (mut reader, mut writer) = TcpTpktConnection::split(connection).await?;

        TcpCotpConnection::send_connection_request(&mut writer, &serialiser, source_reference).await?;
        let connection_confirm = TcpCotpConnection::receive_connection_confirm(&mut reader, &parser).await?;
        let (_, max_payload_size) = TcpCotpConnection::calculate_remote_size_payload(connection_confirm.parameters()).await?;

        Ok(TcpCotpConnection {
            parser,
            serialiser,
            reader,
            writer,
            max_payload_size,
        })
    }

    pub async fn receive(connection: TcpTpktConnection) -> Result<Self, CotpError> {
        let source_reference: u16 = rand::random();
        let parser = TransportProtocolDataUnitParser::new();
        let serialiser = TransportProtocolDataUnitSerialiser::new();
        let (mut reader, mut writer) = TcpTpktConnection::split(connection).await?;

        let connection_request = TcpCotpConnection::receive_connection_request(&mut reader, &parser).await?;
        let (max_payload_indicator, max_payload_size) = TcpCotpConnection::calculate_remote_size_payload(connection_request.parameters()).await?;
        TcpCotpConnection::verify_class_compatibility(&connection_request).await?;
        // Swapping source and destination for the reply.
        let destination_reference = connection_request.source_reference();
        TcpCotpConnection::send_connection_confirm(&mut writer, &serialiser, source_reference, destination_reference, max_payload_indicator).await?;

        Ok(TcpCotpConnection {
            parser,
            serialiser,
            reader,
            writer,
            max_payload_size,
        })
    }

    async fn send_connection_request(writer: &mut TcpTpktWriter, serialiser: &TransportProtocolDataUnitSerialiser, source_reference: u16) -> Result<(), CotpError> {
        let payload = serialiser.serialise(&TransportProtocolDataUnit::CR(ConnectionRequest::new(
            0,
            source_reference,
            0,
            ConnectionClass::Class0,
            vec![],
            vec![CotpParameter::TpduLengthParameter(TpduSize::Size1024)],
            &[],
        )))?;
        Ok(writer.send(&payload.as_slice()).await?)
    }

    async fn send_connection_confirm(writer: &mut TcpTpktWriter, serialiser: &TransportProtocolDataUnitSerialiser, source_reference: u16, destination_reference: u16, size: TpduSize) -> Result<(), CotpError> {
        let payload = serialiser.serialise(&TransportProtocolDataUnit::CC(ConnectionConfirm::new(
            0,
            source_reference,
            destination_reference,
            ConnectionClass::Class0,
            vec![],
            vec![CotpParameter::TpduLengthParameter(size)],
            &[],
        )))?;
        Ok(writer.send(&payload.as_slice()).await?)
    }

    async fn receive_connection_confirm(reader: &mut TcpTpktReader, parser: &TransportProtocolDataUnitParser) -> Result<ConnectionConfirm, CotpError> {
        let data = match reader.recv().await {
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

    async fn receive_connection_request(reader: &mut TcpTpktReader, parser: &TransportProtocolDataUnitParser) -> Result<ConnectionRequest, CotpError> {
        let data = match reader.recv().await {
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
    #[allow(refining_impl_trait)]
    async fn split<'a>(connection: Self) -> Result<(TcpCotpReader, TcpCotpWriter), CotpError> {
        Ok((
            TcpCotpReader::new(connection.reader, connection.parser),
            TcpCotpWriter::new(connection.writer, connection.max_payload_size, connection.serialiser),
        ))
    }
}

pub struct TcpCotpReader {
    // Not caring about the size of the payload we receive.
    reader: TcpTpktReader,
    parser: TransportProtocolDataUnitParser,

    data_buffer: BytesMut,
}

impl TcpCotpReader {
    pub fn new(reader: TcpTpktReader, parser: TransportProtocolDataUnitParser) -> Self {
        Self {
            reader,
            parser,
            data_buffer: BytesMut::new(),
        }
    }
}

impl CotpReader<SocketAddr> for TcpCotpReader {
    async fn recv(&mut self) -> Result<CotpRecvResult, CotpError> {
        loop {
            // I don't really care to check max size. It is 2025.
            let raw_data = match self.reader.recv().await? {
                TpktRecvResult::Closed => return Ok(CotpRecvResult::Closed),
                TpktRecvResult::Data(raw_data) => raw_data,
            };
            let data_transfer = match self.parser.parse(raw_data.as_slice())? {
                // Choosing the standards based option of reporting the TPDU error locally but not sending an error.
                TransportProtocolDataUnit::ER(tpdu_error) => return Err(CotpError::ProtocolError(format!("Received an error from the remote host: {:?}", tpdu_error.reason()).into())),
                TransportProtocolDataUnit::CR(_) => return Err(CotpError::ProtocolError("Received a Connection Request when expecting data.".into())),
                TransportProtocolDataUnit::CC(_) => return Err(CotpError::ProtocolError("Received a Connection Config when expecting data.".into())),
                TransportProtocolDataUnit::DR(_) => return Ok(CotpRecvResult::Closed),
                TransportProtocolDataUnit::DT(data_transfer) => data_transfer,
            };
            // I do not really care about the source and destination reference here. It is over a TCP stream. I'd rather keep it relaxed and avoid interop issues.

            self.data_buffer.extend_from_slice(data_transfer.user_data());
            if data_transfer.end_of_transmission() {
                let data = self.data_buffer.to_vec();
                self.data_buffer.clear();
                return Ok(CotpRecvResult::Data(data));
            }
        }
    }
}

pub struct TcpCotpWriter {
    writer: TcpTpktWriter,
    max_payload_size: usize,
    serialiser: TransportProtocolDataUnitSerialiser,
}

impl TcpCotpWriter {
    pub fn new(writer: TcpTpktWriter, max_payload_size: usize, serialiser: TransportProtocolDataUnitSerialiser) -> Self {
        Self { writer, max_payload_size, serialiser }
    }
}

impl CotpWriter<SocketAddr> for TcpCotpWriter {
    async fn send(&mut self, data: &[u8]) -> Result<(), CotpError> {
        let chunks = data.chunks(self.max_payload_size);
        let chunk_count = chunks.len();
        for (chunk_index, chunk_data) in chunks.enumerate() {
            let end_of_transmission = chunk_index + 1 >= chunk_count;
            let tpdu = DataTransfer::new(end_of_transmission, chunk_data);
            let tpdu_data = self.serialiser.serialise(&TransportProtocolDataUnit::DT(tpdu))?;
            self.writer.send(&tpdu_data).await?;
        }
        Ok(())
    }
}
