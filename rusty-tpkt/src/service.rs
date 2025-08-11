use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{HEADER_LENGTH, MAX_PAYLOAD_LENGTH, TkptConnection, TkptParser, TkptParserResult, TkptServer, TkptService, TktpRecvResult, TpktError};

pub struct TcpTkptService {}

impl TcpTkptService {
    pub fn new() -> Self {
        TcpTkptService {}
    }
}

impl TkptService<SocketAddr> for TcpTkptService {
    async fn create_server(&self, address: SocketAddr) -> Result<impl TkptServer, TpktError> {
        Ok(TcpTkptServer::new(TcpListener::bind(address).await?))
    }

    async fn connect(&self, address: SocketAddr) -> Result<impl TkptConnection, TpktError> {
        return Ok(TcpTkptConnection::new(TcpStream::connect(address).await?));
    }
}

struct TcpTkptServer {
    listener: TcpListener,
}

impl TcpTkptServer {
    pub fn new(listener: TcpListener) -> Self {
        Self { listener }
    }
}

impl TkptServer for TcpTkptServer {
    async fn accept(&self) -> Result<impl TkptConnection, TpktError> {
        let (stream, _) = self.listener.accept().await?;
        Ok(TcpTkptConnection::new(stream))
    }
}

struct TcpTkptConnection {
    stream: TcpStream,
    parser: TkptParser,
    receive_buffer: BytesMut,
}

impl TcpTkptConnection {
    pub fn new(stream: TcpStream) -> Self {
        TcpTkptConnection {
            stream,
            parser: TkptParser::new(),
            receive_buffer: BytesMut::new(),
        }
    }
}

impl TkptConnection for TcpTkptConnection {
    async fn recv(&mut self) -> Result<TktpRecvResult, TpktError> {
        loop {
            let buffer = &mut self.receive_buffer;
            match self.parser.parse(buffer) {
                Ok(TkptParserResult::Data(x)) => return Ok(TktpRecvResult::Data(x)),
                Ok(TkptParserResult::InProgress) => (),
                Err(x) => return Err(x),
            };
            if self.stream.read_buf(buffer).await? == 0 {
                return Ok(TktpRecvResult::Closed);
            };
            match self.parser.parse(buffer) {
                Ok(TkptParserResult::Data(x)) => return Ok(TktpRecvResult::Data(x)),
                Ok(TkptParserResult::InProgress) => (),
                Err(x) => return Err(x),
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), TpktError> {
        if data.len() > MAX_PAYLOAD_LENGTH {
            return Err(TpktError::ProtocolError(format!("TPKT user data must be less than or equal to {} but was {}", MAX_PAYLOAD_LENGTH, data.len())));
        }
        let packet_length = ((data.len() + HEADER_LENGTH) as u16).to_be_bytes();
        self.stream.write_all(&[0x03u8, 0x00u8]).await?;
        self.stream.write_all(&packet_length).await?;
        Ok(self.stream.write_all(data).await?)
    }
}
