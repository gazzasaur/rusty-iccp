use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{HEADER_LENGTH, MAX_PAYLOAD_LENGTH, TpktConnection, TpktError, TpktParser, TpktParserResult, TpktRecvResult, TpktServer, TpktService};

pub struct TcpTpktService {}

impl TpktService<SocketAddr> for TcpTpktService {
    async fn create_server<'a>(address: SocketAddr) -> Result<impl 'a + TpktServer<SocketAddr>, TpktError> {
        Ok(TcpTpktServer::new(address).await?)
    }

    // See Using lower layer services as traits
    #[allow(refining_impl_trait)]
    async fn connect<'a>(address: SocketAddr) -> Result<TcpTpktConnection, TpktError> {
        return Ok(TcpTpktConnection::new(TcpStream::connect(address).await?, address));
    }
}

pub struct TcpTpktServer {
    listener: TcpListener,
}

impl TcpTpktServer {
    pub async fn new(address: SocketAddr) -> Result<Self, TpktError> {
        Ok(Self { listener: TcpListener::bind(address).await? })
    }
}

impl TpktServer<SocketAddr> for TcpTpktServer {
    // See Using lower layer services as traits
    #[allow(refining_impl_trait)]
    async fn accept<'a>(&self) -> Result<TcpTpktConnection, TpktError> {
        let (stream, remote_host) = self.listener.accept().await?;
        Ok(TcpTpktConnection::new(stream, remote_host))
    }
}

pub struct TcpTpktConnection {
    stream: TcpStream,
    parser: TpktParser,
    remote_host: SocketAddr,
    receive_buffer: BytesMut,
}

impl TcpTpktConnection {
    pub fn new(stream: TcpStream, remote_host: SocketAddr) -> Self {
        TcpTpktConnection {
            stream,
            remote_host,
            parser: TpktParser::new(),
            receive_buffer: BytesMut::new(),
        }
    }
}

impl TpktConnection<SocketAddr> for TcpTpktConnection {
    fn remote_host(&self) -> SocketAddr {
        self.remote_host
    }

    async fn recv(&mut self) -> Result<TpktRecvResult, TpktError> {
        loop {
            let buffer = &mut self.receive_buffer;
            match self.parser.parse(buffer) {
                Ok(TpktParserResult::Data(x)) => return Ok(TpktRecvResult::Data(x)),
                Ok(TpktParserResult::InProgress) => (),
                Err(x) => return Err(x),
            };
            if self.stream.read_buf(buffer).await? == 0 {
                return Ok(TpktRecvResult::Closed);
            };
            match self.parser.parse(buffer) {
                Ok(TpktParserResult::Data(x)) => return Ok(TpktRecvResult::Data(x)),
                Ok(TpktParserResult::InProgress) => (),
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
