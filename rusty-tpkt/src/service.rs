use std::net::SocketAddr;

use bytes::{Buf, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split},
    net::{TcpListener, TcpStream},
};

use crate::{TpktConnection, TpktError, TpktParser, TpktParserResult, TpktReader, TpktRecvResult, TpktServer, TpktService, TpktWriter, serialiser::TpktSerialiser};

pub struct TcpTpktService {}

impl TpktService<SocketAddr> for TcpTpktService {
    #[allow(refining_impl_trait)]
    async fn create_server<'a>(address: SocketAddr) -> Result<TcpTpktServer, TpktError> {
        TcpTpktServer::new(address).await
    }

    #[allow(refining_impl_trait)]
    async fn connect<'a>(address: SocketAddr) -> Result<TcpTpktConnection, TpktError> {
        let stream = TcpStream::connect(address).await?;
        let (reader, writer) = split(stream);
        return Ok(TcpTpktConnection::new(address, TcpTpktReader::new(reader), TcpTpktWriter::new(writer)));
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
    #[allow(refining_impl_trait)]
    async fn accept<'a>(&self) -> Result<TcpTpktConnection, TpktError> {
        let (stream, remote_host) = self.listener.accept().await?;
        let (reader, writer) = split(stream);
        Ok(TcpTpktConnection::new(remote_host, TcpTpktReader::new(reader), TcpTpktWriter::new(writer)))
    }
}

pub struct TcpTpktConnection {
    remote_host: SocketAddr,
    reader: TcpTpktReader,
    writer: TcpTpktWriter,
}

impl<'a> TcpTpktConnection {
    pub fn new(remote_host: SocketAddr, reader: TcpTpktReader, writer: TcpTpktWriter) -> Self {
        TcpTpktConnection { remote_host, reader, writer }
    }
}

impl TpktConnection<SocketAddr> for TcpTpktConnection {
    fn remote_host(&self) -> SocketAddr {
        self.remote_host
    }

    #[allow(refining_impl_trait)]
    async fn split<'a>(connection: TcpTpktConnection) -> Result<(TcpTpktReader, TcpTpktWriter), TpktError> {
        Ok((connection.reader, connection.writer))
    }
}

pub struct TcpTpktReader {
    parser: TpktParser,
    receive_buffer: BytesMut,
    reader: ReadHalf<TcpStream>,
}

impl TcpTpktReader {
    pub fn new(reader: ReadHalf<TcpStream>) -> Self {
        Self {
            reader,
            parser: TpktParser::new(),
            receive_buffer: BytesMut::new(),
        }
    }
}

impl TpktReader<SocketAddr> for TcpTpktReader {
    async fn recv(&mut self) -> Result<TpktRecvResult, TpktError> {
        loop {
            let buffer = &mut self.receive_buffer;
            match self.parser.parse(buffer) {
                Ok(TpktParserResult::Data(x)) => return Ok(TpktRecvResult::Data(x)),
                Ok(TpktParserResult::InProgress) => (),
                Err(x) => return Err(x),
            };
            if self.reader.read_buf(buffer).await? == 0 {
                return Ok(TpktRecvResult::Closed);
            };
        }
    }
}

pub struct TcpTpktWriter {
    write_buffer: BytesMut,
    serialiser: TpktSerialiser,
    writer: WriteHalf<TcpStream>,
}

impl TcpTpktWriter {
    pub fn new(writer: WriteHalf<TcpStream>) -> Self {
        Self {
            serialiser: TpktSerialiser::new(),
            writer,
            write_buffer: BytesMut::new(),
        }
    }
}

impl TpktWriter<SocketAddr> for TcpTpktWriter {
    async fn send(&mut self, data: &[u8]) -> Result<(), TpktError> {
        self.write_buffer.extend(self.serialiser.serialise(data)?);
        while self.write_buffer.has_remaining() {
            self.writer.write_buf(&mut self.write_buffer).await?;
        }
        Ok(())
    }
}
