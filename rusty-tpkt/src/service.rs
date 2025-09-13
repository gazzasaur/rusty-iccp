use std::net::SocketAddr;

use bytes::{Buf, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split},
    net::{TcpListener, TcpStream},
};

use crate::{parser::{TpktParser, TpktParserResult}, serialiser::TpktSerialiser, TpktConnection, TpktError, TpktReader, TpktRecvResult, TpktWriter};

pub struct TcpTpktService {}

pub struct TcpTpktServer {
    listener: TcpListener,
}

impl TcpTpktServer {
    pub async fn listen(address: SocketAddr) -> Result<Self, TpktError> {
        Ok(Self { listener: TcpListener::bind(address).await? })
    }

    pub async fn accept<'a>(&self) -> Result<(TcpTpktConnection, SocketAddr), TpktError> {
        let (stream, remote_host) = self.listener.accept().await?;
        let (reader, writer) = split(stream);
        Ok((TcpTpktConnection::new(TcpTpktReader::new(reader), TcpTpktWriter::new(writer)), remote_host))
    }
}

pub struct TcpTpktConnection {
    reader: TcpTpktReader,
    writer: TcpTpktWriter,
}

impl TcpTpktConnection {
    pub async fn connect<'a>(address: SocketAddr) -> Result<TcpTpktConnection, TpktError> {
        let stream = TcpStream::connect(address).await?;
        let (reader, writer) = split(stream);
        return Ok(TcpTpktConnection::new(TcpTpktReader::new(reader), TcpTpktWriter::new(writer)));
    }

    fn new(reader: TcpTpktReader, writer: TcpTpktWriter) -> Self {
        TcpTpktConnection { reader, writer }
    }
}

impl TpktConnection for TcpTpktConnection {
    async fn split(self) -> Result<(impl TpktReader, impl TpktWriter), TpktError> {
        Ok((self.reader, self.writer))
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

impl TpktReader for TcpTpktReader {
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

impl TpktWriter for TcpTpktWriter {
    async fn send(&mut self, data: &[u8]) -> Result<(), TpktError> {
        self.write_buffer.extend(self.serialiser.serialise(data)?);
        while self.write_buffer.has_remaining() {
            self.writer.write_buf(&mut self.write_buffer).await?;
        }
        Ok(())
    }

    async fn continue_send(&mut self) -> Result<(), TpktError> {
        while self.write_buffer.has_remaining() {
            self.writer.write_buf(&mut self.write_buffer).await?;
        }
        Ok(())
    }
}
