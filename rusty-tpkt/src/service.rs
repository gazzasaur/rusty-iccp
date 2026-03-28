use std::{collections::VecDeque, net::SocketAddr};

use bytes::{Buf, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split},
    net::{TcpListener, TcpStream},
};

use crate::{
    TpktConnection, TpktError, TpktReader, TpktRecvResult, TpktWriter,
    parser::{TpktParser, TpktParserResult},
    serialiser::TpktSerialiser,
};

/// A TPKT server implemented over a TCP connection.
pub struct TcpTpktServer {
    listener: TcpListener,
}

impl TcpTpktServer {
    /// Start listening on the provided TCP port.
    pub async fn listen(address: SocketAddr) -> Result<Self, TpktError> {
        Ok(Self { listener: TcpListener::bind(address).await? })
    }

    /// Accept an incoming connection. This may be called multiple times.
    pub async fn accept<'a>(&self) -> Result<(TcpTpktConnection, SocketAddr), TpktError> {
        let (stream, remote_host) = self.listener.accept().await?;
        let (reader, writer) = split(stream);
        Ok((TcpTpktConnection::new(TcpTpktReader::new(reader), TcpTpktWriter::new(writer)), remote_host))
    }
}

/// An established TPKT connection.
pub struct TcpTpktConnection {
    reader: TcpTpktReader,
    writer: TcpTpktWriter,
}

impl TcpTpktConnection {
    /// Initiates a client TPKT connection.
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

/// The read half of a TPKT connection.
pub struct TcpTpktReader {
    parser: TpktParser,
    receive_buffer: BytesMut,
    reader: ReadHalf<TcpStream>,
}

impl TcpTpktReader {
    fn new(reader: ReadHalf<TcpStream>) -> Self {
        Self { reader, parser: TpktParser::new(), receive_buffer: BytesMut::new() }
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

/// The write half of a TPKT connection.
pub struct TcpTpktWriter {
    write_buffer: BytesMut,
    serialiser: TpktSerialiser,
    writer: WriteHalf<TcpStream>,
}

impl TcpTpktWriter {
    fn new(writer: WriteHalf<TcpStream>) -> Self {
        Self { serialiser: TpktSerialiser::new(), writer, write_buffer: BytesMut::new() }
    }
}

impl TpktWriter for TcpTpktWriter {
    async fn send(&mut self, input: &mut VecDeque<Vec<u8>>) -> Result<(), TpktError> {
        while let Some(packet) = input.pop_front() {
            self.write_buffer.extend(self.serialiser.serialise(&packet)?);
        }

        while self.write_buffer.has_remaining() {
            self.writer.write_buf(&mut self.write_buffer).await?;
        }
        Ok(())
    }
}
