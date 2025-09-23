use std::marker::PhantomData;

use rusty_cosp::{CospConnection, CospListener, CospReader, CospWriter};

use crate::{message::ConnectPresentation, serialise::serialise_connect, CoppConnection, CoppConnectionInformation, CoppConnector, CoppError, CoppReader, CoppRecvResult, CoppResponder, CoppWriter};

pub struct RustyCoppConnector<R: CospReader, W: CospWriter> {
    cosp_reader: PhantomData<R>,
    cosp_writer: PhantomData<W>,
}

impl<R: CospReader, W: CospWriter> RustyCoppConnector<R, W> {
    pub async fn new(cosp_connector: impl CospListener) -> Result<RustyCoppConnector<impl CospReader, impl CospWriter>, CoppError> {
        cosp_connector.res
        let (cosp_reader, cosp_writer) = cosp_connection.split().await?;
        Ok(RustyCoppConnector { cosp_reader, cosp_writer })
    }
}

impl<R: CospReader, W: CospWriter> CoppConnector for RustyCoppConnector<R, W> {
    async fn initiator(self, _options: CoppConnectionInformation, _user_data: Option<Vec<u8>>) -> Result<(impl CoppConnection, Option<Vec<u8>>), CoppError> {
        let cosp_reader = self.cosp_reader;
        let mut cosp_writer = self.cosp_writer;

        let message = ConnectPresentation {};
        let data = serialise_connect(message)?;

        cosp_writer.send(&data).await?;

        Ok((RustyCoppConnection::new(cosp_reader, cosp_writer), None))
    }

    async fn responder(self) -> Result<(impl CoppResponder, CoppConnectionInformation, Option<Vec<u8>>), CoppError> {
        Ok((RustyCoppResponder::new(self.cosp_reader, self.cosp_writer), Default::default(), None))
    }
}

pub struct RustyCoppResponder<R: CospReader, W: CospWriter> {
    cosp_reader: R,
    cosp_writer: W,
}

impl<R: CospReader, W: CospWriter> RustyCoppResponder<R, W> {
    fn new(cosp_reader: R, cosp_writer: W) -> RustyCoppResponder<impl CospReader, impl CospWriter> {
        RustyCoppResponder { cosp_reader, cosp_writer }
    }
}

impl<R: CospReader, W: CospWriter> CoppResponder for RustyCoppResponder<R, W> {
    async fn accept(self, _accept_data: Option<&[u8]>) -> Result<impl CoppConnection, CoppError> {
        Ok(RustyCoppConnection::new(self.cosp_reader, self.cosp_writer))
    }
}

pub struct RustyCoppConnection<R: CospReader, W: CospWriter> {
    cosp_reader: R,
    cosp_writer: W,
}

impl<R: CospReader, W: CospWriter> RustyCoppConnection<R, W> {
    fn new(cosp_reader: R, cosp_writer: W) -> RustyCoppConnection<impl CospReader, impl CospWriter> {
        RustyCoppConnection { cosp_reader, cosp_writer }
    }
}

impl<R: CospReader, W: CospWriter> CoppConnection for RustyCoppConnection<R, W> {
    async fn split(self) -> Result<(impl CoppReader, impl CoppWriter), CoppError> {
        Ok((RustyCoppReader::new(self.cosp_reader), RustyCoppWriter::new(self.cosp_writer)))
    }
}

pub struct RustyCoppReader<R: CospReader> {
    cosp_reader: R,
}

impl<R: CospReader> RustyCoppReader<R> {
    fn new(cosp_reader: R) -> RustyCoppReader<impl CospReader> {
        RustyCoppReader { cosp_reader }
    }
}

impl<R: CospReader> CoppReader for RustyCoppReader<R> {
    async fn recv(&mut self) -> Result<CoppRecvResult, CoppError> {
        Ok(CoppRecvResult::Closed)
    }
}

pub struct RustyCoppWriter<W: CospWriter> {
    cosp_writer: W,
}

impl<W: CospWriter> RustyCoppWriter<W> {
    fn new(cosp_writer: W) -> RustyCoppWriter<impl CospWriter> {
        RustyCoppWriter { cosp_writer }
    }
}

impl<W: CospWriter> CoppWriter for RustyCoppWriter<W> {
    async fn send(&mut self, _data: &[u8]) -> Result<(), CoppError> {
        todo!()
    }

    async fn continue_send(&mut self) -> Result<(), CoppError> {
        todo!()
    }
}
