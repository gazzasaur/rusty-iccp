use rusty_cosp::api::{CospConnection, CospReader, CospWriter};
use rusty_cotp::CotpConnection;

use crate::{CoppConnection, CoppConnectionInformation, CoppConnector, CoppError, CoppReader, CoppRecvResult, CoppResponder, CoppWriter};

pub(crate) struct RustyCoppConnector<R: CospReader, W: CospWriter> {
    cosp_reader: R,
    cosp_writer: W,
}

impl<R: CospReader, W: CospWriter> RustyCoppConnector<R, W> {
    pub(crate) async fn new(cosp_connection: impl CospConnection) -> Result<RustyCoppConnector<impl CospReader, impl CospWriter>, CoppError> {
        let (cosp_reader, cosp_writer) = cosp_connection.split().await?;
        Ok(RustyCoppConnector { cosp_reader, cosp_writer })
    }
}

impl<R: CospReader, W: CospWriter> CoppConnector for RustyCoppConnector<R, W> {
    async fn receive(self) -> Result<(impl CoppResponder, CoppConnectionInformation, Option<Vec<u8>>), CoppError> {
        Ok((RustyCoppResponder::new(self.cosp_reader, self.cosp_writer), CoppConnectionInformation::default(), None))
    }
}

pub(crate) struct RustyCoppResponder<R: CospReader, W: CospWriter> {
    cosp_reader: R,
    cosp_writer: W,
}

impl<R: CospReader, W: CospWriter> RustyCoppResponder<R, W> {
    fn new(cosp_reader: R, cosp_writer: W) -> RustyCoppResponder<impl CospReader, impl CospWriter> {
        RustyCoppResponder { cosp_reader, cosp_writer }
    }
}

impl<R: CospReader, W: CospWriter> CoppResponder for RustyCoppResponder<R, W> {
    async fn accept(self, accept_data: Option<&[u8]>) -> Result<impl CoppConnection, CoppError> {
        Ok(RustyCoppConnection::new(self.cosp_reader, self.cosp_writer))
    }
}

pub(crate) struct RustyCoppConnection<R: CospReader, W: CospWriter> {
    cosp_reader: R,
    cosp_writer: W,
}

impl<R: CospReader, W: CospWriter> RustyCoppConnection<R, W> {
    pub(crate) fn initiate(cotp_connection: impl CotpConnection) {

    }

    fn new(cosp_reader: R, cosp_writer: W) -> RustyCoppConnection<impl CospReader, impl CospWriter> {
        RustyCoppConnection { cosp_reader, cosp_writer }
    }
}

impl<R: CospReader, W: CospWriter> CoppConnection for RustyCoppConnection<R, W> {
    async fn split(self) -> Result<(impl CoppReader, impl CoppWriter), CoppError> {
        Ok((RustyCoppReader::new(self.cosp_reader), RustyCoppWriter::new(self.cosp_writer)))
    }
}

pub(crate) struct RustyCoppReader<R: CospReader> {
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

pub(crate) struct RustyCoppWriter<W: CospWriter> {
    cosp_writer: W,
}

impl<W: CospWriter> RustyCoppWriter<W> {
    fn new(cosp_writer: W) -> RustyCoppWriter<impl CospWriter> {
        RustyCoppWriter { cosp_writer }
    }
}

impl<W: CospWriter> CoppWriter for RustyCoppWriter<W> {
    async fn send(&mut self, data: &[u8]) -> Result<(), CoppError> {
        todo!()
    }

    async fn continue_send(&mut self) -> Result<(), CoppError> {
        todo!()
    }
}
