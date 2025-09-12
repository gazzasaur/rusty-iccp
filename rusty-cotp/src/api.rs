use rusty_tpkt::TpktError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CotpError {
    #[error("COTP Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("COTP over TPKT Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] TpktError),

    #[error("COTP IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("COTP Error: {}", .0)]
    InternalError(String),
}

#[derive(PartialEq, Debug)]
pub struct CotpConnectionInformation {
    pub calling_tsap: Option<Vec<u8>>,
    pub called_tsap: Option<Vec<u8>>,
}

impl Default for CotpConnectionInformation {
    fn default() -> Self {
        Self { calling_tsap: None, called_tsap: None }
    }
}

pub enum CotpRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait CotpAcceptor {
    fn accept(self) -> impl std::future::Future<Output = Result<impl CotpConnection, CotpError>> + Send;
}

pub trait CotpConnection {
    fn split(self) -> impl std::future::Future<Output = Result<(impl CotpReader, impl CotpWriter), CotpError>> + Send;
}

pub trait CotpReader {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CotpRecvResult, CotpError>> + Send;
}

pub trait CotpWriter {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), CotpError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), CotpError>> + Send;
}
