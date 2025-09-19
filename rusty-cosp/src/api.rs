use rusty_cotp::CotpError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CospError {
    #[error("COSP Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("COSP over COTP Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] CotpError),

    #[error("COSP IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("COSP Error: {}", .0)]
    InternalError(String),
}

#[derive(PartialEq, Clone, Debug)]
pub struct CospConnectionInformation {
    pub tsdu_maximum_size: Option<u16>,
    pub calling_session_selector: Option<u128>,
    pub called_session_selector: Option<u128>,
}

impl Default for CospConnectionInformation {
    fn default() -> Self {
        Self {
            tsdu_maximum_size: None,
            calling_session_selector: None,
            called_session_selector: None,
        }
    }
}

pub enum CospRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait CospAcceptor {
    fn accept(self, accept_data: Option<&[u8]>) -> impl std::future::Future<Output = Result<impl CospConnection, CospError>> + Send;
}

pub trait CospConnection {
    fn split(self) -> impl std::future::Future<Output = Result<(impl CospReader, impl CospWriter), CospError>> + Send;
}

pub trait CospReader {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CospRecvResult, CospError>> + Send;
}

pub trait CospWriter {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
}
