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
    pub calling_session_selector: Option<Vec<u8>>,
    pub called_session_selector: Option<Vec<u8>>,
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

pub trait CospInitiator: Send {
    fn initiate(self, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(impl CospConnection, Option<Vec<u8>>), CospError>> + Send;
}

pub trait CospListener: Send {
    fn responder(self) -> impl std::future::Future<Output = Result<(impl CospResponder, CospConnectionInformation, Option<Vec<u8>>), CospError>> + Send;
}

pub trait CospResponder: Send {
    fn accept(self, accept_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<impl CospConnection, CospError>> + Send;
}

pub trait CospConnection: Send {
    fn split(self) -> impl std::future::Future<Output = Result<(impl CospReader, impl CospWriter), CospError>> + Send;
}

pub trait CospReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CospRecvResult, CospError>> + Send;
}

pub trait CospWriter: Send {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
}
