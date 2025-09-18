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

#[derive(PartialEq, Clone, Debug)]
pub struct CotpConnectInformation {
    pub initiator_reference: u16,
    pub calling_tsap_id: Option<Vec<u8>>,
    pub called_tsap_id: Option<Vec<u8>>,
}

impl Default for CotpConnectInformation {
    fn default() -> Self {
        Self {
            initiator_reference: rand::random(),
            calling_tsap_id: None,
            called_tsap_id: None,
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct CotpAcceptInformation {
    pub responder_reference: u16,
}

impl Default for CotpAcceptInformation {
    fn default() -> Self {
        Self { responder_reference: rand::random() }
    }
}

pub enum CotpRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait CotpAcceptor: Send {
    fn accept(self, options: CotpAcceptInformation) -> impl std::future::Future<Output = Result<impl CotpConnection, CotpError>> + Send;
}

pub trait CotpConnection: Send {
    fn split(self) -> impl std::future::Future<Output = Result<(impl CotpReader, impl CotpWriter), CotpError>> + Send;
}

pub trait CotpReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CotpRecvResult, CotpError>> + Send;
}

pub trait CotpWriter: Send {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), CotpError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), CotpError>> + Send;
}
