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

pub enum CotpRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub struct CotpConnectOptions<'a> {
    pub calling_tsap: Option<&'a [u8]>,
    pub called_tsap: Option<&'a [u8]>,
}

impl<'a> Default for CotpConnectOptions<'a> {
    fn default() -> Self {
        Self { calling_tsap: None, called_tsap: None }
    }
}

pub trait CotpService<T> {
    fn create_server<'a>(address: T) -> impl std::future::Future<Output = Result<impl 'a + CotpServer<T>, CotpError>> + Send;
    fn connect<'a>(address: T, options: CotpConnectOptions<'a>) -> impl std::future::Future<Output = Result<impl 'a + CotpConnection<T>, CotpError>> + Send;
}

pub trait CotpServer<T> {
    fn accept<'a>(&self) -> impl std::future::Future<Output = Result<impl 'a + CotpConnection<T>, CotpError>> + Send;
}

pub trait CotpConnection<T> {
    fn split(self) -> impl std::future::Future<Output = Result<(impl CotpReader<T> + Send, impl CotpWriter<T> + Send), CotpError>> + Send;
}

pub trait CotpReader<T> {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CotpRecvResult, CotpError>> + Send;
}

pub trait CotpWriter<T> {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), CotpError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), CotpError>> + Send;
}
