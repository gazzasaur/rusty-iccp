use rusty_tpkt::TpktError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CotpError {
    #[error("Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] TpktError),

    #[error("IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("Error: {}", .0)]
    InternalError(String),
}

pub enum CotpRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait CotpService<T> {
    fn create_server<'a>(address: T) -> impl std::future::Future<Output = Result<impl 'a + CotpServer<T>, CotpError>> + Send;
    fn connect<'a>(address: T) -> impl std::future::Future<Output = Result<impl 'a + CotpConnection<T>, CotpError>> + Send;
}

pub trait CotpServer<T> {
    fn accept<'a>(&self) -> impl std::future::Future<Output = Result<impl 'a + CotpConnection<T>, CotpError>> + Send;
}

pub trait CotpConnection<T> {
    fn split<'a>(connection: Self) -> impl std::future::Future<Output = Result<(impl 'a + CotpReader<T> + Send, impl 'a + CotpWriter<T> + Send), CotpError>> + Send;
}

pub trait CotpReader<T> {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CotpRecvResult, CotpError>> + Send;
}

pub trait CotpWriter<T> {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), CotpError>> + Send;
}
