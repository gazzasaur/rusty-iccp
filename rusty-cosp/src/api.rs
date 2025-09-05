use rusty_cotp::api::{CotpConnectOptions, CotpError};
use thiserror::Error;

// Do not allow any more than 1G or data to be buffered.
// This is to help protect us against malicious clients and servers.
pub const MAX_DATA_SIZE: usize = 2_000_000_000;

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

pub enum CospRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait CospService<T> {
    fn create_server<'a>(address: T) -> impl std::future::Future<Output = Result<impl 'a + CospServer<T>, CospError>> + Send;
    fn connect<'a>(address: T, connect_data: Option<&[u8]>, options: CotpConnectOptions<'a>) -> impl std::future::Future<Output = Result<impl 'a + CospConnection<T>, CospError>> + Send;
}

pub trait CospServer<T> {
    fn accept<'a>(&self) -> impl std::future::Future<Output = Result<impl 'a + CospAcceptor<T>, CospError>> + Send;
}

pub trait CospAcceptor<T> {
    fn user_data(&self) -> Option<&[u8]>;
    fn complete_accept<'a>(self, accept_data: Option<&[u8]>) -> impl std::future::Future<Output = Result<impl 'a + CospConnection<T>, CospError>> + Send;
}

pub trait CospConnection<T> {
    fn split<'a>(self) -> impl std::future::Future<Output = Result<(impl 'a + CospReader<T> + Send, impl 'a + CospWriter<T> + Send), CospError>> + Send;
}

pub trait CospReader<T> {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CospRecvResult, CospError>> + Send;
}

pub trait CospWriter<T> {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
}
