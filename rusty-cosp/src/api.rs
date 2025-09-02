use rusty_cotp::api::{CotpConnectOptions, CotpError};
use thiserror::Error;

// Do not allow any more than 1G or data to be buffered.
// This is to help protect us against malicious clients and servers.
pub const MAX_DATA_SIZE: usize = 2_000_000_000;

#[derive(Error, Debug)]
pub enum IsoSpError {
    #[error("COSP Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("COSP over COTP Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] CotpError),

    #[error("COSP IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("COSP Error: {}", .0)]
    InternalError(String),
}

pub enum IsoSpRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait IsoSpService<T> {
    fn create_server<'a>(address: T) -> impl std::future::Future<Output = Result<impl 'a + IsoSpServer<T>, IsoSpError>> + Send;
    fn connect<'a>(address: T, connect_data: Option<&[u8]>, options: CotpConnectOptions<'a>) -> impl std::future::Future<Output = Result<impl 'a + IsoSpConnection<T>, IsoSpError>> + Send;
}

pub trait IsoSpServer<T> {
    fn accept<'a>(&self) -> impl std::future::Future<Output = Result<impl 'a + IsoSpAcceptor<T>, IsoSpError>> + Send;
}

pub trait IsoSpAcceptor<T> {
    fn accept<'a>(self, accept_data: Option<&[u8]>) -> impl std::future::Future<Output = Result<(impl 'a + IsoSpConnection<T>, Option<Vec<u8>>), IsoSpError>> + Send;
}

pub trait IsoSpConnection<T> {
    fn split<'a>(self) -> impl std::future::Future<Output = Result<(impl 'a + IsoSpReader<T> + Send, impl 'a + IsoSpWriter<T> + Send), IsoSpError>> + Send;
}

pub trait IsoSpReader<T> {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<IsoSpRecvResult, IsoSpError>> + Send;
}

pub trait IsoSpWriter<T> {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), IsoSpError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), IsoSpError>> + Send;
}
