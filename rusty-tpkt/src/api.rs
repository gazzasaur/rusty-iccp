use thiserror::Error;

#[derive(Error, Debug)]
pub enum TpktError {
    #[error("Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("Error: {}", .0)]
    InternalError(String),
}

pub enum TktpRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait TkptService<T> {
    fn create_server(&self, address: T) -> impl std::future::Future<Output = Result<impl TkptServer, TpktError>> + Send;
    fn connect(&self, address: T) -> impl std::future::Future<Output = Result<impl TkptConnection, TpktError>> + Send;
}

pub trait TkptServer {
    fn accept(&self) -> impl std::future::Future<Output = Result<impl TkptConnection, TpktError>> + Send;
}

pub trait TkptConnection {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<TktpRecvResult, TpktError>> + Send;
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), TpktError>> + Send;
}
