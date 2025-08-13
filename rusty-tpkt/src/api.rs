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

pub enum TpktRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait TpktService<T> {
    fn create_server<'a>(address: T) -> impl std::future::Future<Output = Result<impl 'a + TpktServer<T>, TpktError>> + Send;
    fn connect<'a>(address: T) -> impl std::future::Future<Output = Result<impl 'a + TpktConnection<T>, TpktError>> + Send;
}

pub trait TpktServer<T> {
    fn accept<'a>(&self) -> impl std::future::Future<Output = Result<impl 'a + TpktConnection<T>, TpktError>> + Send;
}

pub trait TpktConnection<T> {
    fn remote_host(&self) -> T;

    fn recv(&mut self) -> impl std::future::Future<Output = Result<TpktRecvResult, TpktError>> + Send;
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), TpktError>> + Send;
}
