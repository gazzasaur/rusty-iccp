use thiserror::Error;

#[derive(Error, Debug)]
pub enum TpktError {
    #[error("TPKT Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("TPKT IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("TPKT Error: {}", .0)]
    InternalError(String),
}

pub enum TpktRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait TpktConnection {
    fn split<'a>(self) -> impl std::future::Future<Output = Result<(impl 'a + TpktReader, impl 'a + TpktWriter), TpktError>> + Send;
}

pub trait TpktReader {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<TpktRecvResult, TpktError>> + Send;
}

pub trait TpktWriter {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), TpktError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), TpktError>> + Send;
}
