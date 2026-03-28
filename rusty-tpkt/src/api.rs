use std::collections::VecDeque;

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

/// Two normal outcomes may occur when reading from a socket. It may return data, or it may be closed. This enum represents both possible state.
pub enum TpktRecvResult {
    /// The connection has closed normally.
    Closed,
    /// The following data was returned.
    Data(Vec<u8>),
}

/// A trait representing a TPKT connection. There is no distinction between a client and a server connection once they are established.
pub trait TpktConnection: Send {
    /// Splits a connection into reader and writer components. This must be done before the connection is used.
    fn split(self) -> impl std::future::Future<Output = Result<(impl TpktReader, impl TpktWriter), TpktError>> + Send;
}

/// A trait representing the read half of TPKT connection.
pub trait TpktReader: Send {
    /// Reads from a TPKT connection. There are three outcomes.
    /// * TpktRecvResult::Data(_) - Data was read from the socket.
    /// * TpktRecvResult::Closed - The underlying TCP connection was closed normally.
    /// * TpktError - May indicate a TPKT packet was malformed, there was an IO error or some other internal failure occurred.
    fn recv(&mut self) -> impl std::future::Future<Output = Result<TpktRecvResult, TpktError>> + Send;
}

/// A trait representing the write half of TPKT connection.
pub trait TpktWriter: Send {
    /// Writes to a TPKT connection. This uses a VedDeque as a buffer. This is to ensure the operation is cancel safe so long as the buffer is not dropped while it has data.
    fn send(&mut self, input: &mut VecDeque<Vec<u8>>) -> impl std::future::Future<Output = Result<(), TpktError>> + Send;
}
