use std::{any::Any, collections::VecDeque, fmt::Debug};

use dyn_clone::DynClone;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TpktError {
    /// Indicates issues with parsing of incoming packets or protocol violations with input user data.
    #[error("TPKT Protocol Error - {}", .0)]
    ProtocolError(String),

    /// Indicates issues with the underlying TCP socket or hardware.
    #[error("TPKT IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    /// Usually indicates a bug or an unhandled error condition.
    #[error("TPKT Error: {}", .0)]
    InternalError(String),
}

/// Information regarding the protocol stack. This is useful for authentication and logging.
pub trait ProtocolInformation: Any + Send + Debug + DynClone {}

dyn_clone::clone_trait_object!(ProtocolInformation);

/// A trait representing a TPKT connection. There is no distinction between a client and a server connection once they are established.
pub trait TpktConnection: Send {
    fn get_protocol_infomation_list(&self) -> &Vec<Box<dyn ProtocolInformation>>;

    /// Splits a connection into reader and writer components. This must be done before the connection is used.
    fn split(self) -> impl std::future::Future<Output = Result<(impl TpktReader, impl TpktWriter), TpktError>> + Send;
}

/// A trait representing the read half of TPKT connection.
pub trait TpktReader: Send {
    /// Reads from a TPKT connection. There are three outcomes.
    /// * Some(data) - Data was read from the socket.
    /// * None - The underlying TCP connection was closed normally.
    /// * TpktError - May indicate a TPKT packet was malformed, there was an IO error or some other internal failure occurred.
    /// 
    /// This operation is cancel safe.
    fn recv(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, TpktError>> + Send;
}

/// A trait representing the write half of TPKT connection.
pub trait TpktWriter: Send {
    /// Writes to a TPKT connection. This uses a VedDeque as a buffer. This is to ensure the operation is cancel safe so long as the buffer is not dropped while it has data.
    /// 
    /// This operation is cancel safe as long as the data in the input buffer is not dropped.
    /// The Veque is intended to be used as a FIFO buffer stored on the caller and reused.
    fn send(&mut self, input: &mut VecDeque<Vec<u8>>) -> impl std::future::Future<Output = Result<(), TpktError>> + Send;
}
