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
