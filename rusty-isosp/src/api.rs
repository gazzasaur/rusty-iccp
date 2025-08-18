use thiserror::Error;
use rusty_cotp::api::CotpError;

 #[derive(Error, Debug)]
pub enum IsoSpError {
    #[error("Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] CotpError),

    #[error("IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("Error: {}", .0)]
    InternalError(String),
}
