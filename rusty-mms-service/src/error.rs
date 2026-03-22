use std::fmt::Debug;

use rusty_mms::MmsError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MmsServiceError {
    #[error("MMS Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("MMS Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] MmsError),

    #[error("MMS IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("MMS Error: {}", .0)]
    InternalError(String),
}

pub(crate) fn to_mms_error<T: Debug>(message: &str) -> impl FnOnce(T) -> MmsServiceError {
    move |error| MmsServiceError::ProtocolError(format!("{}: {:?}", message, error))
}
