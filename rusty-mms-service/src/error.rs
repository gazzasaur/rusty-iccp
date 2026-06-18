use std::fmt::Debug;

use rusty_mms::MmsError;
use rusty_tpkt::TpktError;
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

impl From<TpktError> for MmsServiceError {
    fn from(e: TpktError) -> Self {
        match e {
            TpktError::ProtocolError(x) => MmsServiceError::ProtocolError(x),
            TpktError::IoError(error) => MmsServiceError::IoError(error),
            TpktError::InternalError(_) => MmsServiceError::InternalError(e.to_string()),
        }
    }
}

pub(crate) fn to_mms_error<T: Debug>(message: &str) -> impl FnOnce(T) -> MmsServiceError {
    move |error| MmsServiceError::ProtocolError(format!("{}: {:?}", message, error))
}
