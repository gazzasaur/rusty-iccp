use std::error::Error;

use crate::CoppError;

pub(crate) fn protocol_error(message: &'static str, e: impl Error) -> CoppError {
    CoppError::ProtocolError(format!("{}: {}", message, e.to_string()))
}
