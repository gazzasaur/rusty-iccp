use std::fmt::Debug;

use rusty_mms::MmsError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IccpError {
    #[error("ICCP Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("ICCP Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] MmsError),

    #[error("ICCP IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("ICCP Error: {}", .0)]
    InternalError(String),
}

pub(crate) fn to_iccp_error<T: Debug>(message: &str) -> impl FnOnce(T) -> IccpError {
    move |error| IccpError::ProtocolError(format!("{}: {:?}", message, error))
}
