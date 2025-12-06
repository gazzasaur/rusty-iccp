use std::fmt::Debug;

use crate::MmsError;

pub(crate) fn to_mms_error<T: Debug>(message: &str) -> impl FnOnce(T) -> MmsError {
    move |error| MmsError::ProtocolError(format!("{}: {:?}", message, error))
}
