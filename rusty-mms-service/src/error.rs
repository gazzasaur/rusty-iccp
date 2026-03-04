use std::fmt::Debug;

use crate::api::MmsServiceError;

pub(crate) fn to_mms_error<T: Debug>(message: &str) -> impl FnOnce(T) -> MmsServiceError {
    move |error| MmsServiceError::ProtocolError(format!("{}: {:?}", message, error))
}
