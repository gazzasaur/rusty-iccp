use crate::{message::ConnectPresentation, CoppError};

pub(crate) fn serialise_connect(message: ConnectPresentation) -> Result<Vec<u8>, CoppError> {
    let message_container = der_parser::ber::BerObject::from_set(vec![]);
    Ok(message_container.to_vec().map_err(|e| CoppError::InternalError(e.to_string()))?)
}