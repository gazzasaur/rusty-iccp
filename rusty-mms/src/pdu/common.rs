use crate::MmsError;


pub(crate) fn expect_value<T>(pdu: &str, field: &str, value: Option<T>) -> Result<T, MmsError> {
    value.ok_or_else(|| MmsError::ProtocolError(format!("MMS Payload '{}' must container the field '{}' but was not found.", pdu, field)))
}
