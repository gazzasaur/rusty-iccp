use der_parser::{asn1_rs::Any, ber::{BerObjectContent, parse_ber_any, parse_ber_content}, der::Tag, error::BerError};
use tokio::io::AsyncReadExt;

use crate::{MmsError, error::to_mms_error};

pub(crate) fn process_constructed_data<'a>(data: &'a [u8]) -> Result<Vec<Any<'a>>, BerError> {
    let mut remaining = data;
    let mut results = vec![];

    while remaining.len() > 0 {
        let (rem, obj) = parse_ber_any(remaining)?;
        results.push(obj);
        remaining = rem;
    }
    Ok(results)
}

pub(crate) fn process_integer_content<'a>(npm_object: Any<'a>, error_message: &str) -> Result<Vec<u8>, MmsError> {
    let (_, inner_object) = parse_ber_content(Tag::Integer)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_mms_error(error_message))?;

    match inner_object {
        BerObjectContent::Integer(value) => Ok(value.to_vec()),
        _ => Err(MmsError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_mms_integer_content<'a>(npm_object: Any<'a>, error_message: &str) -> Result<i32, MmsError> {
    let int_value = process_integer_content(npm_object, error_message)?;
    if int_value.len() > 4 {
        return Err(MmsError::ProtocolError(format!("{}: {}", error_message, "Exceeded Integer32 range")));
    }
    return Ok(i32::from_be_bytes(int_value.into()));
}
