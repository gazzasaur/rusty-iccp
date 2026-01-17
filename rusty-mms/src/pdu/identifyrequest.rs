use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};

use crate::{
    MmsConfirmedRequest, MmsError, MmsVariableAccessSpecification,
    error::to_mms_error,
    parsers::{process_constructed_data, process_mms_boolean_content},
};

pub(crate) fn parse_identify_request(payload: &Any<'_>) -> Result<MmsConfirmedRequest, MmsError> {
    Ok(MmsConfirmedRequest::Identify)
}

pub(crate) fn identify_request_to_ber<'a>() -> BerObject<'a> {
    BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(2), Length::Definite(0)), BerObjectContent::Null)
}
