use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};

use crate::{MmsConfirmedRequest, MmsError};

pub(crate) fn parse_identify_request(_: &Any<'_>) -> Result<MmsConfirmedRequest, MmsError> {
    Ok(MmsConfirmedRequest::Identify)
}

pub(crate) fn identify_request_to_ber<'a>() -> BerObject<'a> {
    BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(2), Length::Definite(0)), BerObjectContent::Null)
}
