use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};

use crate::{MmsConcludeRequest, MmsConfirmedRequest, MmsError};

pub(crate) fn parse_conclude_request(_: &Any<'_>) -> Result<MmsConcludeRequest, MmsError> {
    Ok(MmsConcludeRequest)
}

pub(crate) fn conclude_request_to_ber<'a>() -> BerObject<'a> {
    BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(11), Length::Definite(0)), BerObjectContent::Null)
}
