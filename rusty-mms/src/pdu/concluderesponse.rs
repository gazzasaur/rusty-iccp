use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};

use crate::{MmsConcludeResponse, MmsError, MmsMessage};

pub(crate) fn parse_conclude_response(_: &Any<'_>) -> Result<MmsMessage, MmsError> {
    Ok(MmsMessage::ConcludeResponse { request: MmsConcludeResponse {} })
}

pub(crate) fn conclude_response_to_ber<'a>() -> BerObject<'a> {
    BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(12), Length::Definite(0)), BerObjectContent::Null)
}
