use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};

use crate::{MmsConcludeRequest, MmsError, MmsMessage};

pub(crate) fn parse_conclude_request(_: &Any<'_>) -> Result<MmsMessage, MmsError> {
    Ok(MmsMessage::ConcludeRequest { request: MmsConcludeRequest {} })
}

pub(crate) fn conclude_request_to_ber<'a>() -> BerObject<'a> {
    BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(11), Length::Definite(0)), BerObjectContent::Null)
}
