use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};

use crate::{MmsConfirmedResponse, MmsError};

pub(crate) fn parse_define_named_variable_list_response(_: &Any<'_>) -> Result<MmsConfirmedResponse, MmsError> {
    // This is a Null payload. We'll be super loose and just not bother parsing anything out of it.
    Ok(MmsConfirmedResponse::DefineNamedVariableList)
}

pub(crate) fn define_named_variable_list_response_to_ber<'a>() -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(11), Length::Definite(0)), BerObjectContent::Null))
}
