use der_parser::{
    asn1_rs::{Any, ToDer},
    ber::{BerObject, BerObjectContent, Length, parse_ber_any},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{ListOfVariablesItem, MmsConfirmedRequest, MmsConfirmedResponse, MmsError, MmsObjectName, VariableSpecification, error::to_mms_error, parsers::process_constructed_data};

pub(crate) fn parse_define_named_variable_list_response(payload: &Any<'_>) -> Result<MmsConfirmedResponse, MmsError> {
    // This is a Null payload. We'll be super loose and just not bother parsing anything out of it.
    Ok(MmsConfirmedResponse::DefineNamedVariableList)
}

pub(crate) fn define_named_variable_list_response_to_ber<'a>() -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(11), Length::Definite(0)), BerObjectContent::Null))
}
