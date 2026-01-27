use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};

use crate::{MmsConfirmedRequest, MmsError, MmsObjectName};

pub(crate) fn parse_get_named_variable_list_attributes_reqeust(payload: &Any<'_>) -> Result<MmsConfirmedRequest, MmsError> {
    let object_name = MmsObjectName::parse("MMS GetNamedVariableListAttributes", payload.data)?;
    Ok(MmsConfirmedRequest::GetNamedVariableListAttributes { object_name })
}

pub(crate) fn get_named_variable_list_attributes_reqeust_to_ber<'a>(object_name: &'a MmsObjectName) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(12), Length::Definite(0)),
        BerObjectContent::Sequence(vec![object_name.to_ber()]),
    ))
}
