use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{MmsConfirmedRequest, MmsError, MmsObjectName, error::to_mms_error, parsers::process_constructed_data};

pub(crate) fn parse_get_variable_access_attributes_reqeust(payload: &Any<'_>) -> Result<MmsConfirmedRequest, MmsError> {
    let mut object_name = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Get VariableAccess Attributes PDU"))? {
        match item.header.raw_tag() {
            Some([160]) => {
                object_name = Some(MmsObjectName::parse("Get VariableAccess Attributes Request PDU - Object Class", &item.data)?);
            }
            x => warn!("Unsupported tag in MMS Get VariableAccess Attributes Request PDU: {:?}", x),
        }
    }

    let object_name = object_name.ok_or_else(|| MmsError::ProtocolError("No Object Name on Get VariableAccess Attributes Request PDU".into()))?;

    Ok(MmsConfirmedRequest::GetVariableAccessAttributes { object_name })
}

pub(crate) fn get_variable_access_attributes_reqeust_to_ber<'a>(object_name: &'a MmsObjectName) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(6), Length::Definite(0)),
        BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
            Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
            BerObjectContent::Sequence(vec![object_name.to_ber()]),
        )]),
    ))
}
