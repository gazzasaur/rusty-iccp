use std::{collections::VecDeque, rc::Rc};

use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsConfirmedResponse, MmsError, MmsTypeDescription,
    error::to_mms_error,
    parsers::{process_constructed_data, process_mms_boolean_content},
};

pub(crate) fn parse_get_variable_access_attributes_response(payload: &Any<'_>) -> Result<MmsConfirmedResponse, MmsError> {
    let mut deletable = None;
    let mut type_description = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Get Variable Access Attributes PDU"))? {
        match item.header.raw_tag() {
            Some([128]) => {
                deletable = Some(process_mms_boolean_content(&item, "Get Variable Access Attributes Response PDU - Deletable Flag")?);
            }
            Some([162]) => {
                type_description = Some(MmsTypeDescription::parse("Get Variable Access Attributes Response PDU - Type Description", &item)?);
            }
            x => warn!("Unsupported tag in MMS Get Variable Access Attributes Response PDU: {:?}", x),
        }
    }

    let deletable = deletable.ok_or_else(|| MmsError::ProtocolError("No Deletable Flag on Get Variable Access Attributes Response PDU".into()))?;
    let type_description = type_description.ok_or_else(|| MmsError::ProtocolError("No Type Description on Get Variable Access Attributes Response PDU".into()))?;

    Ok(MmsConfirmedResponse::GetVariableAccessAttributes { deletable, type_description })
}

pub(crate) fn get_variable_access_attributes_response_to_ber<'a>(deletable: bool, type_description: &'a MmsTypeDescription) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(6), Length::Definite(0)),
        BerObjectContent::Sequence(vec![
            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)), BerObjectContent::Boolean(deletable)),
            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(2), Length::Definite(0)), BerObjectContent::Sequence(vec![type_description.to_ber()?])),
        ]),
    ))
}
