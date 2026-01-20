use der_parser::{
    asn1_rs::{Any, ToDer},
    ber::{BerObject, BerObjectContent, Length, parse_ber_any, parse_ber_content},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsConfirmedRequest, MmsData, MmsError, MmsObjectClass, MmsObjectScope, MmsVariableAccessSpecification,
    error::to_mms_error,
    parsers::{process_constructed_data, process_mms_boolean_content, process_mms_string},
};

pub(crate) fn parse_get_name_list_request(payload: &Any<'_>) -> Result<MmsConfirmedRequest, MmsError> {
    let mut object_class = None;
    let mut object_scope = None;
    let mut continue_after = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Get Name List Request PDU"))? {
        match item.header.raw_tag() {
            Some([160]) => {
                object_class = Some(MmsObjectClass::parse("Get Name List Request PDU - Object Class", &item)?);
            }
            Some([161]) => {
                let scope_items = process_constructed_data(item.data).map_err(to_mms_error("Failed to parse Object Scope in Get Name List Request PDU"))?;
                if let Some(scope_item) = scope_items.first() {
                    object_scope = Some(MmsObjectScope::parse(&scope_item)?);
                }
            }
            Some([162]) => {
                let (_, target) = parse_ber_any(item.data).map_err(to_mms_error("Failed to parse Continue After in Get Name List Request PDU"))?;
                continue_after = Some(process_mms_string(&target, "Failed to parse Continue After in Get Name List Request PDU")?);
            }
            x => warn!("Unsupported tag in MMS Get Name List Request PDU: {:?}", x),
        }
    }

    let object_class = object_class.ok_or_else(|| MmsError::ProtocolError("No Object Class on Get Name List Request PDU".into()))?;
    let object_scope = object_scope.ok_or_else(|| MmsError::ProtocolError("No Object Scope on Get Name List Request PDU".into()))?;

    Ok(MmsConfirmedRequest::GetNameList { object_class, object_scope, continue_after })
}

pub(crate) fn get_name_list_request_to_ber<'a>(object_class: &'a MmsObjectClass, object_scope: &'a MmsObjectScope, continue_after: &'a Option<String>) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
        BerObjectContent::Sequence(
            vec![
                Some(BerObject::from_header_and_content(
                    Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
                    BerObjectContent::Sequence(vec![object_class.to_ber()]),
                )),
                Some(BerObject::from_header_and_content(
                    Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
                    BerObjectContent::Sequence(vec![object_scope.to_ber()]),
                )),
                continue_after
                    .iter()
                    .map(|x| {
                        BerObject::from_header_and_content(
                            Header::new(Class::ContextSpecific, true, Tag::from(2), Length::Definite(0)),
                            BerObjectContent::Sequence(vec![BerObject::from(BerObjectContent::VisibleString(x))]),
                        )
                    })
                    .last(),
            ]
            .into_iter()
            .filter_map(|i| i)
            .collect(),
        ),
    ))
}
