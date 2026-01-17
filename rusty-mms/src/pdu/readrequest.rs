use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsConfirmedRequest, MmsError, MmsVariableAccessSpecification,
    error::to_mms_error,
    parsers::{process_constructed_data, process_mms_boolean_content},
};

pub(crate) fn parse_read_request(payload: &Any<'_>) -> Result<MmsConfirmedRequest, MmsError> {
    let mut specification_with_result = None;
    let mut variable_access_specification = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Request PDU"))? {
        match item.header.raw_tag() {
            Some([80]) => specification_with_result = Some(process_mms_boolean_content(&item, "Failed to parse Specification With Result parameter on MMS Request PDU")?),
            Some([161]) => variable_access_specification = Some(MmsVariableAccessSpecification::parse("Read Request PDU", item.data)?),
            x => warn!("Unsupported tag in MMS Read Request PDU: {:?}", x),
        }
    }

    let variable_access_specification = variable_access_specification.ok_or_else(|| MmsError::ProtocolError("No Variable Access Specification on Request PDU".into()))?;
    Ok(MmsConfirmedRequest::Read {
        specification_with_result,
        variable_access_specification,
    })
}

pub(crate) fn read_request_to_ber<'a>(specification_with_result: &Option<bool>, variable_access_specification: &'a MmsVariableAccessSpecification) -> BerObject<'a> {
    BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(4), Length::Definite(0)),
        BerObjectContent::Sequence(
            vec![
                match specification_with_result {
                    Some(specification_with_result) => Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)),
                        BerObjectContent::Boolean(*specification_with_result),
                    )),
                    None => None,
                },
                Some(BerObject::from_header_and_content(
                    Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
                    BerObjectContent::Sequence(vec![variable_access_specification.to_ber()]),
                )),
            ]
            .into_iter()
            .filter_map(|i| i)
            .collect(),
        ),
    )
}
