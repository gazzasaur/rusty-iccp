use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsAccessResult, MmsConfirmedResponse, MmsError, MmsVariableAccessSpecification,
    error::to_mms_error,
    parsers::{process_constructed_data, process_mms_boolean_content},
};

pub(crate) fn parse_read_response(payload: &Any<'_>) -> Result<MmsConfirmedResponse, MmsError> {
    let mut variable_access_specification = None;
    let mut access_results = Vec::new();

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Response PDU"))? {
        match item.header.raw_tag() {
            Some([160]) => variable_access_specification = Some(MmsVariableAccessSpecification::parse("Read Response PDU", item.data)?),
            Some([161]) => {
                for item in process_constructed_data(item.data).map_err(to_mms_error("Failed to parse acess result list"))? {
                    access_results.push(MmsAccessResult::parse("Read Response PDU - Access Result", &item)?);
                }
            }
            x => warn!("Unsupported tag in MMS Read Response PDU: {:?}", x),
        }
    }

    Ok(MmsConfirmedResponse::Read {
        variable_access_specification,
        access_results,
    })
}

pub(crate) fn read_response_to_ber<'a>(variable_access_specification: &'a Option<MmsVariableAccessSpecification>, access_results: &'a Vec<MmsAccessResult>) -> Result<BerObject<'a>, MmsError> {
    let mut access_results_ber = vec![];
    for access_result in access_results {
        access_results_ber.push(access_result.to_ber()?);
    }

    let mut variable_access_specification_ber = None;
    if let Some(variable_access_specification) = variable_access_specification {
        variable_access_specification_ber = Some(BerObject::from_header_and_content(
            Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
            BerObjectContent::Sequence(vec![variable_access_specification.to_ber()]),
        ));
    }

    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(4), Length::Definite(0)),
        BerObjectContent::Sequence(
            vec![
                variable_access_specification_ber,
                Some(BerObject::from_header_and_content(
                    Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
                    BerObjectContent::Sequence(access_results_ber),
                )),
            ]
            .into_iter()
            .filter_map(|i| i)
            .collect(),
        ),
    ))
}

#[derive(Debug)]
pub(crate) struct ReadRequestPdu {
    pub(crate) specification_with_result: Option<bool>,
    pub(crate) variable_access_specification: MmsVariableAccessSpecification,
}

impl ReadRequestPdu {
    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        BerObject::from_header_and_content(
            Header::new(Class::ContextSpecific, true, Tag::from(4), Length::Definite(0)),
            BerObjectContent::Sequence(
                vec![
                    match &self.specification_with_result {
                        Some(specification_with_result) => Some(BerObject::from_header_and_content(
                            Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)),
                            BerObjectContent::Boolean(*specification_with_result),
                        )),
                        None => None,
                    },
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
                        BerObjectContent::Sequence(vec![self.variable_access_specification.to_ber()]),
                    )),
                ]
                .into_iter()
                .filter_map(|i| i)
                .collect(),
            ),
        )
    }

    pub(crate) fn parse(pdu: &Any<'_>) -> Result<ReadRequestPdu, MmsError> {
        let mut specification_with_result = None;
        let mut variable_access_specification = None;

        match pdu.header.raw_tag() {
            Some(&[164]) => {
                for item in process_constructed_data(pdu.data).map_err(to_mms_error("Failed to parse MMS Request PDU"))? {
                    match item.header.raw_tag() {
                        Some([80]) => specification_with_result = Some(process_mms_boolean_content(&item, "Failed to parse Specification With Result parameter on MMS Request PDU")?),
                        Some([161]) => variable_access_specification = Some(MmsVariableAccessSpecification::parse("Read Request PDU", item.data)?),
                        x => return Err(MmsError::ProtocolError(format!("Unsupported tag in MMS Read Request PDU: {:?}", x))),
                    }
                }
            }
            x => return Err(MmsError::ProtocolError(format!("Expected MMS Read Request PDU to have a tag of 164 a but {:?} was found", x))),
        };

        let variable_access_specification = variable_access_specification.ok_or_else(|| MmsError::ProtocolError("No Variable Access Specification on Request PDU".into()))?;
        Ok(ReadRequestPdu {
            specification_with_result,
            variable_access_specification,
        })
    }
}
