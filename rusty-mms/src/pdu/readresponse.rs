use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsAccessResult, MmsConfirmedResponse, MmsError, MmsVariableAccessSpecification,
    error::to_mms_error,
    parsers::process_constructed_data,
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
