use std::os::unix::process;

use der_parser::{
    asn1_rs::{Any, ToDer},
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsAccessResult, MmsConfirmedResponse, MmsError, MmsUnconfirmedService, MmsVariableAccessSpecification, MmsWriteResult, error::to_mms_error, parsers::{mms_access_error_to_ber, process_constructed_data, process_mms_access_error}
};

pub(crate) fn parse_information_report(payload: &Any<'_>) -> Result<MmsUnconfirmedService, MmsError> {
    let mut list_of_access_result = Vec::new();
    let mut variable_access_specification = None;

    // Order matters here
    let items = process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Write Request PDU"))?;
    if items.len() < 2 {
        return Err(MmsError::ProtocolError("Not enough items in Information Report PDU".into()));
    }

    match items[0].header.raw_tag() {
        Some([160]) => {
            variable_access_specification = Some(MmsVariableAccessSpecification::parse(
                "Information Report PDU",
                items[0].to_der_vec().map_err(to_mms_error("Failed to parse Information Report"))?.as_slice(),
            )?)
        }
        x => warn!("Unsupported tag in MMS Information Report PDU: {:?}", x),
    }
    for data in process_constructed_data(items[1].data).map_err(to_mms_error("Failed to parse list of data in Information Report PDU"))? {
        list_of_access_result.push(MmsAccessResult::parse("Information Report PDU - Access Results", &data)?);
    }

    let variable_access_specification = variable_access_specification.ok_or_else(|| MmsError::ProtocolError("No Variable Access Specification on Request PDU".into()))?;
    Ok(MmsUnconfirmedService::InformationReport {
        variable_access_specification,
        access_results: list_of_access_result,
    })
}

pub(crate) fn information_report_to_ber<'a>(variable_access_specification: &'a MmsVariableAccessSpecification, access_results: &'a Vec<MmsAccessResult>) -> Result<BerObject<'a>, MmsError> {
    let mut results_ber = vec![];
    for access_result in access_results {
        results_ber.push(access_result.to_ber()?);
    }

    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
        BerObjectContent::Sequence(vec![
            variable_access_specification.to_ber(),
            BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
                BerObjectContent::Sequence(results_ber),
            ),
        ]),
    ))
}
