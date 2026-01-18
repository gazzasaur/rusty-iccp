use std::os::unix::process;

use der_parser::{
    asn1_rs::{Any, ToDer},
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsConfirmedRequest, MmsData, MmsError, MmsVariableAccessSpecification,
    error::to_mms_error,
    parsers::{process_constructed_data, process_mms_boolean_content},
};

pub(crate) fn parse_write_request(payload: &Any<'_>) -> Result<MmsConfirmedRequest, MmsError> {
    let mut list_of_data = Vec::new();
    let mut variable_access_specification = None;

    // Order matters here
    let items = process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Write Request PDU"))?;
    if items.len() < 2 {
        return Err(MmsError::ProtocolError("Not enough items in Read Response PDU".into()));
    }

    match items[0].header.raw_tag() {
        Some([160]) => {
            variable_access_specification = Some(MmsVariableAccessSpecification::parse(
                "Read Response PDU",
                items[0].to_der_vec().map_err(to_mms_error("Failed to parse WriteRequest"))?.as_slice(),
            )?)
        }
        x => warn!("Unsupported tag in MMS Write Request PDU: {:?}", x),
    }
    for data in process_constructed_data(items[1].data).map_err(to_mms_error("Failed to parse list of data in Write Request PDU"))? {
        list_of_data.push(MmsData::parse("Write Request PDU - List of Data", &data)?);
    }

    let variable_access_specification = variable_access_specification.ok_or_else(|| MmsError::ProtocolError("No Variable Access Specification on Request PDU".into()))?;
    Ok(MmsConfirmedRequest::Write {
        variable_access_specification,
        list_of_data,
    })
}

pub(crate) fn write_request_to_ber<'a>(variable_access_specification: &'a MmsVariableAccessSpecification, list_of_data: &'a Vec<MmsData>) -> Result<BerObject<'a>, MmsError> {
    let mut list_of_data_ber = vec![];
    for data in list_of_data {
        list_of_data_ber.push(data.serialise(true, true)?);
    }

    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(5), Length::Definite(0)),
        BerObjectContent::Sequence(
            vec![
                Some(variable_access_specification.to_ber()),
                Some(BerObject::from_header_and_content(
                    Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
                    BerObjectContent::Sequence(list_of_data_ber),
                )),
            ]
            .into_iter()
            .filter_map(|i| i)
            .collect(),
        ),
    ))
}
