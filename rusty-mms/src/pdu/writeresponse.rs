use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsConfirmedResponse, MmsError, MmsWriteResult,
    error::to_mms_error,
    parsers::{mms_access_error_to_ber, process_constructed_data, process_mms_access_error},
};

pub(crate) fn parse_write_response(payload: &Any<'_>) -> Result<MmsConfirmedResponse, MmsError> {
    let mut write_results = Vec::new();

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Write Response PDU"))? {
        match item.header.raw_tag() {
            Some([129]) => write_results.push(MmsWriteResult::Success),
            Some([128]) => {
                let error = process_mms_access_error(&item, "Failed to parse MMS Write Response PDU Write Result")?;
                write_results.push(MmsWriteResult::Failure(error));
            }
            x => warn!("Unsupported tag in MMS Write Response PDU Write Result: {:?}", x),
        }
    }

    Ok(MmsConfirmedResponse::Write { write_results })
}

pub(crate) fn write_response_to_ber<'a>(write_results: &'a Vec<MmsWriteResult>) -> Result<BerObject<'a>, MmsError> {
    let mut write_results_ber = vec![];
    for write_result in write_results {
        match write_result {
            MmsWriteResult::Success => write_results_ber.push(BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(1), Length::Definite(0)), BerObjectContent::Null)),
            MmsWriteResult::Failure(error) => {
                write_results_ber.push(mms_access_error_to_ber(error));
            }
        }
    }

    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(5), Length::Definite(0)),
        BerObjectContent::Sequence(write_results_ber),
    ))
}
