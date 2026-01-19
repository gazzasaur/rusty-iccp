use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{MmsUnconfirmedService, pdu::{identifyresponse::{identify_response_to_ber, parse_identify_response}, informationreport::{information_report_to_ber, parse_information_report}, writeresponse::{parse_write_response, write_response_to_ber}}};
use crate::{
    MmsError, MmsMessage,
    error::to_mms_error,
    parsers::process_constructed_data,
};

pub(crate) fn parse_unconfirmed(payload: Any<'_>) -> Result<MmsMessage, MmsError> {
    let mut unconfirmed_payload = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse Confirmed Response Payload"))? {
        match item.header.raw_tag() {
            Some(&[160]) => unconfirmed_payload = Some(parse_information_report(&item)?),
            x => warn!("Failed to parse unknown MMS Unconfirmed Item: {:?}", x),
        }
    }

    Ok(MmsMessage::Unconfirmed {
        unconfirmed_service: unconfirmed_payload.ok_or_else(|| MmsError::ProtocolError("No payload on confirmed response".into()))?,
    })
}

pub(crate) fn unconfirmed_to_ber<'a>(payload: &'a MmsUnconfirmedService) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(3), Length::Definite(0)),
        BerObjectContent::Sequence(vec![
            match payload {
                MmsUnconfirmedService::InformationReport {
                    variable_access_specification,
                    access_results,
                } => information_report_to_ber(variable_access_specification, access_results)?,
            },
        ]),
    ))
}
