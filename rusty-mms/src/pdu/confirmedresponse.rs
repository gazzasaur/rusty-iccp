use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::pdu::{
    identifyresponse::{identify_response_to_ber, parse_identify_response},
    writeresponse::{parse_write_response, write_response_to_ber},
};
use crate::{
    MmsConfirmedResponse, MmsError, MmsMessage,
    error::to_mms_error,
    parsers::process_constructed_data,
    pdu::readresponse::{parse_read_response, read_response_to_ber},
};

pub(crate) fn parse_confirmed_response(payload: Any<'_>) -> Result<MmsMessage, MmsError> {
    let mut invocation_id = None;
    let mut confirmed_payload = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse Confirmed Response Payload"))? {
        match item.header.raw_tag() {
            Some(&[2]) => invocation_id = Some(item.data.to_vec()),
            Some(&[162]) => confirmed_payload = Some(parse_identify_response(&item)?),
            Some(&[164]) => confirmed_payload = Some(parse_read_response(&item)?),
            Some(&[165]) => confirmed_payload = Some(parse_write_response(&item)?),
            // TODO Moar!!!
            x => warn!("Failed to parse unknown MMS Confirmed Response Item: {:?}", x),
        }
    }

    Ok(MmsMessage::ConfirmedResponse {
        invocation_id: invocation_id.ok_or_else(|| MmsError::ProtocolError("No invocation id on confirmed response".into()))?,
        response: confirmed_payload.ok_or_else(|| MmsError::ProtocolError("No payload on confirmed response".into()))?,
    })
}

pub(crate) fn confirmed_response_to_ber<'a>(invocation_id: &'a [u8], payload: &'a MmsConfirmedResponse) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
        BerObjectContent::Sequence(vec![
            BerObject::from(BerObjectContent::Integer(invocation_id)),
            match payload {
                MmsConfirmedResponse::Identify {
                    vendor_name,
                    model_name,
                    revision,
                    abstract_syntaxes,
                } => identify_response_to_ber(vendor_name, model_name, revision, abstract_syntaxes),
                MmsConfirmedResponse::Read {
                    variable_access_specification,
                    access_results,
                } => read_response_to_ber(variable_access_specification, access_results)?,
                MmsConfirmedResponse::Write { write_results } => write_response_to_ber(write_results)?,
            },
        ]),
    ))
}
