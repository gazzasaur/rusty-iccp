use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsConfirmedRequest, MmsError, MmsMessage,
    error::to_mms_error,
    parsers::process_constructed_data,
    pdu::{
        identifyrequest::{identify_request_to_ber, parse_identify_request},
        readrequest::{parse_read_request, read_request_to_ber},
    },
};

pub(crate) fn parse_confirmed_request(payload: Any<'_>) -> Result<MmsMessage, MmsError> {
    let mut invocation_id = None;
    let mut confirmed_payload = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse Confirmed Request Payload"))? {
        match item.header.raw_tag() {
            Some(&[2]) => invocation_id = Some(item.data.to_vec()),
            Some(&[162]) => confirmed_payload = Some(parse_identify_request(&item)?),
            Some(&[164]) => confirmed_payload = Some(parse_read_request(&item)?),
            // TODO Moar!!!
            x => warn!("Failed to parse unknown MMS Confirmed Request Item: {:?}", x),
        }
    }

    Ok(MmsMessage::ConfirmedRequest {
        invocation_id: invocation_id.ok_or_else(|| MmsError::ProtocolError("No invocation id on confirmed request".into()))?,
        request: confirmed_payload.ok_or_else(|| MmsError::ProtocolError("No payload on confired request".into()))?,
    })
}

pub(crate) fn confirmed_request_to_ber<'a>(invocation_id: &'a [u8], payload: &'a MmsConfirmedRequest) -> BerObject<'a> {
    BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
        BerObjectContent::Sequence(vec![
            BerObject::from(BerObjectContent::Integer(invocation_id)),
            match payload {
                MmsConfirmedRequest::Identify => identify_request_to_ber(),
                MmsConfirmedRequest::Read {
                    specification_with_result,
                    variable_access_specification,
                } => read_request_to_ber(specification_with_result, variable_access_specification),
            },
        ]),
    )
}
