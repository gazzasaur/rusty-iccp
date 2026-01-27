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
        definenamedvariablelistrequest::{define_named_variable_list_reqeust_to_ber, parse_define_named_variable_list_reqeust},
        getnamelistrequest::{get_name_list_request_to_ber, parse_get_name_list_request},
        getvariableaccessattributesrequest::{get_variable_access_attributes_reqeust_to_ber, parse_get_variable_access_attributes_reqeust},
        identifyrequest::{identify_request_to_ber, parse_identify_request},
        readrequest::{parse_read_request, read_request_to_ber},
        writerequest::{parse_write_request, write_request_to_ber},
    },
};

pub(crate) fn parse_confirmed_request(payload: Any<'_>) -> Result<MmsMessage, MmsError> {
    let mut invocation_id = None;
    let mut confirmed_payload = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse Confirmed Request Payload"))? {
        match item.header.raw_tag() {
            Some(&[2]) => invocation_id = Some(item.data.to_vec()),
            Some(&[161]) => confirmed_payload = Some(parse_get_name_list_request(&item)?),
            Some(&[162]) => confirmed_payload = Some(parse_identify_request(&item)?),
            Some(&[164]) => confirmed_payload = Some(parse_read_request(&item)?),
            Some(&[165]) => confirmed_payload = Some(parse_write_request(&item)?),
            Some(&[166]) => confirmed_payload = Some(parse_get_variable_access_attributes_reqeust(&item)?),
            Some(&[171]) => confirmed_payload = Some(parse_define_named_variable_list_reqeust(&item)?),
            // TODO Moar!!!
            x => warn!("Failed to parse unknown MMS Confirmed Request Item: {:?}", x),
        }
    }

    Ok(MmsMessage::ConfirmedRequest {
        invocation_id: invocation_id.ok_or_else(|| MmsError::ProtocolError("No invocation id on confirmed request".into()))?,
        request: confirmed_payload.ok_or_else(|| MmsError::ProtocolError("No payload on confired request".into()))?,
    })
}

pub(crate) fn confirmed_request_to_ber<'a>(invocation_id: &'a [u8], payload: &'a MmsConfirmedRequest) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
        BerObjectContent::Sequence(vec![
            BerObject::from(BerObjectContent::Integer(invocation_id)),
            match payload {
                MmsConfirmedRequest::GetNameList { object_class, object_scope, continue_after } => get_name_list_request_to_ber(object_class, object_scope, continue_after)?,
                MmsConfirmedRequest::Identify => identify_request_to_ber(),
                MmsConfirmedRequest::Read {
                    specification_with_result,
                    variable_access_specification,
                } => read_request_to_ber(specification_with_result, variable_access_specification),
                MmsConfirmedRequest::Write { variable_access_specification, list_of_data } => write_request_to_ber(variable_access_specification, list_of_data)?,
                MmsConfirmedRequest::GetVariableAccessAttributes { object_name } => get_variable_access_attributes_reqeust_to_ber(object_name)?,
                MmsConfirmedRequest::DefineNamedVariableList { variable_list_name, list_of_variables } => define_named_variable_list_reqeust_to_ber(variable_list_name, list_of_variables)?,
            },
        ]),
    ))
}
