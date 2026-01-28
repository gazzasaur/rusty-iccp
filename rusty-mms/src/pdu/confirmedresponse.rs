use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::pdu::{
    definenamedvariablelistresponse::{define_named_variable_list_response_to_ber, parse_define_named_variable_list_response}, deletenamedvariablelistresponse::{delete_named_variable_list_response_to_ber, parse_delete_named_variable_list_response}, getnamedvariablelistattributesresponse::{get_named_variable_list_attributes_response_to_ber, parse_get_named_variable_list_attributes_response}, getnamelistresponse::{get_name_list_response_to_ber, parse_get_name_list_response}, getvariableaccessattributesresponse::{get_variable_access_attributes_response_to_ber, parse_get_variable_access_attributes_response}, identifyresponse::{identify_response_to_ber, parse_identify_response}, writeresponse::{parse_write_response, write_response_to_ber}
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
            Some(&[161]) => confirmed_payload = Some(parse_get_name_list_response(&item)?),
            Some(&[162]) => confirmed_payload = Some(parse_identify_response(&item)?),
            Some(&[164]) => confirmed_payload = Some(parse_read_response(&item)?),
            Some(&[165]) => confirmed_payload = Some(parse_write_response(&item)?),
            Some(&[166]) => confirmed_payload = Some(parse_get_variable_access_attributes_response(&item)?),
            Some(&[139]) => confirmed_payload = Some(parse_define_named_variable_list_response(&item)?),
            Some(&[172]) => confirmed_payload = Some(parse_get_named_variable_list_attributes_response(&item)?),
            Some(&[173]) => confirmed_payload = Some(parse_delete_named_variable_list_response(&item)?),
            // TODO Send an error if the message is not known
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
                MmsConfirmedResponse::GetNameList { list_of_identifiers, more_follows } => get_name_list_response_to_ber(list_of_identifiers, more_follows)?,
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
                MmsConfirmedResponse::GetVariableAccessAttributes { deletable, type_description } => get_variable_access_attributes_response_to_ber(*deletable, type_description)?,
                MmsConfirmedResponse::DefineNamedVariableList => define_named_variable_list_response_to_ber()?,
                MmsConfirmedResponse::GetNamedVariableListAttributes { deletable, list_of_variables } => get_named_variable_list_attributes_response_to_ber(*deletable, list_of_variables)?,
                MmsConfirmedResponse::DeleteNamedVariableList { number_matched, number_deleted } => delete_named_variable_list_response_to_ber(number_matched, number_deleted)?,
            },
        ]),
    ))
}
