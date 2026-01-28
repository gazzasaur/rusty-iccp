use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsConfirmedResponse, MmsError, error::to_mms_error,
    parsers::{process_constructed_data, process_integer_content},
    pdu::common::expect_value,
};

pub(crate) fn parse_delete_named_variable_list_response(payload: &Any<'_>) -> Result<MmsConfirmedResponse, MmsError> {
    let mut number_matched = None;
    let mut number_deleted = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse DeleteNamedVariableList"))? {
        match item.header.raw_tag() {
            Some([128]) => number_matched = Some(process_integer_content(&item, "Failed to parse Number Matched on DeleteNamedVariableList PDU")?),
            Some([129]) => number_deleted = Some(process_integer_content(&item, "Failed to parse Number Matched on DeleteNamedVariableList PDU")?),
            x => warn!("Unknown item on DeleteNamedVariableList: {:?}", x),
        }
    }

    let number_matched = expect_value("DeleteNamedVariableList", "NumberMatched", number_matched)?;
    let number_deleted = expect_value("DeleteNamedVariableList", "NumberDeleted", number_deleted)?;

    Ok(MmsConfirmedResponse::DeleteNamedVariableList { number_matched, number_deleted })
}

pub(crate) fn delete_named_variable_list_response_to_ber<'a>(number_matched: &'a Vec<u8>, number_deleted: &'a Vec<u8>) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(13), Length::Definite(0)),
        BerObjectContent::Sequence(vec![
            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)), BerObjectContent::Integer(number_matched)),
            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(1), Length::Definite(0)), BerObjectContent::Integer(number_deleted)),
        ]),
    ))
}
