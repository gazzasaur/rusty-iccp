use std::fmt::Debug;

use der_parser::{
    Oid,
    asn1_rs::Any,
    ber::{BerObjectContent, BitStringObject, parse_ber_any},
    der::Tag,
    error::BerError,
    parse_ber,
};
use rusty_copp::UserData;
use tracing::warn;

use crate::{AcseError, AcseRequestInformation, AeQualifier, ApTitle};

pub(crate) fn to_acse_error<T: Debug>(message: &str) -> impl FnOnce(T) -> AcseError {
    move |error| AcseError::ProtocolError(format!("{}: {:?}", message, error))
}

pub(crate) fn process_request(data: Vec<u8>) -> Result<(AcseRequestInformation, Option<UserData>), AcseError> {
    let mut version = BitStringObject { data: &[0x80] }; // Default protocol version 1
    let mut application_context_name = None;
    let mut called_ap_title = None;
    let mut called_ae_qualifier = None;
    let mut called_ap_invocation_identifier = None;
    let mut called_ae_invocation_identifier = None;
    let mut calling_ap_title = None;
    let mut calling_ae_qualifier = None;
    let mut calling_ap_invocation_identifier = None;
    let mut calling_ae_invocation_identifier = None;
    let mut implementation_information = None;
    let mut user_data = None;

    let (_, pdu) = parse_ber_any(&data).map_err(to_acse_error("Failed to parse ACSE Request"))?;
    pdu.header.assert_class(der_parser::der::Class::Application).map_err(to_acse_error("Expected ACSE Request was not found"))?;
    pdu.header.assert_tag(Tag::from(0)).map_err(to_acse_error("Expected ACSE Request was not found"))?;
    pdu.header.assert_constructed().map_err(to_acse_error("Expected ACSE Request was not found"))?;
    let pdu_parts = process_constructed_data(pdu.data).map_err(to_acse_error("Could not deconstruct ACSE Request"))?;

    for pdu_part in pdu_parts {
        match pdu_part.header.raw_tag() {
            Some(&[64]) => version = process_bitstring(pdu_part, "Failed to extract protocol version from ACSE Request")?,
            Some(&[65]) => application_context_name = Some(process_oid(pdu_part, "Failed to parse Application Context Name in ACSE Request")?),

            Some(&[66]) => called_ap_title = Some(process_ap_title(pdu_part, "Failed to parse Called AP Title in ACSE Request")?),
            Some(&[67]) => called_ae_qualifier = Some(process_ae_qualifier(pdu_part, "Failed to parse Called AE Title in ACSE Request")?),
            Some(&[68]) => called_ap_invocation_identifier = Some(process_integer(pdu_part, "Failed to parse Called AP Invocation Identifier in ACSE Request")?),
            Some(&[69]) => called_ae_invocation_identifier = Some(process_integer(pdu_part, "Failed to parse Called AE Invocation Identifier in ACSE Request")?),

            Some(&[70]) => calling_ap_title = Some(process_ap_title(pdu_part, "Failed to parse Calling AP Title in ACSE Request")?),
            Some(&[71]) => calling_ae_qualifier = Some(process_ae_qualifier(pdu_part, "Failed to parse Calling AE Title in ACSE Request")?),
            Some(&[72]) => calling_ap_invocation_identifier = Some(process_integer(pdu_part, "Failed to parse Calling AP Invocation Identifier in ACSE Request")?),
            Some(&[73]) => calling_ae_invocation_identifier = Some(process_integer(pdu_part, "Failed to parse Calling AE Invocation Identifier in ACSE Request")?),

            Some(&[74]) => implementation_information = Some(process_graphical_string(pdu_part, "Failed to parse Implementation Information in ACSE Request")?),
            Some(&[75]) => user_data = Some(UserData::parse(pdu_part).map_err(to_acse_error("Failed to process User Data in ACSE Request"))?),

            x => warn!("Unexpected tag in ACSE Request: {:?}", x),
        }
    }

    Ok((
        AcseRequestInformation {
            application_context_name: application_context_name.unwrap(),
            called_ap_title,
            called_ae_qualifier,
            called_ap_invocation_identifier,
            called_ae_invocation_identifier,
            calling_ap_title,
            calling_ae_qualifier,
            calling_ap_invocation_identifier,
            calling_ae_invocation_identifier,
            implementation_information,
        },
        user_data,
    ))
}

pub(crate) fn process_constructed_data<'a>(data: &'a [u8]) -> Result<Vec<Any<'a>>, BerError> {
    let mut remaining = data;
    let mut results = vec![];

    while remaining.len() > 0 {
        let (rem, obj) = parse_ber_any(remaining)?;
        results.push(obj);
        remaining = rem;
    }
    Ok(results)
}

pub(crate) fn process_bitstring<'a>(npm_object: Any<'a>, error_message: &str) -> Result<BitStringObject<'a>, AcseError> {
    let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::BitString)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_acse_error(error_message))?;

    match inner_object {
        BerObjectContent::BitString(_, value) => Ok(value),
        _ => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_integer<'a>(npm_object: Any<'a>, error_message: &str) -> Result<Vec<u8>, AcseError> {
    let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::Integer)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_acse_error(error_message))?;

    match inner_object {
        BerObjectContent::Integer(value) => Ok(value.to_vec()),
        _ => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_graphical_string<'a>(npm_object: Any<'a>, error_message: &str) -> Result<String, AcseError> {
    let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::GeneralString)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_acse_error(error_message))?;

    match inner_object {
        BerObjectContent::GeneralString(value) => Ok(value.to_owned()),
        _ => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_oid(npm_object: Any<'_>, error_message: &str) -> Result<Oid<'static>, AcseError> {
    let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::Oid)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_acse_error(error_message))?;

    match inner_object {
        BerObjectContent::OID(value) => Ok(value.to_owned()),
        _ => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_ap_title<'a>(npm_object: Any<'a>, error_message: &str) -> Result<ApTitle, AcseError> {
    let (_, ap_title) = parse_ber(npm_object.data).map_err(to_acse_error(error_message))?;

    match (ap_title.header.tag(), ap_title.content) {
        (Tag::Oid, BerObjectContent::OID(oid)) => Ok(ApTitle::Form2(oid.to_owned())),
        (_, _) => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_ae_qualifier<'a>(npm_object: Any<'a>, error_message: &str) -> Result<AeQualifier, AcseError> {
    let (_, ap_title) = parse_ber(npm_object.data).map_err(to_acse_error(error_message))?;

    match (ap_title.header.tag(), ap_title.content) {
        (Tag::Integer, BerObjectContent::Integer(qualifier)) => Ok(AeQualifier::Form2(qualifier.to_owned())),
        (_, _) => Err(AcseError::ProtocolError(error_message.into())),
    }
}
