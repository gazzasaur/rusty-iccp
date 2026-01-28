use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, parse_ber_any, parse_ber_content},
    der::{Header, Tag},
    error::BerError,
    num_bigint::BigInt,
};
use num_traits::ToPrimitive;
use tracing::warn;

use crate::{
    MmsAccessError, MmsAccessResult, MmsData, MmsError,
    error::to_mms_error,
    parameters::{ParameterSupportOption, ParameterSupportOptions, ServiceSupportOption, ServiceSupportOptions},
};

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

// Pretty much visible string as we are not supporting the MMS char feature.
pub(crate) fn process_mms_string<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<String, MmsError> {
    let (_, inner_object) = parse_ber_content(Tag::VisibleString)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_mms_error(error_message))?;

    match inner_object {
        BerObjectContent::VisibleString(value) => Ok(value.into()),
        _ => Err(MmsError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_mms_bitstring_content<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<MmsData, MmsError> {
    let (_, inner_object) = parse_ber_content(Tag::BitString)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_mms_error(error_message))?;

    match inner_object {
        BerObjectContent::BitString(padding, data) => Ok(MmsData::BitString(padding, data.data.to_vec())),
        _ => Err(MmsError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_mms_boolean_content<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<bool, MmsError> {
    let (_, inner_object) = parse_ber_content(Tag::Boolean)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_mms_error(error_message))?;

    match inner_object {
        BerObjectContent::Boolean(value) => Ok(value),
        _ => Err(MmsError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_integer_content<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<Vec<u8>, MmsError> {
    let (_, inner_object) = parse_ber_content(Tag::Integer)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_mms_error(error_message))?;

    match inner_object {
        BerObjectContent::Integer(value) => Ok(value.to_vec()),
        _ => Err(MmsError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_mms_access_error<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<MmsAccessError, MmsError> {
    let (_, inner_object) = parse_ber_content(Tag::Integer)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_mms_error(error_message))?;

    match inner_object {
        BerObjectContent::Integer(&[0x00]) => Ok(MmsAccessError::ObjectInvalidated),
        BerObjectContent::Integer(x) => Ok(MmsAccessError::Unknown(x.to_vec())),
        // TODO: More error codes
        _ => Err(MmsError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn mms_access_error_to_ber<'a>(error: &'a MmsAccessError) -> BerObject<'a> {
    BerObject::from_header_and_content(
        Header::new(der_parser::der::Class::ContextSpecific, false, Tag::from(0), der_parser::ber::Length::Definite(0)),
        BerObjectContent::Integer(match error {
            MmsAccessError::ObjectInvalidated => &[0],
            MmsAccessError::HardwareFault => &[1],
            MmsAccessError::TemporarilyUnavailable => &[2],
            MmsAccessError::ObjectAccessDenied => &[3],
            MmsAccessError::ObjectUndefined => &[4],
            MmsAccessError::InvalidAddress => &[5],
            MmsAccessError::TypeUnsupported => &[6],
            MmsAccessError::TypeInconsistent => &[7],
            MmsAccessError::ObjectAttributeInconsistent => &[8],
            MmsAccessError::ObjectAccessUnsupported => &[9],
            MmsAccessError::ObjectNonExistent => &[10],
            MmsAccessError::ObjectValueInvalid => &[11],
            MmsAccessError::Unknown(x) => x.as_slice(),
        }),
    )
}

pub(crate) fn process_mms_integer_8_content<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<i8, MmsError> {
    let int_value = process_integer_content(npm_object, error_message)?;
    if int_value.len() > 1 {
        return Err(MmsError::ProtocolError(format!("{}: {} - {:?}", error_message, "Exceeded Integer8 range", int_value)));
    }
    BigInt::from_signed_bytes_be(&int_value)
        .to_i8()
        .ok_or_else(|| MmsError::ProtocolError(format!("{}: Failed to parse MMS int8 from {:?}", error_message, int_value)))
}

pub(crate) fn process_mms_integer_16_content<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<i16, MmsError> {
    let int_value = process_integer_content(npm_object, error_message)?;
    if int_value.len() > 2 {
        return Err(MmsError::ProtocolError(format!("{}: {} - {:?}", error_message, "Exceeded Integer16 range", int_value)));
    }
    BigInt::from_signed_bytes_be(&int_value)
        .to_i16()
        .ok_or_else(|| MmsError::ProtocolError(format!("{}: Failed to parse MMS int16 from {:?}", error_message, int_value)))
}

pub(crate) fn process_mms_integer_32_content<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<i32, MmsError> {
    let int_value = process_integer_content(npm_object, error_message)?;
    if int_value.len() > 4 {
        return Err(MmsError::ProtocolError(format!("{}: {} - {:?}", error_message, "Exceeded Integer32 range", int_value)));
    }
    BigInt::from_signed_bytes_be(&int_value)
        .to_i32()
        .ok_or_else(|| MmsError::ProtocolError(format!("{}: Failed to parse MMS int32 from {:?}", error_message, int_value)))
}

pub(crate) fn process_mms_parameter_support_options<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<ParameterSupportOptions, MmsError> {
    let (_, bit_string) = parse_ber_content(Tag::BitString)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_mms_error(error_message))?;

    let bit_string_obj = match bit_string {
        BerObjectContent::BitString(_, bit_string_object) => bit_string_object,
        x => return Err(MmsError::ProtocolError(format!("{}: {:?}", error_message, x))),
    };

    Ok(ParameterSupportOptions {
        options: vec![
            if bit_string_obj.is_set(0) { Some(ParameterSupportOption::Str1) } else { None },
            if bit_string_obj.is_set(1) { Some(ParameterSupportOption::Str2) } else { None },
            if bit_string_obj.is_set(2) { Some(ParameterSupportOption::Vnam) } else { None },
            if bit_string_obj.is_set(3) { Some(ParameterSupportOption::Valt) } else { None },
            if bit_string_obj.is_set(7) { Some(ParameterSupportOption::Vlis) } else { None },
        ]
        .into_iter()
        .filter_map(|i| i)
        .collect(),
    })
}

pub(crate) fn process_mms_service_support_option<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<ServiceSupportOptions, MmsError> {
    let (_, bit_string) = parse_ber_content(Tag::BitString)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_mms_error(error_message))?;

    let bit_string_obj = match bit_string {
        BerObjectContent::BitString(_, bit_string_object) => bit_string_object,
        x => return Err(MmsError::ProtocolError(format!("{}: {:?}", error_message, x))),
    };

    Ok(ServiceSupportOptions {
        options: vec![
            if bit_string_obj.is_set(1) { Some(ServiceSupportOption::GetNameList) } else { None },
            if bit_string_obj.is_set(2) { Some(ServiceSupportOption::Identify) } else { None },
            if bit_string_obj.is_set(4) { Some(ServiceSupportOption::Read) } else { None },
            if bit_string_obj.is_set(5) { Some(ServiceSupportOption::Write) } else { None },
            if bit_string_obj.is_set(6) { Some(ServiceSupportOption::GetVariableAccessAttributes) } else { None },
            if bit_string_obj.is_set(7) { Some(ServiceSupportOption::GetNamedVariableListAttribute) } else { None },
            if bit_string_obj.is_set(11) { Some(ServiceSupportOption::DefineNamedVariableList) } else { None },
            if bit_string_obj.is_set(13) { Some(ServiceSupportOption::DeleteNamedVariableList) } else { None },
            if bit_string_obj.is_set(79) { Some(ServiceSupportOption::InformationReport) } else { None },
        ]
        .into_iter()
        .filter_map(|i| i)
        .collect(),
    })
}

impl MmsAccessResult {
    pub(crate) fn parse(pdu: &str, value: &Any<'_>) -> Result<MmsAccessResult, MmsError> {
        let mut access_result = None;

        match value.header.raw_tag() {
            Some([128]) => access_result = Some(MmsAccessResult::Failure(process_mms_access_error(value, "Failed to parse MMS Access Error on Access Result")?)),
            Some(_) => access_result = Some(MmsAccessResult::Success(MmsData::parse(pdu, value)?)),
            x => warn!("Unknown MMS Access Result item {:?}", x),
        }

        access_result.ok_or_else(|| MmsError::ProtocolError(format!("No Access Result found on MMS {}", pdu)))
    }

    pub(crate) fn to_ber(&self) -> Result<BerObject<'_>, MmsError> {
        match self {
            MmsAccessResult::Failure(mms_access_error) => Ok(mms_access_error_to_ber(mms_access_error)),
            MmsAccessResult::Success(mms_data) => mms_data.serialise(true, true), // TODO: pass in correct flags
        }
    }
}
