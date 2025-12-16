use der_parser::{
    asn1_rs::Any,
    ber::{BerObjectContent, parse_ber_any, parse_ber_content},
    der::Tag,
    error::BerError, num_bigint::BigInt,
};
use num_traits::ToPrimitive;

use crate::{
    MmsError,
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

// Pretty much visible string.
pub(crate) fn process_mms_string<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<String, MmsError> {
    let (_, inner_object) = parse_ber_content(Tag::VisibleString)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_mms_error(error_message))?;

    match inner_object {
        BerObjectContent::VisibleString(value) => Ok(value.into()),
        _ => Err(MmsError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_mms_boolean_content<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<bool, MmsError> {
    let (_, inner_object) = parse_ber_content(Tag::Integer)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_mms_error(error_message))?;

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

pub(crate) fn process_mms_integer_8_content<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<i8, MmsError> {
    let int_value = process_integer_content(npm_object, error_message)?;
    if int_value.len() > 1 {
        return Err(MmsError::ProtocolError(format!("{}: {} - {:?}", error_message, "Exceeded Integer8 range", int_value)));
    }
    Ok(i8::from_be_bytes(int_value.try_into().map_err(to_mms_error(error_message))?))
}

pub(crate) fn process_mms_integer_16_content<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<i16, MmsError> {
    let int_value = process_integer_content(npm_object, error_message)?;
    if int_value.len() > 2 {
        return Err(MmsError::ProtocolError(format!("{}: {} - {:?}", error_message, "Exceeded Integer16 range", int_value)));
    }
    Ok(i16::from_be_bytes(int_value.try_into().map_err(to_mms_error(error_message))?))
}

pub(crate) fn process_mms_integer_32_content<'a>(npm_object: &Any<'a>, error_message: &str) -> Result<i32, MmsError> {
    let int_value = process_integer_content(npm_object, error_message)?;
    if int_value.len() > 4 {
        return Err(MmsError::ProtocolError(format!("{}: {} - {:?}", error_message, "Exceeded Integer32 range", int_value)));
    }
    let bi = BigInt::from_signed_bytes_be(&int_value);
    let m: i32 = bi.to_i32().unwrap();
    Ok(m)
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
