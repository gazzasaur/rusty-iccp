use crate::{
    api::CotpError,
    packet::parameters::{ALTERNATIVE_CLASS_PARAMETER_CODE, ConnectionClass, CotpParameter, TPDU_SIZE_PARAMETER_CODE, TpduSize},
};

pub fn parse_parameters(buffer: &[u8]) -> Result<Vec<CotpParameter>, CotpError> {
    let mut offset = 0;
    let mut parameter_list = Vec::new();

    while offset < buffer.len() {
        let (parameter, consumed) = parse_parameter(&buffer[offset..])?;
        parameter_list.push(parameter);
        offset += consumed;
    }
    Ok(parameter_list)
}

pub fn parse_parameter(buffer: &[u8]) -> Result<(CotpParameter, usize), CotpError> {
    if buffer.len() < 2 {
        return Err(CotpError::ProtocolError(format!("Insufficient data to parse parameter header: {}", buffer.len())));
    }

    let parameter_code = buffer[0];
    let parameter_value_length = buffer[1] as usize;
    if buffer.len() < parameter_value_length + 2 {
        return Err(CotpError::ProtocolError(format!(
            "Insufficient data to parse parameter. The buffer has {} bytes but the header claims the parameter is {} bytes.",
            buffer.len(),
            parameter_value_length + 2
        )));
    }

    match parameter_code {
        TPDU_SIZE_PARAMETER_CODE => Ok((parse_tpdu_size_parameter(&buffer[2..(2 + parameter_value_length)])?, 2 + parameter_value_length)),
        ALTERNATIVE_CLASS_PARAMETER_CODE => Ok((parse_alternative_class_parameter(&buffer[2..(2 + parameter_value_length)])?, 2 + parameter_value_length)),
        _ => Ok((CotpParameter::UnknownParameter(parameter_code, Vec::from(&buffer[2..(2 + parameter_value_length)])), 2 + parameter_value_length)),
    }
}

pub fn parse_tpdu_size_parameter(buffer: &[u8]) -> Result<CotpParameter, CotpError> {
    if buffer.len() != 1 {
        return Err(CotpError::ProtocolError(format!("Invalid TPDU length: {}", buffer.len())));
    }
    Ok(CotpParameter::TpduLengthParameter(TpduSize::from(buffer[0])))
}

pub fn parse_alternative_class_parameter(buffer: &[u8]) -> Result<CotpParameter, CotpError> {
    Ok(CotpParameter::AlternativeClassParameter(buffer.iter().map(|x| ConnectionClass::from((x & 0xF0) >> 4)).collect()))
}
