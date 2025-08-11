use crate::{
    error::CotpError,
    model::{
        connection_request::{CONNECTION_REQUEST_CODE, ConnectionOption, ConnectionRequest},
        parameter::{CotpParameter, TpduLength},
        payload::TransportProtocolDataUnit,
    },
};

pub struct TransportProtocolDataUnitParser {}

impl TransportProtocolDataUnitParser {
    pub fn new() -> Self {
        TransportProtocolDataUnitParser {}
    }

    pub fn parse(&mut self, data: &[u8]) -> Result<TransportProtocolDataUnit, CotpError> {
        let buffer_length = data.len();
        if buffer_length < 2 {
            return Err(CotpError::ProtocolError(format!("Invalid payload data. Need at least 2 bytes but only {} bytes was received.", buffer_length)));
        }

        let header_length = data[0] as usize;
        if header_length < 2 || header_length > 254 {
            return Err(CotpError::ProtocolError(format!("Invalid header length value. The value must be greater than 1 and less that 255 but was {}.", header_length)));
        }

        if buffer_length < header_length + 1 {
            return Err(CotpError::ProtocolError(format!(
                "The buffer length {} cannot fit the required payload with a header length of {}",
                buffer_length, header_length
            )));
        }

        let class_code = data[1] & 0xF0u8;
        let class_code_variable = data[1] & 0x0Fu8;

        match (class_code, class_code_variable) {
            (CONNECTION_REQUEST_CODE, 0x00u8) => parse_create_request(&data[2..(header_length + 1)], &data[(header_length + 1)..]),
            _ => return Err(CotpError::ProtocolError(format!("Unsupported class code was receiveed: {}", class_code).into())),
        }
    }
}

pub fn parse_create_request(header_data: &[u8], user_data: &[u8]) -> Result<TransportProtocolDataUnit, CotpError> {
    if header_data.len() < 5 {
        return Err(CotpError::ProtocolError(format!("At least 5 bytes are required to parse the payload but got {}", header_data.len())).into());
    }

    let destination_reference = parse_u16(&header_data[0..2])?;
    let source_reference = parse_u16(&header_data[2..4])?;
    let preferred_class = header_data[4] & 0xF0 >> 4;
    let request_options = header_data[4] & 0x0F;
    let variable_part = &header_data[5..];

    let parameters = parse_parameters(variable_part)?;

    Ok(TransportProtocolDataUnit::CR(ConnectionRequest::new(
        source_reference,
        destination_reference,
        preferred_class.into(),
        ConnectionOption::from(request_options),
        parameters,
        &user_data,
    )))
}

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
    let parameter_length = 2 + parameter_value_length;
    if buffer.len() < parameter_length {
        return Err(CotpError::ProtocolError(format!("Insufficient data to parse parameter: {}", buffer.len())));
    }

    match parameter_code {
        0b11000000 => Ok((parse_tpdu_size_parameter(&buffer[2..parameter_length])?, parameter_length)),
        _ => Ok((CotpParameter::UnknownParameter(parameter_code), parameter_length)),
    }
}

pub fn parse_tpdu_size_parameter(buffer: &[u8]) -> Result<CotpParameter, CotpError> {
    if buffer.len() != 1 {
        return Err(CotpError::ProtocolError(format!("Invalid TPDU length: {}", buffer.len())));
    }
    Ok(CotpParameter::TpduLengthParameter(TpduLength::from(buffer[0])))
}

pub fn parse_u16(buffer: &[u8]) -> Result<u16, CotpError> {
    Ok(u16::from_ne_bytes(buffer.try_into().map_err(|e: std::array::TryFromSliceError| CotpError::UnknownError(e.into()))?))
}

#[cfg(test)]
mod tests {
    use crate::{
        model::{
            connection_request::{ConnectionClass, ConnectionRequest},
            payload::TransportProtocolDataUnit,
        },
        parser::TransportProtocolDataUnitParser,
    };

    #[test]
    fn parse_payloads_happy() -> Result<(), anyhow::Error> {
        let mut subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            subject.parse(hex::decode("06E00000000000")?.as_slice())?,
            TransportProtocolDataUnit::CR(ConnectionRequest::new(0, 0, ConnectionClass::Class0, vec![], vec![], &[]))
        );

        Ok(())
    }
}
