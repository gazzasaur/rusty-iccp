/**
 * MIT License
 *
 * Copyright (c) 2025 gazzasaur
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

use crate::{
    api::CotpError,
    packet::parameter::{ALTERNATIVE_CLASS_PARAMETER_CODE, ConnectionClass, CotpParameter, TPDU_SIZE_PARAMETER_CODE, TpduSize},
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
