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
    packet::parameter::{ALTERNATIVE_CLASS_PARAMETER_CODE, ConnectionClass, CotpParameter, TPDU_SIZE_PARAMETER_CODE},
};

pub fn serialise_parameters(params: &[CotpParameter]) -> Result<Vec<u8>, CotpError> {
    let mut buffer = Vec::new();

    // Going to let unknown parameters through here as previous logic should filter it.
    for param in params {
        buffer.push(cotp_parameter_code_to_u8(param));

        match param {
            CotpParameter::AlternativeClassParameter(items) => {
                if items.len() > 255 {
                    return Err(CotpError::ProtocolError(format!("{} alternative connection classes have been specified. Only 4 exist.", buffer.len())));
                }
                buffer.push(items.len() as u8);
                buffer.extend(items.iter().map(|item| <&ConnectionClass as Into<u8>>::into(item)));
            }
            CotpParameter::TpduLengthParameter(tpdu_size) => {
                buffer.push(1);
                buffer.push(tpdu_size.into());
            }
            CotpParameter::UnknownParameter(_, items) => {
                if buffer.len() > 255 {
                    return Err(CotpError::ProtocolError(format!("Parameter bodies can only be a maximum of 255 bytes but found {} bytes.", buffer.len())));
                }
                buffer.push(items.len() as u8);
                buffer.extend_from_slice(items.as_slice());
            }
        }
    }

    Ok(buffer)
}

pub fn cotp_parameter_code_to_u8(param: &CotpParameter) -> u8 {
    match param {
        CotpParameter::AlternativeClassParameter(_) => ALTERNATIVE_CLASS_PARAMETER_CODE,
        CotpParameter::TpduLengthParameter(_) => TPDU_SIZE_PARAMETER_CODE,
        CotpParameter::UnknownParameter(x, _) => *x,
    }
}
