use crate::{
    api::CotpError,
    packet::parameters::{ConnectionClass, CotpParameter, ALTERNATIVE_CLASS_PARAMETER_CODE, CALLED_TSAP_PARAMETER_CODE, CALLING_TSAP_PARAMETER_CODE, TPDU_SIZE_PARAMETER_CODE},
};

pub fn serialise_parameters(params: &[CotpParameter]) -> Result<Vec<u8>, CotpError> {
    let mut buffer = Vec::new();

    // Going to let unknown parameters through here as previous logic should filter it.
    for param in params {
        buffer.push(cotp_parameter_code_to_u8(param));

        match param {
            CotpParameter::CallingTsap(value) => {
                if value.len() >= 255 {
                    return Err(CotpError::ProtocolError(format!("{} The calling TSAP address must be less than 255 bytes.", buffer.len())));
                }
                buffer.push(value.len() as u8);
                buffer.extend(value);
            }
            CotpParameter::CalledTsap(value) => {
                if value.len() >= 255 {
                    return Err(CotpError::ProtocolError(format!("{} The called TSAP address must be less than 255 bytes.", buffer.len())));
                }
                buffer.push(value.len() as u8);
                buffer.extend(value);
            }
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
        CotpParameter::CallingTsap(_) => CALLING_TSAP_PARAMETER_CODE,
        CotpParameter::CalledTsap(_) => CALLED_TSAP_PARAMETER_CODE,
        CotpParameter::AlternativeClassParameter(_) => ALTERNATIVE_CLASS_PARAMETER_CODE,
        CotpParameter::TpduLengthParameter(_) => TPDU_SIZE_PARAMETER_CODE,
        CotpParameter::UnknownParameter(x, _) => *x,
    }
}
