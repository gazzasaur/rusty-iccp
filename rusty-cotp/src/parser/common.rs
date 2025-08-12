use crate::error::CotpError;

pub fn parse_u16(buffer: &[u8]) -> Result<u16, CotpError> {
    Ok(u16::from_be_bytes(
        buffer
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| CotpError::InternalError(format!("Failed to parse bytes to u16: {}", e.to_string())))?,
    ))
}
