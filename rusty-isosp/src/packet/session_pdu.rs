use bitfield::bitfield;

use crate::api::IsoSpError;

pub const CONNECT_SERVICE_PDU_CODE: u8 = 13;

pub const CONNECT_ACCEPT_ITEM_PARAMETER_CODE: u8 = 5;
pub const USER_DATA_PARAMETER_CODE: u8 = 193;
pub const EXTENDED_USER_DATA_PARAMETER_CODE: u8 = 194;

pub const SESSION_USER_REQUIREMENTS_PARAMETER_CODE: u8 = 20;
pub const DATA_OVERFLOW_PARAMETER_CODE: u8 = 60;

pub const PROTOCOL_OPTIONS_PARAMETER_CODE: u8 = 19;
pub const TSDU_MAXIMUM_SIZE_PARAMETER_CODE: u8 = 21;
pub const VERSION_NUMBER_PARAMETER_CODE: u8 = 22;

pub enum SessionPdu {
    Connect(Vec<SessionPduParameter>),
    Unknown(u8, Vec<u8>),
}

impl TryFrom<&[u8]> for SessionPdu {
    type Error = IsoSpError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let pdus = slice_data(data)?;

        if pdus.len() > 1 {
            return Err(IsoSpError::ProtocolError("Concatenated pdus were detected but it is not supported.".into()));
        } else if pdus.len() == 0 {
            return Err(IsoSpError::ProtocolError("No data detected.".into()));
        }

        Ok(match pdus[0].0 {
            CONNECT_SERVICE_PDU_CODE => SessionPdu::Connect(into_parameters(pdus[0].1)?),
            _ => SessionPdu::Unknown(pdus[0].0, pdus[0].1.to_vec()),
        })
    }
}

fn into_parameters(data: &[u8]) -> Result<Vec<SessionPduParameter>, IsoSpError> {
    let raw_parameters = slice_data(data)?;
    let mut parameters = Vec::new();

    for (parameter_tag, parameter_value) in raw_parameters {
        parameters.push(match parameter_tag {
            CONNECT_ACCEPT_ITEM_PARAMETER_CODE => SessionPduParameter::ConnectAcceptItem(into_sub_parameters(parameter_value)?),
            SESSION_USER_REQUIREMENTS_PARAMETER_CODE => SessionPduParameter::SessionUserRequirementsItem(parse_session_user_requirements(parameter_value)?),
            USER_DATA_PARAMETER_CODE => SessionPduParameter::UserData(parameter_value.to_vec()),
            DATA_OVERFLOW_PARAMETER_CODE => SessionPduParameter::DataOverflowItem(parse_data_overflow(data)?),
            EXTENDED_USER_DATA_PARAMETER_CODE => SessionPduParameter::ExtendedUserData(parameter_value.to_vec()),
            _ => SessionPduParameter::Unknown(parameter_tag, parameter_value.to_vec()),
        });
    }
    Ok(parameters)
}

fn into_sub_parameters(data: &[u8]) -> Result<Vec<SessionPduSubParameter>, IsoSpError> {
    let raw_parameters = slice_data(data)?;
    let mut parameters = Vec::new();

    for (parameter_tag, parameter_value) in raw_parameters {
        parameters.push(match parameter_tag {
            PROTOCOL_OPTIONS_PARAMETER_CODE => SessionPduSubParameter::ProtocolOptionsParameter(parse_protocol_options(parameter_value)?),
            VERSION_NUMBER_PARAMETER_CODE => SessionPduSubParameter::VersionNumberParameter(parse_version_number(parameter_value)?),
            TSDU_MAXIMUM_SIZE_PARAMETER_CODE => SessionPduSubParameter::TsduMaximumSizeParameter(parse_tsdu_maximum_size(data)?),
            _ => SessionPduSubParameter::Unknown(parameter_tag, parameter_value.to_vec()),
        });
    }
    Ok(parameters)
}

pub enum SessionPduParameter {
    ConnectAcceptItem(Vec<SessionPduSubParameter>),
    SessionUserRequirementsItem(SessionUserRequirements),
    UserData(Vec<u8>),
    DataOverflowItem(DataOverflow),
    ExtendedUserData(Vec<u8>),
    Unknown(u8, Vec<u8>),
}

pub enum SessionPduSubParameter {
    ProtocolOptionsParameter(ProtocolOptions),
    VersionNumberParameter(SupportedVersions),
    TsduMaximumSizeParameter(TsduMaximumSize),
    SessionUserRequirements(SessionUserRequirements),
    Unknown(u8, Vec<u8>),
}

fn parse_protocol_options(data: &[u8]) -> Result<ProtocolOptions, IsoSpError> {
    verify_length("Protocol Parameters", 1, data)?;
    Ok(ProtocolOptions(data[0]))
}

fn parse_version_number(data: &[u8]) -> Result<SupportedVersions, IsoSpError> {
    verify_length("Version Number", 1, data)?;
    Ok(SupportedVersions(data[0]))
}

fn parse_tsdu_maximum_size(data: &[u8]) -> Result<TsduMaximumSize, IsoSpError> {
    verify_length("TSDU Maximum Size", 4, data)?;
    Ok(TsduMaximumSize(u32::from_be_bytes(data.try_into().map_err(|e: std::array::TryFromSliceError| IsoSpError::ProtocolError(e.to_string()))?)))
}

fn parse_session_user_requirements(data: &[u8]) -> Result<SessionUserRequirements, IsoSpError> {
    verify_length("Session User Requirements", 2, data)?;
    Ok(SessionUserRequirements(u16::from_be_bytes(
        data.try_into().map_err(|e: std::array::TryFromSliceError| IsoSpError::ProtocolError(e.to_string()))?,
    )))
}

fn parse_data_overflow(data: &[u8]) -> Result<DataOverflow, IsoSpError> {
    verify_length("Data Overflow", 1, data)?;
    Ok(DataOverflow(data[0]))
}

fn verify_length(label: &str, expected_length: usize, data: &[u8]) -> Result<(), IsoSpError> {
    if expected_length != data.len() {
        return Err(IsoSpError::ProtocolError(format!("Invalid Length: {} - Expected {}, Got {}", label, expected_length, data.len())));
    }
    Ok(())
}

bitfield! {
    pub struct ProtocolOptions(u8);

    extended_concatenated_spdu_support, _ : 0;
    reserved, _ : 7, 1;
}

bitfield! {
    pub struct SupportedVersions(u8);

    version1, _ : 0;
    version2, _ : 1;
    reserved2, _ : 7, 2;
}

impl Default for SupportedVersions {
    fn default() -> Self {
        Self(0x01)
    }
}

bitfield! {
    pub struct TsduMaximumSize(u32);

    initiator, _ : 15, 0;
    responder, _ : 16, 31;
}

bitfield! {
    pub struct SessionUserRequirements(u16);

    half_duplex, _ : 0;
    full_duplex, _ : 1;
    expedited, _ : 2;
    minor_synchronize, _ : 3;
    major_synchronize, _ : 4;
    resynchronize, _ : 5;
    activity_management, _ : 6;
    negotiated_release, _ : 7;
    capability_data, _ : 8;
    exceptions, _ : 9;
    typed_data, _ : 10;
    reserved, _ : 15, 11;
}

impl Default for SessionUserRequirements {
    fn default() -> Self {
        Self(0x0349) // Default as per X.225
    }
}

bitfield! {
    pub struct DataOverflow(u8);

    more_data, _ : 0; // The only valid value is true
    reserved, _ : 1, 7;
}

impl Default for DataOverflow {
    fn default() -> Self {
        Self(0x01)
    }
}

fn slice_data(data: &[u8]) -> Result<Vec<(u8, &[u8])>, IsoSpError> {
    let mut offset = 0;
    let mut slices = Vec::new();

    while offset < data.len() {
        let (tag, data_offset, data_length) = if (data.len() - offset) < 2 {
            return Err(IsoSpError::ProtocolError(format!("Not enough data to form an SPDU. Needed at least 2 bytes but {} found", data.len())));
        } else if data[offset + 1] == 0xFF && data.len() < 4 {
            return Err(IsoSpError::ProtocolError(format!("Not enough data to form an SPDU. Needed at least 4 bytes but {} found", data.len())));
        } else if data[offset + 1] == 0xFF {
            (
                data[offset],
                offset + 4,
                u16::from_be_bytes(data[(offset + 2)..(offset + 4)].try_into().map_err(|e: std::array::TryFromSliceError| IsoSpError::InternalError(e.to_string()))?) as usize,
            )
        } else {
            (data[offset], offset + 2, data[offset + 1] as usize)
        };

        if data.len() < data_offset + data_length {
            return Err(IsoSpError::ProtocolError(format!(
                "Not enough data to form an SPDU. Needed at least {} bytes but {} found",
                data_offset + data_length,
                data.len()
            )));
        }

        slices.push((tag, &data[data_offset..(data_offset + data_length)]));
        offset = data_offset + data_length
    }

    Ok(slices)
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_split_data() -> Result<(), anyhow::Error> {
        let mut payload_data = vec![0u8; 0x32];
        rand::fill(payload_data.as_mut_slice());

        let mut payload: Vec<u8> = vec![0x12, 0x32];
        payload.extend_from_slice(payload_data.as_slice());
        let data_items = slice_data(&payload)?;
        assert_eq!(1, data_items.len());
        assert_eq!(0x12, data_items[0].0);
        assert_eq!(payload_data, data_items[0].1);

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_should_split_long_data() -> Result<(), anyhow::Error> {
        let mut payload_data = vec![0u8; 61234];
        rand::fill(payload_data.as_mut_slice());

        let mut payload: Vec<u8> = vec![0xab, 0xff, 0xef, 0x32];
        payload.extend_from_slice(payload_data.as_slice());
        let data_items = slice_data(&payload)?;
        assert_eq!(1, data_items.len());
        assert_eq!(0xab, data_items[0].0);
        assert_eq!(payload_data, data_items[0].1);

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_should_split_composite_data() -> Result<(), anyhow::Error> {
        let mut payload: Vec<u8> = vec![0xab, 0x03, 0xfe, 0xdc, 0xba];
        payload.extend_from_slice(&[0x98, 0x00]);
        payload.extend_from_slice(&[0x76, 0x01, 0x54]);

        let data_items = slice_data(&payload)?;
        assert_eq!(3, data_items.len());
        assert_eq!(0xab, data_items[0].0);
        assert_eq!(&[0xfe, 0xdc, 0xba], data_items[0].1.iter().as_slice());
        assert_eq!(0x98, data_items[1].0);
        assert_eq!(0, data_items[1].1.len());
        assert_eq!(0x76, data_items[2].0);
        assert_eq!(&[0x54], data_items[2].1.iter().as_slice());

        Ok(())
    }
}
