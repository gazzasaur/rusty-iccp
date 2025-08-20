use bitfield::bitfield;
use rusty_cotp::packet::parameter;

use crate::api::IsoSpError;

pub const CONNECT_SERVICE_PDU_CODE: u8 = 13;

pub const CONNECT_ACCEPT_PARAMETER_CODE: u8 = 5;
pub const PROTOCOL_OPTIONS_PARAMETER_CODE: u8 = 19;
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
            // CONNECT_ACCEPT_PARAMETER_CODE => SessionPduParameter::ConnectAcceptItem(())
            _ => SessionPduParameter::Unknown(parameter_tag, parameter_value.to_vec()),
        });
    }
    Ok(parameters)
}

fn into_sub_parameters(data: &[u8]) -> Result<Vec<SessionPduSubParameter>, IsoSpError> {
    let mut offset = 0;
    let mut parameters = Vec::new();

    while offset < data.len() {
        let (parameter_tag, parameter_offset, parameter_length) = if (data.len() - offset) < 2 {
            return Err(IsoSpError::ProtocolError(format!("Not enough data to form an SPDU sub parameter group. Needed at least 2 bytes but {} found", data.len())));
        } else if data[offset + 1] == 0xFF && (data.len() - offset) < 4 {
            return Err(IsoSpError::ProtocolError(format!("Not enough data to form an SPDU sub parameter group. Needed at least 4 bytes but {} found", data.len())));
        } else if data[offset + 1] == 0xFF {
            (
                data[offset],
                offset + 4,
                u16::from_be_bytes(data[(offset + 1)..(offset + 3)].try_into().map_err(|e: std::array::TryFromSliceError| IsoSpError::InternalError(e.to_string()))?) as usize,
            )
        } else {
            (data[offset], offset + 2, data[offset + 1] as usize)
        };

        parameters.push(match parameter_tag {
            // CONNECT_ACCEPT_PARAMETER_CODE => SessionPduSubParameter::ProtocolOptionsParameter(())
            _ => SessionPduSubParameter::Unknown(parameter_tag, Vec::new()),
        });
    }

    Ok(parameters)
}

pub enum SessionPduParameter {
    ConnectAcceptItem(Vec<SessionPduSubParameter>),
    Unknown(u8, Vec<u8>),
}

pub enum SessionPduSubParameter {
    ProtocolOptionsParameter(ProtocolOptions),
    VersionNumberParameter(SupportedVersions),
    TsduMaximumSizeParameter(TsduMaximumSize),
    SessionUserRequirements(SessionUserRequirements),
    UserData(Vec<u8>),         // Techincally a parameter group. But it parses like a parameter.
    ExtendedUserData(Vec<u8>), // Techincally a parameter group. But it parses like a parameter.
    DataOverflow(u8),
    Unknown(u8, Vec<u8>),
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
                u16::from_be_bytes(data[(offset + 1)..(offset + 3)].try_into().map_err(|e: std::array::TryFromSliceError| IsoSpError::InternalError(e.to_string()))?) as usize,
            )
        } else {
            (data[offset], offset + 2, data[offset + 1] as usize)
        };

        slices.push((data[offset], &data[data_offset..(data_offset + data_length)]));
        offset = data_offset + data_length
    }

    Ok(slices)
}
