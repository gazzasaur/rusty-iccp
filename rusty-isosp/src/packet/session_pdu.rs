use std::collections::VecDeque;

use bitfield::bitfield;
use strum::IntoStaticStr;

use crate::api::IsoSpError;

pub const REMAINING_DATA_VIRTUAL_PDU_CODE: u8 = 0;

pub const CONNECT_SERVICE_PDU_CODE: u8 = 13;
pub const OVERFLOW_ACCEPT_SERVICE_PDU_CODE: u8 = 16;
pub const CONNECT_DATA_OVERFLOW_SERVICE_PDU_CODE: u8 = 15;
pub const ACCEPT_SERVICE_PDU_CODE: u8 = 14;
pub const REFUSE_SERVICE_PDU_CODE: u8 = 12;
pub const FINISH_SERVICE_PDU_CODE: u8 = 9;
pub const DISCONNECT_SERVICE_PDU_CODE: u8 = 10;
pub const ABORT_SERVICE_PDU_CODE: u8 = 25;
pub const DATA_TRANSFER_SERVICE_PDU_CODE: u8 = 1;
pub const ABORT_ACCEEPT_SERVICE_PDU_CODE: u8 = 26;
pub const GIVE_TOKENS_SERVICE_PDU_CODE: u8 = 1;

pub const CONNECT_ACCEPT_ITEM_PARAMETER_CODE: u8 = 5;
pub const USER_DATA_PARAMETER_CODE: u8 = 193;
pub const EXTENDED_USER_DATA_PARAMETER_CODE: u8 = 194;
pub const TRANSPORT_DISCONNECT_PARAMETER_CODE: u8 = 17;

pub const SESSION_USER_REQUIREMENTS_PARAMETER_CODE: u8 = 20;
pub const DATA_OVERFLOW_PARAMETER_CODE: u8 = 60;
pub const ENCLOSURE_ITEM_PARAMETER_CODE: u8 = 25;
pub const REASON_CODE_PARAMETER_CODE: u8 = 50;
pub const REFLECT_PARAMETER_VALUES_PARAMETER_CODE: u8 = 49;

pub const PROTOCOL_OPTIONS_PARAMETER_CODE: u8 = 19;
pub const TSDU_MAXIMUM_SIZE_PARAMETER_CODE: u8 = 21;
pub const VERSION_NUMBER_PARAMETER_CODE: u8 = 22;

#[derive(Debug, IntoStaticStr)]
pub enum SessionPdu {
    Connect(Vec<SessionPduParameter>),
    OverflowAccept(Vec<SessionPduParameter>),
    ConnectDataOverflow(Vec<SessionPduParameter>),
    Accept(Vec<SessionPduParameter>),
    Refuse(Vec<SessionPduParameter>),
    Finish(Vec<SessionPduParameter>),
    Disconnect(Vec<SessionPduParameter>),
    Abort(Vec<SessionPduParameter>),
    DataTransfer(Vec<SessionPduParameter>), // Data Transfer and Give Tokens has the same SI.
    AbortAccept(Vec<SessionPduParameter>),
    GiveTokens(Vec<SessionPduParameter>),

    Unknown(u8, Vec<u8>),
}

pub enum TsduMaximumSizeSelected {
    Unlimited,
    Size(u16),
}

#[derive(Debug)]
pub struct SessionPduList(pub Vec<SessionPdu>);

impl SessionPduList {
    pub fn deserialise(tsdu_size: TsduMaximumSizeSelected, data: &[u8]) -> Result<Self, IsoSpError> {
        let pdus = slice_data(data, 0)?;
        let mut session_pdus = Vec::new();

        let slice_limit = match tsdu_size {
            TsduMaximumSizeSelected::Unlimited => 1,
            _ => usize::MAX,
        };

        for (tag, pdu_data) in pdus {
            session_pdus.push(match tag {
                CONNECT_SERVICE_PDU_CODE => SessionPdu::Connect(into_parameters(pdu_data)?),
                OVERFLOW_ACCEPT_SERVICE_PDU_CODE => SessionPdu::OverflowAccept(into_parameters(pdu_data)?),
                ACCEPT_SERVICE_PDU_CODE => SessionPdu::Accept(into_parameters(pdu_data)?),
                CONNECT_DATA_OVERFLOW_SERVICE_PDU_CODE => SessionPdu::ConnectDataOverflow(into_parameters(pdu_data)?),
                REFUSE_SERVICE_PDU_CODE => SessionPdu::Refuse(into_parameters(pdu_data)?),
                FINISH_SERVICE_PDU_CODE => SessionPdu::Finish(into_parameters(pdu_data)?),
                DISCONNECT_SERVICE_PDU_CODE => SessionPdu::Disconnect(into_parameters(pdu_data)?),
                ABORT_SERVICE_PDU_CODE => SessionPdu::Abort(into_parameters(pdu_data)?),
                ABORT_ACCEEPT_SERVICE_PDU_CODE => SessionPdu::AbortAccept(into_parameters(pdu_data)?),

                // Give token and data transfer are the same, but give token is always first.
                GIVE_TOKENS_SERVICE_PDU_CODE if session_pdus.len() == 0 => SessionPdu::DataTransfer(into_parameters(pdu_data)?),
                DATA_TRANSFER_SERVICE_PDU_CODE => SessionPdu::DataTransfer(into_parameters_with_limit(pdu_data, slice_limit)?),

                _ => SessionPdu::Unknown(tag, pdu_data.to_vec()),
            });
        }

        Ok(SessionPduList(session_pdus))
    }

    pub fn serialise(&self) -> Result<Vec<u8>, IsoSpError> {
        let mut data: VecDeque<u8> = VecDeque::new();

        for pdu in self.0.as_slice() {
            match pdu {
                SessionPdu::Connect(session_pdu_parameters) => {
                    let parameter_data = encode_parameters(session_pdu_parameters)?;
                    data.push_back(CONNECT_SERVICE_PDU_CODE);
                    data.extend(encode_length(parameter_data.len())?);
                    data.extend(parameter_data);
                }
                SessionPdu::OverflowAccept(session_pdu_parameters) => todo!(),
                SessionPdu::ConnectDataOverflow(session_pdu_parameters) => todo!(),
                SessionPdu::Accept(session_pdu_parameters) => {
                    let parameter_data = encode_parameters(session_pdu_parameters)?;
                    data.push_back(ACCEPT_SERVICE_PDU_CODE);
                    data.extend(encode_length(parameter_data.len())?);
                    data.extend(parameter_data);
                }
                SessionPdu::Refuse(session_pdu_parameters) => todo!(),
                SessionPdu::Finish(session_pdu_parameters) => todo!(),
                SessionPdu::Disconnect(session_pdu_parameters) => todo!(),
                SessionPdu::Abort(session_pdu_parameters) => todo!(),
                SessionPdu::DataTransfer(session_pdu_parameters) => todo!(),
                SessionPdu::AbortAccept(session_pdu_parameters) => todo!(),
                SessionPdu::GiveTokens(session_pdu_parameters) => todo!(),
                SessionPdu::Unknown(_, items) => todo!(),
            }
        }

        Ok(data.into())
    }
}

fn encode_parameters(parameters: &Vec<SessionPduParameter>) -> Result<Vec<u8>, IsoSpError> {
    let mut data: VecDeque<u8> = VecDeque::new();

    for parameter in parameters {
        match parameter {
            SessionPduParameter::ConnectAcceptItem(session_pdu_sub_parameters) => {
                        let parameter_data = encode_sub_parameters(session_pdu_sub_parameters);
                        data.push_back(CONNECT_ACCEPT_ITEM_PARAMETER_CODE);
                        data.extend(encode_length(parameter_data.len())?);
                        data.extend(parameter_data);
                    }
            SessionPduParameter::SessionUserRequirementsItem(session_user_requirements) => {
                        data.extend(vec![SESSION_USER_REQUIREMENTS_PARAMETER_CODE, 0x02]);
                        data.extend(session_user_requirements.0.to_be_bytes());
                    }
            SessionPduParameter::UserData(items) => todo!(),
            SessionPduParameter::DataOverflowItem(data_overflow) => todo!(),
            SessionPduParameter::EnclosureItem(enclosure) => todo!(),
            SessionPduParameter::ExtendedUserData(items) => todo!(),
            SessionPduParameter::TransportDisconnectItem(transport_disconnect) => todo!(),
            SessionPduParameter::ReasonCodeItem(reason_code, items) => todo!(),
            SessionPduParameter::ReflectParameterValues(items) => todo!(),
            SessionPduParameter::Unknown(_, items) => todo!(),
            SessionPduParameter::VersionNumberParameter(supported_versions) => todo!(),
            SessionPduParameter::TsduMaximumSizeParameter(tsdu_maximum_size) => todo!(),
        }
    }

    Ok(data.into())
}

fn encode_length(length: usize) -> Result<Vec<u8>, IsoSpError> {
    if length > u16::MAX as usize {
        Err(IsoSpError::InternalError(format!("Parameter length is greater than max length {}", length)).into())
    } else if length < 255 {
        Ok(vec![length as u8])
    } else {
        let length_bytes = length.to_be_bytes();
        Ok(vec![0xFF, length_bytes[0], length_bytes[1]])
    }
}

fn encode_sub_parameters(parameters: &Vec<SessionPduSubParameter>) -> Vec<u8> {
    let mut data: VecDeque<u8> = VecDeque::new();

    for parameter in parameters {
        match parameter {
            SessionPduSubParameter::ProtocolOptionsParameter(protocol_options) => data.extend(vec![PROTOCOL_OPTIONS_PARAMETER_CODE, 0x01, protocol_options.0]),
            SessionPduSubParameter::VersionNumberParameter(supported_versions) => data.extend(vec![VERSION_NUMBER_PARAMETER_CODE, 0x01, supported_versions.0]),
            SessionPduSubParameter::TsduMaximumSizeParameter(tsdu_maximum_size) => todo!(),
            SessionPduSubParameter::SessionUserRequirements(session_user_requirements) => {
                data.extend(vec![SESSION_USER_REQUIREMENTS_PARAMETER_CODE, 0x02]);
                data.extend(session_user_requirements.0.to_be_bytes());
            }
            SessionPduSubParameter::Unknown(_, items) => todo!(),
        }
    }

    data.into()
}

fn into_parameters(data: &[u8]) -> Result<Vec<SessionPduParameter>, IsoSpError> {
    into_parameters_with_limit(data, usize::MAX)
}

fn into_parameters_with_limit(data: &[u8], slice_limit: usize) -> Result<Vec<SessionPduParameter>, IsoSpError> {
    let raw_parameters = slice_data(data, slice_limit)?;
    let mut parameters = Vec::new();

    for (parameter_tag, parameter_value) in raw_parameters {
        parameters.push(match parameter_tag {
            CONNECT_ACCEPT_ITEM_PARAMETER_CODE => SessionPduParameter::ConnectAcceptItem(into_sub_parameters(parameter_value)?),
            SESSION_USER_REQUIREMENTS_PARAMETER_CODE => SessionPduParameter::SessionUserRequirementsItem(parse_session_user_requirements(parameter_value)?),
            USER_DATA_PARAMETER_CODE => SessionPduParameter::UserData(parameter_value.to_vec()),
            DATA_OVERFLOW_PARAMETER_CODE => SessionPduParameter::DataOverflowItem(parse_data_overflow(data)?),
            EXTENDED_USER_DATA_PARAMETER_CODE => SessionPduParameter::ExtendedUserData(parameter_value.to_vec()),
            ENCLOSURE_ITEM_PARAMETER_CODE => SessionPduParameter::EnclosureItem(parse_enclosure_item(data)?),
            TRANSPORT_DISCONNECT_PARAMETER_CODE => SessionPduParameter::TransportDisconnectItem(parse_transport_disconnect(data)?),
            REASON_CODE_PARAMETER_CODE => parse_reason_code(data)?,
            REFLECT_PARAMETER_VALUES_PARAMETER_CODE => SessionPduParameter::ReflectParameterValues(data.to_vec()),
            REMAINING_DATA_VIRTUAL_PDU_CODE => SessionPduParameter::UserData(parameter_value.to_vec()),
            _ => SessionPduParameter::Unknown(parameter_tag, parameter_value.to_vec()),
        });
    }
    Ok(parameters)
}

fn into_sub_parameters(data: &[u8]) -> Result<Vec<SessionPduSubParameter>, IsoSpError> {
    let raw_parameters = slice_data(data, 0)?;
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

#[derive(Debug)]
pub enum SessionPduParameter {
    ConnectAcceptItem(Vec<SessionPduSubParameter>),
    SessionUserRequirementsItem(SessionUserRequirements),
    UserData(Vec<u8>),
    DataOverflowItem(DataOverflow),
    EnclosureItem(Enclosure),
    ExtendedUserData(Vec<u8>),
    TransportDisconnectItem(TransportDisconnect),
    ReasonCodeItem(ReasonCode, Vec<u8>),
    ReflectParameterValues(Vec<u8>),

    VersionNumberParameter(SupportedVersions),
    TsduMaximumSizeParameter(TsduMaximumSize),

    Unknown(u8, Vec<u8>),
}

#[derive(Debug)]
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

fn parse_enclosure_item(data: &[u8]) -> Result<Enclosure, IsoSpError> {
    verify_length("Enclosure Item", 1, data)?;
    Ok(Enclosure(data[0]))
}

fn parse_transport_disconnect(data: &[u8]) -> Result<TransportDisconnect, IsoSpError> {
    verify_length("Transport Disconnect", 1, data)?;
    Ok(TransportDisconnect(data[0]))
}

fn parse_reason_code(data: &[u8]) -> Result<SessionPduParameter, IsoSpError> {
    verify_length_greater("Reason Code", 0, data)?;
    Ok(SessionPduParameter::ReasonCodeItem(data[0].into(), data[1..].to_vec()))
}

fn verify_length(label: &str, expected_length: usize, data: &[u8]) -> Result<(), IsoSpError> {
    if expected_length != data.len() {
        return Err(IsoSpError::ProtocolError(format!("Invalid Length: {} - Expected {}, Got {}", label, expected_length, data.len())));
    }
    Ok(())
}

fn verify_length_greater(label: &str, expected_length: usize, data: &[u8]) -> Result<(), IsoSpError> {
    if expected_length >= data.len() {
        return Err(IsoSpError::ProtocolError(format!("Invalid Length: {} - Expected to be greater than {}, Got {}", label, expected_length, data.len())));
    }
    Ok(())
}

bitfield! {
    #[derive(Debug)]
    pub struct ProtocolOptions(u8);

    pub extended_concatenated_spdu_support, _ : 0;
    reserved, _ : 7, 1;
}

bitfield! {
    #[derive(Debug)]
    pub struct SupportedVersions(u8);

    pub version1, _ : 0;
    pub version2, _ : 1;
    reserved2, _ : 7, 2;
}

impl Default for SupportedVersions {
    fn default() -> Self {
        Self(0x01)
    }
}

bitfield! {
    // Zero means unlimited
    #[derive(Debug)]
    pub struct TsduMaximumSize(u32);

    pub u16, responder, _ : 0, 15;
    pub u16, initiator, _ : 16, 31;
}

bitfield! {
    #[derive(Debug)]
    pub struct SessionUserRequirements(u16);

    pub half_duplex, _ : 0;
    pub full_duplex, _ : 1;
    pub expedited, _ : 2;
    pub minor_synchronize, _ : 3;
    pub major_synchronize, _ : 4;
    pub resynchronize, _ : 5;
    pub activity_management, _ : 6;
    pub negotiated_release, _ : 7;
    pub capability_data, _ : 8;
    pub exceptions, _ : 9;
    pub typed_data, _ : 10;
    pub reserved, _ : 15, 11;
}

impl Default for SessionUserRequirements {
    fn default() -> Self {
        Self(0x0349) // Default as per X.225
    }
}

bitfield! {
    #[derive(Debug)]
    pub struct DataOverflow(u8);

    pub more_data, _ : 0; // The only valid value is true
    reserved, _ : 1, 7;
}

impl Default for DataOverflow {
    fn default() -> Self {
        Self(0x01)
    }
}

bitfield! {
    #[derive(Debug)]
    pub struct Enclosure(u8);

    begining, _ : 0; // The only valid value is false
    end, _ : 1;
    reserved, _ : 2, 7;
}

impl Default for Enclosure {
    fn default() -> Self {
        Self(0x00)
    }
}

bitfield! {
    #[derive(Debug)]
    pub struct TransportDisconnect(u8);

    keep_connection, _ : 0;
    user_abort, _ : 1;
    protocol_error, _ : 2;
    no_reason, _ : 3;
    implementation_restriction, _ : 4;
    reserved, _ : 5, 7;
}

#[derive(Debug)]
pub enum ReasonCode {
    RejectionByCalledSsUser,
    RejectionByCalledSsUserDueToTemporaryCongestion,
    RejectionByCalledSsUserWithData,
    SessionSelectorUnknown,
    SsUserNotAttachedToSsap,
    SpmCongestionAtConnectTime,
    ProposedProtocolVersionsNotSupported,
    RejectionByTheSpm,
    RejectionByTheSpm2,
    Unknown(u8),
}

impl From<u8> for ReasonCode {
    fn from(value: u8) -> Self {
        match value {
            0 => ReasonCode::RejectionByCalledSsUser,
            1 => ReasonCode::RejectionByCalledSsUserDueToTemporaryCongestion,
            2 => ReasonCode::RejectionByCalledSsUserWithData,
            129 => ReasonCode::SessionSelectorUnknown,
            130 => ReasonCode::SsUserNotAttachedToSsap,
            131 => ReasonCode::SpmCongestionAtConnectTime,
            132 => ReasonCode::ProposedProtocolVersionsNotSupported,
            133 => ReasonCode::RejectionByTheSpm,
            134 => ReasonCode::RejectionByTheSpm2,
            x => ReasonCode::Unknown(x),
        }
    }
}

fn slice_data(data: &[u8], slice_limit: usize) -> Result<Vec<(u8, &[u8])>, IsoSpError> {
    let mut offset = 0;
    let mut slice_count: usize = 0;
    let mut slices = Vec::new();

    while offset < data.len() && (slice_limit == 0 || slice_count < slice_limit) {
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
    if offset < data.len() {
        slices.push((0, &data[offset..]));
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
        let data_items = slice_data(&payload, 0)?;
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
        let data_items = slice_data(&payload, 0)?;
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

        let data_items = slice_data(&payload, 0)?;
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
