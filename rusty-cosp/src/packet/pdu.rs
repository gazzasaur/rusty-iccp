use std::collections::VecDeque;

use bitfield::bitfield;
use rusty_cotp::packet::data_transfer::DataTransfer;
use tracing::warn;

use crate::{
    api::CospError,
    common::slice_tlv_data,
    packet::{
        constants::{
            ACCEPT_SI_CODE, CONNECT_ACCEPT_ITEM_PARAMETER_CODE, CONNECT_DATA_OVERFLOW_SI_CODE, CONNECT_SI_CODE, DATA_OVERFLOW_PARAMETER_CODE, DATA_TRANSFER_SI_CODE, ENCLOSURE_PARAMETER_CODE, EXTENDED_USER_DATA_PARAMETER_CODE,
            GIVE_TOKENS_SI_CODE, OVERFLOW_ACCEPT_SI_CODE, PROTOCOL_OPTIONS_PARAMETER_CODE, SESSION_USER_REQUIREMENTS_PARAMETER_CODE, TSDU_MAXIMUM_SIZE_PARAMETER_CODE, VERSION_NUMBER_PARAMETER_CODE,
        },
        parameters::{DataOverflowField, EnclosureField, ProtocolOptionsField, ReasonCode, SessionPduParameter, SessionUserRequirementsField, TsduMaximumSizeField, VersionNumberField, encode_length},
    },
    serialise_parameter_value,
};

#[derive(Debug)]
pub(crate) struct SessionPduList {
    session_pdus: Vec<SessionPduParameter>,
    user_information: Vec<u8>,
}

impl SessionPduList {
    pub(crate) fn new(session_pdus: Vec<SessionPduParameter>, user_information: Vec<u8>) -> Self {
        Self { session_pdus, user_information }
    }

    pub(crate) fn session_pdus(&self) -> &[SessionPduParameter] {
        &self.session_pdus
    }

    pub(crate) fn session_pdus_mut(&mut self) -> &mut Vec<SessionPduParameter> {
        &mut self.session_pdus
    }

    pub(crate) fn user_information(&self) -> &[u8] {
        self.user_information.as_slice()
    }

    pub(crate) fn serialise(&self) -> Result<Vec<u8>, CospError> {
        let mut buffer: VecDeque<u8> = VecDeque::new();
        buffer.extend(serialise_parameters(self.session_pdus())?);
        buffer.extend(self.user_information());
        Ok(buffer.into_iter().collect())
    }

    pub(crate) fn deserialise(data: &[u8]) -> Result<Self, CospError> {
        let (session_pdus, user_information_offset) = deserialise_parameters(data)?;
        let user_information = data[user_information_offset..].to_vec();
        Ok(SessionPduList::new(session_pdus, user_information))
    }
}

fn serialise_parameters(parameters: &[SessionPduParameter]) -> Result<Vec<u8>, CospError> {
    let mut buffer = VecDeque::new();

    for parameter in parameters {
        buffer.extend(match parameter {
            SessionPduParameter::Connect(sub_parameters) => serialise_composite_parameter(CONNECT_SI_CODE, &sub_parameters)?,
            SessionPduParameter::OverflowAccept(sub_parameters) => serialise_composite_parameter(OVERFLOW_ACCEPT_SI_CODE, &sub_parameters)?,
            SessionPduParameter::ConnectDataOverflow(sub_parameters) => serialise_composite_parameter(CONNECT_DATA_OVERFLOW_SI_CODE, &sub_parameters)?,
            SessionPduParameter::Accept(sub_parameters) => serialise_composite_parameter(ACCEPT_SI_CODE, &sub_parameters)?,
            SessionPduParameter::DataTransfer(sub_parameters) => serialise_composite_parameter(DATA_TRANSFER_SI_CODE, &sub_parameters)?,

            SessionPduParameter::GiveTokens() => vec![GIVE_TOKENS_SI_CODE, 00],

            SessionPduParameter::ConnectAcceptItemParameter(sub_parameters) => serialise_composite_parameter(CONNECT_ACCEPT_ITEM_PARAMETER_CODE, &sub_parameters)?,

            SessionPduParameter::ProtocolOptionsParameter(field) => serialise_parameter_value!(PROTOCOL_OPTIONS_PARAMETER_CODE, field.0)?,
            SessionPduParameter::TsduMaximumSizeParameter(field) => serialise_parameter_value!(TSDU_MAXIMUM_SIZE_PARAMETER_CODE, field.0)?,
            SessionPduParameter::VersionNumberParameter(field) => serialise_parameter_value!(VERSION_NUMBER_PARAMETER_CODE, field.0)?,
            SessionPduParameter::ReasonCodeParameter(reason_code) => reason_code.try_into()?,
            SessionPduParameter::SessionUserRequirementsParameter(field) => serialise_parameter_value!(SESSION_USER_REQUIREMENTS_PARAMETER_CODE, field.0)?,
            SessionPduParameter::UserDataParameter(data) => serialise_data_parameter(SESSION_USER_REQUIREMENTS_PARAMETER_CODE, data)?,
            SessionPduParameter::ExtendedUserDataParameter(data) => serialise_data_parameter(EXTENDED_USER_DATA_PARAMETER_CODE, data)?,
            SessionPduParameter::DataOverflowParameter(field) => serialise_parameter_value!(DATA_OVERFLOW_PARAMETER_CODE, field.0)?,
            SessionPduParameter::Enclosure(field) => serialise_parameter_value!(ENCLOSURE_PARAMETER_CODE, field.0)?,

            SessionPduParameter::Unknown => todo!(),
        });
    }
    Ok(buffer.drain(..).collect())
}

fn serialise_composite_parameter(code: u8, sub_parameters: &[SessionPduParameter]) -> Result<Vec<u8>, CospError> {
    let mut buffer = VecDeque::new();

    let sub_parameter_data = serialise_parameters(sub_parameters)?;
    buffer.push_back(code);
    buffer.extend(encode_length(sub_parameter_data.len())?);
    buffer.extend(sub_parameter_data);

    Ok(buffer.drain(..).collect())
}

fn serialise_data_parameter(code: u8, data: &[u8]) -> Result<Vec<u8>, CospError> {
    let mut buffer = VecDeque::new();

    buffer.push_back(code);
    buffer.extend(encode_length(data.len())?);
    buffer.extend(data);

    Ok(buffer.drain(..).collect())
}

fn deserialise_parameters(data: &[u8]) -> Result<(Vec<SessionPduParameter>, usize), CospError> {
    let mut offset = 0;
    let mut parameters = VecDeque::new();

    while offset < data.len() {
        let (tag, payload, consumed_data) = slice_tlv_data(&data[offset..])?;
        offset += consumed_data;

        let parameter = match tag {
            CONNECT_SI_CODE => SessionPduParameter::Connect(deserialise_parameters(payload)?.0),
            ACCEPT_SI_CODE => SessionPduParameter::Accept(deserialise_parameters(payload)?.0),

            // Category 0 message. Must always be the the first SPDU in a concatenated list. Otherwise it is a Data Transfer. Their SI codes are the same.
            GIVE_TOKENS_SI_CODE if parameters.len() == 0 => SessionPduParameter::GiveTokens(),
            // Category 2 message. Must come after Give Tokens. Their SI codes are the same.
            DATA_TRANSFER_SI_CODE => SessionPduParameter::DataTransfer(deserialise_parameters(payload)?.0),

            CONNECT_ACCEPT_ITEM_PARAMETER_CODE => SessionPduParameter::ConnectAcceptItemParameter(deserialise_parameters(payload)?.0),

            PROTOCOL_OPTIONS_PARAMETER_CODE => SessionPduParameter::ProtocolOptionsParameter(parse_protocol_options(payload)?),
            TSDU_MAXIMUM_SIZE_PARAMETER_CODE => SessionPduParameter::TsduMaximumSizeParameter(parse_tsdu_maximum_size(payload)?),
            SESSION_USER_REQUIREMENTS_PARAMETER_CODE => SessionPduParameter::SessionUserRequirementsParameter(parse_session_user_requirements(payload)?),
            VERSION_NUMBER_PARAMETER_CODE => SessionPduParameter::VersionNumberParameter(parse_version_number(payload)?),

            // USER_DATA_PARAMETER_CODE => SessionPduParameter::UserData(parameter_value.to_vec()),
            // DATA_OVERFLOW_PARAMETER_CODE => SessionPduParameter::DataOverflowItem(parse_data_overflow(data)?),
            // EXTENDED_USER_DATA_PARAMETER_CODE => SessionPduParameter::ExtendedUserData(parameter_value.to_vec()),
            // ENCLOSURE_ITEM_PARAMETER_CODE => SessionPduParameter::EnclosureItem(parse_enclosure_item(data)?),
            // TRANSPORT_DISCONNECT_PARAMETER_CODE => SessionPduParameter::TransportDisconnectItem(parse_transport_disconnect(data)?),
            // REASON_CODE_PARAMETER_CODE => parse_reason_code(data)?,
            // REFLECT_PARAMETER_VALUES_PARAMETER_CODE => SessionPduParameter::ReflectParameterValues(data.to_vec()),
            // REMAINING_DATA_VIRTUAL_PDU_CODE => SessionPduParameter::UserData(parameter_value.to_vec()),
            unknown_code => {
                warn!("Unknown parameter code: {}", unknown_code);
                SessionPduParameter::Unknown
            }
        };
        if let SessionPduParameter::DataTransfer(_) = parameter {
            parameters.push_back(parameter);
            break;
        }
        parameters.push_back(parameter);
    }
    Ok((parameters.drain(..).collect(), offset))
}

fn parse_protocol_options(data: &[u8]) -> Result<ProtocolOptionsField, CospError> {
    verify_length("Protocol Parameters", 1, data)?;
    Ok(ProtocolOptionsField(data[0]))
}

fn parse_tsdu_maximum_size(data: &[u8]) -> Result<TsduMaximumSizeField, CospError> {
    verify_length("TSDU Maximum Size", 4, data)?;
    Ok(TsduMaximumSizeField(u32::from_be_bytes(data.try_into().map_err(|e: std::array::TryFromSliceError| CospError::ProtocolError(e.to_string()))?)))
}

fn parse_session_user_requirements(data: &[u8]) -> Result<SessionUserRequirementsField, CospError> {
    verify_length("Session User Requirements", 2, data)?;
    Ok(SessionUserRequirementsField(u16::from_be_bytes(
        data.try_into().map_err(|e: std::array::TryFromSliceError| CospError::ProtocolError(e.to_string()))?,
    )))
}

fn parse_version_number(data: &[u8]) -> Result<VersionNumberField, CospError> {
    verify_length("Protocol Parameters", 1, data)?;
    Ok(VersionNumberField(data[0]))
}

fn parse_data_overflow(data: &[u8]) -> Result<DataOverflowField, CospError> {
    verify_length("Data Overflow", 1, data)?;
    Ok(DataOverflowField(data[0]))
}

fn parse_enclosure_item(data: &[u8]) -> Result<EnclosureField, CospError> {
    verify_length("Enclosure Field", 1, data)?;
    Ok(EnclosureField(data[0]))
}

fn parse_transport_disconnect(data: &[u8]) -> Result<TransportDisconnect, CospError> {
    verify_length("Transport Disconnect", 1, data)?;
    Ok(TransportDisconnect(data[0]))
}

fn parse_reason_code(data: &[u8]) -> Result<SessionPduParameter, CospError> {
    verify_length_greater("Reason Code", 0, data)?;
    Ok(SessionPduParameter::ReasonCodeParameter(ReasonCode::new(data[1], &data[1..])))
}

fn verify_length(label: &str, expected_length: usize, data: &[u8]) -> Result<(), CospError> {
    if expected_length != data.len() {
        return Err(CospError::ProtocolError(format!("Invalid Length: {} - Expected {}, Got {}", label, expected_length, data.len())));
    }
    Ok(())
}

fn verify_length_greater(label: &str, expected_length: usize, data: &[u8]) -> Result<(), CospError> {
    if expected_length >= data.len() {
        return Err(CospError::ProtocolError(format!("Invalid Length: {} - Expected to be greater than {}, Got {}", label, expected_length, data.len())));
    }
    Ok(())
}

bitfield! {
    #[derive(Debug)]
    pub(crate) struct TransportDisconnect(u8);

    keep_connection, _ : 0;
    user_abort, _ : 1;
    protocol_error, _ : 2;
    no_reason, _ : 3;
    implementation_restriction, _ : 4;
    reserved, _ : 5, 7;
}
