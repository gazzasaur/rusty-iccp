use std::collections::VecDeque;

use rusty_cotp::{CotpReader, CotpRecvResult, CotpWriter};

use crate::{
    api::CospError,
    message::{CospMessage, accept::AcceptMessage, connect::ConnectMessage, overflow_accept::OverflowAcceptMessage, parameters::TsduMaximumSize},
    packet::{
        parameters::{DataOverflowField, EnclosureField, ProtocolOptionsField, SessionPduParameter, SessionUserRequirementsField, TsduMaximumSizeField, VersionNumberField},
        pdu::SessionPduList,
    },
};

pub(crate) enum SendConnectionRequestResult {
    Complete,
    Overflow(usize),
}

pub(crate) async fn send_connect_reqeust(writer: &mut impl CotpWriter, user_data: Option<&[u8]>) -> Result<SendConnectionRequestResult, CospError> {
    const MAX_USER_DATA_PAYLOAD_SIZE: usize = 512;
    const MAX_EXTENDED_USER_DATA_PAYLOAD_SIZE: usize = 10240;

    let mut parameters = vec![
        SessionPduParameter::ConnectAcceptItemParameter(vec![
            SessionPduParameter::ProtocolOptionsParameter(ProtocolOptionsField(2)), // Only set the duplex functionall unit
            SessionPduParameter::VersionNumberParameter(VersionNumberField(2)),     // Version 2 only
        ]),
        SessionPduParameter::SessionUserRequirementsParameter(SessionUserRequirementsField(2)), // Full Duplex only
    ];
    let overflow_length = match user_data {
        Some(user_data) if user_data.len() <= MAX_USER_DATA_PAYLOAD_SIZE => {
            parameters.push(SessionPduParameter::UserDataParameter(user_data.to_vec()));
            0
        }
        Some(user_data) if user_data.len() <= MAX_EXTENDED_USER_DATA_PAYLOAD_SIZE => {
            parameters.push(SessionPduParameter::ExtendedUserDataParameter(user_data.to_vec()));
            0
        }
        Some(user_data) => {
            parameters.push(SessionPduParameter::DataOverflowParameter(DataOverflowField(1)));
            parameters.push(SessionPduParameter::ExtendedUserDataParameter(user_data[..MAX_EXTENDED_USER_DATA_PAYLOAD_SIZE].to_vec()));
            MAX_EXTENDED_USER_DATA_PAYLOAD_SIZE
        }
        None => 0,
    };

    let pdus = SessionPduList::new(vec![SessionPduParameter::Connect(parameters)], vec![]);
    writer.send(&pdus.serialise()?).await?;
    Ok(match overflow_length {
        0 => SendConnectionRequestResult::Complete,
        _ => SendConnectionRequestResult::Overflow(overflow_length),
    })
}
