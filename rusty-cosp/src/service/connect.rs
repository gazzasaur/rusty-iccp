use rusty_cotp::CotpWriter;

use crate::{
    api::{CospConnectionInformation, CospError},
    packet::{
        parameters::{DataOverflowField, ProtocolOptionsField, SessionPduParameter, SessionUserRequirementsField, TsduMaximumSizeField, VersionNumberField},
        pdu::SessionPduList,
    },
};

pub(crate) enum SendConnectionRequestResult {
    Complete,
    Overflow(usize),
}

pub(crate) async fn send_connect_reqeust(writer: &mut impl CotpWriter, options: CospConnectionInformation, user_data: Option<&[u8]>) -> Result<SendConnectionRequestResult, CospError> {
    const MAX_USER_DATA_PAYLOAD_SIZE: usize = 512;
    const MAX_EXTENDED_USER_DATA_PAYLOAD_SIZE: usize = 10240;

    let mut connect_accept_parameters = vec![
        SessionPduParameter::ProtocolOptionsParameter(ProtocolOptionsField(2)), // Only set the duplex functionall unit
        SessionPduParameter::VersionNumberParameter(VersionNumberField(2)),     // Version 2 only
    ];
    if let Some(size) = options.tsdu_maximum_size {
        connect_accept_parameters.push(SessionPduParameter::TsduMaximumSizeParameter(TsduMaximumSizeField::new(size, 0)));
    }

    let mut parameters = vec![
        SessionPduParameter::ConnectAcceptItemParameter(connect_accept_parameters),
        SessionPduParameter::SessionUserRequirementsParameter(SessionUserRequirementsField(2)), // Full Duplex only
    ];
    match options.calling_session_selector {
        Some(calling_session) => parameters.push(SessionPduParameter::CallingSessionSelectorParameter(calling_session)),
        None => todo!(),
    };
    if let Some(called_session) = options.called_session_selector {
        parameters.push(SessionPduParameter::CalledSessionSelectorParameter(called_session));
    }
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
