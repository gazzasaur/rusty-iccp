use std::{collections::VecDeque, net::SocketAddr};

use rusty_cotp::api::{CotpReader, CotpRecvResult, CotpWriter};
use tracing::warn;

use crate::{
    api::CospError,
    common::TsduMaximumSize,
    message::{accept::AcceptMessage, CospMessage},
    packet::{
        parameters::{DataOverflowField, EnclosureField, ProtocolOptionsField, SessionPduParameter, SessionUserRequirementsField, TsduMaximumSizeField, VersionNumberField},
        pdu::SessionPduList,
    },
};

const MAX_PAYLOAD_SIZE: usize = 65520; // Technically the maximum is 65528 but it seems to be an issue with some frameworks.

pub(crate) enum IcpIsoState {
    Connecting,
}

pub(crate) struct IcpIsoStateMachine {
    state: IcpIsoState,
}

impl Default for IcpIsoStateMachine {
    fn default() -> Self {
        Self { state: IcpIsoState::Connecting }
    }
}

pub(crate) enum SendConnectionRequestResult {
    Complete,
    Overflow(usize),
}

pub(crate) async fn send_connect_reqeust(writer: &mut impl CotpWriter<SocketAddr>, user_data: Option<&[u8]>) -> Result<SendConnectionRequestResult, CospError> {
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

pub(crate) async fn send_overflow_accept(writer: &mut impl CotpWriter<SocketAddr>, initiator_size: &TsduMaximumSize) -> Result<(), CospError> {
    let mut connect_accept_sub_parameters = Vec::new();
    if let TsduMaximumSize::Size(initiator_size) = initiator_size {
        // This will set the responder size to 0x0000 to indicate that we (the responder) accept unlimited size. But we also echo back the initiator size.
        connect_accept_sub_parameters.push(SessionPduParameter::TsduMaximumSizeParameter(TsduMaximumSizeField((*initiator_size as u32) << 16)));
    }
    connect_accept_sub_parameters.push(SessionPduParameter::VersionNumberParameter(VersionNumberField(2))); // Accept version 2

    let pdus = SessionPduList::new(
        vec![SessionPduParameter::OverflowAccept(vec![
            SessionPduParameter::ConnectAcceptItemParameter(connect_accept_sub_parameters),
            SessionPduParameter::SessionUserRequirementsParameter(SessionUserRequirementsField(2)), // Accept Full Duplex only
        ])],
        vec![],
    );
    Ok(writer.send(&pdus.serialise()?).await?)
}

// We do not really need to return anything here. We will inspect the accept payload at the end.
pub(crate) async fn receive_overflow_accept(reader: &mut impl CotpReader<SocketAddr>) -> Result<(), CospError> {
    let data = match reader.recv().await? {
        CotpRecvResult::Closed => return Err(CospError::ProtocolError("The transport connection was closed before the conection overflow was accepted.".into())),
        CotpRecvResult::Data(data) => data,
    };

    let mut pdus = SessionPduList::deserialise(&data)?;
    if pdus.session_pdus().len() > 1 {
        warn!("Received extra SPDUs on overflow accept. Ignoring the extra PDUs.");
    }
    let mut parameters = match pdus.session_pdus_mut().pop() {
        Some(SessionPduParameter::OverflowAccept(session_pdu_parameters)) => session_pdu_parameters,
        Some(pdu) => return Err(CospError::ProtocolError(format!("Expected an overflow accept but got {}", <SessionPduParameter as Into<&'static str>>::into(pdu)))),
        _ => return Err(CospError::ProtocolError("Cannot accept connection. The peer did not send data.".into())),
    };

    let mut version_number = None;
    let mut session_requirements = SessionUserRequirementsField::default();
    // Protocol options is not required as we are not going to send packets with extended concatenation.

    // Not minding about order or duplicates.
    for parameter in parameters.drain(..) {
        match parameter {
            SessionPduParameter::ConnectAcceptItemParameter(sub_parameters) => {
                for sub_parameter in sub_parameters {
                    match sub_parameter {
                        SessionPduParameter::VersionNumberParameter(value) => version_number = Some(value),
                        _ => (), // Technically, we should compare parameters with the follow-up accept, but it feels like too much. Ignore everything else.
                    }
                }
            }
            SessionPduParameter::SessionUserRequirementsParameter(value) => session_requirements = value,
            _ => (), // Ignore everything else.
        };
    }
    match version_number {
        Some(version) if version.version2() => (),
        _ => return Err(CospError::ProtocolError("Only version 2 is supported but version 1 was requested by the server in overflow accept.".into())),
    }
    if session_requirements.0 != 2 {
        // TODO Reject
        return Err(CospError::ProtocolError("More than the full duplex function was requested.".into()));
    }
    Ok(())
}

pub(crate) async fn send_connect_data_overflow(writer: &mut impl CotpWriter<SocketAddr>, data: &[u8]) -> Result<(), CospError> {
    let mut cursor = 0;

    while cursor < data.len() {
        let start_index = cursor;
        cursor += MAX_PAYLOAD_SIZE;
        let mut end_flag: u8 = 0;

        if cursor >= data.len() {
            cursor = data.len();
            end_flag = 1
        };

        writer
            .send(
                &SessionPduList::new(
                    vec![SessionPduParameter::ConnectDataOverflow(vec![
                        SessionPduParameter::EnclosureParameter(EnclosureField(2*end_flag)),
                        SessionPduParameter::UserDataParameter(data[start_index..cursor].to_vec()),
                    ])],
                    vec![],
                )
                .serialise()?,
            )
            .await?;
    }
    Ok(())
}

pub(crate) async fn receive_connect_data_overflow(reader: &mut impl CotpReader<SocketAddr>) -> Result<Vec<u8>, CospError> {
    let mut buffer = VecDeque::new();

    let mut has_more_data = true;
    while has_more_data {
        let message = receive_message(reader).await?;
        let cdo_message = match message {
            CospMessage::CDO(overflow_message) => overflow_message,
            _ => return Err(CospError::ProtocolError(format!("Expected a Connect Data Overflow message but got: {}", <CospMessage as Into<&'static str>>::into(message)))),
        };
        if let Some(user_data) = cdo_message.user_data() {
            buffer.extend(user_data);
        }
        has_more_data = cdo_message.has_more_data();
    }
    Ok(buffer.drain(..).collect())
}

pub(crate) async fn send_accept(writer: &mut impl CotpWriter<SocketAddr>, initiator_size: &TsduMaximumSize, user_data: Option<&[u8]>) -> Result<(), CospError> {
    const MAX_SPDU_SIZE: usize = 65539;

    // As we may need to send multiple accept payloads, we will precalculate the size of the header without enclosure.
    // Enclosure is a fixed 3 bytes which we only need to take into account if we are doing segmentation.
    let optimistic_accept = serialise_accept(initiator_size, None, Some(&[]))?;
    let requires_segmentation = optimistic_accept.len() > MAX_SPDU_SIZE;

    if !requires_segmentation {
        return Ok(writer.send(&optimistic_accept).await?);
    }

    let mut cursor = 0;
    let default_user_data = [];
    // The -2 accounts a 16-bit encoded length when the size is >254 bytes.
    let maximum_data_size = MAX_SPDU_SIZE - serialise_accept(initiator_size, Some(false), None)?.len() - 2;
    let user_data = match user_data {
        Some(user_data) => user_data,
        None => &default_user_data,
    };
    loop {
        let start_index = cursor;
        cursor = cursor + maximum_data_size;
        if cursor > user_data.len() {
            cursor = user_data.len()
        }

        writer.send(&serialise_accept(initiator_size, Some(cursor >= user_data.len()), Some(&user_data[start_index..cursor]))?).await?;
        if cursor >= user_data.len() {
            return Ok(());
        }
    }
}

pub(crate) fn serialise_accept(initiator_size: &TsduMaximumSize, is_last: Option<bool>, user_data: Option<&[u8]>) -> Result<Vec<u8>, CospError> {
    let mut connect_accept_sub_parameters = Vec::new();
    if let TsduMaximumSize::Size(initiator_size) = initiator_size {
        // This will set the responder size to 0x0000 to indicate that we accept unlimited size. But we also echo back the initiator size if it is not unlimited.
        connect_accept_sub_parameters.push(SessionPduParameter::TsduMaximumSizeParameter(TsduMaximumSizeField(*initiator_size as u32)));
    }
    connect_accept_sub_parameters.push(SessionPduParameter::VersionNumberParameter(VersionNumberField(2))); // Accept version 2

    let mut session_parameters = vec![
        SessionPduParameter::ConnectAcceptItemParameter(connect_accept_sub_parameters),
        SessionPduParameter::SessionUserRequirementsParameter(SessionUserRequirementsField(2)), // Accept Full Duplex only
    ];
    match (is_last, user_data) {
        (None, None) => (),
        (None, Some(user_data)) => {
            session_parameters.push(SessionPduParameter::UserDataParameter(user_data.to_vec()));
        }
        (Some(is_last), None) if is_last => {
            session_parameters.push(SessionPduParameter::EnclosureParameter(EnclosureField(2)));
            session_parameters.push(SessionPduParameter::UserDataParameter(vec![]));
        }
        (Some(_), None) => {
            session_parameters.push(SessionPduParameter::EnclosureParameter(EnclosureField(0)));
            session_parameters.push(SessionPduParameter::UserDataParameter(vec![]));
        }
        (Some(is_last), Some(user_data)) if is_last => {
            session_parameters.push(SessionPduParameter::EnclosureParameter(EnclosureField(2)));
            session_parameters.push(SessionPduParameter::UserDataParameter(user_data.to_vec()));
        }
        (Some(_), Some(user_data)) => {
            session_parameters.push(SessionPduParameter::EnclosureParameter(EnclosureField(0)));
            session_parameters.push(SessionPduParameter::UserDataParameter(user_data.to_vec()));
        }
    }

    SessionPduList::new(vec![SessionPduParameter::Accept(session_parameters)], vec![]).serialise()
}

pub(crate) async fn receive_accept_with_all_user_data(reader: &mut impl CotpReader<SocketAddr>) -> Result<AcceptMessage, CospError> {
    let message = receive_message(reader).await?;
    let accept_message = match message {
        CospMessage::AC(accept_message) => accept_message,
        _ => return Err(CospError::ProtocolError(format!("Expected an Accept message but got: {}", <CospMessage as Into<&'static str>>::into(message)))),
    };

    let mut buffer = VecDeque::new();
    let has_data = accept_message.user_data().is_some();
    let mut has_more_data = accept_message.has_more_data();
    if let Some(user_data) = accept_message.user_data() {
        buffer.extend(user_data);
    }

    while has_more_data {
        let message = receive_message(reader).await?;
        let accept_message = match message {
            CospMessage::AC(accept_message) => accept_message,
            _ => return Err(CospError::ProtocolError(format!("Expected an Accept message but got: {}", <CospMessage as Into<&'static str>>::into(message)))),
        };

        has_more_data = accept_message.has_more_data();
        if let Some(user_data) = accept_message.user_data() {
            buffer.extend(user_data);
        }
    }

    let user_data = match has_data {
        true => Some(buffer.drain(..).collect()),
        false => None,
    };
    Ok(AcceptMessage::new(false, *accept_message.maximum_size_to_responder(), user_data))
}

pub(crate) async fn receive_message(reader: &mut impl CotpReader<SocketAddr>) -> Result<CospMessage, CospError> {
    let data = match reader.recv().await? {
        CotpRecvResult::Closed => return Err(CospError::ProtocolError("The transport connection was closed before the conection could be established.".into())),
        CotpRecvResult::Data(data) => data,
    };
    CospMessage::from_spdu_list(SessionPduList::deserialise(&data)?)
}
