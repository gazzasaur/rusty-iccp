use std::{collections::VecDeque, net::SocketAddr};

use rusty_cotp::{CotpReader, CotpRecvResult, CotpWriter};

use crate::{
    api::CospError,
    common::TsduMaximumSize,
    message::{CospMessage, accept::AcceptMessage, overflow_accept::OverflowAcceptMessage},
    packet::{
        parameters::{DataOverflowField, EnclosureField, ProtocolOptionsField, SessionPduParameter, SessionUserRequirementsField, TsduMaximumSizeField, VersionNumberField},
        pdu::SessionPduList,
    },
};

const MAX_PAYLOAD_SIZE: usize = 65510; // Technically the maximum is 65528 but it seems to be an issue with some frameworks. Leaving buffer with this one.

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

pub(crate) async fn send_overflow_accept(writer: &mut impl CotpWriter, initiator_size: &TsduMaximumSize) -> Result<(), CospError> {
    let mut sub_parameters = Vec::new();
    if let TsduMaximumSize::Size(initiator_size) = initiator_size {
        // This will set the responder size to 0x0000 to indicate that we (the responder) accept unlimited size. But we also echo back the initiator size.
        sub_parameters.push(SessionPduParameter::TsduMaximumSizeParameter(TsduMaximumSizeField((*initiator_size as u32) << 16)));
    }
    sub_parameters.push(SessionPduParameter::VersionNumberParameter(VersionNumberField(2))); // Accept version 2

    let pdus = SessionPduList::new(vec![SessionPduParameter::OverflowAccept(sub_parameters)], vec![]);
    Ok(writer.send(&pdus.serialise()?).await?)
}

// We do not really need to return anything here. We will inspect the accept payload at the end.
pub(crate) async fn receive_overflow_accept(reader: &mut impl CotpReader) -> Result<OverflowAcceptMessage, CospError> {
    let message = receive_message(reader).await?;
    let overflow_accept_message = match message {
        CospMessage::OA(accept_message) => accept_message,
        _ => return Err(CospError::ProtocolError(format!("Expected an Overflow Accept message but got: {}", <CospMessage as Into<&'static str>>::into(message)))),
    };
    Ok(overflow_accept_message)
}

pub(crate) async fn send_connect_data_overflow(writer: &mut impl CotpWriter, data: &[u8]) -> Result<(), CospError> {
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
                        SessionPduParameter::EnclosureParameter(EnclosureField(2 * end_flag)),
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

pub(crate) async fn receive_connect_data_overflow(reader: &mut impl CotpReader) -> Result<Vec<u8>, CospError> {
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

pub(crate) async fn send_accept(writer: &mut impl CotpWriter, initiator_size: &TsduMaximumSize, user_data: Option<&[u8]>) -> Result<(), CospError> {
    // As we may need to send multiple accept payloads, we will precalculate the size of the header without enclosure.
    let optimistic_accept = serialise_accept(initiator_size, None, None, Some(&[]))?;
    // Add an extra 8 bytes for enclosure and headers.
    let optimistic_size = optimistic_accept.len() + user_data.map(|data| data.len()).unwrap_or(0) + 8;

    if optimistic_size <= MAX_PAYLOAD_SIZE {
        return Ok(writer.send(&serialise_accept(initiator_size, None, None, user_data)?).await?);
    }

    let mut cursor = 0;
    let mut beginning = true;
    let default_user_data = [];
    // The -2 accounts a 16-bit encoded length when the size is >254 bytes.
    let maximum_data_size = MAX_PAYLOAD_SIZE;
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

        writer.send(&serialise_accept(initiator_size, Some(beginning), Some(cursor >= user_data.len()), Some(&user_data[start_index..cursor]))?).await?;
        if cursor >= user_data.len() {
            return Ok(());
        }
        beginning = false;
    }
}

pub(crate) fn serialise_accept(initiator_size: &TsduMaximumSize, is_first: Option<bool>, is_last: Option<bool>, user_data: Option<&[u8]>) -> Result<Vec<u8>, CospError> {
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
    let enclosure_value = match is_first {
        Some(value) if value => 1,
        _ => 0,
    } + match is_last {
        Some(value) if value => 2,
        _ => 0,
    };
    match (is_first, is_last) {
        (Some(_), _) => session_parameters.push(SessionPduParameter::EnclosureParameter(EnclosureField(enclosure_value))),
        (_, Some(_)) => session_parameters.push(SessionPduParameter::EnclosureParameter(EnclosureField(enclosure_value))),
        (_, _) => (),
    };
    if let Some(user_data) = user_data {
        session_parameters.push(SessionPduParameter::UserDataParameter(user_data.to_vec()));
    }

    SessionPduList::new(vec![SessionPduParameter::Accept(session_parameters)], vec![]).serialise()
}

pub(crate) async fn receive_accept_with_all_user_data(reader: &mut impl CotpReader) -> Result<AcceptMessage, CospError> {
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

pub(crate) async fn receive_message(reader: &mut impl CotpReader) -> Result<CospMessage, CospError> {
    let data = match reader.recv().await? {
        CotpRecvResult::Closed => return Err(CospError::ProtocolError("The transport connection was closed before the conection could be established.".into())),
        CotpRecvResult::Data(data) => data,
    };
    CospMessage::from_spdu_list(SessionPduList::deserialise(&data)?)
}
