use std::collections::VecDeque;

use rusty_cotp::{CotpReader, CotpWriter};

use crate::{
    CospError,
    message::{CospMessage, accept::AcceptMessage, parameters::TsduMaximumSize},
    packet::{
        parameters::{EnclosureField, SessionPduParameter, SessionUserRequirementsField, TsduMaximumSizeField, VersionNumberField},
        pdu::SessionPduList,
    },
    service::message::{MAX_PAYLOAD_SIZE, receive_message},
};

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
