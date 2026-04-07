use std::collections::VecDeque;

use rusty_cotp::{CotpReader, CotpWriter};

use crate::{
    CospConnectionParameters, CospError, message::{CospMessage, finish::FinishMessage, parameters::TsduMaximumSize}, packet::{
        parameters::{EnclosureField, SessionPduParameter},
        pdu::SessionPduList,
    }, service::message::{MAX_PAYLOAD_SIZE, receive_message}
};

pub(crate) async fn send_finish(writer: &mut impl CotpWriter, negotiated_size: TsduMaximumSize, user_data: Option<Vec<u8>>) -> Result<(), CospError> {
    // As we may need to send multiple finish payloads, we will precalculate the size of the header without enclosure.
    let optimistic_finish = serialise_finish(None, None, Some(&[]))?;
    // Add an extra 8 bytes for enclosure and headers.
    let optimistic_size = optimistic_finish.len() + user_data.as_ref().map(|data| data.len()).unwrap_or(0) + 8;

    let calculated_max_payload_size = match negotiated_size {
        TsduMaximumSize::Unlimited => MAX_PAYLOAD_SIZE,
        TsduMaximumSize::Size(x) => x as usize,
    };

    if optimistic_size <= calculated_max_payload_size {
        let payload_data = serialise_finish(None, None, user_data.as_ref().map(|x| x.as_slice()))?;
        return Ok(writer.send(&mut VecDeque::from(vec![payload_data])).await?);
    }

    let mut cursor = 0;
    let mut beginning = true;
    let default_user_data = vec![];
    // The -2 accounts a 16-bit encoded length when the size is >254 bytes.
    let maximum_data_size = calculated_max_payload_size;
    let user_data = match user_data {
        Some(user_data) => user_data,
        None => default_user_data,
    };
    loop {
        let start_index = cursor;
        cursor = cursor + maximum_data_size;
        if cursor > user_data.len() {
            cursor = user_data.len()
        }

        let payload_data = serialise_finish(Some(beginning), Some(cursor >= user_data.len()), Some(&user_data[start_index..cursor]))?;
        writer.send(&mut VecDeque::from(vec![payload_data])).await?;
        if cursor >= user_data.len() {
            return Ok(());
        }
        beginning = false;
    }
}

pub(crate) fn serialise_finish(is_first: Option<bool>, is_last: Option<bool>, user_data: Option<&[u8]>) -> Result<Vec<u8>, CospError> {
    let mut session_parameters = vec![];
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

    SessionPduList::new(vec![SessionPduParameter::Finish(session_parameters)], vec![]).serialise()
}

pub(crate) async fn receive_finish_with_all_user_data(reader: &mut impl CotpReader, finish_message: FinishMessage, connection_options: &CospConnectionParameters) -> Result<FinishMessage, CospError> {
    let mut buffer = VecDeque::new();
    let has_data = finish_message.user_data().is_some();
    let mut has_more_data = finish_message.has_more_data();
    if let Some(user_data) = finish_message.user_data() {
        buffer.extend(user_data);
    }

    while has_more_data {
        let message = receive_message(reader).await?;
        let finish_message = match message {
            CospMessage::FN(finish_message) => finish_message,
            _ => return Err(CospError::ProtocolError(format!("Expected an Finish message but got: {}", <CospMessage as Into<&'static str>>::into(message)))),
        };

        has_more_data = finish_message.has_more_data();
        if let Some(user_data) = finish_message.user_data() {
            buffer.extend(user_data);
        }

        if buffer.len() > connection_options.maximum_reassembled_payload_size {
            return Err(CospError::ProtocolError("Message length is exceeds maximum payload size.".into()))
        }
    }

    let user_data = match has_data {
        true => Some(buffer.drain(..).collect()),
        false => None,
    };
    Ok(FinishMessage::new(false, user_data))
}
