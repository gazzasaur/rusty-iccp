use std::collections::VecDeque;

use rusty_cotp::{CotpReader, CotpWriter};

use crate::{
    CospConnectionParameters, CospError, ReasonCode, message::{CospMessage, parameters::TsduMaximumSize, refuse::RefuseMessage}, packet::{
        parameters::{EnclosureField, SessionPduParameter},
        pdu::SessionPduList,
    }, service::message::{MAX_PAYLOAD_SIZE, receive_message}
};

pub(crate) async fn send_refuse(writer: &mut impl CotpWriter, negotiated_size: TsduMaximumSize, reason_code: Option<&ReasonCode>) -> Result<(), CospError> {
    // As we may need to send multiple refuse payloads, we will precalculate the size of the header without enclosure.
    let optimistic_refuse = serialise_refuse(None, None, None)?;

    let calculated_max_payload_size = match negotiated_size {
        TsduMaximumSize::Unlimited => MAX_PAYLOAD_SIZE,
        TsduMaximumSize::Size(x) => x as usize,
    };

    // Fetch the user data that is included in the Ss User reason
    let user_data = match reason_code {
        Some(ReasonCode::RejectionByCalledSsUserWithData(user_data)) => Some(user_data),
        _ => None,
    };

    // Add an extra 8 bytes for enclosure and headers.
    let optimistic_size = optimistic_refuse.len() + user_data.as_ref().map(|data| data.len()).unwrap_or(0) + 8;

    if !matches!(reason_code, Some(ReasonCode::RejectionByCalledSsUserWithData(_))) || optimistic_size <= calculated_max_payload_size {
        let payload_data = serialise_refuse(reason_code, None, None)?;
        return Ok(writer.send(&mut VecDeque::from(vec![payload_data])).await?);
    }

    let mut cursor = 0;
    let mut beginning = true;
    let default_user_data = &vec![];
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

        let payload_data = serialise_refuse(Some(&ReasonCode::RejectionByCalledSsUserWithData(user_data[start_index..cursor].to_vec())), Some(beginning), Some(cursor >= user_data.len()))?;
        writer.send(&mut VecDeque::from(vec![payload_data])).await?;
        if cursor >= user_data.len() {
            return Ok(());
        }
        beginning = false;
    }
}

pub(crate) fn serialise_refuse(reason_code: Option<&ReasonCode>, is_first: Option<bool>, is_last: Option<bool>) -> Result<Vec<u8>, CospError> {
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
    if let Some(reason_code) = reason_code {
        session_parameters.push(SessionPduParameter::ReasonCodeParameter(reason_code.clone()));
    }

    SessionPduList::new(vec![SessionPduParameter::Refuse(session_parameters)], vec![]).serialise()
}

pub(crate) async fn receive_refuse_with_all_user_data(reader: &mut impl CotpReader, refuse_message: RefuseMessage, connection_options: &CospConnectionParameters) -> Result<RefuseMessage, CospError> {
    let mut buffer = VecDeque::new();
    let has_data = match refuse_message.reason_code() {
        Some(ReasonCode::RejectionByCalledSsUserWithData(_)) => true,
        _ => false,
    };

    let mut has_more_data = refuse_message.has_more_data();
    if let Some(ReasonCode::RejectionByCalledSsUserWithData(user_data)) = refuse_message.reason_code() {
        buffer.extend(user_data);
    }

    while has_more_data {
        let message = receive_message(reader).await?;
        let refuse_message = match message {
            CospMessage::RF(refuse_message) => refuse_message,
            _ => return Err(CospError::ProtocolError(format!("Expected an Refuse message but got: {}", <CospMessage as Into<&'static str>>::into(message)))),
        };

        has_more_data = refuse_message.has_more_data();
        if let Some(ReasonCode::RejectionByCalledSsUserWithData(user_data)) = refuse_message.reason_code() {
            buffer.extend(user_data);
        }

        if buffer.len() > connection_options.maximum_reassembled_payload_size {
            return Err(CospError::ProtocolError("Message length is exceeds maximum payload size.".into()))
        }
    }

    let reason_code = match has_data {
        true => Some(ReasonCode::RejectionByCalledSsUserWithData(buffer.drain(..).collect())),
        false => refuse_message.reason_code().cloned(),
    };
    Ok(RefuseMessage::new(false, reason_code))
}
