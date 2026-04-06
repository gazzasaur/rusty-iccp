use std::collections::VecDeque;

use rusty_cotp::{CotpReader, CotpWriter};

use crate::{
    CospError, ReasonCode, message::{CospMessage, refuse::RefuseMessage}, packet::{
        parameters::{EnclosureField, SessionPduParameter},
        pdu::SessionPduList,
    }, service::message::receive_message
};

// FIXME SPEC Support fragmented refuse payloads
pub(crate) async fn send_refuse(writer: &mut impl CotpWriter, reason_code: Option<&ReasonCode>) -> Result<(), CospError> {
    let payload_data = serialise_refuse(reason_code, None, None)?;
    return Ok(writer.send(&mut VecDeque::from(vec![payload_data])).await?);
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

pub(crate) async fn receive_refuse_with_all_user_data(reader: &mut impl CotpReader, refuse_message: RefuseMessage) -> Result<RefuseMessage, CospError> {
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
    }

    let reason_code = match has_data {
        true => Some(ReasonCode::RejectionByCalledSsUserWithData(buffer.drain(..).collect())),
        false => refuse_message.reason_code().cloned(),
    };
    Ok(RefuseMessage::new(false, reason_code))
}
