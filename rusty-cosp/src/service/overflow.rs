use std::collections::VecDeque;

use rusty_cotp::{CotpReader, CotpWriter};

use crate::{
    api::CospError,
    message::{CospMessage, overflow_accept::OverflowAcceptMessage, parameters::TsduMaximumSize},
    packet::{
        parameters::{EnclosureField, SessionPduParameter, TsduMaximumSizeField, VersionNumberField},
        pdu::SessionPduList,
    },
    service::{MAX_PAYLOAD_SIZE, MIN_PAYLOAD_SIZE, receive_message},
};

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

pub(crate) async fn send_connect_data_overflow(writer: &mut impl CotpWriter, max_tsdu_size: TsduMaximumSize, data: &[u8]) -> Result<(), CospError> {
    let mut cursor = 0;
    let payload_length = match max_tsdu_size {
        TsduMaximumSize::Unlimited => MAX_PAYLOAD_SIZE,
        TsduMaximumSize::Size(x) => usize::max(MIN_PAYLOAD_SIZE, usize::min(x as usize, MAX_PAYLOAD_SIZE)),
    };

    while cursor < data.len() {
        let start_index = cursor;
        cursor += payload_length;
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
