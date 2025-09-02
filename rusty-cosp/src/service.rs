use std::{collections::VecDeque, net::SocketAddr};

use rusty_cotp::api::{CotpReader, CotpRecvResult, CotpWriter};
use tracing::{trace, warn};

use crate::{
    api::IsoSpError, common::TsduMaximumSize, message::{connect::ConnectMessage, CospMessage}, packet::{
        parameters::{DataOverflowField, EnclosureField, ProtocolOptionsField, SessionPduParameter, SessionUserRequirementsField, TsduMaximumSizeField, VersionNumberField},
        pdu::SessionPduList,
    }
};

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

pub(crate) async fn send_connect_reqeust(writer: &mut impl CotpWriter<SocketAddr>, user_data: Option<&[u8]>) -> Result<SendConnectionRequestResult, IsoSpError> {
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

pub(crate) struct ReceivedConnectionRequest {
    pub user_data: Option<Vec<u8>>,
    pub data_overflow: Option<DataOverflowField>,
    pub maximum_size_to_initiator: TsduMaximumSize,
}

pub(crate) async fn receive_message(reader: &mut impl CotpReader<SocketAddr>) -> Result<CospMessage, IsoSpError> {
    let data = match reader.recv().await? {
        CotpRecvResult::Closed => return Err(IsoSpError::ProtocolError("The transport connection was closed before the conection could be established.".into())),
        CotpRecvResult::Data(data) => data,
    };
    CospMessage::from_spdu_list(SessionPduList::deserialise(&data)?)
}

pub(crate) async fn send_overflow_accept(writer: &mut impl CotpWriter<SocketAddr>, initiator_size: &TsduMaximumSize) -> Result<(), IsoSpError> {
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

pub(crate) struct ReceivedAcceptRequest {
    pub maximum_size_to_responder: TsduMaximumSize,
    pub user_data: Option<Vec<u8>>,
}

pub(crate) async fn receive_overflow_accept(reader: &mut impl CotpReader<SocketAddr>) -> Result<ReceivedAcceptRequest, IsoSpError> {
    let data = match reader.recv().await? {
        CotpRecvResult::Closed => return Err(IsoSpError::ProtocolError("The transport connection was closed before the conection overflow was accepted.".into())),
        CotpRecvResult::Data(data) => data,
    };

    let mut pdus = SessionPduList::deserialise(&data)?;
    if pdus.session_pdus().len() > 1 {
        warn!("Received extra SPDUs on overflow accept. Ignoring the extra PDUs.");
    }
    let mut parameters = match pdus.session_pdus_mut().pop() {
        Some(SessionPduParameter::OverflowAccept(session_pdu_parameters)) => session_pdu_parameters,
        Some(pdu) => return Err(IsoSpError::ProtocolError(format!("Expected am overflow accept but got {}", <SessionPduParameter as Into<&'static str>>::into(pdu)))),
        _ => return Err(IsoSpError::ProtocolError("Cannot accept connection. The peer did not send data.".into())),
    };

    let mut version_number = None;
    let mut maximum_size_to_responder = TsduMaximumSize::Unlimited;

    // Not minding about order or duplicates.
    for parameter in parameters.drain(..) {
        match parameter {
            SessionPduParameter::VersionNumberParameter(value) => version_number = Some(value),
            SessionPduParameter::TsduMaximumSizeParameter(value) => {
                if value.to_initiator() != 0 {
                    maximum_size_to_responder = TsduMaximumSize::Size(value.to_responder()) // Ignore the initiator as that is us.
                }
            }
            _ => (), // Ignore everything else.
        };
    }
    match version_number {
        Some(version) if version.version2() => (),
        _ => return Err(IsoSpError::ProtocolError("Only version 2 is supported but version 1 was requested by the server in overflow accept.".into())),
    }

    // There is no userbdata on overflow accept.
    Ok(ReceivedAcceptRequest { maximum_size_to_responder, user_data: None })
}

pub(crate) async fn send_connect_data_overflow(writer: &mut impl CotpWriter<SocketAddr>, data: &[u8]) -> Result<(), IsoSpError> {
    const MAX_PAYLOAD_SIZE: usize = 65528;
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
                        SessionPduParameter::Enclosure(EnclosureField(end_flag)),
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

pub(crate) async fn receive_connect_data_overflow(reader: &mut impl CotpReader<SocketAddr>) -> Result<Vec<u8>, IsoSpError> {
    const MAX_PAYLOAD_SIZE: usize = 65528;
    let mut buffer = VecDeque::new();

    let mut end_flag = false;
    while !end_flag {
        let data = match reader.recv().await? {
            CotpRecvResult::Closed => return Err(IsoSpError::ProtocolError("The transport connection was closed before the conection overflow was accepted.".into())),
            CotpRecvResult::Data(data) => data,
        };

        let mut pdus = SessionPduList::deserialise(&data)?;
        if pdus.session_pdus().len() > 1 {
            warn!("Received extra SPDUs on connect data overflow. Ignoring the extra PDUs.");
        }
        let mut parameters = match pdus.session_pdus_mut().pop() {
            Some(SessionPduParameter::ConnectDataOverflow(session_pdu_parameters)) => session_pdu_parameters,
            Some(pdu) => return Err(IsoSpError::ProtocolError(format!("Expected a connect data overflow but got {}", <SessionPduParameter as Into<&'static str>>::into(pdu)))),
            _ => return Err(IsoSpError::ProtocolError("Cannot finish connect. The peer did not send data.".into())),
        };

        // Not minding about order or duplicates.
        for parameter in parameters.drain(..) {
            match parameter {
                SessionPduParameter::Enclosure(value) => end_flag = value.end(),
                SessionPduParameter::UserDataParameter(value) => {
                    buffer.extend(value);
                }
                _ => (), // Ignore everything else.
            };
        }
    }
    Ok(buffer.drain(..).collect())
}

pub(crate) async fn send_accept(writer: &mut impl CotpWriter<SocketAddr>, initiator_size: &TsduMaximumSize, user_data: Option<&[u8]>) -> Result<(), IsoSpError> {
    const MAX_SPDU_SIZE: usize = 65539;

    // As we may need to send multiple accept payloads, we will precalculate the size of the header without enclosure.
    // Enclosure is a fixed 3 bytes which we only need to take into account if we are doing segmentation.
    let optimistic_accept = serialise_accept(initiator_size, None, user_data)?;
    let requires_segmentation = optimistic_accept.len() > MAX_SPDU_SIZE;

    if !requires_segmentation {
        return Ok(writer.send(&optimistic_accept).await?);
    }

    let mut cursor = 0;
    let default_user_data = []; // This will never be used. It is only used to keep rusts safety happy.
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

pub(crate) fn serialise_accept(initiator_size: &TsduMaximumSize, is_last: Option<bool>, user_data: Option<&[u8]>) -> Result<Vec<u8>, IsoSpError> {
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
            session_parameters.push(SessionPduParameter::Enclosure(EnclosureField(2)));
            session_parameters.push(SessionPduParameter::UserDataParameter(vec![]));
        }
        (Some(_), None) => {
            session_parameters.push(SessionPduParameter::Enclosure(EnclosureField(0)));
            session_parameters.push(SessionPduParameter::UserDataParameter(vec![]));
        }
        (Some(is_last), Some(user_data)) if is_last => {
            session_parameters.push(SessionPduParameter::Enclosure(EnclosureField(2)));
            session_parameters.push(SessionPduParameter::UserDataParameter(user_data.to_vec()));
        }
        (Some(_), Some(user_data)) => {
            session_parameters.push(SessionPduParameter::Enclosure(EnclosureField(0)));
            session_parameters.push(SessionPduParameter::UserDataParameter(user_data.to_vec()));
        }
    }
    if let Some(user_data) = user_data {
        session_parameters.push(SessionPduParameter::UserDataParameter(user_data.to_vec()));
    }

    SessionPduList::new(vec![SessionPduParameter::Accept(session_parameters)], vec![]).serialise()
}

pub(crate) async fn receive_accept(reader: &mut impl CotpReader<SocketAddr>) -> Result<ReceivedAcceptRequest, IsoSpError> {
    let mut user_data_buffer = None;
    loop {
        let data = match reader.recv().await? {
            CotpRecvResult::Closed => return Err(IsoSpError::ProtocolError("The transport connection was closed before the conection was accepted.".into())),
            CotpRecvResult::Data(data) => data,
        };

        let deserialise_result = deserialise_accept(&data)?;
        match (&mut user_data_buffer, deserialise_result.user_data) {
            (None, Some(user_data)) => {
                let mut buffer = VecDeque::new();
                buffer.extend(user_data);
                user_data_buffer = Some(buffer);
            }
            (Some(buffer), Some(user_data)) => {
                buffer.extend(user_data);
            }
            (_, _) => (),
        };

        if !deserialise_result.has_more {
            return Ok(ReceivedAcceptRequest {
                maximum_size_to_responder: deserialise_result.maximum_size_to_responder,
                user_data: user_data_buffer.map(|x| x.into_iter().collect()),
            });
        }
    }
}

struct DeserialiseResult {
    pub has_more: bool,
    pub user_data: Option<Vec<u8>>,
    maximum_size_to_responder: TsduMaximumSize,
}

fn deserialise_accept(data: &[u8]) -> Result<DeserialiseResult, IsoSpError> {
    let mut pdus = SessionPduList::deserialise(&data)?;
    if pdus.session_pdus().len() > 1 {
        warn!("Received extra SPDUs on accept. Ignoring the extra PDUs.");
    }
    let mut parameters = match pdus.session_pdus_mut().pop() {
        Some(SessionPduParameter::Accept(session_pdu_parameters)) => session_pdu_parameters,
        Some(pdu) => return Err(IsoSpError::ProtocolError(format!("Expected am accept but got {}", <SessionPduParameter as Into<&'static str>>::into(pdu)))),
        _ => return Err(IsoSpError::ProtocolError("Cannot accept connection. The peer did not send data.".into())),
    };

    let mut has_more = false;
    let mut user_data = None;
    let mut version_number = None;
    let mut maximum_size_to_responder = TsduMaximumSize::Unlimited;

    // Not minding about order or duplicates.
    for parameter in parameters.drain(..) {
        match parameter {
            SessionPduParameter::ConnectAcceptItemParameter(sub_pdus) => {
                for sub_pdu in sub_pdus {
                    match sub_pdu {
                        SessionPduParameter::VersionNumberParameter(supported_versions) => version_number = Some(supported_versions),
                        SessionPduParameter::TsduMaximumSizeParameter(tsdu_maximum_size) => maximum_size_to_responder = TsduMaximumSize::Size(tsdu_maximum_size.to_responder()),
                        _ => (), // Ignore everything else.
                    }
                }
            }
            SessionPduParameter::TsduMaximumSizeParameter(value) => {
                if value.to_initiator() != 0 {
                    maximum_size_to_responder = TsduMaximumSize::Size(value.to_initiator()) // Ignore the initiator as that is us.
                }
            }
            SessionPduParameter::Enclosure(field) => {
                has_more = !field.end();
            }
            SessionPduParameter::UserDataParameter(data) => {
                user_data = Some(data);
            }
            _ => (), // Ignore everything else.
        };
    }
    match version_number {
        Some(version) if version.version2() => (),
        Some(version) if version.version1() => return Err(IsoSpError::ProtocolError("Only version 2 is supported but version 1 was requested by the server on accept.".into())),
        Some(_) => return Err(IsoSpError::ProtocolError("Only version 2 is supported but no was requested by the server on accept.".into())),
        None => return Err(IsoSpError::ProtocolError("Only version 2 is supported but version 1 was implied by the server on accept.".into())),
    }

    Ok(DeserialiseResult {
        has_more,
        user_data,
        maximum_size_to_responder,
    })
}
