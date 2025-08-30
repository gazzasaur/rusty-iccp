use std::{collections::VecDeque, net::SocketAddr};

use rusty_cotp::api::{CotpReader, CotpRecvResult, CotpWriter};
use tracing::warn;

use crate::{
    api::IsoSpError,
    packet::session_pdu::{DataOverflow, Enclosure, ProtocolOptions, SessionPdu, SessionPduList, SessionPduParameter, SessionPduSubParameter, SessionUserRequirements, SupportedVersions, TsduMaximumSize, TsduMaximumSizeSelected},
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
        SessionPduParameter::ConnectAcceptItem(vec![
            SessionPduSubParameter::ProtocolOptionsParameter(ProtocolOptions(2)), // Only set the duplex functionall unit
            SessionPduSubParameter::VersionNumberParameter(SupportedVersions(2)), // Version 2 only
        ]),
        SessionPduParameter::SessionUserRequirementsItem(SessionUserRequirements(2)), // Full Duplex only
    ];
    let overflow_length = match user_data {
        Some(user_data) if user_data.len() <= MAX_USER_DATA_PAYLOAD_SIZE => {
            parameters.push(SessionPduParameter::UserData(user_data.to_vec()));
            0
        }
        Some(user_data) if user_data.len() <= MAX_EXTENDED_USER_DATA_PAYLOAD_SIZE => {
            parameters.push(SessionPduParameter::ExtendedUserData(user_data.to_vec()));
            0
        }
        Some(user_data) => {
            parameters.push(SessionPduParameter::DataOverflowItem(DataOverflow(1)));
            parameters.push(SessionPduParameter::ExtendedUserData(user_data[..MAX_EXTENDED_USER_DATA_PAYLOAD_SIZE].to_vec()));
            MAX_EXTENDED_USER_DATA_PAYLOAD_SIZE
        }
        None => 0,
    };

    let pdus = SessionPduList(vec![SessionPdu::Connect(parameters)]);
    writer.send(&pdus.serialise()?).await?;
    Ok(match overflow_length {
        0 => SendConnectionRequestResult::Complete,
        _ => SendConnectionRequestResult::Overflow(overflow_length),
    })
}

pub(crate) struct ReceivedConnectionRequest {
    pub user_data: Option<Vec<u8>>,
    pub data_overflow: Option<DataOverflow>,
    pub maximum_size_to_initiator: TsduMaximumSizeSelected,
}

pub(crate) async fn receive_connection_request(reader: &mut impl CotpReader<SocketAddr>) -> Result<ReceivedConnectionRequest, IsoSpError> {
    let data = match reader.recv().await? {
        CotpRecvResult::Closed => return Err(IsoSpError::ProtocolError("The transport connection was closed before the conection could be established.".into())),
        CotpRecvResult::Data(data) => data,
    };

    let mut pdus = SessionPduList::deserialise(TsduMaximumSizeSelected::Unlimited, &data)?;
    if pdus.0.len() > 1 {
        warn!("Received extra SPDUs on connect. Ignoring the extra PDUs.");
    }
    let mut parameters = match pdus.0.pop() {
        Some(SessionPdu::Connect(session_pdu_parameters)) => session_pdu_parameters,
        Some(pdu) => return Err(IsoSpError::ProtocolError(format!("Expected a connection request but got {}", <SessionPdu as Into<&'static str>>::into(pdu)))),
        _ => return Err(IsoSpError::ProtocolError("Cannot accept connection. The peer did not send data.".into())),
    };

    let mut user_data = None;
    let mut data_overflow = None;
    let mut extended_user_data = None;
    let mut version_number = None;
    let mut maximum_size_to_initiator = TsduMaximumSizeSelected::Unlimited;
    let mut session_user_requirements = SessionUserRequirements::default();

    // Not minding about order or duplicates.
    for parameter in parameters.drain(..) {
        match parameter {
            SessionPduParameter::ConnectAcceptItem(session_pdu_sub_parameters) => {
                for sub_parameters in session_pdu_sub_parameters {
                    match sub_parameters {
                        // We don't really care about protocol options. We are not going to support extended concatentation.
                        SessionPduSubParameter::VersionNumberParameter(value) => version_number = Some(value),
                        SessionPduSubParameter::TsduMaximumSizeParameter(value) => {
                            if value.initiator() != 0 {
                                maximum_size_to_initiator = TsduMaximumSizeSelected::Size(value.initiator()) // Ignore the responder as that is us.
                            }
                        }
                        _ => (), // Ignore everything else.
                    }
                }
            }
            SessionPduParameter::SessionUserRequirementsItem(value) => session_user_requirements = value,
            SessionPduParameter::UserData(value) => user_data = Some(value),
            SessionPduParameter::DataOverflowItem(value) if value.more_data() => data_overflow = Some(value), // Ignore it if there is no more data.
            SessionPduParameter::ExtendedUserData(value) => extended_user_data = Some(value),
            _ => (), // Ignore everything else.
        };
    }
    match version_number {
        Some(version) if version.version2() => (),
        _ => return Err(IsoSpError::ProtocolError("Only version 2 is supported but version 1 was requested by the client.".into())),
    }
    if !session_user_requirements.full_duplex() {
        return Err(IsoSpError::ProtocolError(format!("Full duplex mode is not supported by peer.")));
    }
    if extended_user_data.is_none() && data_overflow.is_some() {
        return Err(IsoSpError::ProtocolError(format!("An overflow parameter was found but no data was provided.")));
    }
    let user_data = match (user_data, extended_user_data) {
        (None, None) => None,
        (None, Some(data)) => Some(data),
        (Some(data), None) => Some(data),
        (Some(_), Some(_)) => return Err(IsoSpError::ProtocolError(format!("User Data and Overflow data was detected. Cannot continue to connect."))),
    };

    Ok(ReceivedConnectionRequest {
        user_data,
        data_overflow,
        maximum_size_to_initiator,
    })
}

pub(crate) async fn send_overflow_accept(writer: &mut impl CotpWriter<SocketAddr>, initiator_size: &TsduMaximumSizeSelected) -> Result<(), IsoSpError> {
    let mut connect_accept_sub_parameters = Vec::new();
    if let TsduMaximumSizeSelected::Size(initiator_size) = initiator_size {
        // This will set the responder size to 0x0000 to indicate that we (the responder) accept unlimited size. But we also echo back the initiator size.
        connect_accept_sub_parameters.push(SessionPduSubParameter::TsduMaximumSizeParameter(TsduMaximumSize((*initiator_size as u32) << 16)));
    }
    connect_accept_sub_parameters.push(SessionPduSubParameter::VersionNumberParameter(SupportedVersions(2))); // Accept version 2

    let pdus = SessionPduList(vec![SessionPdu::OverflowAccept(vec![
        SessionPduParameter::ConnectAcceptItem(connect_accept_sub_parameters),
        SessionPduParameter::SessionUserRequirementsItem(SessionUserRequirements(2)), // Accept Full Duplex only
    ])]);
    Ok(writer.send(&pdus.serialise()?).await?)
}

pub(crate) struct ReceivedAcceptRequest {
    pub maximum_size_to_responder: TsduMaximumSizeSelected,
    pub user_data: Option<Vec<u8>>,
}

pub(crate) async fn receive_overflow_accept(reader: &mut impl CotpReader<SocketAddr>) -> Result<ReceivedAcceptRequest, IsoSpError> {
    let data = match reader.recv().await? {
        CotpRecvResult::Closed => return Err(IsoSpError::ProtocolError("The transport connection was closed before the conection overflow was accepted.".into())),
        CotpRecvResult::Data(data) => data,
    };

    let mut pdus = SessionPduList::deserialise(TsduMaximumSizeSelected::Unlimited, &data)?;
    if pdus.0.len() > 1 {
        warn!("Received extra SPDUs on overflow accept. Ignoring the extra PDUs.");
    }
    let mut parameters = match pdus.0.pop() {
        Some(SessionPdu::OverflowAccept(session_pdu_parameters)) => session_pdu_parameters,
        Some(pdu) => return Err(IsoSpError::ProtocolError(format!("Expected am overflow accept but got {}", <SessionPdu as Into<&'static str>>::into(pdu)))),
        _ => return Err(IsoSpError::ProtocolError("Cannot accept connection. The peer did not send data.".into())),
    };

    let mut version_number = None;
    let mut maximum_size_to_responder = TsduMaximumSizeSelected::Unlimited;

    // Not minding about order or duplicates.
    for parameter in parameters.drain(..) {
        match parameter {
            SessionPduParameter::VersionNumberParameter(value) => version_number = Some(value),
            SessionPduParameter::TsduMaximumSizeParameter(value) => {
                if value.initiator() != 0 {
                    maximum_size_to_responder = TsduMaximumSizeSelected::Size(value.responder()) // Ignore the initiator as that is us.
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
                &SessionPduList(vec![SessionPdu::ConnectDataOverflow(vec![
                    SessionPduParameter::EnclosureItem(Enclosure(end_flag)),
                    SessionPduParameter::UserData(data[start_index..cursor].to_vec()),
                ])])
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

        let mut pdus = SessionPduList::deserialise(TsduMaximumSizeSelected::Unlimited, &data)?;
        if pdus.0.len() > 1 {
            warn!("Received extra SPDUs on connect data overflow. Ignoring the extra PDUs.");
        }
        let mut parameters = match pdus.0.pop() {
            Some(SessionPdu::ConnectDataOverflow(session_pdu_parameters)) => session_pdu_parameters,
            Some(pdu) => return Err(IsoSpError::ProtocolError(format!("Expected a connect data overflow but got {}", <SessionPdu as Into<&'static str>>::into(pdu)))),
            _ => return Err(IsoSpError::ProtocolError("Cannot finish connect. The peer did not send data.".into())),
        };

        // Not minding about order or duplicates.
        for parameter in parameters.drain(..) {
            match parameter {
                SessionPduParameter::EnclosureItem(value) => end_flag = value.end(),
                SessionPduParameter::UserData(value) => {
                    buffer.extend(value);
                }
                _ => (), // Ignore everything else.
            };
        }
    }
    Ok(buffer.drain(..).collect())
}

pub(crate) async fn send_accept(writer: &mut impl CotpWriter<SocketAddr>, initiator_size: &TsduMaximumSizeSelected, user_data: Option<&[u8]>) -> Result<(), IsoSpError> {
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

pub(crate) fn serialise_accept(initiator_size: &TsduMaximumSizeSelected, is_last: Option<bool>, user_data: Option<&[u8]>) -> Result<Vec<u8>, IsoSpError> {
    let mut connect_accept_sub_parameters = Vec::new();
    if let TsduMaximumSizeSelected::Size(initiator_size) = initiator_size {
        // This will set the responder size to 0x0000 to indicate that we accept unlimited size. But we also echo back the initiator size if it is not unlimited.
        connect_accept_sub_parameters.push(SessionPduSubParameter::TsduMaximumSizeParameter(TsduMaximumSize(*initiator_size as u32)));
    }
    connect_accept_sub_parameters.push(SessionPduSubParameter::VersionNumberParameter(SupportedVersions(2))); // Accept version 2

    let mut session_parameters = vec![
        SessionPduParameter::ConnectAcceptItem(connect_accept_sub_parameters),
        SessionPduParameter::SessionUserRequirementsItem(SessionUserRequirements(2)), // Accept Full Duplex only
    ];
    match (is_last, user_data) {
        (None, None) => (),
        (None, Some(user_data)) => {
            session_parameters.push(SessionPduParameter::UserData(user_data.to_vec()));
        }
        (Some(is_last), None) if is_last => {
            session_parameters.push(SessionPduParameter::EnclosureItem(Enclosure(2)));
            session_parameters.push(SessionPduParameter::UserData(vec![]));
        }
        (Some(_), None) => {
            session_parameters.push(SessionPduParameter::EnclosureItem(Enclosure(0)));
            session_parameters.push(SessionPduParameter::UserData(vec![]));
        }
        (Some(is_last), Some(user_data)) if is_last => {
            session_parameters.push(SessionPduParameter::EnclosureItem(Enclosure(2)));
            session_parameters.push(SessionPduParameter::UserData(user_data.to_vec()));
        }
        (Some(_), Some(user_data)) => {
            session_parameters.push(SessionPduParameter::EnclosureItem(Enclosure(0)));
            session_parameters.push(SessionPduParameter::UserData(user_data.to_vec()));
        }
    }
    if let Some(user_data) = user_data {
        session_parameters.push(SessionPduParameter::UserData(user_data.to_vec()));
    }

    SessionPduList(vec![SessionPdu::Accept(session_parameters)]).serialise()
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
    maximum_size_to_responder: TsduMaximumSizeSelected,
}

fn deserialise_accept(data: &[u8]) -> Result<DeserialiseResult, IsoSpError> {
    let mut pdus = SessionPduList::deserialise(TsduMaximumSizeSelected::Unlimited, &data)?;
    if pdus.0.len() > 1 {
        warn!("Received extra SPDUs on accept. Ignoring the extra PDUs.");
    }
    let mut parameters = match pdus.0.pop() {
        Some(SessionPdu::Accept(session_pdu_parameters)) => session_pdu_parameters,
        Some(pdu) => return Err(IsoSpError::ProtocolError(format!("Expected am accept but got {}", <SessionPdu as Into<&'static str>>::into(pdu)))),
        _ => return Err(IsoSpError::ProtocolError("Cannot accept connection. The peer did not send data.".into())),
    };

    let mut has_more = false;
    let mut user_data = None;
    let mut version_number = None;
    let mut maximum_size_to_responder = TsduMaximumSizeSelected::Unlimited;

    // Not minding about order or duplicates.
    for parameter in parameters.drain(..) {
        match parameter {
            SessionPduParameter::ConnectAcceptItem(sub_pdus) => {
                for sub_pdu in sub_pdus {
                    match sub_pdu {
                        SessionPduSubParameter::VersionNumberParameter(supported_versions) => version_number = Some(supported_versions),
                        SessionPduSubParameter::TsduMaximumSizeParameter(tsdu_maximum_size) => maximum_size_to_responder = TsduMaximumSizeSelected::Size(tsdu_maximum_size.responder()),
                        _ => (), // Ignore everything else.
                    }
                }
            }
            SessionPduParameter::TsduMaximumSizeParameter(value) => {
                if value.initiator() != 0 {
                    maximum_size_to_responder = TsduMaximumSizeSelected::Size(value.initiator()) // Ignore the initiator as that is us.
                }
            }
            SessionPduParameter::EnclosureItem(value) => {
                has_more = !value.end();
            }
            SessionPduParameter::UserData(value) => {
                user_data = Some(value);
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
