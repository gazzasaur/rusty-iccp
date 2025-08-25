use std::net::SocketAddr;

use rusty_cotp::api::{CotpReader, CotpRecvResult, CotpWriter};
use tracing::warn;

use crate::{
    api::IsoSpError,
    packet::session_pdu::{DataOverflow, Enclosure, ProtocolOptions, SessionPdu, SessionPduList, SessionPduParameter, SessionPduSubParameter, SessionUserRequirements, SupportedVersions, TsduMaximumSize, TsduMaximumSizeSelected},
};

pub(crate) enum IcpIsoState {
    Connecting,
    TransmitData,
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
        _ => return Err(IsoSpError::ProtocolError("Only version 2 is supported but version1 was requested.".into())),
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
        // This will set the responder size to 0xFFFF to indicate that we accept unlimited size. But we also echo back the initiator size.
        connect_accept_sub_parameters.push(SessionPduSubParameter::TsduMaximumSizeParameter(TsduMaximumSize(*initiator_size as u32)));
    }
    connect_accept_sub_parameters.push(SessionPduSubParameter::VersionNumberParameter(SupportedVersions(2))); // Accept version 2

    let pdus = SessionPduList(vec![SessionPdu::OverflowAccept(vec![
        SessionPduParameter::ConnectAcceptItem(connect_accept_sub_parameters),
        SessionPduParameter::SessionUserRequirementsItem(SessionUserRequirements(2)), // Accept Full Duplex only
    ])]);
    Ok(writer.send(&pdus.serialise()?).await?)
}

pub(crate) struct ReceivedOverflowAcceptRequest {
    pub maximum_size_to_responder: TsduMaximumSizeSelected,
}

pub(crate) async fn receive_overflow_accept(reader: &mut impl CotpReader<SocketAddr>) -> Result<ReceivedOverflowAcceptRequest, IsoSpError> {
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
                    maximum_size_to_responder = TsduMaximumSizeSelected::Size(value.initiator()) // Ignore the initiator as that is us.
                }
            }
            _ => (), // Ignore everything else.
        };
    }
    match version_number {
        Some(version) if version.version2() => (),
        _ => return Err(IsoSpError::ProtocolError("Only version 2 is supported but version1 was requested.".into())),
    }

    Ok(ReceivedOverflowAcceptRequest { maximum_size_to_responder })
}

pub(crate) async fn send_connection_overflow_data(writer: &mut impl CotpWriter<SocketAddr>, data: &[u8]) -> Result<(), IsoSpError> {
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
