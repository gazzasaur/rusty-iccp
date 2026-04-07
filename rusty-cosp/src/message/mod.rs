use strum::IntoStaticStr;
use tracing::warn;

use crate::{
    api::CospError,
    message::{abort::AbortMessage, accept::AcceptMessage, connect::ConnectMessage, connect_data_overflow::ConnectDataOverflowMessage, data_transfer::DataTransferMessage, disconnect::DisconnectMessage, finish::FinishMessage, overflow_accept::OverflowAcceptMessage, refuse::RefuseMessage},
    packet::{parameters::SessionPduParameter, pdu::SessionPduList},
};

pub(crate) mod accept;
pub(crate) mod connect;
pub(crate) mod connect_data_overflow;
pub(crate) mod data_transfer;
pub(crate) mod overflow_accept;
pub(crate) mod parameters;
pub(crate) mod refuse;
pub(crate) mod finish;
pub(crate) mod disconnect;
pub(crate) mod abort;

#[derive(IntoStaticStr)]
pub(crate) enum CospMessage {
    CN(ConnectMessage),
    AC(AcceptMessage),
    RF(RefuseMessage),
    FN(FinishMessage),
    DN(DisconnectMessage),
    AB(AbortMessage),
    CDO(ConnectDataOverflowMessage),
    OA(OverflowAcceptMessage),
    DT(DataTransferMessage),
}

impl CospMessage {
    pub(crate) fn from_spdu_list(spdu_list: SessionPduList) -> Result<Self, CospError> {
        if spdu_list.session_pdus().len() == 0 {
            return Err(CospError::ProtocolError("Cannot process empty PDU.".into()));
        } else if spdu_list.session_pdus().len() == 1 {
            CospMessage::process_basic(&spdu_list.session_pdus()[0])
        } else if spdu_list.session_pdus().len() == 2 {
            CospMessage::process_basic_concatenated(&spdu_list.session_pdus()[0], &spdu_list.session_pdus()[1], spdu_list.user_information())
        } else {
            warn!("Extended PDUs are not supported: {:?}", spdu_list);
            return Err(CospError::ProtocolError("Extended PDUs are not supported.".into()));
        }
    }

    fn process_basic(message_parameter: &SessionPduParameter) -> Result<Self, CospError> {
        Ok(match message_parameter {
            SessionPduParameter::Connect(parameters) => CospMessage::CN(ConnectMessage::from_parameters(parameters.as_slice())?),
            SessionPduParameter::Accept(parameters) => CospMessage::AC(AcceptMessage::from_parameters(parameters.as_slice())?),
            SessionPduParameter::Refuse(parameters) => CospMessage::RF(RefuseMessage::from_parameters(parameters.as_slice())?),
            SessionPduParameter::Finish(parameters) => CospMessage::FN(FinishMessage::from_parameters(parameters.as_slice())?),
            SessionPduParameter::Disconnect(parameters) => CospMessage::DN(DisconnectMessage::from_parameters(parameters.as_slice())?),
            SessionPduParameter::Abort(parameters) => CospMessage::AB(AbortMessage::from_parameters(parameters.as_slice())?),
            SessionPduParameter::ConnectDataOverflow(parameters) => CospMessage::CDO(ConnectDataOverflowMessage::from_parameters(parameters.as_slice())?),
            SessionPduParameter::OverflowAccept(parameters) => CospMessage::OA(OverflowAcceptMessage::from_parameters(parameters.as_slice())?),
            _ => return Err(CospError::ProtocolError(format!("Unsupported SPDU: {}", <&SessionPduParameter as Into<&'static str>>::into(message_parameter)))),
        })
    }

    fn process_basic_concatenated(header_parameter: &SessionPduParameter, message_parameter: &SessionPduParameter, user_information: &[u8]) -> Result<Self, CospError> {
        match header_parameter {
            SessionPduParameter::GiveTokens() => (),
            _ => {
                return Err(CospError::ProtocolError(format!("Unsupported SPDU as concatenated token header: {}", <&SessionPduParameter as Into<&'static str>>::into(header_parameter))));
            }
        };
        Ok(match message_parameter {
            SessionPduParameter::DataTransfer(parameters) => CospMessage::DT(DataTransferMessage::from_parameters(parameters.as_slice(), user_information.to_vec())?),
            _ => {
                return Err(CospError::ProtocolError(format!("Unsupported SPDU as concatenated body: {}", <&SessionPduParameter as Into<&'static str>>::into(message_parameter))));
            }
        })
    }
}
