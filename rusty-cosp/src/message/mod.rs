use strum::IntoStaticStr;

use crate::{
    api::IsoSpError,
    message::{connect::ConnectMessage, data_transfer::DataTransferMessage},
    packet::{parameters::SessionPduParameter, pdu::SessionPduList},
};

pub(crate) mod connect;
pub(crate) mod data_transfer;

#[derive(IntoStaticStr)]
pub(crate)  enum CospMessage {
    CN(ConnectMessage),
    DT(DataTransferMessage),
}

impl CospMessage {
    pub(crate) fn from_spdu_list(spdu_list: SessionPduList) -> Result<Self, IsoSpError> {
        if spdu_list.session_pdus().len() == 0 {
            return Err(IsoSpError::ProtocolError("Cannot process empty PDU.".into()));
        } else if spdu_list.session_pdus().len() == 1 {
            CospMessage::process_basic(&spdu_list.session_pdus()[0])
        } else if spdu_list.session_pdus().len() == 2 {
            CospMessage::process_basic_concatenated(&spdu_list.session_pdus()[0], &spdu_list.session_pdus()[1])
        } else {
            return Err(IsoSpError::ProtocolError("Extended PDUs are not supported.".into()));
        }
    }

    fn process_basic(message_parameter: &SessionPduParameter) -> Result<Self, IsoSpError> {
        Ok(match message_parameter {
            SessionPduParameter::Connect(parameters) => CospMessage::CN(ConnectMessage::from_parameters(parameters.as_slice())?),
            SessionPduParameter::OverflowAccept(parameters) => todo!(),
            SessionPduParameter::ConnectDataOverflow(parameters) => todo!(),
            SessionPduParameter::Accept(parameters) => todo!(),
            _ => return Err(IsoSpError::ProtocolError(format!("Unsupported SPDU: {}", <&SessionPduParameter as Into<&'static str>>::into(message_parameter)))),
        })
    }

    fn process_basic_concatenated(header_parameter: &SessionPduParameter, message_parameter: &SessionPduParameter) -> Result<Self, IsoSpError> {
        match header_parameter {
            SessionPduParameter::GiveTokens() => (),
            _ => return Err(IsoSpError::ProtocolError(format!("Unsupported SPDU as concatenated token header: {}", <&SessionPduParameter as Into<&'static str>>::into(header_parameter)))),
        };
        Ok(match message_parameter {
            SessionPduParameter::DataTransfer(parameters) => CospMessage::DT(DataTransferMessage::from_parameters(parameters.as_slice())?),
            _ => return Err(IsoSpError::ProtocolError(format!("Unsupported SPDU as concatenated body: {}", <&SessionPduParameter as Into<&'static str>>::into(message_parameter)))),
        })
    }
}
