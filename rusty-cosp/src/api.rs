use std::collections::VecDeque;

use rusty_cotp::CotpError;
use rusty_tpkt::ProtocolInformation;
use strum::IntoStaticStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CospError {
    #[error("COSP Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("COSP over COTP Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] CotpError),

    #[error("COSP IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("COSP Error: {}", .0)]
    InternalError(String),

    #[error("COSP Refused")]
    Refused(Option<ReasonCode>),
}

#[derive(Clone, Debug, IntoStaticStr, PartialEq, Eq)]
pub enum ReasonCode {
    RejectionByCalledSsUser,
    RejectionByCalledSsUserDueToTemporaryCongestion,
    RejectionByCalledSsUserWithData(Vec<u8>),
    SessionSelectorUnknown,
    SsUserNotAttachedToSsap,
    SpmCongestionAtConnectTime,
    ProposedProtocolVersionsNotSupported,
    RejectionByTheSpm,
    RejectionByTheSpm2,
    Unknown(u8),
}

/// Connection parameters required by the COSP protocol.
#[derive(PartialEq, Clone, Debug)]
pub struct CospConnectionParameters {
    /// A limit on the reassembled payload. If this is exceeded, an error will be raised on the read operation.
    ///
    /// Defaults to None. This allows for infinite length payloads or for the server to set a length.
    pub tsdu_maximum_size: Option<u16>,
    // FIXME SECURITY Need a reassembled payload size.
}

impl Default for CospConnectionParameters {
    fn default() -> Self {
        Self { tsdu_maximum_size: None }
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct CospProtocolInformation {
    calling_session_selector: Option<Vec<u8>>,
    called_session_selector: Option<Vec<u8>>,
}

impl CospProtocolInformation {
    pub fn new(calling_session_selector: Option<Vec<u8>>, called_session_selector: Option<Vec<u8>>) -> Self {
        Self { calling_session_selector, called_session_selector }
    }

    pub fn calling_session_selector(&self) -> Option<&Vec<u8>> {
        self.calling_session_selector.as_ref()
    }

    pub fn called_session_selector(&self) -> Option<&Vec<u8>> {
        self.called_session_selector.as_ref()
    }
}

impl ProtocolInformation for CospProtocolInformation {}

pub enum CospRecvResult {
    Closed,
    Data(Vec<u8>),
    Finish(Option<Vec<u8>>),
}

pub trait CospInitiator: Send {
    fn initiate(self, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(impl CospConnection, Option<Vec<u8>>), CospError>> + Send;
}

pub trait CospAcceptor: Send {
    fn accept(self) -> impl std::future::Future<Output = Result<(impl CospResponder, Option<Vec<u8>>), CospError>> + Send;
    fn refuse(self, reason_code: Option<ReasonCode>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
}

pub trait CospResponder: Send {
    fn complete_connection(self, accept_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<impl CospConnection, CospError>> + Send;

    // fn abort(self, accept_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
}

pub trait CospConnection: Send {
    /// Gets the information regarding the protocols that have been negotiated during the connect phase.
    fn get_protocol_infomation_list(&self) -> &Vec<Box<dyn ProtocolInformation>>;

    fn split(self) -> impl std::future::Future<Output = Result<(impl CospReader, impl CospWriter), CospError>> + Send;
}

pub trait CospReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CospRecvResult, CospError>> + Send;
}

pub trait CospWriter: Send {
    fn send(&mut self, input: &mut VecDeque<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
    fn finish(self, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
    // fn disconnect(self, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;

    // fn abort(self, accept_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
}
