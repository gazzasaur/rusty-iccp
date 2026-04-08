use std::collections::VecDeque;

use rusty_cotp::CotpError;
use rusty_tpkt::ProtocolInformation;
use strum::IntoStaticStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CospError {
    /// Indicates issues with parsing of incoming packets or protocol violations with input user data.
    #[error("COSP Protocol Error - {}", .0)]
    ProtocolError(String),

    /// Indicates issues with lower layers.
    #[error("COSP over COTP Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] CotpError),

    /// Indicates issues with the underlying TCP socket or hardware.
    #[error("COSP IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    /// Usually indicates a bug or an unhandled error condition.
    #[error("COSP Error: {}", .0)]
    InternalError(String),

    /// Indicated a connection was refused. The connection should be dropped.
    /// This should only be received by the initiator during the initiate phase.
    #[error("COSP Refused")]
    Refused(Option<ReasonCode>),

    /// Indicated a connection was aborted. The connection should be dropped.
    /// This may occur during any read operation.
    #[error("COSP Abort")]
    Aborted(Option<Vec<u8>>),
}

/// If a connection is refused, the reason the connection was refused will be indicated by one of the following.
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

/// Provides a set of parameters used to tune timers or prevent the runaway consumption or resources due to a malicious client.
#[derive(PartialEq, Clone, Debug)]
pub struct CospConnectionParameters {
    /// A limit on the reassembled payload. If this is exceeded, an error will be raised on the read operation.
    ///
    /// Defaults to 1MB for payload plus a 1024 byte overhead to account
    pub maximum_reassembled_payload_size: usize,
}

impl Default for CospConnectionParameters {
    fn default() -> Self {
        Self { maximum_reassembled_payload_size: 1024 * 1024 + 1024 }
    }
}

/// Protocol information such as the calling party and the called party.
#[derive(PartialEq, Clone, Debug)]
pub struct CospProtocolInformation {
    calling_session_selector: Option<Vec<u8>>,
    called_session_selector: Option<Vec<u8>>,
}

impl CospProtocolInformation {
    /// Creates the protocol information including an optional calling party and called party.
    pub fn new(calling_session_selector: Option<Vec<u8>>, called_session_selector: Option<Vec<u8>>) -> Self {
        Self { calling_session_selector, called_session_selector }
    }

    /// Returns the calling party.
    pub fn calling_session_selector(&self) -> Option<&Vec<u8>> {
        self.calling_session_selector.as_ref()
    }

    /// Returns the called party.
    pub fn called_session_selector(&self) -> Option<&Vec<u8>> {
        self.called_session_selector.as_ref()
    }
}

impl ProtocolInformation for CospProtocolInformation {}

/// Possible values from the read operation.
#[derive(IntoStaticStr)]
pub enum CospRecvResult {
    /// Indicates the underlying connection was closed.
    Closed,

    /// Indicates data was received.
    Data(Vec<u8>),

    /// Indicates the remote side intends to close the connection. A disconnect should be sent in response before dropping the reader and writer.
    Finish(Option<Vec<u8>>),

    /// Indicates the remote side accepts the finish indication. The reader and writer may now be dropped.
    Disconnect(Option<Vec<u8>>),
}

/// A trait representing the client.
pub trait CospInitiator: Send {
    /// Starts signalling a COSP connection. A Refuse error may be received during this phase.
    fn initiate(self, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(impl CospConnection, Option<Vec<u8>>), CospError>> + Send;
}

/// Once a connect request has been received, the following actions may be taken.
pub trait CospAcceptor: Send {
    /// Accept the incoming request.
    /// In this case, the initiator may send us connection data, typically from a higher layer protocol.
    fn accept(self) -> impl std::future::Future<Output = Result<(impl CospResponder, Option<Vec<u8>>), CospError>> + Send;

    /// Refuse the incoming request with a reason.
    fn refuse(self, reason_code: Option<ReasonCode>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;

    /// Abort the connection.
    fn abort(self, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
}

/// After a connection is accepted, the initiator may send more data. The responder may reply with response data.
pub trait CospResponder: Send {
    /// Completes the connection signalling with optional response data. The response data is typically from a higher layer protocol.
    fn complete_connection(self, accept_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<impl CospConnection, CospError>> + Send;

    /// Abort the connection.
    fn abort(self, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
}

/// A trait representing a connection.
pub trait CospConnection: Send {
    /// Gets the information regarding the protocols that have been negotiated during the connect phase.
    fn get_protocol_infomation_list(&self) -> &Vec<Box<dyn ProtocolInformation>>;

    /// Splits a connection into reader and writer components. This must be done before the connection is used.
    fn split(self) -> impl std::future::Future<Output = Result<(impl CospReader, impl CospWriter), CospError>> + Send;
}

/// A trait representing the read half of a connection.
pub trait CospReader: Send {
    /// Receives data. An Abort error may also be received.
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CospRecvResult, CospError>> + Send;
}

/// A trait representing the write half of a connection.
pub trait CospWriter: Send {
    /// Send data to the remote host.
    fn send(&mut self, input: &mut VecDeque<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;

    /// Signals the intent to close a connection. A disconnect should be received before dropping the reader and writer.
    fn finish(self, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;

    /// Confirms that a finish was received and this side is okay to close the connection.
    /// As this is a kernel implementation, this is the only normal flow options.
    /// Abnormal flows would be to send back an abort, or simply close the connection by dropping the reader and writer.
    fn disconnect(self, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;

    /// Abort the connection. The reader and writer should be dropped after this is sent.
    fn abort(self, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CospError>> + Send;
}
