use std::collections::VecDeque;

use der_parser::Oid;
use rusty_cosp::CospError;
use strum::IntoStaticStr;
use thiserror::Error;

pub use crate::messages::user_data::*;

#[derive(Error, Debug)]
pub enum CoppError {
    #[error("COPP Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("COPP over COSP Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] CospError),

    #[error("COPP IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    /// Usually indicates a bug or an unhandled error condition.
    #[error("COPP Error: {}", .0)]
    InternalError(String),

    /// Indicated a connection was rejected. The connection should be dropped.
    /// This should only be received by the initiator during the initiate phase.
    #[error("COPP Rejected")]
    Rejected(Option<ProviderReason>, PresentationContextResultType, Option<UserData>),

    /// Indicated a connection was aborted. The connection should be dropped.
    /// This may occur during any read operation.
    #[error("COPP User Abort")]
    UserAborted(Option<Vec<PresentationContextIdentifier>>, Option<UserData>),

    /// Indicated a connection was aborted. The connection should be dropped.
    /// This may occur during any read operation.
    #[error("COPP Provider Abort")]
    ProviderAborted(Option<ProviderReason>, Option<EventIdentifier>),
}

/// If an error occurs at this layer of the protocol the fllowing provider reasons may be received.
#[derive(Debug, PartialEq, Eq)]
pub enum ProviderReasonValue {
    ReasonNotSpecified = 0,
    TemporaryCongestion = 1,
    LocalLimitExceeded = 2,
    CalledPresentationAddressUnknown = 3,
    ProtocolVersionNotSupported = 4,
    DefaultContextNotSupported = 5,
    UserDataNotReadable = 6,
    NoPsapAvailable = 7,
}

/// A container to support unknown provider reasons.
#[derive(Debug, PartialEq, Eq)]
pub enum ProviderReason {
    Value(ProviderReasonValue),
    Unknown(Vec<u8>),
}

impl From<&[u8]> for ProviderReason {
    fn from(value: &[u8]) -> Self {
        match value {
            &[0] => ProviderReason::Value(ProviderReasonValue::ReasonNotSpecified),
            &[1] => ProviderReason::Value(ProviderReasonValue::TemporaryCongestion),
            &[2] => ProviderReason::Value(ProviderReasonValue::LocalLimitExceeded),
            &[3] => ProviderReason::Value(ProviderReasonValue::CalledPresentationAddressUnknown),
            &[4] => ProviderReason::Value(ProviderReasonValue::ProtocolVersionNotSupported),
            &[5] => ProviderReason::Value(ProviderReasonValue::DefaultContextNotSupported),
            &[6] => ProviderReason::Value(ProviderReasonValue::UserDataNotReadable),
            &[7] => ProviderReason::Value(ProviderReasonValue::NoPsapAvailable),
            x => ProviderReason::Unknown(x.to_vec()),
        }
    }
}

impl From<&ProviderReason> for Vec<u8> {
    fn from(value: &ProviderReason) -> Self {
        match value {
            ProviderReason::Value(ProviderReasonValue::ReasonNotSpecified) => vec![0],
            ProviderReason::Value(ProviderReasonValue::TemporaryCongestion) => vec![1],
            ProviderReason::Value(ProviderReasonValue::LocalLimitExceeded) => vec![2],
            ProviderReason::Value(ProviderReasonValue::CalledPresentationAddressUnknown) => vec![3],
            ProviderReason::Value(ProviderReasonValue::ProtocolVersionNotSupported) => vec![4],
            ProviderReason::Value(ProviderReasonValue::DefaultContextNotSupported) => vec![5],
            ProviderReason::Value(ProviderReasonValue::UserDataNotReadable) => vec![6],
            ProviderReason::Value(ProviderReasonValue::NoPsapAvailable) => vec![7],
            ProviderReason::Unknown(data) => data.to_vec(),
        }
    }
}

#[derive(Debug)]
pub enum EventIdentifierValue {
    CpPpdu = 0,
    CpaPpdu = 1,
    CprPpdu = 2,
    AruPpdu = 3,
    ArpPpdu = 4,
    AcPpdu = 5,
    AcaPpdu = 6,
    TdPpdu = 7,
    TtdPpdu = 8,
    TePpdu = 9,
    TcPpdu = 10,
    TccPpdu = 11,
    RsPpdu = 12,
    RsaPpdu = 13,
    SessionReleaseIndication = 14,
    SessionReleaseConfirm = 15,
    SessionTokenGiveIndication = 16,
    SessionTokenPleaseIndication = 17,
    SessionControlGiveIndication = 18,
    SessionSyncMinorIndication = 19,
    SessionSyncMinorConfirm = 20,
    SessionSyncMajorIndication = 21,
    SessionSyncMajorConfirm = 22,
    SessionProviderExceptionReportIndication = 23,
    SessionUserExceptionReportIndication = 24,
    SessionActivityStartIndication = 25,
    SessionActivityResumeIndication = 26,
    SessionActivityInterruptIndication = 27,
    SessionActivityInterruptConfirm = 28,
    SessionActivityDiscardIndication = 29,
    SessionActivityDiscardConfirm = 30,
    SessionActivityEndIndication = 31,
    SessionActivityEndConfirm = 32,
}

/// Used in provider abort to indicate where issues may reside.
#[derive(Debug)]
pub enum EventIdentifier {
    Value(EventIdentifierValue),
    Unknown(Vec<u8>),
}

impl From<&[u8]> for EventIdentifier {
    fn from(value: &[u8]) -> Self {
        match value {
            &[0] => EventIdentifier::Value(EventIdentifierValue::CpPpdu),
            &[1] => EventIdentifier::Value(EventIdentifierValue::CpaPpdu),
            &[2] => EventIdentifier::Value(EventIdentifierValue::CprPpdu),
            &[3] => EventIdentifier::Value(EventIdentifierValue::AruPpdu),
            &[4] => EventIdentifier::Value(EventIdentifierValue::ArpPpdu),
            &[5] => EventIdentifier::Value(EventIdentifierValue::AcPpdu),
            &[6] => EventIdentifier::Value(EventIdentifierValue::AcaPpdu),
            &[7] => EventIdentifier::Value(EventIdentifierValue::TdPpdu),
            &[8] => EventIdentifier::Value(EventIdentifierValue::TtdPpdu),
            &[9] => EventIdentifier::Value(EventIdentifierValue::TePpdu),
            &[10] => EventIdentifier::Value(EventIdentifierValue::TcPpdu),
            &[11] => EventIdentifier::Value(EventIdentifierValue::TccPpdu),
            &[12] => EventIdentifier::Value(EventIdentifierValue::RsPpdu),
            &[13] => EventIdentifier::Value(EventIdentifierValue::RsaPpdu),
            &[14] => EventIdentifier::Value(EventIdentifierValue::SessionReleaseIndication),
            &[15] => EventIdentifier::Value(EventIdentifierValue::SessionReleaseConfirm),
            &[16] => EventIdentifier::Value(EventIdentifierValue::SessionTokenGiveIndication),
            &[17] => EventIdentifier::Value(EventIdentifierValue::SessionTokenPleaseIndication),
            &[18] => EventIdentifier::Value(EventIdentifierValue::SessionControlGiveIndication),
            &[19] => EventIdentifier::Value(EventIdentifierValue::SessionSyncMinorIndication),
            &[20] => EventIdentifier::Value(EventIdentifierValue::SessionSyncMinorConfirm),
            &[21] => EventIdentifier::Value(EventIdentifierValue::SessionSyncMajorIndication),
            &[22] => EventIdentifier::Value(EventIdentifierValue::SessionSyncMajorConfirm),
            &[23] => EventIdentifier::Value(EventIdentifierValue::SessionProviderExceptionReportIndication),
            &[24] => EventIdentifier::Value(EventIdentifierValue::SessionUserExceptionReportIndication),
            &[25] => EventIdentifier::Value(EventIdentifierValue::SessionActivityStartIndication),
            &[26] => EventIdentifier::Value(EventIdentifierValue::SessionActivityResumeIndication),
            &[27] => EventIdentifier::Value(EventIdentifierValue::SessionActivityInterruptIndication),
            &[28] => EventIdentifier::Value(EventIdentifierValue::SessionActivityInterruptConfirm),
            &[29] => EventIdentifier::Value(EventIdentifierValue::SessionActivityDiscardIndication),
            &[30] => EventIdentifier::Value(EventIdentifierValue::SessionActivityDiscardConfirm),
            &[31] => EventIdentifier::Value(EventIdentifierValue::SessionActivityEndIndication),
            &[32] => EventIdentifier::Value(EventIdentifierValue::SessionActivityEndConfirm),
            x => EventIdentifier::Unknown(x.to_vec()),
        }
    }
}

impl From<&EventIdentifier> for Vec<u8> {
    fn from(value: &EventIdentifier) -> Self {
        match value {
            EventIdentifier::Value(EventIdentifierValue::CpPpdu) => vec![0],
            EventIdentifier::Value(EventIdentifierValue::CpaPpdu) => vec![1],
            EventIdentifier::Value(EventIdentifierValue::CprPpdu) => vec![2],
            EventIdentifier::Value(EventIdentifierValue::AruPpdu) => vec![3],
            EventIdentifier::Value(EventIdentifierValue::ArpPpdu) => vec![4],
            EventIdentifier::Value(EventIdentifierValue::AcPpdu) => vec![5],
            EventIdentifier::Value(EventIdentifierValue::AcaPpdu) => vec![6],
            EventIdentifier::Value(EventIdentifierValue::TdPpdu) => vec![7],
            EventIdentifier::Value(EventIdentifierValue::TtdPpdu) => vec![8],
            EventIdentifier::Value(EventIdentifierValue::TePpdu) => vec![9],
            EventIdentifier::Value(EventIdentifierValue::TcPpdu) => vec![10],
            EventIdentifier::Value(EventIdentifierValue::TccPpdu) => vec![11],
            EventIdentifier::Value(EventIdentifierValue::RsPpdu) => vec![12],
            EventIdentifier::Value(EventIdentifierValue::RsaPpdu) => vec![13],
            EventIdentifier::Value(EventIdentifierValue::SessionReleaseIndication) => vec![14],
            EventIdentifier::Value(EventIdentifierValue::SessionReleaseConfirm) => vec![15],
            EventIdentifier::Value(EventIdentifierValue::SessionTokenGiveIndication) => vec![16],
            EventIdentifier::Value(EventIdentifierValue::SessionTokenPleaseIndication) => vec![17],
            EventIdentifier::Value(EventIdentifierValue::SessionControlGiveIndication) => vec![18],
            EventIdentifier::Value(EventIdentifierValue::SessionSyncMinorIndication) => vec![19],
            EventIdentifier::Value(EventIdentifierValue::SessionSyncMinorConfirm) => vec![20],
            EventIdentifier::Value(EventIdentifierValue::SessionSyncMajorIndication) => vec![21],
            EventIdentifier::Value(EventIdentifierValue::SessionSyncMajorConfirm) => vec![22],
            EventIdentifier::Value(EventIdentifierValue::SessionProviderExceptionReportIndication) => vec![23],
            EventIdentifier::Value(EventIdentifierValue::SessionUserExceptionReportIndication) => vec![24],
            EventIdentifier::Value(EventIdentifierValue::SessionActivityStartIndication) => vec![25],
            EventIdentifier::Value(EventIdentifierValue::SessionActivityResumeIndication) => vec![26],
            EventIdentifier::Value(EventIdentifierValue::SessionActivityInterruptIndication) => vec![27],
            EventIdentifier::Value(EventIdentifierValue::SessionActivityInterruptConfirm) => vec![28],
            EventIdentifier::Value(EventIdentifierValue::SessionActivityDiscardIndication) => vec![29],
            EventIdentifier::Value(EventIdentifierValue::SessionActivityDiscardConfirm) => vec![30],
            EventIdentifier::Value(EventIdentifierValue::SessionActivityEndIndication) => vec![31],
            EventIdentifier::Value(EventIdentifierValue::SessionActivityEndConfirm) => vec![32],
            EventIdentifier::Unknown(data) => data.to_vec(),
        }
    }
}

/// A context is used to indicate the protocols used and the supported encodings.
///
/// Default contexts are not supported.
#[derive(PartialEq, Clone, Debug)]
pub enum PresentationContextType {
    // DefaultContext,
    ContextDefinitionList(Vec<PresentationContext>),
}

/// Indicates which subset of encodings, if any, requested by the caller, are supported by the callee.
#[derive(PartialEq, Clone, Debug)]
pub enum PresentationContextResultType {
    // DefaultContextAccept,
    // DefaultContextReject,
    ContextDefinitionList(Vec<PresentationContextResult>),
}

/// Identifies the previously negotiated protocol and the encoding that is being used in a PPDU.
#[derive(PartialEq, Clone, Debug)]
pub struct PresentationContextIdentifier {
    pub identifier: Vec<u8>, // ASN1 Integer
    pub transfer_syntax_name: Oid<'static>,
}

/// Indicates the supported encodings for a protocol.
#[derive(PartialEq, Clone, Debug)]
pub struct PresentationContext {
    pub identifier: Vec<u8>, // ASN1 Integer
    pub abstract_syntax_name: Oid<'static>,
    pub transfer_syntax_name_list: Vec<Oid<'static>>,
}

/// The result of a notification.
///
/// Acceptance is the only successful outcome.
#[derive(PartialEq, Clone, Debug)]
pub enum PresentationContextResultCause {
    Acceptance,
    UserRejection,
    ProviderRejection,
    Unknown,
}

impl From<PresentationContextResultCause> for &[u8] {
    fn from(value: PresentationContextResultCause) -> Self {
        match value {
            PresentationContextResultCause::Acceptance => &[0],
            PresentationContextResultCause::UserRejection => &[1],
            PresentationContextResultCause::ProviderRejection => &[2],
            PresentationContextResultCause::Unknown => &[1], // Map Unknown to User Rejection
        }
    }
}

/// The possible reasons a negotiation was not accepted.
#[derive(PartialEq, Clone, Debug)]
pub enum PresentationContextResultProviderReasonValue {
    ReasonNotSpecified,
    AbstrctSyntaxNotSupported,
    ProposedAbstrctSyntaxNotSupported,
    LocalLimitOnDcsExceeded,
}

/// A container used to support unknown abort reasons.
#[derive(PartialEq, Clone, Debug)]
pub enum PresentationContextResultProviderReason {
    Value(PresentationContextResultProviderReasonValue),
    Unknown(Vec<u8>),
}

impl<'a> From<&'a PresentationContextResultProviderReason> for &'a [u8] {
    fn from(value: &'a PresentationContextResultProviderReason) -> Self {
        match value {
            PresentationContextResultProviderReason::Value(PresentationContextResultProviderReasonValue::ReasonNotSpecified) => &[0],
            PresentationContextResultProviderReason::Value(PresentationContextResultProviderReasonValue::AbstrctSyntaxNotSupported) => &[1],
            PresentationContextResultProviderReason::Value(PresentationContextResultProviderReasonValue::ProposedAbstrctSyntaxNotSupported) => &[2],
            PresentationContextResultProviderReason::Value(PresentationContextResultProviderReasonValue::LocalLimitOnDcsExceeded) => &[3],
            PresentationContextResultProviderReason::Unknown(data) => &data,
        }
    }
}

impl From<&[u8]> for PresentationContextResultProviderReason {
    fn from(value: &[u8]) -> Self {
        match value {
            &[0] => PresentationContextResultProviderReason::Value(PresentationContextResultProviderReasonValue::ReasonNotSpecified),
            &[1] => PresentationContextResultProviderReason::Value(PresentationContextResultProviderReasonValue::AbstrctSyntaxNotSupported),
            &[2] => PresentationContextResultProviderReason::Value(PresentationContextResultProviderReasonValue::ProposedAbstrctSyntaxNotSupported),
            &[3] => PresentationContextResultProviderReason::Value(PresentationContextResultProviderReasonValue::LocalLimitOnDcsExceeded),
            x => PresentationContextResultProviderReason::Unknown(x.to_vec()),
        }
    }
}

/// The result of a negotiation indicating the accepted encodings for a protocol.
///
/// This will typically only be required by a user when rejecting a request or receiving an error. Accepting the encodings is handled when the responder is created.
#[derive(PartialEq, Clone, Debug)]
pub struct PresentationContextResult {
    /// The result of the negotiation for this protocol.
    pub result: PresentationContextResultCause,

    /// The protocol oid.
    pub transfer_syntax_name: Option<Oid<'static>>,

    /// The reason the negotiation was rejected (or accepted).
    pub provider_reason: Option<PresentationContextResultProviderReason>,
}

/// The addressing used to identify the caller and callee endpoints.
#[derive(PartialEq, Clone, Debug)]
pub struct CoppConnectionInformation {
    pub calling_presentation_selector: Option<Vec<u8>>,
    pub called_presentation_selector: Option<Vec<u8>>,
}

impl Default for CoppConnectionInformation {
    fn default() -> Self {
        Self { calling_presentation_selector: None, called_presentation_selector: None }
    }
}

/// The result of an Initiate request.
///
/// This protocol may encapsulate the data of the protocol above.
#[derive(IntoStaticStr)]
pub enum CoppInitResult<T: CoppConnection> {
    /// The remote host accepted our proposal.
    Success(T, Option<UserData>),
}

/// Data received from the remote host.
///
/// The finish and disconnect phases may contain data for higher layer protocols.
#[derive(IntoStaticStr)]
pub enum CoppRecvResult {
    /// The underlying connection is closed. Close out side too.
    Closed,

    /// Data was received. Pass this on to the higher layer.
    Data(UserData),

    /// The remote host is proposing the close the connection. This may be initiated by a higher layer protocol. Pass the user data on.
    Finish(Option<UserData>),

    /// The remote host accepted our proposal to close the connection. This may be initiated by a higher layer protocol. Pass the user data on.
    Disconnect(Option<UserData>),
}

/// Initiates a COPP connection.
pub trait CoppInitiator: Send {
    /// Starts signalling a COPP connection. An Refuse error may be received during this phase.
    ///
    /// This will return a connection on success. A Rejected error will be returned if the negotiation failed.
    /// Higher layer negotiations may be inciuded.
    /// A provider abort will be returned if there was a protocol error on this layer or a user abort at a higher layer..
    fn initiate(self, presentation_contexts: PresentationContextType, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<CoppInitResult<impl CoppConnection>, CoppError>> + Send;
}

/// Used to accept or reject an incoming request.
pub trait CoppAcceptor: Send {
    /// Accept the incoming connection.
    ///
    /// Higher layer protocol information may be returned.
    fn accept(self) -> impl std::future::Future<Output = Result<(impl CoppResponder, PresentationContextType, Option<UserData>), CoppError>> + Send;

    /// Reject the incoming connection.
    fn reject(self, context_definition_result_list: PresentationContextResultType, provider_reason: Option<ProviderReason>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    /// Indicate a failure at a higher layer.
    fn user_abort(self, presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    /// Indicate a failure at a this layer.
    fn provider_abort(self, provider_reason: Option<ProviderReason>, event_identifier: Option<EventIdentifier>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;
}

/// Used to complete negoitations
pub trait CoppResponder: Send {
    /// Accept the negotiation and respond to the remote host.
    fn complete_connection(self, accept_data: Option<UserData>) -> impl std::future::Future<Output = Result<impl CoppConnection, CoppError>> + Send;

    /// Reject the incoming connection.
    fn reject(self, context_definition_result_list: PresentationContextResultType, provider_reason: Option<ProviderReason>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    /// Indicate a failure at a higher layer.
    fn user_abort(self, presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    /// Indicate a failure at a this layer.
    fn provider_abort(self, provider_reason: Option<ProviderReason>, event_identifier: Option<EventIdentifier>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;
}

/// A trait representing a connection.
pub trait CoppConnection: Send {
    /// Splits a connection into reader and writer components. This must be done before the connection is used.
    fn split(self) -> impl std::future::Future<Output = Result<(impl CoppReader, impl CoppWriter), CoppError>> + Send;
}

/// A trait representing the read half of a connection.
pub trait CoppReader: Send {
    /// Receives data. An Abort error may also be received.
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CoppRecvResult, CoppError>> + Send;
}

/// A trait representing the write half of a connection.
pub trait CoppWriter: Send {
    /// Send data to the remote host.
    fn send(&mut self, user_data: &mut VecDeque<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    /// Signals the intent to close a connection. A disconnect should be received before dropping the reader and writer.
    fn finish(&mut self, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    /// Confirms that a finish was received and this side is okay to close the connection.
    fn disconnect(&mut self, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    /// Abort the connection. The reader and writer should be dropped after this is sent.
    fn user_abort(&mut self, presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    /// If a protocol error is received. Use this to close the connection.
    fn provider_abort(&mut self, provider_reason: Option<ProviderReason>, event_identifier: Option<EventIdentifier>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;
}
