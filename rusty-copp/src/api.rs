use std::collections::VecDeque;

use der_parser::Oid;
use rusty_cosp::CospError;
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

    /// Indicated a connection was refused. The connection should be dropped.
    /// This should only be received by the initiator during the initiate phase.
    #[error("COPP Refused")]
    Refused(Option<UserData>),

    /// Indicated a connection was aborted. The connection should be dropped.
    /// This may occur during any read operation.
    #[error("COPP Abort")]
    Aborted(Option<UserData>),
}

#[derive(Debug)]
pub enum ProviderReason {
    ReasonNotSpecified = 0,
    TemporaryCongestion = 1,
    LocalLimitExceeded = 2,
    CalledPresentationAddressUnknown = 3,
    ProtocolVersionNotSupported = 4,
    DefaultContextNotSupported = 5,
    UserDataNotReadable = 6,
    NoPsapAvailable = 7,
}

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
pub enum EventIdentifier {
    Value(EventIdentifierValue),
    Unknown(Vec<u8>),
}

// TODO Support Default Context. This library is targeted towards ACSE/MMS which does not require the default context.
#[derive(PartialEq, Clone, Debug)]
pub enum PresentationContextType {
    // DefaultContext,
    ContextDefinitionList(Vec<PresentationContext>),
}

#[derive(PartialEq, Clone, Debug)]
pub enum PresentationContextResultType {
    // DefaultContextAccept,
    // DefaultContextReject,
    ContextDefinitionList(Vec<PresentationContextResult>),
}

#[derive(PartialEq, Clone, Debug)]
pub struct PresentationContextIdentifier {
    pub identifier: Vec<u8>, // ASN1 Integer
    pub transfer_syntax_name: Oid<'static>,
}

#[derive(PartialEq, Clone, Debug)]
pub struct PresentationContext {
    pub identifier: Vec<u8>, // ASN1 Integer
    pub abstract_syntax_name: Oid<'static>,
    pub transfer_syntax_name_list: Vec<Oid<'static>>,
}

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

#[derive(PartialEq, Clone, Debug)]
pub enum PresentationContextResultProviderReason {
    ReasonNotSpecified,
    AbstrctSyntaxNotSupported,
    ProposedAbstrctSyntaxNotSupported,
    LocalLimitOnDcsExceeded,
}

impl From<PresentationContextResultProviderReason> for &[u8] {
    fn from(value: PresentationContextResultProviderReason) -> Self {
        match value {
            PresentationContextResultProviderReason::ReasonNotSpecified => &[0],
            PresentationContextResultProviderReason::AbstrctSyntaxNotSupported => &[1],
            PresentationContextResultProviderReason::ProposedAbstrctSyntaxNotSupported => &[2],
            PresentationContextResultProviderReason::LocalLimitOnDcsExceeded => &[3],
        }
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct PresentationContextResult {
    pub result: PresentationContextResultCause,
    pub transfer_syntax_name: Option<Oid<'static>>,
    pub provider_reason: Option<PresentationContextResultProviderReason>,
}

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

pub enum CoppRecvResult {
    Closed,
    Data(UserData),
}

pub trait CoppInitiator: Send {
    fn initiate(self, presentation_contexts: PresentationContextType, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(impl CoppConnection, Option<UserData>), CoppError>> + Send;
}

pub trait CoppListener: Send {
    fn accept(self) -> impl std::future::Future<Output = Result<(impl CoppResponder, PresentationContextType, Option<UserData>), CoppError>> + Send;

    /// Not cancel safe
    fn abort_user(self, presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;
}

pub trait CoppResponder: Send {
    fn complete_connection(self, accept_data: Option<UserData>) -> impl std::future::Future<Output = Result<impl CoppConnection, CoppError>> + Send;

    // fn refuse(self) -> impl std::future::Future<Output = Result<(impl CoppResponder, Option<UserData>), CoppError>> + Send;
    // fn abort_user(self, presentation_contexts: Vec<PresentationContextIdentifier>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;
}

pub trait CoppConnection: Send {
    fn split(self) -> impl std::future::Future<Output = Result<(impl CoppReader, impl CoppWriter), CoppError>> + Send;
}

pub trait CoppReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CoppRecvResult, CoppError>> + Send;
}

pub trait CoppWriter: Send {
    fn send(&mut self, user_data: &mut VecDeque<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    fn abort_user(self, presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;
}
