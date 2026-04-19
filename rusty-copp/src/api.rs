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
    Refused(Option<ProviderReason>, PresentationContextResultType, Option<UserData>),

    /// Indicated a connection was aborted. The connection should be dropped.
    /// This may occur during any read operation.
    #[error("COPP User Abort")]
    UserAborted(Option<Vec<PresentationContextIdentifier>>, Option<UserData>),

    /// Indicated a connection was aborted. The connection should be dropped.
    /// This may occur during any read operation.
    #[error("COPP Provider Abort")]
    ProviderAborted(Option<ProviderReason>, Option<EventIdentifier>),
}

#[derive(Debug)]
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

#[derive(Debug)]
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

    fn reject(self, context_definition_result_list: PresentationContextResultType, provider_reason: Option<ProviderReason>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    fn user_abort(self, presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    fn provider_abort(self, provider_reason: Option<ProviderReason>, event_identifier: Option<EventIdentifier>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;
}

pub trait CoppResponder: Send {
    fn complete_connection(self, accept_data: Option<UserData>) -> impl std::future::Future<Output = Result<impl CoppConnection, CoppError>> + Send;

    fn reject(self, context_definition_result_list: PresentationContextResultType, provider_reason: Option<ProviderReason>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    fn user_abort(self, presentation_contexts: Option<Vec<PresentationContextIdentifier>>, user_data: Option<UserData>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;

    fn provider_abort(self, provider_reason: Option<ProviderReason>, event_identifier: Option<EventIdentifier>) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;
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
