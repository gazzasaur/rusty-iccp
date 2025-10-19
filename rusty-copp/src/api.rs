use der_parser::Oid;
use rusty_cosp::CospError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoppError {
    #[error("COPP Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("COPP over COSP Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] CospError),

    #[error("COPP IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("COPP Error: {}", .0)]
    InternalError(String),
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
pub struct PresentationContext {
    pub indentifier: Vec<u8>, // ASN1 Integer
    pub abstract_syntax_name: Oid<'static>,
    pub transfer_syntax_name_list: Vec<Oid<'static>>,
}

#[derive(PartialEq, Clone, Debug)]
pub enum PresentationContextResultCause {
    Acceptance,
    UserRejection,
    ProviderRejection,
}

impl From<PresentationContextResultCause> for &[u8] {
    fn from(value: PresentationContextResultCause) -> Self {
        match value {
            PresentationContextResultCause::Acceptance => &[0],
            PresentationContextResultCause::UserRejection => &[1],
            PresentationContextResultCause::ProviderRejection => &[2],
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
    pub presentation_context: PresentationContextType,
}

impl Default for CoppConnectionInformation {
    fn default() -> Self {
        Self {
            calling_presentation_selector: None,
            called_presentation_selector: None,
            presentation_context: PresentationContextType::ContextDefinitionList(vec![]),
        }
    }
}

pub enum CoppRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait CoppInitiator: Send {
    fn initiate(self, presentation_contexts: PresentationContextType, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(impl CoppConnection, Option<Vec<u8>>), CoppError>> + Send;
}

pub trait CoppListener: Send {
    fn responder(self) -> impl std::future::Future<Output = Result<(impl CoppResponder, Option<Vec<u8>>), CoppError>> + Send;
}

pub trait CoppResponder: Send {
    fn accept(self, accept_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<impl CoppConnection, CoppError>> + Send;
}

pub trait CoppConnection: Send {
    fn split(self) -> impl std::future::Future<Output = Result<(impl CoppReader, impl CoppWriter), CoppError>> + Send;
}

pub trait CoppReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CoppRecvResult, CoppError>> + Send;
}

pub trait CoppWriter: Send {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), CoppError>> + Send;
}
