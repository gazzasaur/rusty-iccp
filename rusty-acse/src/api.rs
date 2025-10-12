use der_parser::Oid;
use rusty_copp::CoppError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AcseError {
    #[error("ACSE Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("ACSE over COSP Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] CoppError),

    #[error("ACSE IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("ACSE Error: {}", .0)]
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

#[derive(PartialEq, Clone, Debug)]
pub enum PresentationContextResultProviderReason {
    ReasonNotSpecified,
    AbstrctSyntaxNotSupported,
    ProposedAbstrctSyntaxNotSupported,
    LocalLimitOnDcsExceeded,
}

#[derive(PartialEq, Clone, Debug)]
pub struct PresentationContextResult {
    pub result: PresentationContextResultCause,
    pub transfer_syntax_name: Option<Oid<'static>>,
    pub provider_reason: Option<PresentationContextResultProviderReason>,
}

#[derive(PartialEq, Clone, Debug)]
pub struct AcseConnectionInformation {
    pub calling_presentation_selector: Option<Vec<u8>>,
    pub called_presentation_selector: Option<Vec<u8>>,
    pub presentation_context: PresentationContextType,
}

impl Default for AcseConnectionInformation {
    fn default() -> Self {
        Self {
            calling_presentation_selector: None,
            called_presentation_selector: None,
            presentation_context: PresentationContextType::ContextDefinitionList(vec![]),
        }
    }
}

pub enum AcseRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait AcseInitiator: Send {
    fn initiate(self, presentation_contexts: PresentationContextType, user_data: Option<Vec<u8>>) -> impl std::future::Future<Output = Result<(impl AcseConnection, Option<Vec<u8>>), AcseError>> + Send;
}

pub trait AcseListener: Send {
    fn responder(self) -> impl std::future::Future<Output = Result<(impl AcseResponder, AcseConnectionInformation, Option<Vec<u8>>), AcseError>> + Send;
}

pub trait AcseResponder: Send {
    fn accept(self, accept_data: Option<&[u8]>) -> impl std::future::Future<Output = Result<impl AcseConnection, AcseError>> + Send;
}

pub trait AcseConnection: Send {
    fn split(self) -> impl std::future::Future<Output = Result<(impl AcseReader, impl AcseWriter), AcseError>> + Send;
}

pub trait AcseReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<AcseRecvResult, AcseError>> + Send;
}

pub trait AcseWriter: Send {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), AcseError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), AcseError>> + Send;
}
