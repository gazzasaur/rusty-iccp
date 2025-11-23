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

// Only BER encoding is supported.

#[derive(Clone, PartialEq, Debug)]
pub struct AcseRequestInformation {
    pub application_context_name: Oid<'static>,

    pub called_ap_title: Option<ApTitle>,
    pub called_ae_qualifier: Option<AeQualifier>,
    pub called_ap_invocation_identifier: Option<Vec<u8>>, // Integer
    pub called_ae_invocation_identifier: Option<Vec<u8>>, // Integer

    pub calling_ap_title: Option<ApTitle>,
    pub calling_ae_qualifier: Option<AeQualifier>,
    pub calling_ap_invocation_identifier: Option<Vec<u8>>, // Integer
    pub calling_ae_invocation_identifier: Option<Vec<u8>>, // Integer

    pub implementation_information: Option<String>,
}

#[derive(PartialEq, Debug)]
pub struct AcseResponseInformation {
    pub application_context_name: Oid<'static>,

    pub associate_result: AssociateResult,
    pub associate_source_diagnostic: AssociateSourceDiagnostic,

    pub responding_ap_title: Option<ApTitle>,
    pub responding_ae_qualifier: Option<AeQualifier>,
    pub responding_ap_invocation_identifier: Option<Vec<u8>>, // Integer
    pub responding_ae_invocation_identifier: Option<Vec<u8>>, // Integer

    pub implementation_information: Option<String>,
}

#[derive(PartialEq, Debug)]
pub enum AssociateResult {
    Accepted,
    RejectedPermanent,
    RejectedTransient,
    Unknown(Vec<u8>), // Integer
}

#[derive(PartialEq, Debug)]
pub enum AssociateSourceDiagnostic {
    User(AssociateSourceDiagnosticUserCategory),
    Provider(AssociateSourceDiagnosticProviderCategory),
}

#[derive(PartialEq, Debug)]
pub enum AssociateSourceDiagnosticUserCategory {
    Null,
    NoReasonGiven,
    ApplicationContextNameNotSupported,
    CallingApTitleNotRecognized,
    CallingApInvocationIdentifierNotRecognized,
    CallingAeQualifierNotRecognized,
    CallingAeInvocationIdentifierNotRecognized,
    CalledApTitleNotRecognized,
    CalledApInvocationIdentifierNotRecognized,
    CalledAeQualifierNotRecognized,
    CalledAeInvocationIdentifierNotRecognized,
    AuthenticationMechanismNameNotRecognized,
    AuthenticationMechanismNameRequired,
    AuthenticationFailure,
    AuthenticationRequired,
    Unknown(Vec<u8>), // Integer
}

#[derive(PartialEq, Debug)]
pub enum AssociateSourceDiagnosticProviderCategory {
    Null,
    NoReasonGiven,
    NoCommonAcseVersion,
    Unknown(Vec<u8>), // Integer
}

#[derive(Clone, PartialEq, Debug)]
pub enum ApTitle {
    // Form1(...), Not supporting as this library does not support DN.
    Form2(Oid<'static>),
}

#[derive(Clone, PartialEq, Debug)]
pub enum AeQualifier {
    // Form1(...), Not supporting as this library does not support DN.
    Form2(Vec<u8>), // Integer
}

pub enum AcseRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait OsiSingleValueAcseInitiator: Send {
    fn initiate(self, abstract_syntax_name: Oid<'static>, user_data: Vec<u8>) -> impl std::future::Future<Output = Result<(impl OsiSingleValueAcseConnection, AcseResponseInformation, Vec<u8>), AcseError>> + Send;
}

pub trait OsiSingleValueAcseListener: Send {
    fn responder(self, response: AcseResponseInformation) -> impl std::future::Future<Output = Result<(impl OsiSingleValueAcseResponder, AcseRequestInformation, Vec<u8>), AcseError>> + Send;
}

pub trait OsiSingleValueAcseResponder: Send {
    fn accept(self, user_data: Vec<u8>) -> impl std::future::Future<Output = Result<impl OsiSingleValueAcseConnection, AcseError>> + Send;
}

pub trait OsiSingleValueAcseConnection: Send {
    fn split(self) -> impl std::future::Future<Output = Result<(impl OsiSingleValueAcseReader, impl OsiSingleValueAcseWriter), AcseError>> + Send;
}

pub trait OsiSingleValueAcseReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<AcseRecvResult, AcseError>> + Send;
}

pub trait OsiSingleValueAcseWriter: Send {
    fn send(&mut self, data: Vec<u8>) -> impl std::future::Future<Output = Result<(), AcseError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), AcseError>> + Send;
}
