use der_parser::{Oid, asn1_rs::{GraphicString, Integer}};
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

#[derive(PartialEq, Debug)]
pub struct AcseRequestInformation {
    pub application_context_name: Oid<'static>,

    pub called_ap_title: Option<ApTitle>,
    pub called_ae_qualifier: Option<AeQualifier>,
    pub called_ap_invocation_identifier: Option<Integer<'static>>,
    pub called_ae_invocation_identifier: Option<Integer<'static>>,

    pub calling_ap_title: Option<ApTitle>,
    pub calling_ae_qualifier: Option<AeQualifier>,
    pub calling_ap_invocation_identifier: Option<Integer<'static>>,
    pub calling_ae_invocation_identifier: Option<Integer<'static>>,

    pub implementation_information: Option<GraphicString<'static>>,
    pub user_data: Option<Vec<Vec<u8>>>,
}

#[derive(PartialEq, Debug)]
pub struct AcseResponseInformation {
    pub application_context_name: Oid<'static>,

    pub associate_result: AssociateResult,
    pub associate_source_diagnostic: AssociateSourceDiagnostic,

    pub called_ap_title: Option<ApTitle>,
    pub called_ae_qualifier: Option<AeQualifier>,
    pub called_ap_invocation_identifier: Option<Integer<'static>>,
    pub called_ae_invocation_identifier: Option<Integer<'static>>,

    pub calling_ap_title: Option<ApTitle>,
    pub calling_ae_qualifier: Option<AeQualifier>,
    pub calling_ap_invocation_identifier: Option<Integer<'static>>,
    pub calling_ae_invocation_identifier: Option<Integer<'static>>,

    pub implementation_information: Option<GraphicString<'static>>,
    pub user_data: Option<Vec<Vec<u8>>>,
}

#[derive(PartialEq, Debug)]
pub enum AssociateResult {
    Accepted,
    RejectedPermanent,
    RejectedTransient,
}

#[derive(PartialEq, Debug)]
pub enum AssociateSourceDiagnostic {
    User,
    Provider,
}

#[derive(PartialEq, Debug)]
pub enum ApTitle {
    Form1(Vec<u8>), // DN
    Form2(Oid<'static>),
}

#[derive(PartialEq, Debug)]
pub enum AeQualifier {
    Form1(Vec<u8>), // DN
    Form2(Vec<u8>), // Integer
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
