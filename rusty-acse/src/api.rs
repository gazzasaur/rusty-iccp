use der_parser::{
    Oid,
    asn1_rs::{GraphicString, Integer},
    ber::{BerObject, BerObjectContent, compat::BerObjectHeader},
    der::{Class, Header, Tag},
};
use rusty_copp::{CoppError, UserData};
use thiserror::Error;

use crate::messages::parsers::to_acse_error;

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
    pub called_ap_invocation_identifier: Option<Vec<u8>>, // Integer
    pub called_ae_invocation_identifier: Option<Vec<u8>>, // Integer

    pub calling_ap_title: Option<ApTitle>,
    pub calling_ae_qualifier: Option<AeQualifier>,
    pub calling_ap_invocation_identifier: Option<Vec<u8>>, // Integer
    pub calling_ae_invocation_identifier: Option<Vec<u8>>, // Integer

    pub implementation_information: Option<String>,
}

impl AcseRequestInformation {
    pub fn serialisee(&self, user_data: &Option<UserData>) -> Result<Vec<u8>, AcseError> {
        let payload = BerObject::from_header_and_content(Header::new(Class::Application, true, Tag::from(0), der_parser::ber::Length::Definite(0)), der_parser::ber::BerObjectContent::Sequence(vec![
            // Version Default 1
            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(1), der_parser::ber::Length::Definite(0)), BerObjectContent::OID(self.application_context_name.clone()))
        ]));
        Ok(payload.to_vec().map_err(to_acse_error("Failed to serialise Application Request Information"))?)
    }
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
    Data(UserData),
}

pub trait AcseInitiator: Send {
    fn initiate(self, user_data: UserData) -> impl std::future::Future<Output = Result<(impl AcseConnection, AcseResponseInformation, UserData), AcseError>> + Send;
}

pub trait AcseListener: Send {
    fn responder(self) -> impl std::future::Future<Output = Result<(impl AcseResponder, AcseRequestInformation, UserData), AcseError>> + Send;
}

pub trait AcseResponder: Send {
    fn accept(self, response: AcseResponseInformation, user_data: UserData) -> impl std::future::Future<Output = Result<impl AcseConnection, AcseError>> + Send;
}

pub trait AcseConnection: Send {
    fn split(self) -> impl std::future::Future<Output = Result<(impl AcseReader, impl AcseWriter), AcseError>> + Send;
}

pub trait AcseReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<AcseRecvResult, AcseError>> + Send;
}

pub trait AcseWriter: Send {
    fn send(&mut self, data: UserData) -> impl std::future::Future<Output = Result<(), AcseError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), AcseError>> + Send;
}
