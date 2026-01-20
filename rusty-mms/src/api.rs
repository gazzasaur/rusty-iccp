use der_parser::{Oid, asn1_rs::ASN1DateTime};
use rusty_acse::AcseError;
use thiserror::Error;

/**
 * This MMS stack is designed to be used with ICCP/TASE2.
 * The Packet API itself is left intentionally low-level.
 * High level adaptors should be used.
 *
 * It supports the following.
 *
 * Parameter CBB
 * - str1
 * - str2
 * - vnam
 * - valt -- Optional. Leaving out for now.
 * - vlis
 *
 * VMD Support
 * - GetNameList
 * - Identify
 *    
 * Variable Access
 * - Read
 * - Write
 * - InformationReport
 * - GetVariableAccessAttributes
 * - DefineNamedVariableList
 * - GetNamedVariableListAttribute
 * - DeleteNamedVariableList
 */

#[derive(Error, Debug)]
pub enum MmsError {
    #[error("MMS Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("MMS over ACSE Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] AcseError),

    #[error("MMS IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("MMS Error: {}", .0)]
    InternalError(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsObjectName {
    VmdSpecific(String),
    DomainSpecific(String, String), // Domain, Item Id
    AaSpecific(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsObjectScope {
    Vmd,
    Domain(String),
    Aa,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsObjectClass {
    Basic(MmsBasicObjectClass),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsBasicObjectClass {
    NamedVariable,
    NamedVariableList,
    NamedType,

    Semaphore,
    EventCondition,
    EventAction,
    EventEnrollment,
    Journal,
    Domain,
    ProgramInvocation,
    OperatorStation,
    DataExchange,
    AccessControlList,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsVariableAccessSpecification {
    ListOfVariables(Vec<ListOfVariablesItem>),
    VariableListName(MmsObjectName),
    // AlternateAccess, TODO Part of valt
}

#[derive(Debug, PartialEq, Eq)]
pub struct ListOfVariablesItem {
    pub variable_specification: VariableSpecification,
    // Using a struct as this has an optional part that is currently not supported.
}

#[derive(Debug, PartialEq, Eq)]
pub enum VariableSpecification {
    Name(MmsObjectName),
    Invalidated,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsAccessError {
    ObjectInvalidated,
    // TODO Add other error codes
    Unknown(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsAccessResult {
    Success(MmsData),
    Failure(MmsAccessError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsWriteResult {
    Success,
    Failure(MmsAccessError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsData {
    Array(Vec<MmsData>),
    Structure(Vec<MmsData>),
    Boolean(bool),
    BitString(u8, Vec<u8>),
    Integer(Vec<u8>),
    Unsigned(Vec<u8>),
    FloatingPoint(Vec<u8>),
    OctetString(Vec<u8>),
    VisibleString(String),
    GeneralizedTime(ASN1DateTime),
    BinaryTime(Vec<u8>),
    Bcd(Vec<u8>),
    BooleanArray(u8, Vec<u8>),
    ObjectId(Oid<'static>),
    MmsString(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsRecvResult {
    Closed,
    Message(MmsMessage),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsMessage {
    // InitiateRequest, Handled internally
    // InitiateResponse, Handled internally
    ConfirmedRequest { invocation_id: Vec<u8>, request: MmsConfirmedRequest },
    ConfirmedResponse { invocation_id: Vec<u8>, response: MmsConfirmedResponse },
    Unconfirmed { unconfirmed_service: MmsUnconfirmedService },
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsConfirmedRequest {
    GetNameList {
        object_class: MmsObjectClass,
        object_scope: MmsObjectScope,
        continue_after: Option<String>, // MMS Identifier
    },
    Identify,
    Read {
        specification_with_result: Option<bool>,
        variable_access_specification: MmsVariableAccessSpecification,
    },
    Write {
        variable_access_specification: MmsVariableAccessSpecification,
        list_of_data: Vec<MmsData>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsConfirmedResponse {
    GetNameList {
        list_of_identifiers: Vec<String>, // MMS Identifiers
        more_follows: Option<bool>, // Defaults to true if not present
    },
    Identify {
        vendor_name: String,
        model_name: String,
        revision: String,
        abstract_syntaxes: Option<Vec<Oid<'static>>>,
    },
    Read {
        variable_access_specification: Option<MmsVariableAccessSpecification>,
        access_results: Vec<MmsAccessResult>,
    },
    Write {
        write_results: Vec<MmsWriteResult>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsUnconfirmedService {
    InformationReport {
        variable_access_specification: MmsVariableAccessSpecification,
        access_results: Vec<MmsAccessResult>,
    },
}

pub trait MmsInitiator: Send {
    fn initiate(self) -> impl std::future::Future<Output = Result<impl MmsConnection, MmsError>> + Send;
}

pub trait MmsListener: Send {
    fn responder(self) -> impl std::future::Future<Output = Result<impl MmsResponder, MmsError>> + Send;
}

pub trait MmsResponder: Send {
    fn accept(self) -> impl std::future::Future<Output = Result<impl MmsConnection, MmsError>> + Send;
}

pub trait MmsConnection: Send {
    fn split(self) -> impl std::future::Future<Output = Result<(impl MmsReader, impl MmsWriter), MmsError>> + Send;

    // ParameterSupportOption::Str1, Array
    // ParameterSupportOption::Str2, Map
    // ParameterSupportOption::Vnam,
    // ParameterSupportOption::Valt,
    // ParameterSupportOption::Vlis,

    // ServiceSupportOption::GetNameList,
    // ServiceSupportOption::Identify,
    // ServiceSupportOption::Read,
    // ServiceSupportOption::Write,
    // ServiceSupportOption::GetVariableAccessAttributes,
    // ServiceSupportOption::GetNamedVariableListAttribute,
    // ServiceSupportOption::DefineNamedVariableList,
    // ServiceSupportOption::DeleteNamedVariableList,
    // ServiceSupportOption::InformationReport,
}

pub trait MmsReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<MmsRecvResult, MmsError>> + Send;

    // ParameterSupportOption::Str1, Array
    // ParameterSupportOption::Str2, Map
    // ParameterSupportOption::Vnam,
    // ParameterSupportOption::Valt,
    // ParameterSupportOption::Vlis,

    // ServiceSupportOption::GetNameList,
    // ServiceSupportOption::Identify,
    // ServiceSupportOption::Read,
    // ServiceSupportOption::Write,
    // ServiceSupportOption::GetVariableAccessAttributes,
    // ServiceSupportOption::GetNamedVariableListAttribute,
    // ServiceSupportOption::DefineNamedVariableList,
    // ServiceSupportOption::DeleteNamedVariableList,
    // ServiceSupportOption::InformationReport,
}

pub trait MmsWriter: Send {
    fn send(&mut self, message: MmsMessage) -> impl std::future::Future<Output = Result<(), MmsError>> + Send;

    // ParameterSupportOption::Str1, Array
    // ParameterSupportOption::Str2, Map
    // ParameterSupportOption::Vnam,
    // ParameterSupportOption::Valt,
    // ParameterSupportOption::Vlis,

    // ServiceSupportOption::GetNameList,
    // ServiceSupportOption::Identify,
    // ServiceSupportOption::Read,
    // ServiceSupportOption::Write,
    // ServiceSupportOption::GetVariableAccessAttributes,
    // ServiceSupportOption::GetNamedVariableListAttribute,
    // ServiceSupportOption::DefineNamedVariableList,
    // ServiceSupportOption::DeleteNamedVariableList,
    // ServiceSupportOption::InformationReport,
}
