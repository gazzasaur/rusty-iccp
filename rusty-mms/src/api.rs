use std::{collections::HashMap, time::Instant};

use der_parser::Oid;
use rusty_copp::CoppError;
use thiserror::Error;

/**
 * This MMS stack is designed to be used with ICCP. It supports the following.
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
 * - Information Report
 * - GetVariableAccessAttributes
 * - DefineNamedVariableList
 * - GetNamedVariableListAttribute
 * - DeleteNamedVariableList
 */

pub enum MmsObjectName {
    VmdSpecific(String),
    DomainSpecific(String, String), // Domain, Item Id
    AaSpecific(String)
}

pub enum MmsVariableAccessSpecification {
    ListOfVariable(Vec<ListOfVariableItem>),
    // AlternateAccess, valt
    VariableListName(MmsObjectName),
}

pub struct ListOfVariableItem {
    variable_specification: VariableSpecification
}

pub enum VariableSpecification {
    Name(MmsObjectName),
}

pub enum MmsAccessError {
    Unknown(Vec<u8>)
}

pub enum MmsAccessResult {
    Failure(MmsAccessError),
    Success(MmsData),
}

pub struct MmsBitString {
    padding: u8,
    buffer: Vec<u8>,
}

pub enum MmsData {
    Array(Vec<MmsData>),
    Structure(Vec<MmsData>),
    Boolean(bool),
    BitString(MmsBitString),
    Integer(Vec<u8>),
    Unsigned(Vec<u8>),
    FloatingPoint(Vec<u8>),
    OctetString(Vec<u8>),
    VisibleString(String),
    GeneralizedTime(Instant),
    BinaryTime(Vec<u8>),
    Bcd(Vec<u8>),
    BooleanArray(MmsBitString),
    ObjectId(Oid<'static>),
    MmsString(String),
}

pub enum MmsSimpleData {
    MmsString(String) // Printable characters only.
}

#[derive(Error, Debug)]
pub enum MmsError {
    #[error("MMS Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("MMS over ACSE Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] CoppError),

    #[error("MMS IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("MMS Error: {}", .0)]
    InternalError(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsRecvResult {
    Closed,
    Data(MmsMessage),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsMessage {
    ConfirmedRequest,
    InitiateRequest,
    InitiateResponse,
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

pub trait MmsConnection: Send + Sync {
    fn read(&mut self, access_specifications: Vec<MmsVariableAccessSpecification>) -> impl std::future::Future<Output = Result<Vec<MmsAccessResult>, MmsError>> + Send;

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
