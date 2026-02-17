use der_parser::{Oid, asn1_rs::ASN1DateTime};
use num_bigfloat::BigFloat;
use num_bigint::{BigInt, BigUint};
use rusty_mms::{ListOfVariablesItem, MmsAccessResult, MmsData, MmsError, MmsObjectClass, MmsObjectName, MmsObjectScope, MmsVariableAccessSpecification, MmsWriteResult};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MmsServiceError {
    #[error("MMS Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("MMS Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] MmsError),

    #[error("MMS IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("MMS Error: {}", .0)]
    InternalError(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsServiceBcd {
    Bcd0,
    Bcd1,
    Bcd2,
    Bcd3,
    Bcd4,
    Bcd5,
    Bcd6,
    Bcd7,
    Bcd8,
    Bcd9,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsServiceData {
    Array(Vec<MmsServiceData>), // Arrays are meant to contain a consistent type across all elements. This is not enforced as it means traversing trees.
    Structure(Vec<MmsServiceData>),
    Boolean(bool),
    BitString(Vec<bool>),
    Integer(BigInt),
    Unsigned(BigUint),
    FloatingPoint(BigFloat),
    OctetString(Vec<u8>),
    VisibleString(String),
    GeneralizedTime(ASN1DateTime),
    BinaryTime(Vec<u8>),
    Bcd(Vec<MmsServiceBcd>),
    BooleanArray(Vec<bool>),
    ObjectId(Oid<'static>),
    MmsString(String),
}

pub struct Identity {
    pub vendor_name: String,
    pub model_name: String,
    pub revision: String,
    pub abstract_syntaxes: Option<Vec<Oid<'static>>>,
}

pub struct NameList {
    pub identifiers: String,
    pub more_follows: bool,
}

pub enum TypeDescription {
    Array {
        packed: Option<bool>,
        number_of_elements: u32,
        element_type: Box<TypeDescription>,
    },
    Structure {
        packed: Option<bool>,
        components: Vec<TypeDescription>,
    },
    Boolean,
    BitString(i32),
    Integer(i32),
    Unsigned(u8),
    FloatingPoint {
        format_width: u8,
        exponent_width: u8,
    },
    OctetString(i32),
    VisibleString(i32),
    GeneralizedTime,
    BinaryTime(bool),
    Bcd(u8),
    ObjId,
    MmsString(i32),
}

pub struct VariableAccessAttributes {
    pub deletable: bool,
    pub type_description: TypeDescription,
}

pub trait MmsInitiatorService: Send + Sync {
    fn idemtify(&mut self) -> impl std::future::Future<Output = Result<Identity, MmsServiceError>> + Send;

    fn get_name_list(&mut self, object_class: MmsObjectClass, object_scope: MmsObjectScope, continue_after: Option<String>) -> impl std::future::Future<Output = Result<NameList, MmsServiceError>> + Send;
    fn get_variable_access_attributes(&mut self, object_name: MmsObjectName) -> impl std::future::Future<Output = Result<VariableAccessAttributes, MmsServiceError>> + Send;

    fn define_named_variable_list(
        &mut self,
        variable_list_name: MmsObjectName,
        list_of_variables: Vec<ListOfVariablesItem>,
    ) -> impl std::future::Future<Output = Result<(Option<MmsVariableAccessSpecification>, Vec<MmsAccessResult>), MmsServiceError>> + Send;
    fn get_named_variable_list_attributes(&mut self, variable_list_name: MmsObjectName) -> impl std::future::Future<Output = Result<(Option<MmsVariableAccessSpecification>, Vec<MmsAccessResult>), MmsServiceError>> + Send;
    fn delete_named_variable_list(&mut self, variable_list_name: MmsObjectName) -> impl std::future::Future<Output = Result<(Option<MmsVariableAccessSpecification>, Vec<MmsAccessResult>), MmsServiceError>> + Send;

    fn read(&mut self, specification: MmsVariableAccessSpecification) -> impl std::future::Future<Output = Result<(Option<MmsVariableAccessSpecification>, Vec<MmsAccessResult>), MmsServiceError>> + Send;
    fn write(&mut self, specification: MmsVariableAccessSpecification, values: Vec<MmsServiceData>) -> impl std::future::Future<Output = Result<MmsWriteResult, MmsServiceError>> + Send;
}

