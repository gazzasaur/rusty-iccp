use der_parser::{Oid, asn1_rs::ASN1DateTime};
use num_bigfloat::BigFloat;
use num_bigint::{BigInt, BigUint};
use rusty_mms::{MmsError, MmsObjectName};
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
    Array(Vec<MmsServiceData>), // Srrays are meant to contain a consistent type across all elements. This is not enforced.
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

pub trait MmsInitiatorService: Send + Sync {
    fn read(&mut self, variables: Vec<MmsObjectName>) -> impl std::future::Future<Output = Result<(), MmsServiceError>> + Send;
    fn write(&mut self, variables: Vec<MmsObjectName>) -> impl std::future::Future<Output = Result<(), MmsServiceError>> + Send;
}
