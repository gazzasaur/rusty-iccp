use der_parser::{Oid, asn1_rs::ASN1DateTime};
use num_bigint::{BigInt, BigUint};
use rusty_mms::{MmsAccessResult, MmsData, MmsError, MmsTypeDescription, MmsVariableAccessSpecification};
use num_bigint::ToBigInt;

use crate::error::{MmsServiceError, to_mms_error};

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

#[derive(Debug, PartialEq)]
pub struct MmsServiceDataFloat {
    data: Vec<u8>,
}

impl MmsServiceDataFloat {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn from_f32(value: f32) -> Self {
        Self { data: value.to_be_bytes().to_vec() }
    }

    pub fn to_f32(&self) -> Result<f32, MmsServiceError> {
        Ok(f32::from_be_bytes(self.data[..].try_into().map_err(to_mms_error("Failed to convert to f32"))?))
    }

    pub fn from_f64(value: f64) -> Self {
        Self { data: value.to_be_bytes().to_vec() }
    }

    pub fn to_f64(&self) -> Result<f64, MmsServiceError> {
        Ok(f64::from_be_bytes(self.data[..].try_into().map_err(to_mms_error("Failed to convert to f64"))?))
    }

    pub fn get_raw_data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Debug, PartialEq)]
pub enum MmsServiceData {
    Array(Vec<MmsServiceData>), // Arrays are meant to contain a consistent type across all elements. This is not enforced as it means traversing trees.
    Structure(Vec<MmsServiceData>),
    Boolean(bool),
    BitString(Vec<bool>),
    Integer(BigInt),
    Unsigned(BigUint),
    FloatingPoint(MmsServiceDataFloat),
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

#[derive(Debug, PartialEq)]
pub struct NameList {
    pub identifiers: Vec<String>,
    pub more_follows: bool,
}

pub struct VariableAccessAttributes {
    pub deletable: bool,
    pub type_description: MmsTypeDescription,
}

#[derive(Debug)]
pub struct InformationReportMmsServiceMessage {
    pub variable_access_specification: MmsVariableAccessSpecification,
    pub access_results: Vec<MmsAccessResult>,
}

pub(crate) fn convert_high_level_data_to_low_level_data(service_data: &MmsServiceData) -> Result<MmsData, MmsError> {
    match service_data {
        MmsServiceData::Array(items) => {
            let mut low_level_data = vec![];
            for item in items {
                low_level_data.push(convert_high_level_data_to_low_level_data(item)?);
            }
            Ok(MmsData::Array(low_level_data))
        }
        MmsServiceData::Structure(items) => {
            let mut low_level_data = vec![];
            for item in items {
                low_level_data.push(convert_high_level_data_to_low_level_data(item)?);
            }
            Ok(MmsData::Structure(low_level_data))
        }
        MmsServiceData::Boolean(x) => Ok(MmsData::Boolean(*x)),
        MmsServiceData::BitString(items) => {
            let buffer_length = items.len() / 8 + 1 - (if items.len() % 8 == 0 { 1 } else { 0 });
            let padding_length = (buffer_length * 8 - items.len()) as u8;
            let mut bit_string_data = vec![0; buffer_length];
            for i in 0..items.len() {
                let byte_index = i / 8;
                let bit_index = 7 - (i % 8) as u8;
                if items[i] {
                    bit_string_data[byte_index] |= 1 << bit_index // This is lsb and LSB first.
                }
            }
            Ok(MmsData::BitString(padding_length, bit_string_data))
        }
        MmsServiceData::Integer(big_int) => Ok(MmsData::Integer(big_int.to_signed_bytes_be())),
        MmsServiceData::Unsigned(big_uint) => Ok(MmsData::Unsigned(big_uint.to_bigint().ok_or_else(|| MmsError::InternalError("This is a bug. Please contact the project team.".into()))?.to_signed_bytes_be())),
        MmsServiceData::FloatingPoint(value) => Ok(MmsData::FloatingPoint(value.get_raw_data().clone())),
        MmsServiceData::OctetString(items) => todo!(),
        MmsServiceData::VisibleString(_) => todo!(),
        MmsServiceData::GeneralizedTime(asn1_date_time) => todo!(),
        MmsServiceData::BinaryTime(items) => todo!(),
        MmsServiceData::Bcd(mms_service_bcds) => todo!(),
        MmsServiceData::BooleanArray(items) => todo!(),
        MmsServiceData::ObjectId(oid) => todo!(),
        MmsServiceData::MmsString(_) => todo!(),
    }
}

pub(crate) fn convert_low_level_data_to_high_level_data(service_data: &MmsData) -> Result<MmsServiceData, MmsError> {
    match service_data {
        MmsData::Array(items) => {
            let mut high_level_data = vec![];
            for item in items {
                high_level_data.push(convert_low_level_data_to_high_level_data(item)?);
            }
            Ok(MmsServiceData::Array(high_level_data))
        }
        MmsData::Structure(items) => {
            let mut high_level_data = vec![];
            for item in items {
                high_level_data.push(convert_low_level_data_to_high_level_data(item)?);
            }
            Ok(MmsServiceData::Structure(high_level_data))
        }
        MmsData::Boolean(x) => Ok(MmsServiceData::Boolean(*x)),
        // MmsServiceData::BitString(items) => {
        //     let buffer_length = items.len() / 8 + 1 - (if items.len() % 8 == 0 { 1 } else { 0 });
        //     let padding_length = (buffer_length * 8 - items.len()) as u8;
        //     let mut bit_string_data = vec![0; buffer_length];
        //     for i in 0..items.len() {
        //         let byte_index = i / 8;
        //         let bit_index = 7 - (i % 8) as u8;
        //         if items[i] {
        //             bit_string_data[byte_index] |= 1 << bit_index // This is lsb and LSB first.
        //         }
        //     }
        //     Ok(MmsData::BitString(padding_length, bit_string_data))
        // }
        // MmsServiceData::Integer(big_int) => Ok(MmsData::Integer(big_int.to_signed_bytes_be())),
        // MmsServiceData::Unsigned(big_uint) => Ok(MmsData::Unsigned(
        //     big_uint.to_bigint().ok_or_else(|| MmsError::InternalError("This is a bug. Please contact the project team.".into()))?.to_signed_bytes_be(),
        // )),
        // MmsServiceData::FloatingPoint(value) => Ok(MmsData::FloatingPoint(value.get_raw_data().clone())),
        // MmsServiceData::OctetString(items) => todo!(),
        // MmsServiceData::VisibleString(_) => todo!(),
        // MmsServiceData::GeneralizedTime(asn1_date_time) => todo!(),
        // MmsServiceData::BinaryTime(items) => todo!(),
        // MmsServiceData::Bcd(mms_service_bcds) => todo!(),
        // MmsServiceData::BooleanArray(items) => todo!(),
        // MmsServiceData::ObjectId(oid) => todo!(),
        // MmsServiceData::MmsString(_) => todo!(),
        _ => todo!(),
    }
}
