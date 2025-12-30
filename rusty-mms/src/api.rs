use der_parser::{
    Oid,
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, BitStringObject, Length, parse_ber_any},
    der::{Class, Header, Tag},
};
use rusty_acse::AcseError;
use std::time::Instant;
use thiserror::Error;
use tracing::warn;

use crate::{
    error::to_mms_error,
    parsers::{process_constructed_data, process_mms_string}, pdu::common::{MmsPduType, expect_value},
};

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

#[derive(Debug)]
pub enum MmsObjectName {
    VmdSpecific(String),
    DomainSpecific(String, String), // Domain, Item Id
    AaSpecific(String),
}

impl MmsObjectName {
    // Tecnically only a-zA-Z0-9 and $ and _ with no more than 32 char. We leave that to a higher layer to validate
    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        match &self {
            MmsObjectName::VmdSpecific(name) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)), BerObjectContent::VisibleString(&name.as_str())),
            MmsObjectName::DomainSpecific(domain, name) => BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
                BerObjectContent::Sequence(vec![
                    BerObject::from_obj(BerObjectContent::VisibleString(&domain.as_str())),
                    BerObject::from_obj(BerObjectContent::VisibleString(&name.as_str())),
                ]),
            ),
            MmsObjectName::AaSpecific(name) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(2), Length::Definite(0)), BerObjectContent::VisibleString(&name.as_str())),
        }
    }

    pub(crate) fn parse(pdu: &str, data: &[u8]) -> Result<MmsObjectName, MmsError> {
        let error_message = format!("Failed to parse ObjectName on {}", pdu);
        let (_, npm_object) = parse_ber_any(data).map_err(to_mms_error(error_message.as_str()))?;
        match npm_object.header.raw_tag() {
            Some([128]) => Ok(MmsObjectName::VmdSpecific(process_mms_string(&npm_object, error_message.as_str())?)),
            Some([161]) => {
                let values = process_constructed_data(npm_object.data).map_err(to_mms_error(&error_message))?;
                let mut values_iter = values.iter();
                let domain = expect_value(pdu, "ObjectName", values_iter.next())?;
                let name = expect_value(pdu, "ObjectName", values_iter.next())?;
                Ok(MmsObjectName::DomainSpecific(process_mms_string(domain, &error_message)?, process_mms_string(name, &error_message)?))
            }
            Some([130]) => Ok(MmsObjectName::AaSpecific(process_mms_string(&npm_object, error_message.as_str())?)),
            x => Err(MmsError::ProtocolError(error_message)),
        }
    }
}

#[derive(Debug)]
pub enum MmsVariableAccessSpecification {
    ListOfVariable(Vec<ListOfVariableItem>),
    // AlternateAccess, valt
    VariableListName(MmsObjectName),
}

impl MmsVariableAccessSpecification {
    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        match &self {
            MmsVariableAccessSpecification::ListOfVariable(list_of_variable_items) => BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
                BerObjectContent::Sequence(list_of_variable_items.iter().map(|i| i.to_ber()).collect()),
            ),
            MmsVariableAccessSpecification::VariableListName(mms_object_name) => {
                BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)), BerObjectContent::Sequence(vec![mms_object_name.to_ber()]))
            }
        }
    }

    pub(crate) fn parse(pdu_name: &str, data: &[u8]) -> Result<MmsVariableAccessSpecification, MmsError> {
        let items = process_constructed_data(data).map_err(to_mms_error(format!("Failed to parse Variable Access Specification on {:?}", pdu_name).as_str()))?;
        if items.len() != 1 {
            return Err(MmsError::ProtocolError(format!("Expected one item on variable access specification but got {}", items.len())));
        }
        match items[0].header.raw_tag() {
            Some([160]) => {
                let mut variables = vec![];
                for variable_ber in process_constructed_data(items[0].data).map_err(to_mms_error(format!("Failed to parse Variable Access Specification on {:?}", pdu_name).as_str()))? {
                    variables.push(ListOfVariableItem::parse(&variable_ber, pdu_name)?);
                }
                return Ok(MmsVariableAccessSpecification::ListOfVariable(variables));
            }
            Some([161]) => {
                let mms_object = MmsObjectName::parse(pdu_name, items[0].data)?;
                return Ok(MmsVariableAccessSpecification::VariableListName(mms_object));
            }
            Some(x) => return Err(MmsError::InternalError(format!("Unsupported variable type found {:?} on {:?}", x, pdu_name))),
            None => return Err(MmsError::InternalError(format!("No variable found in payload: {:?}", pdu_name))),
        }
    }
}

#[derive(Debug)]
pub struct ListOfVariableItem {
    pub variable_specification: VariableSpecification,
}

impl ListOfVariableItem {
    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        BerObject::from_seq(vec![self.variable_specification.to_ber()])
    }

    pub(crate) fn parse(item: &Any<'_>, error_message: &str) -> Result<ListOfVariableItem, MmsError> {
        let mut variable_specification = None;

        for item in process_constructed_data(item.data).map_err(to_mms_error(error_message))? {
            match item.header.raw_tag() {
                Some([160]) => variable_specification = Some(VariableSpecification::parse(item.data)?),
                x => warn!("Ignoring unknown variable specification: {:?}", x),
            }
        }
        let variable_specification = expect_value(error_message, "Variable Specification", variable_specification)?;
        Ok(ListOfVariableItem { variable_specification })
    }
}

#[derive(Debug)]
pub enum VariableSpecification {
    Name(MmsObjectName),
    Invalidated,
}

impl VariableSpecification {
    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        match &self {
            VariableSpecification::Name(mms_object_name) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)), BerObjectContent::Sequence(vec![mms_object_name.to_ber()])),
            VariableSpecification::Invalidated => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(4), Length::Definite(0)), BerObjectContent::Null),
        }
    }

    fn parse(data: &[u8]) -> Result<VariableSpecification, MmsError> {
        let (_, variable_spec_ber) = parse_ber_any(data).map_err(to_mms_error("Failed to parse Variable Specification"))?;
        match variable_spec_ber.header.raw_tag() {
            Some([128]) => Ok(VariableSpecification::Name(MmsObjectName::parse("", data)?)),
            Some([161]) => Ok(VariableSpecification::Name(MmsObjectName::parse("", data)?)),
            Some([130]) => Ok(VariableSpecification::Name(MmsObjectName::parse("", data)?)),
            Some([132]) => Ok(VariableSpecification::Invalidated),
            x => Err(MmsError::ProtocolError(format!("Unknown Variable Specification: {:?}", x))),
        }
    }
}

pub enum MmsAccessError {
    Unknown(Vec<u8>),
}

pub enum MmsAccessResult {
    Failure(MmsAccessError),
    Success(MmsData),
}

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
    GeneralizedTime(Instant),
    BinaryTime(Vec<u8>),
    Bcd(Vec<u8>),
    BooleanArray(u8, Vec<u8>),
    ObjectId(Oid<'static>),
    MmsString(String),
}

impl MmsData {
    pub(crate) fn serialise(&self, str1: bool, str2: bool) -> Result<BerObject<'_>, MmsError> {
        let payload = match &self {
            MmsData::Array(mms_array_items) if str1 => {
                let mut mms_array_data = vec![];
                for mms_array_item in mms_array_items {
                    mms_array_data.push(mms_array_item.serialise(str1, str2)?)
                }
                BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)), BerObjectContent::Sequence(mms_array_data))
            }
            MmsData::Array(_) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(1), Length::Definite(0)), BerObjectContent::Null),

            MmsData::Structure(mms_array_items) if str2 => {
                let mut mms_array_data = vec![];
                for mms_array_item in mms_array_items {
                    mms_array_data.push(mms_array_item.serialise(str1, str2)?)
                }
                BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(2), Length::Definite(0)), BerObjectContent::Sequence(mms_array_data))
            }
            MmsData::Structure(_) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(2), Length::Definite(0)), BerObjectContent::Null),

            MmsData::Boolean(value) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(3), Length::Definite(0)), BerObjectContent::Boolean(*value)),
            MmsData::BitString(padding, bit_data) => BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, false, Tag::from(4), Length::Definite(0)),
                BerObjectContent::BitString(*padding, BitStringObject { data: &bit_data }),
            ),
            MmsData::Integer(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(5), Length::Definite(0)), BerObjectContent::Integer(&object_data)),
            MmsData::Unsigned(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(6), Length::Definite(0)), BerObjectContent::Integer(&object_data)),
            MmsData::FloatingPoint(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(7), Length::Definite(0)), BerObjectContent::OctetString(&object_data)),
            MmsData::OctetString(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(8), Length::Definite(0)), BerObjectContent::OctetString(&object_data)),
            MmsData::VisibleString(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(5), Length::Definite(0)), BerObjectContent::VisibleString(&object_data)),
            MmsData::GeneralizedTime(instant) => todo!(),
            MmsData::BinaryTime(items) => todo!(),
            MmsData::Bcd(items) => todo!(),
            MmsData::BooleanArray(paddibg, object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(5), Length::Definite(0)), BerObjectContent::BitString(*paddibg, BitStringObject { data: &object_data })),
            MmsData::ObjectId(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(5), Length::Definite(0)), BerObjectContent::OID(object_data.to_owned())),
            MmsData::MmsString(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(5), Length::Definite(0)), BerObjectContent::VisibleString(&object_data)),
        };
        Ok(payload)
    }
}

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
    fn initiate(self) -> impl std::future::Future<Output = Result<impl MmsInitiatorConnection, MmsError>> + Send;
}

pub trait MmsListener: Send {
    fn responder(self) -> impl std::future::Future<Output = Result<impl MmsResponder, MmsError>> + Send;
}

pub trait MmsResponder: Send {
    fn accept(self) -> impl std::future::Future<Output = Result<impl MmsResponderConnection, MmsError>> + Send;
}

pub trait MmsInitiatorConnection: Send + Sync {
    fn read(&mut self, variable_access_specification: MmsVariableAccessSpecification) -> impl std::future::Future<Output = Result<Vec<MmsAccessResult>, MmsError>> + Send;

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

pub enum MmsResponderRecvResult {
    Pdu(MmsPduType),
    Closed,
}

pub trait MmsResponderConnection: Send + Sync {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<MmsResponderRecvResult, MmsError>> + Send;
}
