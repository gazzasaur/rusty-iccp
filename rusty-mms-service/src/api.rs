use der_parser::{Oid, asn1_rs::ASN1DateTime};
use futures::{SinkExt, channel::mpsc::{self, UnboundedSender}};
use num_bigint::{BigInt, BigUint};
use rusty_mms::{ListOfVariablesItem, MmsAccessResult, MmsError, MmsMessage, MmsObjectClass, MmsObjectName, MmsObjectScope, MmsTypeDescription, MmsVariableAccessSpecification, MmsWriteResult};
use thiserror::Error;

use crate::error::to_mms_error;

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

pub struct NameList {
    pub identifiers: String,
    pub more_follows: bool,
}

pub struct VariableAccessAttributes {
    pub deletable: bool,
    pub type_description: MmsTypeDescription,
}

pub struct InformationReportMmsServiceMessage {
    variable_access_specification: MmsVariableAccessSpecification,
    access_results: Vec<MmsAccessResult>,
}

pub struct IdentifyMmsServiceMessage {
    invocation_id: u32,
    sender: mpsc::UnboundedSender<MmsMessage>,
}
impl IdentifyMmsServiceMessage {
    pub(crate) fn new(invocation_id: u32, sender: UnboundedSender<MmsMessage>) -> Self {
        Self { invocation_id, sender }
    }

    pub async fn respond(self, identity: Identity) -> Result<(), MmsServiceError> {
        let mut sender = self.sender;
        sender.send(MmsMessage::ConfirmedResponse {
            invocation_id: self.invocation_id.to_be_bytes().to_vec(),
            response: rusty_mms::MmsConfirmedResponse::Identify {
                vendor_name: identity.vendor_name,
                model_name: identity.model_name,
                revision: identity.revision,
                abstract_syntaxes: identity.abstract_syntaxes,
            },
        }).await.map_err(to_mms_error(""))
    }
}

pub struct GetNameListMmsServiceMessage {
    invocation_id: u32,
    object_class: MmsObjectClass,
    object_scope: MmsObjectScope,
    continue_after: Option<String>,

    sender: mpsc::UnboundedSender<MmsMessage>,
}

pub struct GetVariableAccessAttributesMmsServiceMessage {
    invocation_id: u32,
    object_name: MmsObjectName,

    sender: mpsc::UnboundedSender<MmsMessage>,
}

pub struct DefineNamedVariableListMmsServiceMessage {
    invocation_id: u32,
    variable_list_name: MmsObjectName,
    list_of_variables: Vec<ListOfVariablesItem>,

    sender: mpsc::UnboundedSender<MmsMessage>,
}

pub struct GetNamedVariableListAttributesMmsServiceMessage {
    invocation_id: u32,
    variable_list_name: MmsObjectName,

    sender: mpsc::UnboundedSender<MmsMessage>,
}

pub struct DeleteNamedVariableListMmsServiceMessage {
    invocation_id: u32,
    variable_list_name: MmsObjectName,

    sender: mpsc::UnboundedSender<MmsMessage>,
}

pub struct ReadMmsServiceMessage {
    invocation_id: u32,
    specification: MmsVariableAccessSpecification,

    sender: mpsc::UnboundedSender<MmsMessage>,
}

pub struct WriteMmsServiceMessage {
    invocation_id: u32,
    specification: MmsVariableAccessSpecification,
    values: Vec<MmsServiceData>,

    sender: mpsc::UnboundedSender<MmsMessage>,
}

pub enum MmsServiceMessage {
    Identify(IdentifyMmsServiceMessage),
    GetNameList(GetNameListMmsServiceMessage),
    GetVariableAccessAttributes(GetVariableAccessAttributesMmsServiceMessage),
    DefineNamedVariableList(DefineNamedVariableListMmsServiceMessage),
    GetNamedVariableListAttributes(GetNamedVariableListAttributesMmsServiceMessage),
    DeleteNamedVariableList(DeleteNamedVariableListMmsServiceMessage),
    Read(ReadMmsServiceMessage),
    Write(WriteMmsServiceMessage),

    InformationReport(InformationReportMmsServiceMessage),
}

pub trait MmsInitiatorService: Send + Sync {
    fn identify(&mut self) -> impl std::future::Future<Output = Result<Identity, MmsServiceError>> + Send;

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

    fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsAccessResult>) -> impl std::future::Future<Output = Result<(), MmsServiceError>> + Send;
    fn receive_information_report(&mut self) -> impl std::future::Future<Output = Result<InformationReportMmsServiceMessage, MmsServiceError>> + Send;
}

pub trait MmsResponderService: Send + Sync {
    fn receive_message(&mut self) -> impl std::future::Future<Output = Result<MmsServiceMessage, MmsServiceError>> + Send;
    fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsAccessResult>) -> impl std::future::Future<Output = Result<(), MmsServiceError>> + Send;
}
