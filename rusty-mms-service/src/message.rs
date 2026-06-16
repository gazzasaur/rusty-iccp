use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::BoxFuture;
use num_bigint::{BigInt, BigUint};
use rusty_mms::{ListOfVariablesItem, MmsAccessResult, MmsData, MmsMessage, MmsObjectClass, MmsObjectName, MmsObjectScope, MmsVariableAccessSpecification, MmsWriteResult};
use tokio::sync::mpsc::UnboundedSender;

use crate::data::{
    InformationReportMmsServiceMessage, MmsServiceAccessResult, MmsServiceData, MmsServiceDeleteObjectScope, MmsServiceTypeDescription, convert_high_level_data_to_low_level_data, convert_high_level_data_types_to_low_level_data_types,
    convert_low_level_data_to_high_level_data,
};
use crate::error::to_mms_error;
use crate::{data::Identity, error::MmsServiceError};

pub struct IdentifyMmsServiceMessage {
    pub invocation_id: u32,
    response: Box<dyn Fn(MmsMessage) -> BoxFuture<'static, ()> + Send + Sync>,
}
impl fmt::Debug for IdentifyMmsServiceMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentifyMmsServiceMessage").field("invocation_id", &self.invocation_id).finish()
    }
}
impl IdentifyMmsServiceMessage {
    pub(crate) fn new(invocation_id: u32, response: Box<dyn Fn(MmsMessage) -> BoxFuture<'static, ()> + Send + Sync>) -> Self {
        Self { invocation_id, response }
    }

    pub async fn respond(self, identity: Identity) -> Result<(), MmsServiceError> {
        (self.response)(MmsMessage::ConfirmedResponse {
            invocation_id: BigInt::from(self.invocation_id).to_signed_bytes_be(),
            response: rusty_mms::MmsConfirmedResponse::Identify { vendor_name: identity.vendor_name, model_name: identity.model_name, revision: identity.revision, abstract_syntaxes: identity.abstract_syntaxes },
        })
        .await;
        Ok(())
    }
}

pub struct GetNameListMmsServiceMessage {
    invocation_id: u32,
    object_class: MmsObjectClass,
    object_scope: MmsObjectScope,
    continue_after: Option<String>,
    response: Box<dyn Fn(MmsMessage) -> BoxFuture<'static, ()> + Send + Sync>,
}
impl fmt::Debug for GetNameListMmsServiceMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetNameListMmsServiceMessage").field("invocation_id", &self.invocation_id).field("object_class", &self.object_class).field("object_scope", &self.object_scope).field("continue_after", &self.continue_after).finish()
    }
}
impl GetNameListMmsServiceMessage {
    pub(crate) fn new(invocation_id: u32, object_class: MmsObjectClass, object_scope: MmsObjectScope, continue_after: Option<String>, response: Box<dyn Fn(MmsMessage) -> BoxFuture<'static, ()> + Send + Sync>) -> Self {
        Self { invocation_id, object_class, object_scope, continue_after, response }
    }

    pub fn object_class(&self) -> &MmsObjectClass {
        &self.object_class
    }

    pub fn object_scope(&self) -> &MmsObjectScope {
        &self.object_scope
    }

    pub fn continue_after(&self) -> &Option<String> {
        &self.continue_after
    }

    pub async fn respond(self, list_of_identifiers: Vec<String>, more_follows: bool) -> Result<(), MmsServiceError> {
        let more_follows = if more_follows { None } else { Some(false) };
        (self.response)(MmsMessage::ConfirmedResponse { invocation_id: BigInt::from(self.invocation_id).to_signed_bytes_be().to_vec(), response: rusty_mms::MmsConfirmedResponse::GetNameList { list_of_identifiers, more_follows } }).await;
        Ok(())
    }
}

#[derive(Debug)]
pub struct GetVariableAccessAttributesMmsServiceMessage {
    invocation_id: u32,
    object_name: MmsObjectName,
    sender: UnboundedSender<MmsMessage>,
}
impl GetVariableAccessAttributesMmsServiceMessage {
    pub(crate) fn new(invocation_id: u32, object_name: MmsObjectName, sender: UnboundedSender<MmsMessage>) -> Self {
        Self { invocation_id, object_name, sender }
    }

    pub fn object_name(&self) -> &MmsObjectName {
        &self.object_name
    }

    pub async fn respond(self, deletable: bool, type_description: MmsServiceTypeDescription) -> Result<(), MmsServiceError> {
        let sender = self.sender;
        sender
            .send(MmsMessage::ConfirmedResponse {
                invocation_id: BigInt::from(self.invocation_id).to_signed_bytes_be().to_vec(),
                response: rusty_mms::MmsConfirmedResponse::GetVariableAccessAttributes { deletable, type_description: convert_high_level_data_types_to_low_level_data_types(&type_description)? },
            })
            .map_err(to_mms_error("The receive channel has been closed"))
    }
}

#[derive(Debug)]
pub struct DefineNamedVariableListMmsServiceMessage {
    invocation_id: u32,
    variable_list_name: MmsObjectName,
    list_of_variables: Vec<ListOfVariablesItem>,

    sender: UnboundedSender<MmsMessage>,
}
impl DefineNamedVariableListMmsServiceMessage {
    pub(crate) fn new(invocation_id: u32, variable_list_name: MmsObjectName, list_of_variables: Vec<ListOfVariablesItem>, sender: UnboundedSender<MmsMessage>) -> Self {
        Self { invocation_id, variable_list_name, list_of_variables, sender }
    }

    pub fn variable_list_name(&self) -> &MmsObjectName {
        &self.variable_list_name
    }

    pub fn list_of_variables(&self) -> &Vec<ListOfVariablesItem> {
        &self.list_of_variables
    }

    pub async fn respond(self) -> Result<(), MmsServiceError> {
        let sender = self.sender;
        sender
            .send(MmsMessage::ConfirmedResponse { invocation_id: BigInt::from(self.invocation_id).to_signed_bytes_be().to_vec(), response: rusty_mms::MmsConfirmedResponse::DefineNamedVariableList {} })
            .map_err(to_mms_error("The receive channel has been closed"))
    }
}

#[derive(Debug)]
pub struct GetNamedVariableListAttributesMmsServiceMessage {
    invocation_id: u32,
    variable_list_name: MmsObjectName,

    sender: UnboundedSender<MmsMessage>,
}
impl GetNamedVariableListAttributesMmsServiceMessage {
    pub(crate) fn new(invocation_id: u32, variable_list_name: MmsObjectName, sender: UnboundedSender<MmsMessage>) -> Self {
        Self { invocation_id, variable_list_name, sender }
    }

    pub fn variable_list_name(&self) -> &MmsObjectName {
        &self.variable_list_name
    }

    pub async fn respond(self, deletable: bool, list_of_variables: Vec<ListOfVariablesItem>) -> Result<(), MmsServiceError> {
        let sender = self.sender;
        sender
            .send(MmsMessage::ConfirmedResponse { invocation_id: BigInt::from(self.invocation_id).to_signed_bytes_be().to_vec(), response: rusty_mms::MmsConfirmedResponse::GetNamedVariableListAttributes { deletable, list_of_variables } })
            .map_err(to_mms_error("The receive channel has been closed"))
    }
}

#[derive(Debug)]
pub struct DeleteNamedVariableListMmsServiceMessage {
    invocation_id: u32,

    scope_of_delete: MmsServiceDeleteObjectScope,

    sender: UnboundedSender<MmsMessage>,
}
impl DeleteNamedVariableListMmsServiceMessage {
    pub(crate) fn new(invocation_id: u32, scope_of_delete: MmsServiceDeleteObjectScope, sender: UnboundedSender<MmsMessage>) -> Self {
        Self { invocation_id, scope_of_delete, sender }
    }

    pub fn scope_of_delete(&self) -> &MmsServiceDeleteObjectScope {
        &self.scope_of_delete
    }

    pub async fn respond(self, number_matched: u32, number_deleted: u32) -> Result<(), MmsServiceError> {
        let sender = self.sender;
        let number_matched = BigInt::from(number_matched).to_signed_bytes_be();
        let number_deleted = BigInt::from(number_deleted).to_signed_bytes_be();
        sender
            .send(MmsMessage::ConfirmedResponse { invocation_id: BigInt::from(self.invocation_id).to_signed_bytes_be().to_vec(), response: rusty_mms::MmsConfirmedResponse::DeleteNamedVariableList { number_matched, number_deleted } })
            .map_err(to_mms_error("The receive channel has been closed"))
    }
}

pub struct ReadMmsServiceMessage {
    invocation_id: u32,
    specification_with_result: bool,
    specification: MmsVariableAccessSpecification,
    response: Box<dyn Fn(MmsMessage) -> BoxFuture<'static, ()> + Send + Sync>,
}
impl fmt::Debug for ReadMmsServiceMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadMmsServiceMessage").field("invocation_id", &self.invocation_id).field("specification_with_result", &self.specification_with_result).field("specification", &self.specification).finish()
    }
}
impl ReadMmsServiceMessage {
    pub(crate) fn new(invocation_id: u32, specification: MmsVariableAccessSpecification, specification_with_result: Option<bool>, response: Box<dyn Fn(MmsMessage) -> BoxFuture<'static, ()> + Send + Sync>) -> Self {
        Self {
            invocation_id,
            // TODO HIGH What is the default behaviour for this?
            specification_with_result: specification_with_result.unwrap_or(true),
            specification,
            response,
        }
    }

    pub fn specification(&self) -> &MmsVariableAccessSpecification {
        &self.specification
    }

    pub async fn respond(self, access_results: Vec<MmsServiceAccessResult>) -> Result<(), MmsServiceError> {
        let variable_access_specification = if self.specification_with_result { Some(self.specification) } else { None };
        (self.response)(MmsMessage::ConfirmedResponse {
            invocation_id: BigInt::from(self.invocation_id).to_signed_bytes_be().to_vec(),
            response: rusty_mms::MmsConfirmedResponse::Read {
                variable_access_specification,
                access_results: access_results
                    .into_iter()
                    .map(|x| match x {
                        MmsServiceAccessResult::Success(mms_service_data) => Ok(MmsAccessResult::Success(convert_high_level_data_to_low_level_data(&mms_service_data)?)),
                        MmsServiceAccessResult::Failure(mms_access_error) => Ok(MmsAccessResult::Failure(mms_access_error)),
                    })
                    .collect::<Result<Vec<MmsAccessResult>, MmsServiceError>>()?,
            },
        })
        .await;
        Ok(())
    }
}

#[derive(Debug)]
pub struct WriteMmsServiceMessage {
    invocation_id: u32,
    specification: MmsVariableAccessSpecification,
    values: Vec<MmsServiceData>,

    sender: UnboundedSender<MmsMessage>,
}
impl WriteMmsServiceMessage {
    pub(crate) fn new(invocation_id: u32, specification: MmsVariableAccessSpecification, values: Vec<MmsData>, sender: UnboundedSender<MmsMessage>) -> Result<Self, MmsServiceError> {
        let mut high_level_values = vec![];
        for value in values {
            high_level_values.push(convert_low_level_data_to_high_level_data(&value)?);
        }

        Ok(Self { invocation_id, specification, values: high_level_values, sender })
    }

    pub fn specification(&self) -> &MmsVariableAccessSpecification {
        &self.specification
    }

    pub fn values(&self) -> &Vec<MmsServiceData> {
        &self.values
    }

    pub async fn respond(self, write_results: Vec<MmsWriteResult>) -> Result<(), MmsServiceError> {
        let sender = self.sender;

        sender
            .send(MmsMessage::ConfirmedResponse { invocation_id: BigInt::from(self.invocation_id).to_signed_bytes_be().to_vec(), response: rusty_mms::MmsConfirmedResponse::Write { write_results } })
            .map_err(to_mms_error("The receive channel has been closed"))
    }
}

#[derive(Debug)]
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
