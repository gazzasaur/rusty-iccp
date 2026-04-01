pub mod error;

use std::{result, sync::Arc};

use async_trait::async_trait;

use error::*;
use num_bigint::BigInt;
use rusty_mms::{ListOfVariablesItem, MmsAccessError, MmsBasicObjectClass, MmsData, MmsObjectClass, MmsObjectName, MmsObjectScope, MmsScope, MmsVariableAccessSpecification, VariableSpecification};
use rusty_mms_service::{
    MmsInitiatorService,
    data::{MmsServiceAccessResult, MmsServiceData, MmsServiceDeleteObjectScope, NameList},
};

#[async_trait]
pub trait IccpClient: Send + Sync {
    // --- Completed ---
    // get_data_values
    // get_data_set_names
    // create_data_set
    // delete_data_set
    // get_data_value_names

    // --- Required ---
    // set_data_values
    // get_data_value_types

    // get_data_set_element_names - This is a dataset operation
    // get_data_set_element_values - This is a dataset operation
    // set_data_set_element_values - This is a dataset operation

    // start_transfer - This is a dataset operation
    // stop_transfer - Drop
    // get_next_ds_transfer_set_value - Hide This

    // select
    // operate
    // get_tag_value
    // set_tag_value

    // fn fetch_transfer_report
}

pub enum QualityFlag {
    Bit0,
    Bit1,
    Bit2,
    Bit3,
    Bit4,
    Bit5,
    Bit6,
    Bit7,
}

pub enum IccpData {
    RealQ(f32, Vec<QualityFlag>),
}

pub enum IccpAccessResult {
    Success(IccpData),
    Failure(MmsAccessError),
}

pub enum IccpScope {
    Vcc,
    ICC(String), // Domain
}

#[async_trait]
pub trait IccpServer: Send + Sync + Clone {
    // fn fetch_transfer_report
}

pub struct RustyIccpClient {
    mms_client: Box<dyn MmsInitiatorService>,
}

impl RustyIccpClient {
    pub fn new(mms_client: Box<dyn MmsInitiatorService>) -> Self {
        RustyIccpClient { mms_client }
    }

    pub async fn get_data_values(&mut self, names: Vec<String>) -> Result<Vec<IccpAccessResult>, IccpError> {
        let spec = names.into_iter().map(|x| ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific(x)) }).collect();
        let results = self.mms_client.read(rusty_mms::MmsVariableAccessSpecification::ListOfVariables(spec)).await?;

        Ok(results
            .into_iter()
            .map(|x| match x {
                MmsServiceAccessResult::Failure(x) => Ok(IccpAccessResult::Failure(x)),
                MmsServiceAccessResult::Success(x) => Ok(IccpAccessResult::Success(convert_mms_service_data_to_iccp_data(x)?)),
            })
            .collect::<Result<Vec<IccpAccessResult>, IccpError>>()?)
    }

    pub async fn get_data_set_names(&mut self, scope: IccpScope) -> Result<Vec<String>, IccpError> {
        let mms_scope = match scope {
            IccpScope::Vcc => MmsObjectScope::Vmd,
            IccpScope::ICC(x) => MmsObjectScope::Domain(x),
        };

        let mut full_results = vec![];
        let mut continue_after = None;
        loop {
            let results = self.mms_client.get_name_list(MmsObjectClass::Basic(MmsBasicObjectClass::NamedVariableList), mms_scope.clone(), continue_after).await?;
            let last_result = results.identifiers.last().cloned();
            full_results.extend(results.identifiers);

            if !results.more_follows {
                return Ok(full_results);
            }
            continue_after = Some(last_result.ok_or_else(|| IccpError::ProtocolError("No results to choose from.".into()))?)
        }
    }

    pub async fn get_data_value_names(&mut self, scope: IccpScope) -> Result<Vec<String>, IccpError> {
        let mms_scope = match scope {
            IccpScope::Vcc => MmsObjectScope::Vmd,
            IccpScope::ICC(x) => MmsObjectScope::Domain(x),
        };

        let mut full_results = vec![];
        let mut continue_after = None;
        loop {
            let results = self.mms_client.get_name_list(MmsObjectClass::Basic(MmsBasicObjectClass::NamedVariable), mms_scope.clone(), continue_after).await?;
            let last_result = results.identifiers.last().cloned();
            full_results.extend(results.identifiers);

            if !results.more_follows {
                return Ok(full_results);
            }
            continue_after = Some(last_result.ok_or_else(|| IccpError::ProtocolError("No results to choose from.".into()))?)
        }
    }

    pub async fn create_data_set(&mut self, domain: String, name: String, identifiers: Vec<String>) -> Result<(), IccpError> {
        self.mms_client
            .define_named_variable_list(MmsObjectName::DomainSpecific(domain, name), identifiers.into_iter().map(|x| ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific(x)) }).collect())
            .await?;
        Ok(())
    }

    pub async fn delete_data_sets(&mut self, domain: String, identifiers: Vec<String>) -> Result<(), IccpError> {
        self.mms_client.delete_named_variable_list(MmsServiceDeleteObjectScope::Specific(identifiers.into_iter().map(|x| MmsObjectName::DomainSpecific(domain.clone(), x)).collect())).await?;
        Ok(())
    }

    pub async fn delete_domain_data_sets(&mut self, domain: String) -> Result<(), IccpError> {
        self.mms_client.delete_named_variable_list(MmsServiceDeleteObjectScope::Domain(domain)).await?;
        Ok(())
    }

    pub async fn start_transfer_set(&mut self, domain: String, name: String) -> Result<(), IccpError> {
        let transfer_set_name_structure = self
            .mms_client
            .read(MmsVariableAccessSpecification::ListOfVariables(vec![ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific(domain.clone(), "Next_DSTransfer_Set".into())) }]))
            .await?;

        let transfer_set_name = match transfer_set_name_structure.as_slice() {
            [MmsServiceAccessResult::Success(MmsServiceData::Structure(x))] => match x.as_slice() {
                [MmsServiceData::Integer(_scope), MmsServiceData::VisibleString(_domain), MmsServiceData::VisibleString(transfer_set_name)] => transfer_set_name,
                _ => return Err(IccpError::ProtocolError("Failed to get transfer set name".into())),
            },
            _ => return Err(IccpError::ProtocolError("Failed to get transfer set name".into())),
        };

        self.mms_client
            .write(
                MmsVariableAccessSpecification::ListOfVariables(vec![ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific(domain.clone(), transfer_set_name.clone())) }]),
                vec![
                    MmsServiceData::Structure(vec![MmsServiceData::Structure(vec![
                        MmsServiceData::Integer(BigInt::from(1)),
                        MmsServiceData::VisibleString(domain.clone()),
                        MmsServiceData::VisibleString(name),
                    ])]),
                    MmsServiceData::Integer(BigInt::from(0)), // Start Time
                    MmsServiceData::Integer(BigInt::from(0)), // Interval
                    MmsServiceData::Integer(BigInt::from(0)), // TLE
                    MmsServiceData::Integer(BigInt::from(10)), // Buffer Time
                    MmsServiceData::Integer(BigInt::from(600)), // Integrity Check
                    MmsServiceData::BitString(vec![false, true, true, true, false]), // Interval Timeout: false, Integrity Timeout: True, Object Change: True, Operator Request: true, Other External Event: false
                    MmsServiceData::Boolean(false), // Block Data
                    MmsServiceData::Boolean(false), // Critical
                    MmsServiceData::Boolean(true),  // Report By Exception
                    MmsServiceData::Boolean(false), // All Changes Reported
                    MmsServiceData::Boolean(true), // Status
                    MmsServiceData::Integer(BigInt::from(0)), // Event Code Requested
                ],
            )
            .await?;
        Ok(())
    }
}

fn convert_mms_service_data_to_iccp_data(mms_data: MmsServiceData) -> Result<IccpData, IccpError> {
    match mms_data {
        MmsServiceData::Structure(struct_data) => match struct_data.as_slice() {
            [MmsServiceData::FloatingPoint(value), MmsServiceData::BitString(_)] => Ok(IccpData::RealQ(value.to_f32()?, vec![])),
            x => Err(IccpError::ProtocolError(format!("Unknown MMS Structure Data: {x:?}"))),
        },
        x => Err(IccpError::ProtocolError(format!("Unknown MMS Data: {x:?}"))),
    }
}
