pub mod error;

use async_trait::async_trait;

use error::*;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use rusty_mms::{ListOfVariablesItem, MmsAccessError, MmsBasicObjectClass, MmsObjectClass, MmsObjectName, MmsObjectScope, MmsVariableAccessSpecification, VariableSpecification};
use rusty_mms_service::{
    RustyMmsServiceClient, RustyMmsServiceServer,
    data::{
        MmsServiceAccessResult,
        MmsServiceData::{self},
        MmsServiceDeleteObjectScope,
    },
    message::{DefineNamedVariableListMmsServiceMessage, GetNameListMmsServiceMessage, MmsServiceMessage, ReadMmsServiceMessage},
};

pub struct IccpRbeTransferSetValue {
    pub identifier: IccpScopedIdentifier,
    pub access_result: IccpAccessResult,
}

pub enum IccpTransferSetReport {
    ReportAll(IccpScopedIdentifier, Vec<IccpAccessResult>),
    ReportByException(Vec<IccpRbeTransferSetValue>),
}

#[async_trait]
pub trait IccpClient: Send + Sync {
    async fn clone(&self) -> Box<dyn IccpClient>;

    // --- Completed ---
    async fn get_data_values(&mut self, names: Vec<String>) -> Result<Vec<IccpAccessResult>, IccpError>;
    async fn get_data_set_names(&mut self, scope: IccpScope) -> Result<Vec<String>, IccpError>;
    async fn get_data_value_names(&mut self, scope: IccpScope) -> Result<Vec<String>, IccpError>;
    async fn create_data_set(&mut self, domain: String, name: String, identifiers: Vec<String>) -> Result<(), IccpError>;
    async fn delete_data_sets(&mut self, domain: String, identifiers: Vec<String>) -> Result<(), IccpError>;
    async fn delete_domain_data_sets(&mut self, domain: String) -> Result<(), IccpError>;
    async fn start_transfer_set(&mut self, domain: String, name: String) -> Result<(), IccpError>;

    async fn receive_transfer_set_report(&mut self) -> Result<IccpTransferSetReport, IccpError>;

    // get_data_values
    // get_data_set_names
    // create_data_set
    // delete_data_sets + delete_domain_data_sets
    // get_data_value_names
    //
    // start_transfer_set

    // --- Required ---
    // set_data_values
    // get_data_value_types

    // get_data_set_element_names - This is a dataset operation
    // get_data_set_element_values - This is a dataset operation
    // set_data_set_element_values - This is a dataset operation

    // stop_transfer - Drop
    // get_next_ds_transfer_set_value - Hide This

    // select
    // operate
    // get_tag_value
    // set_tag_value
}

// This can be encoded as a State or Discrete. Discrete should be used of there are more than 4 states.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde_camel_case", serde(rename_all = "camelCase"))]
#[derive(Clone, Debug)]
pub enum StateValue {
    Between, // Between, Invalid
    Tripped, // Tripped, Off, Auto, Normal, Local, Raise, Not Ready, Offline
    Closed,  // Closed, On, Manual, Alarm, Remote, Lower, Ready, Available
    Invalid, // Invalid
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde_camel_case", serde(rename_all = "camelCase"))]
#[derive(Clone, Debug)]
pub enum ExpectedStateValue {
    Between, // Between, Invalid
    Tripped, // Tripped, Off, Auto, Normal, Local, Raise, Not Ready, Offline
    Closed,  // Closed, On, Manual, Alarm, Remote, Lower, Ready, Available
    Invalid, // Invalid
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde_camel_case", serde(rename_all = "camelCase"))]
#[derive(Clone, Debug)]
pub enum ValidityValue {
    Valid,
    Held,
    Suspect,
    NotValid,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde_camel_case", serde(rename_all = "camelCase"))]
#[derive(Clone, Debug)]
pub enum CurrentSourceValue {
    Telemetered,
    Calculated,
    Entered,
    Estimated,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde_camel_case", serde(rename_all = "camelCase"))]
#[derive(Clone, Debug)]
pub enum NormalSourceValue {
    Telemetered,
    Calculated,
    Entered,
    Estimated,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde_camel_case", serde(rename_all = "camelCase"))]
#[derive(Clone, Debug)]
pub enum NormalValue {
    Normal,
    Abnormal,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde_camel_case", serde(rename_all = "camelCase"))]
#[derive(Clone, Debug)]
pub enum TimestampQualityValue {
    Valid,
    Invalid,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde_camel_case", serde(rename_all = "camelCase"))]
#[derive(Clone, Debug)]
pub enum TagValue {
    NoTag,
    OpenAndCloseInhibit,
    CloseOnlyInhibit,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde_camel_case", serde(rename_all = "camelCase"))]
#[derive(Clone, Debug)]
pub enum IccpData {
    // Real(f32),
    // Discrete(i32),
    State(StateValue, ValidityValue, CurrentSourceValue, NormalValue, TimestampQualityValue),
    // StateSupplemental(StateValue, ValidityValue, CurrentSourceValue, NormalValue, TimestampQualityValue, TagValue, ExpectedStateValue),
    RealQ(f32, ValidityValue, CurrentSourceValue, NormalValue, TimestampQualityValue),
    // StateQ(StateValue, ValidityValue, CurrentSourceValue, NormalValue, TimestampQualityValue),
    DiscreteQ(i32, ValidityValue, CurrentSourceValue, NormalValue, TimestampQualityValue),
    // StateSupplementalQ(StateValue, ValidityValue, CurrentSourceValue, NormalValue, TimestampQualityValue, TagValue, ExpectedStateValue),
    // TODO The rest of them. No COV support
}

pub enum IccpAccessResult {
    Success(IccpData),
    Failure(MmsAccessError),
}

#[derive(Debug)]
pub enum IccpScope {
    Vcc,
    Icc(String), // Domain
}

#[derive(Debug)]
pub enum IccpScopedIdentifier {
    Vcc(String),         // Value
    Icc(String, String), // Domain, Value
}

#[derive(Debug)]
pub enum IccpOperation {
    MmsOperation(MmsServiceMessage), // Pass through unhandled MMS operations so servers can process messages like identify and conclude

    StartTransferSet(StartTransferSetOperation),
    CreateDataSet(CreateDataSetOperation),
    GetDataSetNames(GetDataSetNamesOperation),
    GetNextDsTransferSet(GetNextDsTransferSetOperation),
}

#[derive(Debug)]
pub enum TransferSetReportMode {
    Periodic { internal: u64 },
    OnChange { integrity: u64 },
}

#[derive(Debug)]
pub struct StartTransferSetOperation {
    transfer_set_domain: String,
    transfer_set_name: String,

    data_set_domain: String,
    data_set_name: String,

    report_mode: TransferSetReportMode,
}

impl StartTransferSetOperation {
    pub fn transfer_set_domain(&self) -> &str {
        &self.transfer_set_domain
    }

    pub fn transfer_set_name(&self) -> &str {
        &self.transfer_set_name
    }

    pub fn data_set_domain(&self) -> &str {
        &self.data_set_domain
    }

    pub fn data_set_name(&self) -> &str {
        &self.data_set_name
    }

    pub fn report_mode(&self) -> &TransferSetReportMode {
        &self.report_mode
    }
}

#[derive(Debug)]
pub struct CreateDataSetOperation {
    data_set_domain: String,
    data_set_name: String,
    data_set_items: Vec<IccpScopedIdentifier>,
    message: DefineNamedVariableListMmsServiceMessage,
}

impl CreateDataSetOperation {
    pub fn data_set_domain(&self) -> &str {
        &self.data_set_domain
    }

    pub fn data_set_name(&self) -> &str {
        &self.data_set_name
    }

    pub fn data_set_items(&self) -> &[IccpScopedIdentifier] {
        &self.data_set_items
    }

    pub async fn respond(self) -> Result<(), IccpError> {
        Ok(self.message.respond().await?)
    }
}

#[derive(Debug)]
pub struct GetDataSetNamesOperation {
    scope: IccpScope,
    message: GetNameListMmsServiceMessage,
}

impl GetDataSetNamesOperation {
    pub fn scope(&self) -> &IccpScope {
        &self.scope
    }

    pub async fn respond(self, identifiers: Vec<String>, more_follows: bool) -> Result<(), IccpError> {
        Ok(self.message.respond(identifiers, more_follows).await?)
    }
}

#[derive(Debug)]
pub struct GetNextDsTransferSetOperation {
    domain: String,
    message: ReadMmsServiceMessage,
}

impl GetNextDsTransferSetOperation {
    pub fn domain(&self) -> &String {
        &self.domain
    }

    pub async fn respond(self, name: String) -> Result<(), IccpError> {
        Ok(self
            .message
            .respond(vec![MmsServiceAccessResult::Success(MmsServiceData::Structure(vec![
                MmsServiceData::Integer(BigInt::from(1)),
                MmsServiceData::VisibleString(self.domain),
                MmsServiceData::VisibleString(name),
            ]))])
            .await?)
    }
}

#[async_trait]
pub trait IccpServer: Send + Sync + Clone {
    async fn receive_operation(&mut self) -> Result<IccpOperation, IccpError>;
}

#[derive(Clone)]
pub struct RustyIccpServer {
    mms_server: Box<dyn RustyMmsServiceServer>,
}

impl RustyIccpServer {
    pub fn new(mms_server: Box<dyn RustyMmsServiceServer>) -> Self {
        Self { mms_server }
    }
}

#[async_trait]
impl IccpServer for RustyIccpServer {
    async fn receive_operation(&mut self) -> Result<IccpOperation, IccpError> {
        let mms_message = self.mms_server.receive_message().await?;
        match mms_message {
            MmsServiceMessage::DefineNamedVariableList(message) => {
                let (data_set_domain, data_set_name) = match message.variable_list_name() {
                    MmsObjectName::DomainSpecific(domain, name) => (domain.into(), name.into()),
                    x => return Err(IccpError::ProtocolError(format!("Data Sets can only be created in the ICC scope but was: {x:?}"))),
                };
                let data_set_items = message
                    .list_of_variables()
                    .iter()
                    .map(|x| match &x.variable_specification {
                        VariableSpecification::Name(mms_object_name) => mms_object_name.try_into(),
                        VariableSpecification::Invalidated => Err(IccpError::ProtocolError(format!("Invalidated variable specified in create data set request: {data_set_domain}:{data_set_name}"))),
                    })
                    .collect::<Result<Vec<IccpScopedIdentifier>, IccpError>>()?;

                return Ok(IccpOperation::CreateDataSet(CreateDataSetOperation { data_set_domain, data_set_name, data_set_items, message }));
            }
            MmsServiceMessage::GetNameList(message) if matches!(message.object_class(), MmsObjectClass::Basic(MmsBasicObjectClass::NamedVariable)) => {
                let scope = match message.object_scope() {
                    MmsObjectScope::Vmd => IccpScope::Vcc,
                    MmsObjectScope::Domain(x) => IccpScope::Icc(x.into()),
                    x => return Err(IccpError::ProtocolError(format!("Can only list data sets for VCC and ICC but got {x:?}"))),
                };
                return Ok(IccpOperation::GetDataSetNames(GetDataSetNamesOperation { scope, message }));
            }
            MmsServiceMessage::Read(message) => match message.specification() {
                MmsVariableAccessSpecification::ListOfVariables(items) => {
                    if let Some(req) = items.get(0)
                        && let VariableSpecification::Name(MmsObjectName::DomainSpecific(domain, name)) = &req.variable_specification
                        && name.as_str() == "Next_DSTransfer_Set"
                    {
                        return Ok(IccpOperation::GetNextDsTransferSet(GetNextDsTransferSetOperation { domain: domain.clone(), message }));
                    }
                    return Ok(IccpOperation::MmsOperation(MmsServiceMessage::Read(message)));
                }
                MmsVariableAccessSpecification::VariableListName(_) => Ok(IccpOperation::MmsOperation(MmsServiceMessage::Read(message))),
            },
            MmsServiceMessage::Write(message) => match message.values().as_slice() {
                [MmsServiceData::Structure(internal_structure)] => match internal_structure.as_slice() {
                    [
                        MmsServiceData::Structure(data_set_identifier),
                        MmsServiceData::Integer(start_time),
                        MmsServiceData::Integer(interval),
                        MmsServiceData::Integer(useful_time), // TLE
                        MmsServiceData::Integer(buffer_time),
                        MmsServiceData::Integer(integrity_check),
                        MmsServiceData::BitString(transfer_set_options),
                        MmsServiceData::Boolean(block_date),
                        MmsServiceData::Boolean(critical),
                        MmsServiceData::Boolean(report_by_exception),
                        MmsServiceData::Boolean(all_changes_reported),
                        MmsServiceData::Boolean(status),
                        MmsServiceData::Integer(event_code_requested),
                    ] if let [MmsServiceData::Integer(scope), MmsServiceData::VisibleString(data_set_domain), MmsServiceData::VisibleString(data_set_name)] = data_set_identifier.as_slice()
                        && let [interval_timeout_flag, integrity_timeout_flag, object_change_flag, operator_request_flag, other_external_event_flag] = transfer_set_options.as_slice()
                        && let MmsVariableAccessSpecification::ListOfVariables(spec_items) = message.specification()
                        && let [VariableSpecification::Name(MmsObjectName::DomainSpecific(transfer_set_domain, transfer_set_name))] = spec_items.iter().map(|x| x.variable_specification.clone()).collect::<Vec<_>>().as_slice() =>
                    {
                        // TODO Need to fail this if it cannot be decoded.
                        let calculated_start_time: i64 = start_time.to_i64().unwrap_or_else(|| 0);
                        let calculated_interval_timeout = if *integrity_timeout_flag { interval.to_u64() } else { None };
                        let calculated_integrity_check = if *integrity_timeout_flag { integrity_check.to_u64() } else { None };
                        let report_mode = match (calculated_interval_timeout, calculated_integrity_check) {
                            (Some(x), _) if x >= 60 => TransferSetReportMode::OnChange { integrity: x },
                            (_, Some(x)) if x >= 60 => TransferSetReportMode::Periodic { internal: x },
                            _ => TransferSetReportMode::Periodic { internal: 600 },
                        };

                        return Ok(IccpOperation::StartTransferSet(StartTransferSetOperation {
                            transfer_set_domain: transfer_set_domain.clone(),
                            transfer_set_name: transfer_set_name.clone(),
                            data_set_domain: data_set_domain.clone(),
                            data_set_name: data_set_name.clone(),

                            report_mode,
                        }));
                    }
                    _ => Ok(IccpOperation::MmsOperation(MmsServiceMessage::Write(message))),
                },
                _ => Ok(IccpOperation::MmsOperation(MmsServiceMessage::Write(message))),
            },
            MmsServiceMessage::GetVariableAccessAttributes(_) => todo!(),
            MmsServiceMessage::GetNamedVariableListAttributes(_) => todo!(),
            MmsServiceMessage::DeleteNamedVariableList(_) => todo!(),
            MmsServiceMessage::InformationReport(_) => todo!(),
            message => Ok(IccpOperation::MmsOperation(message)),
        }
    }
}

impl TryFrom<&MmsObjectName> for IccpScopedIdentifier {
    type Error = IccpError;

    fn try_from(value: &MmsObjectName) -> Result<Self, Self::Error> {
        match value {
            MmsObjectName::VmdSpecific(name) => Ok(IccpScopedIdentifier::Vcc(name.into())),
            MmsObjectName::DomainSpecific(domain, name) => Ok(IccpScopedIdentifier::Icc(domain.into(), name.into())),
            MmsObjectName::AaSpecific(_) => Err(IccpError::ProtocolError("Cannot convert an AaSpecificScope to an IccpScope".into())),
        }
    }
}

pub struct RustyIccpClient {
    mms_client: Box<dyn RustyMmsServiceClient>,
}

pub struct IccpConnectionParameters {
    version: (u32, u32),
    bilateral_table: String,
    supported_features: String,
}

impl RustyIccpClient {
    pub fn new(mms_client: Box<dyn RustyMmsServiceClient>) -> Self {
        RustyIccpClient { mms_client }
    }

    /**
     * Reads the ICCP Version, Bilateral Table Name and Supported Features.
     */
    pub async fn get_iccp_connection_parameters(&mut self, domain: String) -> Result<(), IccpError> {
        let mms_read_result =
            self.mms_client.read(MmsVariableAccessSpecification::ListOfVariables(vec![ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific(domain, "BilateralTable".into())) }])).await?;
        if mms_read_result.len() != 3 {}
        Ok(())
    }
}

#[async_trait]
impl IccpClient for RustyIccpClient {
    async fn clone(&self) -> Box<dyn IccpClient> {
        Box::new(RustyIccpClient { mms_client: self.mms_client.clone() })
    }

    async fn get_data_values(&mut self, names: Vec<String>) -> Result<Vec<IccpAccessResult>, IccpError> {
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

    async fn get_data_set_names(&mut self, scope: IccpScope) -> Result<Vec<String>, IccpError> {
        let mms_scope = match scope {
            IccpScope::Vcc => MmsObjectScope::Vmd,
            IccpScope::Icc(x) => MmsObjectScope::Domain(x),
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

    async fn get_data_value_names(&mut self, scope: IccpScope) -> Result<Vec<String>, IccpError> {
        let mms_scope = match scope {
            IccpScope::Vcc => MmsObjectScope::Vmd,
            IccpScope::Icc(x) => MmsObjectScope::Domain(x),
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

    async fn create_data_set(&mut self, domain: String, name: String, identifiers: Vec<String>) -> Result<(), IccpError> {
        self.mms_client
            .define_named_variable_list(MmsObjectName::DomainSpecific(domain, name), identifiers.into_iter().map(|x| ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific(x)) }).collect())
            .await?;
        Ok(())
    }

    async fn delete_data_sets(&mut self, domain: String, identifiers: Vec<String>) -> Result<(), IccpError> {
        self.mms_client.delete_named_variable_list(MmsServiceDeleteObjectScope::Specific(identifiers.into_iter().map(|x| MmsObjectName::DomainSpecific(domain.clone(), x)).collect())).await?;
        Ok(())
    }

    async fn delete_domain_data_sets(&mut self, domain: String) -> Result<(), IccpError> {
        self.mms_client.delete_named_variable_list(MmsServiceDeleteObjectScope::Domain(domain)).await?;
        Ok(())
    }

    async fn start_transfer_set(&mut self, domain: String, name: String) -> Result<(), IccpError> {
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
                vec![MmsServiceData::Structure(vec![
                    MmsServiceData::Structure(vec![MmsServiceData::Integer(BigInt::from(1)), MmsServiceData::VisibleString(domain.clone()), MmsServiceData::VisibleString(name)]),
                    MmsServiceData::Integer(BigInt::from(0)),                        // Start Time
                    MmsServiceData::Integer(BigInt::from(0)),                        // Interval
                    MmsServiceData::Integer(BigInt::from(0)),                        // TLE
                    MmsServiceData::Integer(BigInt::from(10)),                       // Buffer Time
                    MmsServiceData::Integer(BigInt::from(600)),                      // Integrity Check
                    MmsServiceData::BitString(vec![false, true, true, true, false]), // Interval Timeout: false, Integrity Timeout: True, Object Change: True, Operator Request: true, Other External Event: false
                    MmsServiceData::Boolean(false),                                  // Block Data
                    MmsServiceData::Boolean(false),                                  // Critical
                    MmsServiceData::Boolean(true),                                   // Report By Exception
                    MmsServiceData::Boolean(false),                                  // All Changes Reported
                    MmsServiceData::Boolean(true),                                   // Status
                    MmsServiceData::Integer(BigInt::from(0)),                        // Event Code Requested
                ])],
            )
            .await?;
        Ok(())
    }

    async fn receive_transfer_set_report(&mut self) -> Result<IccpTransferSetReport, IccpError> {
        let message = self.mms_client.receive_information_report().await?;
        match message.variable_access_specification {
            MmsVariableAccessSpecification::VariableListName(mms_object_name) => {
                let transfer_set_name = match mms_object_name {
                    MmsObjectName::VmdSpecific(name) => IccpScopedIdentifier::Vcc(name),
                    MmsObjectName::DomainSpecific(domain, name) => IccpScopedIdentifier::Icc(domain, name),
                    MmsObjectName::AaSpecific(_) => return Err(IccpError::ProtocolError(format!("Unsupported report type: {mms_object_name:?}"))),
                };

                // Report All
                let mut results = vec![];
                for result in message.access_results {
                    match result {
                        MmsServiceAccessResult::Success(mms_service_data) => results.push(IccpAccessResult::Success(convert_mms_service_data_to_iccp_data(mms_service_data)?)),
                        MmsServiceAccessResult::Failure(mms_access_error) => results.push(IccpAccessResult::Failure(mms_access_error)),
                    }
                }
                return Ok(IccpTransferSetReport::ReportAll(transfer_set_name, results));
            }
            MmsVariableAccessSpecification::ListOfVariables(list_of_variables_items) => {
                if list_of_variables_items.len() != message.access_results.len() {
                    return Err(IccpError::ProtocolError("An RBE payload was received with mismatching names and results".into()));
                }
                let mut results: Vec<IccpRbeTransferSetValue> = vec![];
                for i in 0..list_of_variables_items.len() {
                    let name = match &list_of_variables_items[i].variable_specification {
                        VariableSpecification::Name(MmsObjectName::VmdSpecific(name)) => IccpScopedIdentifier::Vcc(name.clone()),
                        VariableSpecification::Name(MmsObjectName::DomainSpecific(domain, name)) => IccpScopedIdentifier::Icc(domain.clone(), name.clone()),
                        VariableSpecification::Name(mms_object_name) => return Err(IccpError::ProtocolError(format!("Unsupported report type: {mms_object_name:?}"))),
                        // TODO Seems a bit strong, maybe log and warn.
                        VariableSpecification::Invalidated => return Err(IccpError::ProtocolError(format!("Invalid item in transfer set: {:?}", list_of_variables_items[i].variable_specification))),
                    };
                    let result = match &message.access_results[i] {
                        MmsServiceAccessResult::Success(mms_service_data) => IccpAccessResult::Success(convert_mms_service_data_to_iccp_data(mms_service_data.clone())?),
                        MmsServiceAccessResult::Failure(mms_access_error) => IccpAccessResult::Failure(mms_access_error.clone()),
                    };
                    results.push(IccpRbeTransferSetValue { identifier: name, access_result: result });
                }

                return Ok(IccpTransferSetReport::ReportByException(results));
            }
        }
    }
}

fn convert_mms_service_data_to_iccp_data(mms_data: MmsServiceData) -> Result<IccpData, IccpError> {
    match &mms_data {
        MmsServiceData::BitString(x) => Ok(IccpData::State(flags_to_state(x), flags_to_validity(x), flags_to_current_source(x), flags_to_normal(x), flags_to_timestamp_quality(x))),
        MmsServiceData::Structure(struct_data) => match struct_data.as_slice() {
            [MmsServiceData::FloatingPoint(value), MmsServiceData::BitString(x)] => Ok(IccpData::RealQ(value.to_f32()?, flags_to_validity(x), flags_to_current_source(x), flags_to_normal(x), flags_to_timestamp_quality(x))),
            [MmsServiceData::Integer(value), MmsServiceData::BitString(x)] => Ok(IccpData::DiscreteQ(
                value.try_into().map_err(|e| IccpError::ProtocolError(format!("unable to convert data into DiscreteQ: {e}")))?,
                flags_to_validity(x),
                flags_to_current_source(x),
                flags_to_normal(x),
                flags_to_timestamp_quality(x),
            )),
            x => Err(IccpError::ProtocolError(format!("Unknown MMS Structure Data: {x:?}"))),
        },
        x => Err(IccpError::ProtocolError(format!("Unknown MMS Data: {x:?}"))),
    }
}

fn flags_to_state(flags: &Vec<bool>) -> StateValue {
    match (flags.get(0).unwrap_or_else(|| &false), flags.get(1).unwrap_or_else(|| &false)) {
        (false, false) => StateValue::Closed,
        (false, true) => StateValue::Tripped,
        (true, false) => StateValue::Closed,
        (true, true) => StateValue::Invalid,
    }
}

fn flags_to_validity(flags: &Vec<bool>) -> ValidityValue {
    match (flags.get(2).unwrap_or_else(|| &false), flags.get(3).unwrap_or_else(|| &false)) {
        (false, false) => ValidityValue::Valid,
        (false, true) => ValidityValue::Held,
        (true, false) => ValidityValue::Suspect,
        (true, true) => ValidityValue::NotValid,
    }
}

fn flags_to_current_source(flags: &Vec<bool>) -> CurrentSourceValue {
    match (flags.get(4).unwrap_or_else(|| &false), flags.get(5).unwrap_or_else(|| &false)) {
        (false, false) => CurrentSourceValue::Telemetered,
        (false, true) => CurrentSourceValue::Calculated,
        (true, false) => CurrentSourceValue::Entered,
        (true, true) => CurrentSourceValue::Estimated,
    }
}

fn flags_to_normal(flags: &Vec<bool>) -> NormalValue {
    match flags.get(6).unwrap_or_else(|| &false) {
        false => NormalValue::Normal,
        true => NormalValue::Abnormal,
    }
}

fn flags_to_timestamp_quality(flags: &Vec<bool>) -> TimestampQualityValue {
    match flags.get(7).unwrap_or_else(|| &false) {
        false => TimestampQualityValue::Valid,
        true => TimestampQualityValue::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rand::random_range;
    use rusty_mms_service::{MmsServiceConnectionParameters, create_mms_service_client, create_mms_service_server};
    use tokio::{self, join};

    use crate::{IccpClient, IccpServer, RustyIccpClient, RustyIccpServer, error::IccpError};
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_identify_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(|e| IccpError::InternalError(format!("Test Failed: {e}")))?;

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                create_mms_service_client(address, MmsServiceConnectionParameters::default()).await
            },
            async { create_mms_service_server(address, MmsServiceConnectionParameters::default()).await }
        );

        let client = client_results?;
        let server = server_results?;

        let iccp_client = RustyIccpClient::new(client.clone());
        let mut iccp_server = RustyIccpServer::new(server.clone());

        let mut op_iccp_client = iccp_client.clone().await;
        let client_future = tokio::task::spawn(async move { op_iccp_client.create_data_set("MyDomain".into(), "DataSetName".into(), vec!["Variable1".into(), "Variable2".into()]).await });
        let received_value = iccp_server.receive_operation().await?;
        match received_value {
            crate::IccpOperation::CreateDataSet(message) => message.respond().await?,
            x => assert!(false, "Unexpected message: {x:?}"),
        }
        client_future.await??;

        Ok(())
    }
}
