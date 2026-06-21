pub mod error;

use async_trait::async_trait;

use error::*;
use num_bigint::BigInt;
use rusty_mms::{ListOfVariablesItem, MmsAccessError, MmsBasicObjectClass, MmsObjectClass, MmsObjectName, MmsObjectScope, MmsVariableAccessSpecification, VariableSpecification};
use rusty_mms_service::{
    RustyMmsServiceClient, RustyMmsServiceServer, data::{MmsServiceAccessResult, MmsServiceData, MmsServiceDeleteObjectScope}, message::{DefineNamedVariableListMmsServiceMessage, GetNameListMmsServiceMessage, MmsServiceMessage}
};

#[async_trait]
pub trait IccpClient: Send + Sync {
    // --- Completed ---
    async fn get_data_values(&mut self, names: Vec<String>) -> Result<Vec<IccpAccessResult>, IccpError>;
    async fn get_data_set_names(&mut self, scope: IccpScope) -> Result<Vec<String>, IccpError>;
    async fn get_data_value_names(&mut self, scope: IccpScope) -> Result<Vec<String>, IccpError>;
    async fn create_data_set(&mut self, domain: String, name: String, identifiers: Vec<String>) -> Result<(), IccpError>;
    async fn delete_data_sets(&mut self, domain: String, identifiers: Vec<String>) -> Result<(), IccpError>;
    async fn delete_domain_data_sets(&mut self, domain: String) -> Result<(), IccpError>;
    async fn start_transfer_set(&mut self, domain: String, name: String) -> Result<(), IccpError>;

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

    // fn fetch_transfer_report
}

// This can be encoded as a State or Discrete. Discrete should be used of there are more than 4 states.
pub enum StateValue {
    Between, // Between, Invalid
    Tripped, // Tripped, Off, Auto, Normal, Local, Raise, Not Ready, Offline
    Closed,  // Closed, On, Manual, Alarm, Remote, Lower, Ready, Available
    Invalid, // Invalid
}

pub enum ExpectedStateValue {
    Between, // Between, Invalid
    Tripped, // Tripped, Off, Auto, Normal, Local, Raise, Not Ready, Offline
    Closed,  // Closed, On, Manual, Alarm, Remote, Lower, Ready, Available
    Invalid, // Invalid
}

pub enum ValidityValue {
    Valid,
    Held,
    Suspect,
    NotValid,
}

pub enum CurrentSourceValue {
    Telemetered,
    Calculated,
    Entered,
    Estimated,
}

pub enum NormalSourceValue {
    Telemetered,
    Calculated,
    Entered,
    Estimated,
}

pub enum NormalValue {
    Normal,
    Abnormal,
}

pub enum TimeStampQualityValue {
    Valid,
    Invalid,
}

pub enum TagValue {
    NoTag,
    OpenAndCloseInhibit,
    CloseOnlyInhibit,
}

pub enum IccpData {
    Real(f32),
    Discrete(i32),
    State(StateValue, ValidityValue, CurrentSourceValue, NormalValue, TimeStampQualityValue),
    StateSupplemental(StateValue, ValidityValue, CurrentSourceValue, NormalValue, TimeStampQualityValue, TagValue, ExpectedStateValue),

    RealQ(f32, ValidityValue, CurrentSourceValue, NormalValue, TimeStampQualityValue),
    StateQ(StateValue, ValidityValue, CurrentSourceValue, NormalValue, TimeStampQualityValue),
    DiscreteQ(i32, ValidityValue, CurrentSourceValue, NormalValue, TimeStampQualityValue),
    StateSupplementalQ(StateValue, ValidityValue, CurrentSourceValue, NormalValue, TimeStampQualityValue, TagValue, ExpectedStateValue),
    // TODO The rest of them. No COV support
}

pub enum IccpAccessResult {
    Success(IccpData),
    Failure(MmsAccessError),
}

pub enum IccpScope {
    Vcc,
    Icc(String), // Domain
}

pub enum IccpScopedIdentifier {
    Vcc(String),         // Value
    Icc(String, String), // Domain, Value
}

pub enum IccpOperation {
    MmsOperation(MmsServiceMessage), // Pass through unhandled MMS operations so servers can process messages like identify and conclude

    CreateDataSet(CreateDataSetOperation),
    GetDataSetNames(GetDataSetNamesOperation),
}

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

pub struct GetDataSetNamesOperation {
    scope: IccpScope,
    message: GetNameListMmsServiceMessage,
}

impl GetDataSetNamesOperation {
    pub fn scope(&self) -> &IccpScope {
        &self.scope
    }

    pub async fn respond(self) -> Result<(), IccpError> {
        Ok(self.message.respond().await?)
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
                let data_set_items = message.list_of_variables().iter().map(|x| match &x.variable_specification {
                    VariableSpecification::Name(mms_object_name) => mms_object_name.try_into(),
                    VariableSpecification::Invalidated => Err(IccpError::ProtocolError(format!("Invalidated variable specified in create data set request: {data_set_domain}:{data_set_name}"))),
                }).collect::<Result<Vec<IccpScopedIdentifier>, IccpError>>()?;

                return Ok(IccpOperation::CreateDataSet(CreateDataSetOperation { data_set_domain, data_set_name, data_set_items, message }));
            }
            MmsServiceMessage::GetNameList(message) if matches!(message.object_class(), MmsObjectClass::Basic(MmsBasicObjectClass::NamedVariable)) => {
                let scope = match message.object_scope() {
                    MmsObjectScope::Vmd => IccpScope::Vcc,
                    MmsObjectScope::Domain(x) => IccpScope::Icc(x.into()),
                    x => return Err(IccpError::ProtocolError(format!("Can only list data sets for VCC and ICC but got {x:?}"))),
                };
                return Ok(IccpOperation::MmsOperation(()))
            },
            MmsServiceMessage::GetVariableAccessAttributes(message) => todo!(),
            MmsServiceMessage::GetNamedVariableListAttributes(message) => todo!(),
            MmsServiceMessage::DeleteNamedVariableList(message) => todo!(),
            MmsServiceMessage::Read(message) => todo!(),
            MmsServiceMessage::Write(message) => todo!(),
            MmsServiceMessage::InformationReport(message) => todo!(),
            message => Ok(IccpOperation::MmsOperation(message))
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

impl RustyIccpClient {
    pub fn new(mms_client: Box<dyn RustyMmsServiceClient>) -> Self {
        RustyIccpClient { mms_client }
    }
}

#[async_trait]
impl IccpClient for RustyIccpClient {
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
                vec![
                    MmsServiceData::Structure(vec![MmsServiceData::Structure(vec![
                        MmsServiceData::Integer(BigInt::from(1)),
                        MmsServiceData::VisibleString(domain.clone()),
                        MmsServiceData::VisibleString(name),
                    ])]),
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
                ],
            )
            .await?;
        Ok(())
    }
}

fn convert_mms_service_data_to_iccp_data(mms_data: MmsServiceData) -> Result<IccpData, IccpError> {
    match mms_data {
        MmsServiceData::Structure(struct_data) => match struct_data.as_slice() {
            [MmsServiceData::FloatingPoint(value), MmsServiceData::BitString(_)] => Ok(IccpData::RealQ(value.to_f32()?, ValidityValue::Valid, CurrentSourceValue::Telemetered, NormalValue::Normal, TimeStampQualityValue::Valid)),
            x => Err(IccpError::ProtocolError(format!("Unknown MMS Structure Data: {x:?}"))),
        },
        x => Err(IccpError::ProtocolError(format!("Unknown MMS Data: {x:?}"))),
    }
}
