use async_trait::async_trait;
use der_parser::Oid;
use num_bigint::BigInt;
use rusty_acse::{
    AcseRequestInformation, AcseResponseInformation, AeQualifier, ApTitle, AssociateResult, AssociateSourceDiagnostic, AssociateSourceDiagnosticUserCategory, RustyOsiSingleValueAcseInitiatorIsoStack, RustyOsiSingleValueAcseListenerIsoStack,
};
use rusty_copp::{CoppConnectionInformation, RustyCoppInitiatorIsoStack, RustyCoppListenerIsoStack};
use rusty_cosp::{CospConnectionParameters, CospProtocolInformation, RustyCospAcceptorIsoStack, RustyCospInitiatorIsoStack};
use rusty_cotp::{CotpProtocolInformation, CotpResponder, RustyCotpConnection, RustyCotpResponder};
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
};
use tokio::{
    select,
    sync::{
        Mutex, Notify,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
};

use dyn_clone::DynClone;

use rusty_mms::{
    ListOfVariablesItem, MmsAccessResult, MmsConfirmedRequest, MmsConfirmedResponse, MmsConnection, MmsData, MmsError, MmsInitiator, MmsListener, MmsMessage, MmsObjectClass, MmsObjectName, MmsObjectScope, MmsReader, MmsRequestInformation,
    MmsResponder, MmsScope, MmsUnconfirmedService, MmsVariableAccessSpecification, MmsWriteResult, MmsWriter, RustyMmsInitiatorIsoStack, RustyMmsListenerIsoStack,
    parameters::{ParameterSupportOption, ServiceSupportOption},
};
use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter, TpktConnection, TpktReader, TpktWriter};

use crate::{
    data::{
        Identity, InformationReportMmsServiceMessage, MmsServiceAccessResult, MmsServiceData, MmsServiceDeleteObjectScope, NameList, NamedVariableListAttributes, VariableAccessAttributes, convert_high_level_data_to_low_level_data,
        convert_low_level_data_to_high_level_data, convert_low_level_data_types_to_high_level_data_types,
    },
    error::{MmsServiceError, to_mms_error},
    message::{DefineNamedVariableListMmsServiceMessage, GetNameListMmsServiceMessage, GetVariableAccessAttributesMmsServiceMessage, IdentifyMmsServiceMessage, MmsServiceMessage, ReadMmsServiceMessage, WriteMmsServiceMessage},
};

pub mod data;
pub mod error;
pub mod message;

pub trait TpktClientConnectionFactory<T: TpktConnection, R: TpktReader, W: TpktWriter> {
    fn create_connection<'a>(&mut self) -> impl std::future::Future<Output = Result<impl TpktConnection + 'a, MmsServiceError>> + Send;
}

pub struct RustyTpktClientConnectionFactory<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> {
    address: SocketAddr,
    _tpkt_connection: PhantomData<T>,
    _tpkt_reader: PhantomData<R>,
    _tpkt_writer: PhantomData<W>,
}

impl<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> RustyTpktClientConnectionFactory<T, R, W> {
    pub fn new(address: SocketAddr) -> RustyTpktClientConnectionFactory<T, R, W> {
        RustyTpktClientConnectionFactory { address, _tpkt_connection: PhantomData, _tpkt_reader: PhantomData, _tpkt_writer: PhantomData }
    }
}

impl<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> TpktClientConnectionFactory<T, R, W> for RustyTpktClientConnectionFactory<T, R, W> {
    async fn create_connection<'a>(&mut self) -> Result<impl TpktConnection + 'a, MmsServiceError> {
        TcpTpktConnection::connect(self.address).await.map_err(to_mms_error(""))
    }
}

pub trait TpktServerConnectionFactory<T: TpktConnection, R: TpktReader, W: TpktWriter> {
    fn create_connection<'a>(&mut self) -> impl std::future::Future<Output = Result<impl TpktConnection + 'a, MmsServiceError>> + Send;
}

pub struct RustyTpktServerConnectionFactory<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> {
    server: TcpTpktServer,
    _tpkt_reader: PhantomData<R>,
    _tpkt_writer: PhantomData<W>,
    _tpkt_connection: PhantomData<T>,
}

impl<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> RustyTpktServerConnectionFactory<T, R, W> {
    pub async fn listen(address: SocketAddr) -> Result<RustyTpktServerConnectionFactory<T, R, W>, MmsServiceError> {
        Ok(RustyTpktServerConnectionFactory { server: TcpTpktServer::listen(address).await.map_err(to_mms_error(""))?, _tpkt_reader: PhantomData, _tpkt_writer: PhantomData, _tpkt_connection: PhantomData })
    }
}

impl<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> TpktServerConnectionFactory<T, R, W> for RustyTpktServerConnectionFactory<T, R, W> {
    async fn create_connection<'a>(&mut self) -> Result<impl TpktConnection + 'a, MmsServiceError> {
        Ok(self.server.accept().await.map_err(to_mms_error("failed to accept connection"))?)
    }
}

pub struct MmsServiceConnectionIdentityParameters {
    pub tsap_id: Option<Vec<u8>>,
    pub session_selector: Option<Vec<u8>>,
    pub presentation_selector: Option<Vec<u8>>,

    pub ap_title: Option<Oid<'static>>,
    pub ae_qualifier: Option<Vec<u8>>,
    pub ap_invocation_identifier: Option<Vec<u8>>,
    pub ae_invocation_identifier: Option<Vec<u8>>,
}

impl Default for MmsServiceConnectionIdentityParameters {
    fn default() -> Self {
        Self { tsap_id: None, session_selector: None, presentation_selector: None, ap_title: None, ae_qualifier: None, ap_invocation_identifier: None, ae_invocation_identifier: None }
    }
}

pub struct MmsServiceConnectionParameters {
    local_detail_calling: Option<i32>,

    pub called: MmsServiceConnectionIdentityParameters,
    pub calling: MmsServiceConnectionIdentityParameters,

    pub proposed_max_serv_outstanding_calling: i16,
    pub proposed_max_serv_outstanding_called: i16,
    pub proposed_data_structure_nesting_level: Option<i8>,
    pub propsed_parameter_cbb: Vec<ParameterSupportOption>,
    pub services_supported_calling: Vec<ServiceSupportOption>,
}

impl Default for MmsServiceConnectionParameters {
    fn default() -> Self {
        Self {
            local_detail_calling: None,

            calling: Default::default(),
            called: Default::default(),

            proposed_max_serv_outstanding_calling: 10,
            proposed_max_serv_outstanding_called: 10,
            proposed_data_structure_nesting_level: Some(2),
            propsed_parameter_cbb: vec![ParameterSupportOption::Str1, ParameterSupportOption::Str2, ParameterSupportOption::Vnam, ParameterSupportOption::Vlis],
            services_supported_calling: vec![
                ServiceSupportOption::GetNameList,
                ServiceSupportOption::Identify,
                ServiceSupportOption::Write,
                ServiceSupportOption::GetVariableAccessAttributes,
                ServiceSupportOption::DefineNamedVariableList,
                ServiceSupportOption::GetNamedVariableListAttribute,
                ServiceSupportOption::DeleteNamedVariableList,
                ServiceSupportOption::Read,
                ServiceSupportOption::InformationReport,
                ServiceSupportOption::Conclude,
            ],
        }
    }
}

#[async_trait]
pub trait RustyMmsServiceClient: Send + Sync {
    fn clone(&self) -> Box<dyn RustyMmsServiceClient>;

    async fn identify(&mut self) -> Result<Identity, MmsServiceError>;

    async fn get_name_list(&mut self, object_class: MmsObjectClass, object_scope: MmsObjectScope, continue_after: Option<String>) -> Result<NameList, MmsServiceError>;
    async fn get_variable_access_attributes(&mut self, object_name: MmsObjectName) -> Result<VariableAccessAttributes, MmsServiceError>;

    async fn define_named_variable_list(&mut self, variable_list_name: MmsObjectName, list_of_variables: Vec<ListOfVariablesItem>) -> Result<(), MmsServiceError>;
    async fn get_named_variable_list_attributes(&mut self, variable_list_name: MmsObjectName) -> Result<NamedVariableListAttributes, MmsServiceError>;
    async fn delete_named_variable_list(&mut self, scope_of_delete: MmsServiceDeleteObjectScope) -> Result<(i32 /* Number Matched */, i32 /* Number Deleted */), MmsServiceError>;

    /// Reads data from an MMS Server.
    ///
    /// This does not expose the specification with result flag. If this is required, cut a ticket and I will add a read_with_specification method.
    async fn read(&mut self, specification: MmsVariableAccessSpecification) -> Result<Vec<MmsServiceAccessResult>, MmsServiceError>;
    async fn write(&mut self, specification: MmsVariableAccessSpecification, values: Vec<MmsServiceData>) -> Result<Vec<MmsWriteResult>, MmsServiceError>;

    async fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsServiceAccessResult>) -> Result<(), MmsServiceError>;
    async fn receive_information_report(&mut self) -> Result<InformationReportMmsServiceMessage, MmsServiceError>;
}

struct RustyTcpMmsServiceClient<R: MmsReader, W: MmsWriter> {
    reader: Arc<Mutex<R>>,
    writer: Arc<Mutex<W>>,
    invocation_id: Arc<AtomicI32>,
    mail_box: Arc<Mutex<HashMap<Vec<u8>, MmsConfirmedResponse>>>,

    notify: Arc<Notify>,
    info_report_sender: UnboundedSender<MmsUnconfirmedService>,
    info_report_receiver: Arc<Mutex<UnboundedReceiver<MmsUnconfirmedService>>>,
}

impl<R: MmsReader, W: MmsWriter> RustyTcpMmsServiceClient<R, W> {
    async fn fetch_confirmed_message(&mut self, invocation_id: Vec<u8>) -> Result<MmsConfirmedResponse, MmsServiceError> {
        let mut notify_registration = self.notify.notified();
        Ok(loop {
            select! {
                _ = notify_registration => {
                    notify_registration = self.notify.notified();
                    match self.mail_box.lock().await.remove(&invocation_id) {
                        Some(x) => break x,
                        None => (),
                    }
                }
                mut reader = self.reader.lock() => {
                    notify_registration = self.notify.notified();
                    match self.mail_box.lock().await.remove(&invocation_id) {
                        Some(x) => break x,
                        None => (),
                    }

                    match reader.recv().await? {
                        rusty_mms::MmsRecvResult::Message(MmsMessage::ConfirmedResponse { invocation_id: response_invocation_id, response }) => {
                            if invocation_id == response_invocation_id {
                                break response;
                            } else {
                                self.mail_box.lock().await.insert(response_invocation_id, response);
                                self.notify.notify_waiters();
                            }
                        }
                        rusty_mms::MmsRecvResult::Message(MmsMessage::Unconfirmed { unconfirmed_service }) => {
                            let _ = self.info_report_sender.send(unconfirmed_service); // Ignore send errors here. Something has gone wrong but should be detected elsewhere.
                            ()
                        }
                        rusty_mms::MmsRecvResult::Message(_) => return Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())), // TODO Message queue.
                        rusty_mms::MmsRecvResult::Closed => return Err(MmsServiceError::ProtocolError("Connection Closed".into())),
                    }
                }
            };
        })
    }
}

#[async_trait]
impl<R: MmsReader + 'static, W: MmsWriter + 'static> RustyMmsServiceClient for RustyTcpMmsServiceClient<R, W> {
    fn clone(&self) -> Box<dyn RustyMmsServiceClient> {
        Box::new(RustyTcpMmsServiceClient {
            reader: self.reader.clone(),
            writer: self.writer.clone(),
            invocation_id: self.invocation_id.clone(),
            mail_box: self.mail_box.clone(),
            notify: self.notify.clone(),
            info_report_sender: self.info_report_sender.clone(),
            info_report_receiver: self.info_report_receiver.clone(),
        })
    }

    async fn identify(&mut self) -> Result<Identity, MmsServiceError> {
        let invocation_id = BigInt::from(self.invocation_id.fetch_add(1, Ordering::Acquire)).to_signed_bytes_be();
        self.writer.lock().await.send(&mut VecDeque::from(vec![MmsMessage::ConfirmedRequest { invocation_id: invocation_id.clone(), request: MmsConfirmedRequest::Identify }])).await?;

        match self.fetch_confirmed_message(invocation_id).await? {
            MmsConfirmedResponse::Identify { vendor_name, model_name, revision, abstract_syntaxes } => Ok(Identity { vendor_name, model_name, revision, abstract_syntaxes }),
            _ => return Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
        }
    }

    async fn get_name_list(&mut self, object_class: MmsObjectClass, object_scope: MmsObjectScope, continue_after: Option<String>) -> Result<NameList, MmsServiceError> {
        let invocation_id = BigInt::from(self.invocation_id.fetch_add(1, Ordering::Acquire)).to_signed_bytes_be();
        self.writer.lock().await.send(&mut VecDeque::from(vec![MmsMessage::ConfirmedRequest { invocation_id: invocation_id.clone(), request: MmsConfirmedRequest::GetNameList { object_class, object_scope, continue_after } }])).await?;

        match self.fetch_confirmed_message(invocation_id).await? {
            MmsConfirmedResponse::GetNameList { list_of_identifiers, more_follows } => Ok(NameList { identifiers: list_of_identifiers, more_follows: more_follows.unwrap_or(true) }),
            _ => return Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
        }
    }

    async fn get_variable_access_attributes(&mut self, object_name: MmsObjectName) -> Result<VariableAccessAttributes, MmsServiceError> {
        let invocation_id = BigInt::from(self.invocation_id.fetch_add(1, Ordering::Acquire)).to_signed_bytes_be();
        self.writer.lock().await.send(&mut VecDeque::from(vec![MmsMessage::ConfirmedRequest { invocation_id: invocation_id.clone(), request: MmsConfirmedRequest::GetVariableAccessAttributes { object_name } }])).await?;

        match self.fetch_confirmed_message(invocation_id).await? {
            MmsConfirmedResponse::GetVariableAccessAttributes { deletable, type_description } => Ok(VariableAccessAttributes { deletable, type_description: convert_low_level_data_types_to_high_level_data_types(&type_description)? }),
            _ => return Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
        }
    }

    async fn define_named_variable_list(&mut self, variable_list_name: MmsObjectName, list_of_variables: Vec<ListOfVariablesItem>) -> Result<(), MmsServiceError> {
        let invocation_id = BigInt::from(self.invocation_id.fetch_add(1, Ordering::Acquire)).to_signed_bytes_be();
        self.writer
            .lock()
            .await
            .send(&mut VecDeque::from(vec![MmsMessage::ConfirmedRequest { invocation_id: invocation_id.clone(), request: MmsConfirmedRequest::DefineNamedVariableList { variable_list_name, list_of_variables } }]))
            .await?;

        match self.fetch_confirmed_message(invocation_id).await? {
            MmsConfirmedResponse::DefineNamedVariableList {} => Ok(()),
            _ => return Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
        }
    }

    async fn get_named_variable_list_attributes(&mut self, variable_list_name: MmsObjectName) -> Result<NamedVariableListAttributes, MmsServiceError> {
        let invocation_id = BigInt::from(self.invocation_id.fetch_add(1, Ordering::Acquire)).to_signed_bytes_be();
        self.writer
            .lock()
            .await
            .send(&mut VecDeque::from(vec![MmsMessage::ConfirmedRequest { invocation_id: invocation_id.clone(), request: MmsConfirmedRequest::GetNamedVariableListAttributes { object_name: variable_list_name } }]))
            .await?;

        match self.fetch_confirmed_message(invocation_id).await? {
            MmsConfirmedResponse::GetNamedVariableListAttributes { deletable, list_of_variables } => Ok(NamedVariableListAttributes { deletable, list_of_variables }),
            _ => return Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
        }
    }

    async fn delete_named_variable_list(&mut self, scope_of_delete: MmsServiceDeleteObjectScope) -> Result<(i32, i32), MmsServiceError> {
        let request_scope = match scope_of_delete {
            MmsServiceDeleteObjectScope::Specific(mms_object_names) => MmsConfirmedRequest::DeleteNamedVariableList { scope_of_delete: Some(MmsScope::Specific), list_of_variable_list_names: Some(mms_object_names), domain_name: None },
            MmsServiceDeleteObjectScope::AaSpecific => MmsConfirmedRequest::DeleteNamedVariableList { scope_of_delete: Some(MmsScope::AaSpecific), list_of_variable_list_names: None, domain_name: None },
            MmsServiceDeleteObjectScope::Domain(domain_name) => MmsConfirmedRequest::DeleteNamedVariableList { scope_of_delete: Some(MmsScope::Domain), list_of_variable_list_names: None, domain_name: Some(domain_name) },
            MmsServiceDeleteObjectScope::Vmd => MmsConfirmedRequest::DeleteNamedVariableList { scope_of_delete: Some(MmsScope::Vmd), list_of_variable_list_names: None, domain_name: None },
        };

        let invocation_id = BigInt::from(self.invocation_id.fetch_add(1, Ordering::Acquire)).to_signed_bytes_be();
        self.writer.lock().await.send(&mut VecDeque::from(vec![MmsMessage::ConfirmedRequest { invocation_id: invocation_id.clone(), request: request_scope }])).await?;

        match self.fetch_confirmed_message(invocation_id).await? {
            MmsConfirmedResponse::DeleteNamedVariableList { number_matched, number_deleted } => {
                Ok((BigInt::from_signed_bytes_be(&number_matched).try_into().map_err(to_mms_error(""))?, BigInt::from_signed_bytes_be(&number_deleted).try_into().map_err(to_mms_error(""))?))
            }
            _ => return Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
        }
    }

    async fn read(&mut self, specification: MmsVariableAccessSpecification) -> Result<Vec<MmsServiceAccessResult>, MmsServiceError> {
        let invocation_id = BigInt::from(self.invocation_id.fetch_add(1, Ordering::Acquire)).to_signed_bytes_be();
        self.writer
            .lock()
            .await
            .send(&mut VecDeque::from(vec![MmsMessage::ConfirmedRequest { invocation_id: invocation_id.clone(), request: MmsConfirmedRequest::Read { specification_with_result: Some(false), variable_access_specification: specification } }]))
            .await?;

        match self.fetch_confirmed_message(invocation_id).await? {
            MmsConfirmedResponse::Read { variable_access_specification: _, access_results } => Ok(access_results
                .into_iter()
                .map(|x| match x {
                    MmsAccessResult::Success(mms_data) => Ok(MmsServiceAccessResult::Success(convert_low_level_data_to_high_level_data(&mms_data)?)),
                    MmsAccessResult::Failure(mms_access_error) => Ok(MmsServiceAccessResult::Failure(mms_access_error)),
                })
                .collect::<Result<Vec<MmsServiceAccessResult>, MmsServiceError>>()?),
            _ => return Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
        }
    }

    async fn write(&mut self, specification: MmsVariableAccessSpecification, values: Vec<MmsServiceData>) -> Result<Vec<MmsWriteResult>, MmsServiceError> {
        let invocation_id = BigInt::from(self.invocation_id.fetch_add(1, Ordering::Acquire)).to_signed_bytes_be();
        self.writer
            .lock()
            .await
            .send(&mut VecDeque::from(vec![MmsMessage::ConfirmedRequest {
                invocation_id: invocation_id.clone(),
                request: MmsConfirmedRequest::Write { variable_access_specification: specification, list_of_data: values.iter().map(|x| convert_high_level_data_to_low_level_data(x)).collect::<Result<Vec<MmsData>, MmsError>>()? },
            }]))
            .await?;

        match self.fetch_confirmed_message(invocation_id).await? {
            MmsConfirmedResponse::Write { write_results } => Ok(write_results),
            _ => return Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
        }
    }

    async fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsServiceAccessResult>) -> Result<(), MmsServiceError> {
        let access_results = access_results
            .into_iter()
            .map(|x| match x {
                MmsServiceAccessResult::Success(mms_data) => Ok(MmsAccessResult::Success(convert_high_level_data_to_low_level_data(&mms_data)?)),
                MmsServiceAccessResult::Failure(mms_access_error) => Ok(MmsAccessResult::Failure(mms_access_error)),
            })
            .collect::<Result<Vec<MmsAccessResult>, MmsServiceError>>()?;

        self.writer.lock().await.send(&mut VecDeque::from(vec![MmsMessage::Unconfirmed { unconfirmed_service: rusty_mms::MmsUnconfirmedService::InformationReport { variable_access_specification, access_results } }])).await?;
        Ok(())
    }

    async fn receive_information_report(&mut self) -> Result<InformationReportMmsServiceMessage, MmsServiceError> {
        Ok(loop {
            let mut receiver = self.info_report_receiver.lock().await;
            let mut reader = self.reader.lock().await;

            select! {
                value = reader.recv() => {
                    match value? {
                        rusty_mms::MmsRecvResult::Message(MmsMessage::ConfirmedResponse { invocation_id: response_invocation_id, response }) => {
                            self.mail_box.lock().await.insert(response_invocation_id, response);
                        }
                        rusty_mms::MmsRecvResult::Message(MmsMessage::Unconfirmed { unconfirmed_service: MmsUnconfirmedService::InformationReport { variable_access_specification, access_results } }) => {
                            break InformationReportMmsServiceMessage {
                                variable_access_specification,
                                access_results: access_results
                                    .into_iter()
                                    .map(|x| match x {
                                        MmsAccessResult::Success(mms_data) => Ok(MmsServiceAccessResult::Success(convert_low_level_data_to_high_level_data(&mms_data)?)),
                                        MmsAccessResult::Failure(mms_access_error) => Ok(MmsServiceAccessResult::Failure(mms_access_error)),
                                    })
                                    .collect::<Result<Vec<MmsServiceAccessResult>, MmsServiceError>>()?,
                            };
                        }
                        rusty_mms::MmsRecvResult::Message(_) => return Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
                        rusty_mms::MmsRecvResult::Closed => return Err(MmsServiceError::ProtocolError("Connection Closed".into())),
                    }
                },
                value = receiver.recv() => {
                    match value {
                        Some(MmsUnconfirmedService::InformationReport { variable_access_specification, access_results }) =>  {
                            break InformationReportMmsServiceMessage {
                                variable_access_specification,
                                access_results: access_results
                                    .into_iter()
                                    .map(|x| match x {
                                        MmsAccessResult::Success(mms_data) => Ok(MmsServiceAccessResult::Success(convert_low_level_data_to_high_level_data(&mms_data)?)),
                                        MmsAccessResult::Failure(mms_access_error) => Ok(MmsServiceAccessResult::Failure(mms_access_error)),
                                    })
                                    .collect::<Result<Vec<MmsServiceAccessResult>, MmsServiceError>>()?,
                            };
                        },
                        None => todo!(),
                    }
                }
            }
        })
    }
}

pub async fn create_mms_service_client(host: SocketAddr, parameters: MmsServiceConnectionParameters) -> Result<Box<dyn RustyMmsServiceClient>, MmsServiceError> {
    let tpkt_connection = TcpTpktConnection::connect(host).await.map_err(|e| MmsServiceError::ProtocolError(format!("{e}")))?;

    let cotp_connection_info = CotpProtocolInformation::initiator(parameters.calling.tsap_id, parameters.called.tsap_id);
    let cotp_connection = RustyCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_connection, cotp_connection_info, Default::default()).await.map_err(to_mms_error("Failed to create COTP Connection"))?;

    let cosp_connection_info = CospProtocolInformation::new(parameters.calling.session_selector, parameters.called.session_selector);
    let cosp_initiator = RustyCospInitiatorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cotp_connection, cosp_connection_info, Default::default()).await.map_err(to_mms_error("Failed to create COSP Connection"))?;

    let copp_connection_info = CoppConnectionInformation { called_presentation_selector: parameters.called.presentation_selector, calling_presentation_selector: parameters.calling.presentation_selector };
    let copp_initiator = RustyCoppInitiatorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cosp_initiator, copp_connection_info);

    let acse_connection_info = AcseRequestInformation {
        application_context_name: Oid::from(&[1, 0, 9506, 2, 3]).map_err(to_mms_error("Failed to create MMS Application Context Name"))?,
        called_ap_title: parameters.called.ap_title.map(|x| ApTitle::Form2(x)),
        called_ae_qualifier: parameters.called.ae_qualifier.map(|x| AeQualifier::Form2(x)),
        called_ap_invocation_identifier: parameters.called.ap_invocation_identifier,
        called_ae_invocation_identifier: parameters.called.ae_invocation_identifier,
        calling_ap_title: parameters.calling.ap_title.map(|x| ApTitle::Form2(x)),
        calling_ae_qualifier: parameters.calling.ae_qualifier.map(|x| AeQualifier::Form2(x)),
        calling_ap_invocation_identifier: parameters.calling.ap_invocation_identifier,
        calling_ae_invocation_identifier: parameters.calling.ae_invocation_identifier,
        ..Default::default()
    };
    let acse_initiator = RustyOsiSingleValueAcseInitiatorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(copp_initiator, acse_connection_info);

    let mms_connection_info = MmsRequestInformation {
        local_detail_calling: parameters.local_detail_calling,
        proposed_max_serv_outstanding_calling: parameters.proposed_max_serv_outstanding_calling,
        proposed_max_serv_outstanding_called: parameters.proposed_max_serv_outstanding_called,
        proposed_data_structure_nesting_level: parameters.proposed_data_structure_nesting_level,
        proposed_version_number: 1,
        propsed_parameter_cbb: parameters.propsed_parameter_cbb,
        services_supported_calling: parameters.services_supported_calling,
        ..Default::default()
    };
    let mms_initiator = RustyMmsInitiatorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(acse_initiator, mms_connection_info);
    let mms_connection = mms_initiator.initiate().await?;
    let (reader, writer) = mms_connection.split().await?;

    let (sender, receiver) = mpsc::unbounded_channel();

    Ok(Box::new(RustyTcpMmsServiceClient {
        reader: Arc::new(Mutex::new(reader)),
        writer: Arc::new(Mutex::new(writer)),
        invocation_id: Arc::new(AtomicI32::new(0)),
        mail_box: Arc::new(Mutex::new(HashMap::new())),
        notify: Arc::new(Notify::new()),
        info_report_sender: sender,
        info_report_receiver: Arc::new(Mutex::new(receiver)),
    }))
}

#[async_trait]
pub trait RustyMmsServiceServer: Send + Sync {
    fn clone(&self) -> Box<dyn RustyMmsServiceServer>;

    async fn receive_message(&mut self) -> Result<MmsServiceMessage, MmsServiceError>;
    async fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsServiceAccessResult>) -> Result<(), MmsServiceError>;
}

struct RustyTcpMmsServiceServer<R: MmsReader, W: MmsWriter> {
    reader: Arc<Mutex<R>>,
    writer: Arc<Mutex<W>>,
}

impl<R: MmsReader, W: MmsWriter> RustyTcpMmsServiceServer<R, W> {}

#[async_trait]
impl<R: MmsReader + 'static, W: MmsWriter + 'static> RustyMmsServiceServer for RustyTcpMmsServiceServer<R, W> {
    fn clone(&self) -> Box<dyn RustyMmsServiceServer> {
        Box::new(RustyTcpMmsServiceServer { reader: self.reader.clone(), writer: self.writer.clone() })
    }

    async fn receive_message(&mut self) -> Result<MmsServiceMessage, MmsServiceError> {
        let mms_message: MmsMessage = match self.reader.lock().await.recv().await? {
            rusty_mms::MmsRecvResult::Closed => return Err(MmsServiceError::ProtocolError("Connection closed".into())),
            rusty_mms::MmsRecvResult::Message(mms_message) => mms_message,
        };
        let (invocation_id, request) = match mms_message {
            MmsMessage::ConfirmedRequest { invocation_id, request } => (invocation_id, request),
            _ => todo!(),
        };

        let writer = self.writer.clone();
        let invocation_id: u32 = BigInt::from_signed_bytes_be(invocation_id.as_slice()).try_into().map_err(|e| MmsServiceError::ProtocolError(format!("Invalid Invication Id: {:?}", invocation_id)))?;

        Ok(match request {
            MmsConfirmedRequest::GetNameList { object_class, object_scope, continue_after } => MmsServiceMessage::GetNameList(GetNameListMmsServiceMessage::new(
                invocation_id,
                object_class,
                object_scope,
                continue_after,
                Box::new(move |msg: MmsMessage| {
                    let callback_writer = writer.clone();
                    Box::pin(async move { callback_writer.lock().await.send(&mut VecDeque::from(vec![msg])).await.unwrap() })
                }),
            )),
            MmsConfirmedRequest::Identify => MmsServiceMessage::Identify(IdentifyMmsServiceMessage::new(
                invocation_id,
                Box::new(move |msg: MmsMessage| {
                    let callback_writer = writer.clone();
                    Box::pin(async move { callback_writer.lock().await.send(&mut VecDeque::from(vec![msg])).await.unwrap() })
                }),
            )),
            MmsConfirmedRequest::Read { specification_with_result, variable_access_specification } => MmsServiceMessage::Read(ReadMmsServiceMessage::new(
                invocation_id,
                variable_access_specification,
                specification_with_result,
                Box::new(move |msg: MmsMessage| {
                    let callback_writer = writer.clone();
                    Box::pin(async move { callback_writer.lock().await.send(&mut VecDeque::from(vec![msg])).await.unwrap() })
                }),
            )),
            MmsConfirmedRequest::Write { variable_access_specification, list_of_data } => MmsServiceMessage::Write(WriteMmsServiceMessage::new(
                invocation_id,
                variable_access_specification,
                list_of_data,
                Box::new(move |msg: MmsMessage| {
                    let callback_writer = writer.clone();
                    Box::pin(async move { callback_writer.lock().await.send(&mut VecDeque::from(vec![msg])).await.unwrap() })
                }),
            )?),
            MmsConfirmedRequest::GetVariableAccessAttributes { object_name } => MmsServiceMessage::GetVariableAccessAttributes(GetVariableAccessAttributesMmsServiceMessage::new(
                invocation_id,
                object_name,
                Box::new(move |msg: MmsMessage| {
                    let callback_writer = writer.clone();
                    Box::pin(async move { callback_writer.lock().await.send(&mut VecDeque::from(vec![msg])).await.unwrap() })
                }),
            )),
            MmsConfirmedRequest::DefineNamedVariableList { variable_list_name, list_of_variables } => MmsServiceMessage::DefineNamedVariableList(DefineNamedVariableListMmsServiceMessage::new(
                invocation_id,
                variable_list_name,
                list_of_variables,
                Box::new(move |msg: MmsMessage| {
                    let callback_writer = writer.clone();
                    Box::pin(async move { callback_writer.lock().await.send(&mut VecDeque::from(vec![msg])).await.unwrap() })
                }),
            )),
            MmsConfirmedRequest::GetNamedVariableListAttributes { object_name } => todo!(),
            MmsConfirmedRequest::DeleteNamedVariableList { scope_of_delete, list_of_variable_list_names, domain_name } => todo!(),
        })
    }

    async fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsServiceAccessResult>) -> Result<(), MmsServiceError> {
        let access_results = access_results
            .into_iter()
            .map(|x| match x {
                MmsServiceAccessResult::Success(mms_data) => Ok(MmsAccessResult::Success(convert_high_level_data_to_low_level_data(&mms_data)?)),
                MmsServiceAccessResult::Failure(mms_access_error) => Ok(MmsAccessResult::Failure(mms_access_error)),
            })
            .collect::<Result<Vec<MmsAccessResult>, MmsServiceError>>()?;

        self.writer.lock().await.send(&mut VecDeque::from(vec![MmsMessage::Unconfirmed { unconfirmed_service: rusty_mms::MmsUnconfirmedService::InformationReport { variable_access_specification, access_results } }])).await?;
        Ok(())
    }
}

pub async fn create_mms_service_server(address: SocketAddr, parameters: MmsServiceConnectionParameters) -> Result<Box<dyn RustyMmsServiceServer>, MmsServiceError> {
    let tpkt_connection = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await.unwrap().create_connection().await.unwrap();

    let (cotp_listener, cotp_connection_info) = RustyCotpResponder::<TcpTpktReader, TcpTpktWriter>::new(tpkt_connection, Default::default()).await.map_err(to_mms_error("Failed to create COTP Server"))?;
    let cotp_connection = cotp_listener.accept(cotp_connection_info).await.map_err(to_mms_error(""))?;

    let (cosp_listener, _) = RustyCospAcceptorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cotp_connection, CospConnectionParameters::default()).await.map_err(to_mms_error("Failed to create COSP Connection"))?;

    // TODO: Need to expose this.
    let _copp_connection_info = CoppConnectionInformation { called_presentation_selector: parameters.called.presentation_selector, calling_presentation_selector: parameters.calling.presentation_selector };
    let (copp_responder, _) = RustyCoppListenerIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cosp_listener).await.map_err(to_mms_error(""))?;

    let (mut acse_listener, acse_request_info) = RustyOsiSingleValueAcseListenerIsoStack::<TcpTpktReader, TcpTpktWriter>::new(copp_responder).await.map_err(to_mms_error(""))?;
    acse_listener.set_response(Some(AcseResponseInformation {
        application_context_name: Oid::from(&[1, 0, 9506, 2, 3]).map_err(to_mms_error(""))?,
        associate_result: AssociateResult::Accepted,
        associate_source_diagnostic: AssociateSourceDiagnostic::User(AssociateSourceDiagnosticUserCategory::Null),
        responding_ap_title: acse_request_info.called_ap_title,
        responding_ae_qualifier: acse_request_info.called_ae_qualifier,
        responding_ap_invocation_identifier: acse_request_info.called_ap_invocation_identifier,
        responding_ae_invocation_identifier: acse_request_info.called_ae_invocation_identifier,
        implementation_information: None,
    }));

    let mms_listener = RustyMmsListenerIsoStack::<TcpTpktReader, TcpTpktWriter>::new(acse_listener).await.map_err(to_mms_error(""))?;
    let mms_responder = mms_listener.responder().await.map_err(to_mms_error(""))?;
    let mms_connection = mms_responder.accept().await.map_err(to_mms_error(""))?;

    let (mms_reader, mms_writer) = mms_connection.split().await.map_err(to_mms_error(""))?;

    Ok(Box::new(RustyTcpMmsServiceServer { reader: Arc::new(Mutex::new(mms_reader)), writer: Arc::new(Mutex::new(mms_writer)) }))
}

#[async_trait]
pub trait MmsInitiatorService: Send + Sync + DynClone {
    async fn identify(&mut self) -> Result<Identity, MmsServiceError>;

    async fn get_name_list(&mut self, object_class: MmsObjectClass, object_scope: MmsObjectScope, continue_after: Option<String>) -> Result<NameList, MmsServiceError>;
    async fn get_variable_access_attributes(&mut self, object_name: MmsObjectName) -> Result<VariableAccessAttributes, MmsServiceError>;

    async fn define_named_variable_list(&mut self, variable_list_name: MmsObjectName, list_of_variables: Vec<ListOfVariablesItem>) -> Result<(), MmsServiceError>;
    async fn get_named_variable_list_attributes(&mut self, variable_list_name: MmsObjectName) -> Result<NamedVariableListAttributes, MmsServiceError>;
    async fn delete_named_variable_list(&mut self, scope_of_delete: MmsServiceDeleteObjectScope) -> Result<(i32 /* Number Matched */, i32 /* Number Deleted */), MmsServiceError>;

    /// Reads data from an MMS Server.
    ///
    /// This does not expose the specification with result flag. If this is required, cut a ticket and I will add a read_with_specification method.
    async fn read(&mut self, specification: MmsVariableAccessSpecification) -> Result<Vec<MmsServiceAccessResult>, MmsServiceError>;
    async fn write(&mut self, specification: MmsVariableAccessSpecification, values: Vec<MmsServiceData>) -> Result<Vec<MmsWriteResult>, MmsServiceError>;

    async fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsServiceAccessResult>) -> Result<(), MmsServiceError>;
    async fn receive_information_report(&mut self) -> Result<InformationReportMmsServiceMessage, MmsServiceError>;
}

dyn_clone::clone_trait_object!(MmsInitiatorService);

#[async_trait]
pub trait MmsResponderService: Send + Sync + DynClone {
    async fn receive_message(&mut self) -> Result<MmsServiceMessage, MmsServiceError>;
    async fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsServiceAccessResult>) -> Result<(), MmsServiceError>;
}

dyn_clone::clone_trait_object!(MmsResponderService);

#[derive(Clone)]
pub struct RustyMmsResponderService {
    sender_queue: mpsc::UnboundedSender<MmsMessage>,
    receiver_queue: Arc<Mutex<mpsc::UnboundedReceiver<MmsServiceMessage>>>,
}

impl RustyMmsResponderService {
    pub(crate) fn new(sender_queue: mpsc::UnboundedSender<MmsMessage>, receiver_queue: mpsc::UnboundedReceiver<MmsServiceMessage>) -> Self {
        Self { sender_queue, receiver_queue: Arc::new(Mutex::new(receiver_queue)) }
    }
}

#[async_trait]
impl MmsResponderService for RustyMmsResponderService {
    async fn receive_message(&mut self) -> Result<MmsServiceMessage, MmsServiceError> {
        match self.receiver_queue.lock().await.recv().await {
            Some(x) => Ok(x),
            None => Err(MmsServiceError::ProtocolError("Connection closed while waiting for packet.".into())),
        }
    }

    async fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsServiceAccessResult>) -> Result<(), MmsServiceError> {
        let access_results = access_results
            .into_iter()
            .map(|x| match x {
                MmsServiceAccessResult::Success(mms_data) => Ok(MmsAccessResult::Success(convert_high_level_data_to_low_level_data(&mms_data)?)),
                MmsServiceAccessResult::Failure(mms_access_error) => Ok(MmsAccessResult::Failure(mms_access_error)),
            })
            .collect::<Result<Vec<MmsAccessResult>, MmsServiceError>>()?;
        self.sender_queue.send(MmsMessage::Unconfirmed { unconfirmed_service: rusty_mms::MmsUnconfirmedService::InformationReport { variable_access_specification, access_results } }).map_err(to_mms_error("Failed to send message."))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::data::{
        MmsServiceAccessResult, MmsServiceData, MmsServiceDataFloat, MmsServiceDeleteObjectScope, MmsServiceTypeDescription, MmsServiceTypeDescriptionComponent, MmsServiceTypeSpecification, NameList, NamedVariableListAttributes,
        VariableAccessAttributes,
    };
    use crate::error::to_mms_error;
    use crate::{create_mms_service_client, create_mms_service_server};
    use std::
        time::Duration
    ;

    use anyhow::anyhow;
    use der_parser::Oid;
    use num_bigint::{BigInt, BigUint};
    use rand::random_range;
    use rusty_mms::{ListOfVariablesItem, MmsAccessError, MmsBasicObjectClass, MmsObjectClass, MmsObjectName, MmsObjectScope, MmsVariableAccessSpecification, MmsWriteResult, VariableSpecification};
    use tokio::join;
    use tracing_test::traced_test;

    use crate::{Identity, MmsServiceConnectionParameters, error::MmsServiceError, message::MmsServiceMessage};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_a_large_number_of_operations() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{port}").parse().map_err(to_mms_error("Test Failed"))?;


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

        let mut client1 = client.clone();
        let client_task1 = tokio::task::spawn(async move {
            for _ in 1..10000 {
                client1.identify().await?;
            }
            Ok::<(), MmsServiceError>(())
        });
        let mut client2 = client.clone();
        let client_task2 = tokio::task::spawn(async move {
            for _ in 1..10000 {
                client2.identify().await?;
            }
            Ok::<(), MmsServiceError>(())
        });
        let mut client3 = client.clone();
        let client_task3 = tokio::task::spawn(async move {
            for _ in 1..10000 {
                client3.identify().await?;
            }
            Ok::<(), MmsServiceError>(())
        });
        let mut client4 = client.clone();
        let client_task4 = tokio::task::spawn(async move {
            for _ in 1..10000 {
                client4.identify().await?;
            }
            Ok::<(), MmsServiceError>(())
        });
        let mut client5 = client.clone();
        let client_task5 = tokio::task::spawn(async move {
            for _ in 1..10000 {
                client5.identify().await?;
            }
            Ok::<(), MmsServiceError>(())
        });

        let mut server1 = server.clone();
        let server_task1 = tokio::task::spawn(async move {
            for _ in 1..10000 {
                let value = match server1.receive_message().await {
                    Ok(x) => x,
                    Err(_) => {
                        break;
                    }
                };
                if let MmsServiceMessage::Identify(message) = value {
                    message.respond(Identity { vendor_name: "Yo".into(), model_name: "There".into(), revision: "Fool".into(), abstract_syntaxes: None }).await.expect("")
                }
            }
        });
        let mut server2 = server.clone();
        let server_task2 = tokio::task::spawn(async move {
            for _ in 1..10000 {
                let value = match server2.receive_message().await {
                    Ok(x) => x,
                    Err(_) => {
                        break;
                    }
                };
                if let MmsServiceMessage::Identify(message) = value {
                    message.respond(Identity { vendor_name: "Yo".into(), model_name: "There".into(), revision: "Fool".into(), abstract_syntaxes: None }).await.expect("")
                }
            }
        });
        let mut server3 = server.clone();
        let server_task3 = tokio::task::spawn(async move {
            for _ in 1..10000 {
                let value = match server3.receive_message().await {
                    Ok(x) => x,
                    Err(_) => {
                        break;
                    }
                };
                if let MmsServiceMessage::Identify(message) = value {
                    message.respond(Identity { vendor_name: "Yo".into(), model_name: "There".into(), revision: "Fool".into(), abstract_syntaxes: None }).await.expect("")
                }
            }
        });
        let mut server4 = server.clone();
        let server_task4 = tokio::task::spawn(async move {
            for _ in 1..10000 {
                let value = match server4.receive_message().await {
                    Ok(x) => x,
                    Err(_) => {
                        break;
                    }
                };
                if let MmsServiceMessage::Identify(message) = value {
                    message.respond(Identity { vendor_name: "Yo".into(), model_name: "There".into(), revision: "Fool".into(), abstract_syntaxes: None }).await.expect("")
                }
            }
        });
        let mut server5 = server.clone();
        let server_task5 = tokio::task::spawn(async move {
            for _ in 1..10000 {
                let value = match server5.receive_message().await {
                    Ok(x) => x,
                    Err(_) => {
                        break;
                    }
                };
                if let MmsServiceMessage::Identify(message) = value {
                    message.respond(Identity { vendor_name: "Yo".into(), model_name: "There".into(), revision: "Fool".into(), abstract_syntaxes: None }).await.expect("")
                }
            }
        });
        drop(server);

        let (client_task_result1, client_task_result2, client_task_result3, client_task_result4, client_task_result5, server_task_result1, server_task_result2, server_task_result3, server_task_result4, server_task_result5) =
            join!(client_task1, client_task2, client_task3, client_task4, client_task5, server_task1, server_task2, server_task3, server_task4, server_task5);
        client_task_result1??;
        client_task_result2??;
        client_task_result3??;
        client_task_result4??;
        client_task_result5??;
        server_task_result1?;
        server_task_result2?;
        server_task_result3?;
        server_task_result4?;
        server_task_result5?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_identify_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                create_mms_service_client(address, MmsServiceConnectionParameters::default()).await
            },
            async { create_mms_service_server(address, MmsServiceConnectionParameters::default()).await }
        );

        let client = client_results?;
        let mut server = server_results?;

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move { task_client.identify().await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::Identify(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        request.respond(Identity { vendor_name: "Yo".into(), model_name: "There".into(), revision: "Fool".into(), abstract_syntaxes: None }).await.expect("Test Failed");
        assert_eq!(client_task.await??, Identity { vendor_name: "Yo".into(), model_name: "There".into(), revision: "Fool".into(), abstract_syntaxes: None });

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move { task_client.identify().await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::Identify(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        request.respond(Identity { vendor_name: "This".into(), model_name: "Is".into(), revision: "Another".into(), abstract_syntaxes: Some(vec![Oid::from(&[1, 2, 3, 4])?, Oid::from(&[4, 3, 2, 1])?]) }).await.expect("Test Failed");
        assert_eq!(client_task.await??, Identity { vendor_name: "This".into(), model_name: "Is".into(), revision: "Another".into(), abstract_syntaxes: Some(vec![Oid::from(&[1, 2, 3, 4])?, Oid::from(&[4, 3, 2, 1])?]) });

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_get_name_list_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..20001);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                create_mms_service_client(address, MmsServiceConnectionParameters::default()).await
            },
            async { create_mms_service_server(address, MmsServiceConnectionParameters::default()).await }
        );

        let mut client = client_results?;
        let mut server = server_results?;

        let client_task = tokio::task::spawn(async move { client.get_name_list(MmsObjectClass::Basic(MmsBasicObjectClass::Domain), MmsObjectScope::Vmd, Some("Some Thing".into())).await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::GetNameList(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.object_class(), &MmsObjectClass::Basic(MmsBasicObjectClass::Domain));
        assert_eq!(request.object_scope(), &MmsObjectScope::Vmd);
        assert_eq!(request.continue_after(), &Some("Some Thing".into()));
        request.respond(vec!["Domain1".into(), "Domain2".into()], true).await?;

        assert_eq!(client_task.await??, NameList { identifiers: vec!["Domain1".into(), "Domain2".into()], more_follows: true });

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_get_attribute_list_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                create_mms_service_client(address, MmsServiceConnectionParameters::default()).await
            },
            async { create_mms_service_server(address, MmsServiceConnectionParameters::default()).await }
        );

        let client = client_results?;
        let mut server = server_results?;

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move { task_client.get_variable_access_attributes(MmsObjectName::AaSpecific("Mine".into())).await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::GetVariableAccessAttributes(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.object_name(), &MmsObjectName::AaSpecific("Mine".into()));
        request.respond(true, MmsServiceTypeDescription::Boolean).await?;
        assert_eq!(client_task.await??, VariableAccessAttributes { deletable: true, type_description: MmsServiceTypeDescription::Boolean });

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move { task_client.get_variable_access_attributes(MmsObjectName::AaSpecific("Mine".into())).await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::GetVariableAccessAttributes(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.object_name(), &MmsObjectName::AaSpecific("Mine".into()));
        request.respond(false, MmsServiceTypeDescription::FloatingPoint { format_width: 32, exponent_width: 8 }).await?;
        assert_eq!(client_task.await??, VariableAccessAttributes { deletable: false, type_description: MmsServiceTypeDescription::FloatingPoint { format_width: 32, exponent_width: 8 } });

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move { task_client.get_variable_access_attributes(MmsObjectName::VmdSpecific("SomeVar".into())).await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::GetVariableAccessAttributes(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.object_name(), &MmsObjectName::VmdSpecific("SomeVar".into()));
        request
            .respond(
                true,
                MmsServiceTypeDescription::Structure {
                    packed: false,
                    components: vec![
                        MmsServiceTypeDescriptionComponent { component_name: Some("This One".into()), component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::Boolean) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::Integer(10)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::BitString(127)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::Unsigned(128)) },
                        MmsServiceTypeDescriptionComponent {
                            component_name: None,
                            component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::FloatingPoint { format_width: 32, exponent_width: 8 }),
                        },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::OctetString(255)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::VisibleString(256)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::GeneralizedTime) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::BinaryTime(true)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::BinaryTime(false)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::Bcd(255)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::ObjId) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::MmsString(20)) },
                        MmsServiceTypeDescriptionComponent {
                            component_name: Some("Some Array".into()),
                            component_type: crate::data::MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::Array {
                                packed: true,
                                number_of_elements: 10000,
                                element_type: Box::new(crate::data::MmsServiceTypeSpecification::ObjectName(MmsObjectName::VmdSpecific("An Array Type".into()))),
                            }),
                        },
                    ],
                },
            )
            .await?;
        assert_eq!(
            client_task.await??,
            VariableAccessAttributes {
                deletable: true,
                type_description: MmsServiceTypeDescription::Structure {
                    packed: false,
                    components: vec![
                        MmsServiceTypeDescriptionComponent { component_name: Some("This One".into()), component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::Boolean) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::Integer(10)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::BitString(127)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::Unsigned(128)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::FloatingPoint { format_width: 32, exponent_width: 8 }) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::OctetString(255)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::VisibleString(256)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::GeneralizedTime) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::BinaryTime(true)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::BinaryTime(false)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::Bcd(255)) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::ObjId) },
                        MmsServiceTypeDescriptionComponent { component_name: None, component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::MmsString(20)) },
                        MmsServiceTypeDescriptionComponent {
                            component_name: Some("Some Array".into()),
                            component_type: MmsServiceTypeSpecification::TypeDescription(MmsServiceTypeDescription::Array {
                                packed: true,
                                number_of_elements: 10000,
                                element_type: Box::new(MmsServiceTypeSpecification::ObjectName(MmsObjectName::VmdSpecific("An Array Type".into())))
                            })
                        }
                    ]
                }
            }
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_define_named_variable_list_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                create_mms_service_client(address, MmsServiceConnectionParameters::default()).await
            },
            async { create_mms_service_server(address, MmsServiceConnectionParameters::default()).await }
        );

        let client = client_results?;
        let mut server = server_results?;

        let client_task = tokio::task::spawn(async move {
            client
                .clone()
                .define_named_variable_list(
                    MmsObjectName::AaSpecific("Hello".into()),
                    vec![
                        ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("World".into())) },
                        // Not really suitble for this request, but putting it in anyway.
                        ListOfVariablesItem { variable_specification: VariableSpecification::Invalidated },
                    ],
                )
                .await
        });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::DefineNamedVariableList(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.variable_list_name(), &MmsObjectName::AaSpecific("Hello".into()));
        assert_eq!(
            request.list_of_variables(),
            &vec![
                ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("World".into())) },
                ListOfVariablesItem { variable_specification: VariableSpecification::Invalidated }
            ]
        );
        request.respond().await?;

        assert_eq!(client_task.await??, ());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_get_named_variable_list_attributes_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                create_mms_service_client(address, MmsServiceConnectionParameters::default()).await
            },
            async { create_mms_service_server(address, MmsServiceConnectionParameters::default()).await }
        );

        let client = client_results?;
        let mut server = server_results?;

        let client_task = tokio::task::spawn(async move { client.clone().get_named_variable_list_attributes(MmsObjectName::VmdSpecific("AList".into())).await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::GetNamedVariableListAttributes(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.variable_list_name(), &MmsObjectName::VmdSpecific("AList".into()));
        request
            .respond(
                true,
                vec![
                    ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("World".into())) },
                    ListOfVariablesItem { variable_specification: VariableSpecification::Invalidated },
                ],
            )
            .await?;

        assert_eq!(
            client_task.await??,
            NamedVariableListAttributes {
                deletable: true,
                list_of_variables: vec![
                    ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("World".into())) },
                    ListOfVariablesItem { variable_specification: VariableSpecification::Invalidated },
                ]
            }
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_delete_named_variable_list_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                create_mms_service_client(address, MmsServiceConnectionParameters::default()).await
            },
            async { create_mms_service_server(address, MmsServiceConnectionParameters::default()).await }
        );

        let client = client_results?;
        let mut server = server_results?;

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move { task_client.delete_named_variable_list(crate::data::MmsServiceDeleteObjectScope::Vmd).await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::DeleteNamedVariableList(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.scope_of_delete(), &MmsServiceDeleteObjectScope::Vmd);
        request.respond(2, 1).await?;
        assert_eq!(client_task.await??, (2, 1));

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move { task_client.delete_named_variable_list(crate::data::MmsServiceDeleteObjectScope::Domain("TheEntireDomain".into())).await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::DeleteNamedVariableList(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.scope_of_delete(), &MmsServiceDeleteObjectScope::Domain("TheEntireDomain".into()));
        request.respond(10, 3).await?;
        assert_eq!(client_task.await??, (10, 3));

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move { task_client.delete_named_variable_list(crate::data::MmsServiceDeleteObjectScope::AaSpecific).await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::DeleteNamedVariableList(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.scope_of_delete(), &MmsServiceDeleteObjectScope::AaSpecific);
        request.respond(10, 3).await?;
        assert_eq!(client_task.await??, (10, 3));

        let mut task_client = client.clone();
        let client_task =
            tokio::task::spawn(
                async move { task_client.delete_named_variable_list(crate::data::MmsServiceDeleteObjectScope::Specific(vec![MmsObjectName::AaSpecific("AaOne".into()), MmsObjectName::VmdSpecific("ThisDomain".into())])).await },
            );
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::DeleteNamedVariableList(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.scope_of_delete(), &MmsServiceDeleteObjectScope::Specific(vec![MmsObjectName::AaSpecific("AaOne".into()), MmsObjectName::VmdSpecific("ThisDomain".into())]));
        request.respond(10, 3).await?;
        assert_eq!(client_task.await??, (10, 3));

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_read_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                create_mms_service_client(address, MmsServiceConnectionParameters::default()).await
            },
            async { create_mms_service_server(address, MmsServiceConnectionParameters::default()).await }
        );

        let client = client_results?;
        let mut server = server_results?;

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move { task_client.read(MmsVariableAccessSpecification::VariableListName(MmsObjectName::AaSpecific("A list of variables to read".into()))).await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::Read(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.specification(), &MmsVariableAccessSpecification::VariableListName(MmsObjectName::AaSpecific("A list of variables to read".into())));
        request
            .respond(vec![
                MmsServiceAccessResult::Success(MmsServiceData::Boolean(true)),
                MmsServiceAccessResult::Success(MmsServiceData::Boolean(false)),
                MmsServiceAccessResult::Success(MmsServiceData::BitString(vec![true, false, true, true, false, false, true, true, true])),
                MmsServiceAccessResult::Success(MmsServiceData::Integer(BigInt::from(-42))),
                MmsServiceAccessResult::Success(MmsServiceData::Unsigned(BigUint::from(42u128))),
                MmsServiceAccessResult::Success(MmsServiceData::FloatingPoint(MmsServiceDataFloat::from_f32(123.0))),
                MmsServiceAccessResult::Failure(MmsAccessError::ObjectAccessDenied),
                MmsServiceAccessResult::Success(MmsServiceData::OctetString(vec![1, 2, 3, 4, 5])),
                MmsServiceAccessResult::Success(MmsServiceData::MmsString("AnMmsString".into())),
                MmsServiceAccessResult::Success(MmsServiceData::VisibleString("Hello".into())),
            ])
            .await?;
        assert_eq!(
            client_task.await??,
            vec![
                MmsServiceAccessResult::Success(MmsServiceData::Boolean(true)),
                MmsServiceAccessResult::Success(MmsServiceData::Boolean(false)),
                MmsServiceAccessResult::Success(MmsServiceData::BitString(vec![true, false, true, true, false, false, true, true, true])),
                MmsServiceAccessResult::Success(MmsServiceData::Integer(BigInt::from(-42))),
                MmsServiceAccessResult::Success(MmsServiceData::Unsigned(BigUint::from(42u128))),
                MmsServiceAccessResult::Success(MmsServiceData::FloatingPoint(MmsServiceDataFloat::from_f32(123.0))),
                MmsServiceAccessResult::Failure(MmsAccessError::ObjectAccessDenied),
                MmsServiceAccessResult::Success(MmsServiceData::OctetString(vec![1, 2, 3, 4, 5])),
                MmsServiceAccessResult::Success(MmsServiceData::MmsString("AnMmsString".into())),
                MmsServiceAccessResult::Success(MmsServiceData::VisibleString("Hello".into())),
            ]
        );

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move {
            task_client
                .read(MmsVariableAccessSpecification::ListOfVariables(vec![
                    ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One1".into())) },
                    ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One2".into())) },
                    ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One3".into())) },
                ]))
                .await
        });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::Read(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(
            request.specification(),
            &MmsVariableAccessSpecification::ListOfVariables(vec![
                ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One1".into())) },
                ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One2".into())) },
                ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One3".into())) },
            ])
        );
        request.respond(vec![MmsServiceAccessResult::Success(MmsServiceData::Boolean(true))]).await?;
        assert_eq!(client_task.await??, vec![MmsServiceAccessResult::Success(MmsServiceData::Boolean(true)),]);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_write_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                create_mms_service_client(address, MmsServiceConnectionParameters::default()).await
            },
            async { create_mms_service_server(address, MmsServiceConnectionParameters::default()).await }
        );

        let client = client_results?;
        let mut server = server_results?;

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move { task_client.write(MmsVariableAccessSpecification::VariableListName(MmsObjectName::AaSpecific("MyVariable".into())), vec![MmsServiceData::Boolean(true)]).await });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::Write(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(request.specification(), &MmsVariableAccessSpecification::VariableListName(MmsObjectName::AaSpecific("MyVariable".into())));
        request.respond(vec![MmsWriteResult::Success]).await?;
        assert_eq!(client_task.await??, vec![MmsWriteResult::Success]);

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move {
            task_client
                .write(
                    MmsVariableAccessSpecification::ListOfVariables(vec![
                        ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One1".into())) },
                        ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One2".into())) },
                        ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One3".into())) },
                    ]),
                    vec![MmsServiceData::Boolean(true), MmsServiceData::Boolean(false), MmsServiceData::Boolean(true)],
                )
                .await
        });
        let request = match server.receive_message().await {
            Ok(MmsServiceMessage::Write(x)) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(
            request.specification(),
            &MmsVariableAccessSpecification::ListOfVariables(vec![
                ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One1".into())) },
                ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One2".into())) },
                ListOfVariablesItem { variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("One3".into())) },
            ])
        );
        request
            .respond(vec![
                MmsWriteResult::Success,
                MmsWriteResult::Failure(MmsAccessError::HardwareFault),
                MmsWriteResult::Failure(MmsAccessError::ObjectAccessUnsupported),
            ])
            .await?;
        assert_eq!(
            client_task.await??,
            vec![
                MmsWriteResult::Success,
                MmsWriteResult::Failure(MmsAccessError::HardwareFault),
                MmsWriteResult::Failure(MmsAccessError::ObjectAccessUnsupported)
            ]
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_info_report_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                create_mms_service_client(address, MmsServiceConnectionParameters::default()).await
            },
            async { create_mms_service_server(address, MmsServiceConnectionParameters::default()).await }
        );

        let mut client = client_results?;
        let mut server = server_results?;

        let mut task_client = client.clone();
        let client_task = tokio::task::spawn(async move {
            task_client.send_information_report(MmsVariableAccessSpecification::VariableListName(MmsObjectName::AaSpecific("MyVariable".into())), vec![MmsServiceAccessResult::Success(MmsServiceData::Boolean(true))]).await
        });
        let message = match server.receive_message().await? {
            MmsServiceMessage::InformationReport(x) => x,
            x => return Err(anyhow!("Test Failed: {:?}", x)),
        };
        assert_eq!(message.access_results, vec![MmsServiceAccessResult::Success(MmsServiceData::Boolean(true))]);
        client_task.await??;

        let mut task_server = server.clone();
        let server_task = tokio::task::spawn(async move {
            task_server.send_information_report(MmsVariableAccessSpecification::VariableListName(MmsObjectName::AaSpecific("MyVariable".into())), vec![MmsServiceAccessResult::Success(MmsServiceData::Boolean(true))]).await
        });
        let message = client.receive_information_report().await?;
        assert_eq!(message.access_results, vec![MmsServiceAccessResult::Success(MmsServiceData::Boolean(true))]);
        server_task.await??;

        Ok(())
    }
}
