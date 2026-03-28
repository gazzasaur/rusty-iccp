use async_trait::async_trait;
use der_parser::Oid;
use num_bigint::BigInt;
use rusty_acse::{
    AcseRequestInformation, AcseResponseInformation, AeQualifier, ApTitle, AssociateResult, AssociateSourceDiagnostic, AssociateSourceDiagnosticUserCategory, RustyOsiSingleValueAcseInitiatorIsoStack, RustyOsiSingleValueAcseListenerIsoStack,
};
use rusty_copp::{CoppConnectionInformation, RustyCoppInitiatorIsoStack, RustyCoppListenerIsoStack};
use rusty_cosp::{CospConnectionInformation, RustyCospInitiatorIsoStack, RustyCospListenerIsoStack};
use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection};
use std::{marker::PhantomData, net::SocketAddr, sync::Arc};
use tokio::sync::{
    Mutex,
    mpsc::{self},
};
use tracing::error;

use rusty_mms::{
    ListOfVariablesItem, MmsAccessResult, MmsConfirmedRequest, MmsConfirmedResponse, MmsConnection, MmsData, MmsError, MmsInitiator, MmsListener, MmsMessage, MmsObjectClass, MmsObjectName, MmsObjectScope, MmsRequestInformation,
    MmsResponder, MmsScope, MmsVariableAccessSpecification, MmsWriteResult, RustyMmsInitiatorIsoStack, RustyMmsListenerIsoStack,
    parameters::{ParameterSupportOption, ServiceSupportOption},
};
use rusty_tpkt::{TcpTpktConnection, TcpTpktServer, TpktConnection, TpktReader, TpktWriter};

use crate::{
    data::{
        Identity, InformationReportMmsServiceMessage, MmsServiceAccessResult, MmsServiceData, MmsServiceDeleteObjectScope, NameList, NamedVariableListAttributes, VariableAccessAttributes, convert_high_level_data_to_low_level_data,
        convert_low_level_data_to_high_level_data, convert_low_level_data_types_to_high_level_data_types,
    },
    datapump::{MmsServiceDataPump, MmsServiceDataPumpReaderType},
    error::{MmsServiceError, to_mms_error},
    message::MmsServiceMessage,
};

pub mod data;
pub mod datapump;
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

pub struct MmsServiceConnectionParameters {
    pub called_tsap_id: Option<Vec<u8>>,
    pub calling_tsap_id: Option<Vec<u8>>,

    pub called_session_selector: Option<Vec<u8>>,
    pub calling_session_selector: Option<Vec<u8>>,

    pub called_presentation_selector: Option<Vec<u8>>,
    pub calling_presentation_selector: Option<Vec<u8>>,

    pub called_ap_title: Option<Oid<'static>>,
    pub called_ae_qualifier: Option<Vec<u8>>,
    pub called_ap_invocation_identifier: Option<Vec<u8>>,
    pub called_ae_invocation_identifier: Option<Vec<u8>>,

    pub calling_ap_title: Option<Oid<'static>>,
    pub calling_ae_qualifier: Option<Vec<u8>>,
    pub calling_ap_invocation_identifier: Option<Vec<u8>>,
    pub calling_ae_invocation_identifier: Option<Vec<u8>>,

    pub proposed_max_serv_outstanding_calling: i16,
    pub proposed_max_serv_outstanding_called: i16,
    pub proposed_data_structure_nesting_level: Option<i8>,
    pub propsed_parameter_cbb: Vec<ParameterSupportOption>,
    pub services_supported_calling: Vec<ServiceSupportOption>,
}

impl Default for MmsServiceConnectionParameters {
    fn default() -> Self {
        Self {
            called_tsap_id: None,
            calling_tsap_id: None,
            called_session_selector: None,
            calling_session_selector: None,
            called_presentation_selector: None,
            calling_presentation_selector: None,
            called_ap_title: None,
            called_ae_qualifier: None,
            called_ap_invocation_identifier: None,
            called_ae_invocation_identifier: None,
            calling_ap_title: None,
            calling_ae_qualifier: None,
            calling_ap_invocation_identifier: None,
            calling_ae_invocation_identifier: None,
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

pub struct RustyMmsServiceFactory<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> {
    data_pump: Arc<MmsServiceDataPump>,
    _tpkt_connection: PhantomData<T>,
    _tpkt_reader: PhantomData<R>,
    _tpkt_writer: PhantomData<W>,
}

impl<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> RustyMmsServiceFactory<T, R, W> {
    pub fn new(data_pump: Arc<MmsServiceDataPump>) -> RustyMmsServiceFactory<T, R, W> {
        RustyMmsServiceFactory { data_pump, _tpkt_connection: PhantomData, _tpkt_reader: PhantomData, _tpkt_writer: PhantomData }
    }

    pub async fn create_client_connection(&mut self, tpkt_connection_factory: &mut impl TpktClientConnectionFactory<T, R, W>, parameters: MmsServiceConnectionParameters) -> Result<RustyMmsInitiatorService, MmsServiceError> {
        let tpkt_connection = tpkt_connection_factory.create_connection().await?;

        let cotp_connection_info = CotpConnectInformation { called_tsap_id: parameters.called_tsap_id, calling_tsap_id: parameters.calling_tsap_id, ..Default::default() };
        let cotp_connection = TcpCotpConnection::<R, W>::initiate(tpkt_connection, cotp_connection_info).await.map_err(to_mms_error("Failed to create COTP Connection"))?;

        let cosp_connection_info = CospConnectionInformation { called_session_selector: parameters.called_session_selector, calling_session_selector: parameters.calling_session_selector, ..Default::default() };
        let cosp_initiator = RustyCospInitiatorIsoStack::<R, W>::new(cotp_connection, cosp_connection_info).await.map_err(to_mms_error("Failed to create COSP Connection"))?;

        let copp_connection_info = CoppConnectionInformation { called_presentation_selector: parameters.called_presentation_selector, calling_presentation_selector: parameters.calling_presentation_selector };
        let copp_initiator = RustyCoppInitiatorIsoStack::<R, W>::new(cosp_initiator, copp_connection_info);

        let acse_connection_info = AcseRequestInformation {
            application_context_name: Oid::from(&[1, 0, 9506, 2, 3]).map_err(to_mms_error("Failed to create MMS Application Context Name"))?,
            called_ap_title: parameters.called_ap_title.map(|x| ApTitle::Form2(x)),
            called_ae_qualifier: parameters.called_ae_qualifier.map(|x| AeQualifier::Form2(x)),
            called_ap_invocation_identifier: parameters.called_ap_invocation_identifier,
            called_ae_invocation_identifier: parameters.called_ae_invocation_identifier,
            calling_ap_title: parameters.calling_ap_title.map(|x| ApTitle::Form2(x)),
            calling_ae_qualifier: parameters.calling_ae_qualifier.map(|x| AeQualifier::Form2(x)),
            calling_ap_invocation_identifier: parameters.calling_ap_invocation_identifier,
            calling_ae_invocation_identifier: parameters.calling_ae_invocation_identifier,
            ..Default::default()
        };
        let acse_initiator = RustyOsiSingleValueAcseInitiatorIsoStack::<R, W>::new(copp_initiator, acse_connection_info);

        let mms_connection_info = MmsRequestInformation {
            proposed_max_serv_outstanding_calling: parameters.proposed_max_serv_outstanding_calling,
            proposed_max_serv_outstanding_called: parameters.proposed_max_serv_outstanding_called,
            proposed_data_structure_nesting_level: parameters.proposed_data_structure_nesting_level,
            proposed_version_number: 1,
            propsed_parameter_cbb: parameters.propsed_parameter_cbb,
            services_supported_calling: parameters.services_supported_calling,
            ..Default::default()
        };
        let mms_initiator = RustyMmsInitiatorIsoStack::<R, W>::new(acse_initiator, mms_connection_info);
        let mms_connection = mms_initiator.initiate().await?;
        let (mms_reader, mms_writer) = mms_connection.split().await?;
        let (sender, receiver) = self.data_pump.register_initiator(mms_reader, mms_writer).await;

        Ok(RustyMmsInitiatorService::new(sender, receiver))
    }

    pub async fn create_server_connection(&mut self, tpkt_connection_factory: &mut impl TpktServerConnectionFactory<T, R, W>, parameters: MmsServiceConnectionParameters) -> Result<RustyMmsResponderService, MmsServiceError> {
        let tpkt_connection = tpkt_connection_factory.create_connection().await?;

        let cotp_connection_info = CotpAcceptInformation { ..Default::default() };
        let (cotp_listener, _) = TcpCotpAcceptor::<R, W>::new(tpkt_connection).await.map_err(to_mms_error("Failed to create COTP Server"))?;
        let cotp_connection = cotp_listener.accept(cotp_connection_info).await.map_err(to_mms_error(""))?;

        let (cosp_listener, _) = RustyCospListenerIsoStack::<R, W>::new(cotp_connection).await.map_err(to_mms_error("Failed to create COSP Connection"))?;

        // TODO: Need to expose this.
        let _copp_connection_info = CoppConnectionInformation { called_presentation_selector: parameters.called_presentation_selector, calling_presentation_selector: parameters.calling_presentation_selector };
        let (copp_responder, _) = RustyCoppListenerIsoStack::<R, W>::new(cosp_listener).await.map_err(to_mms_error(""))?;

        let (mut acse_listener, acse_request_info) = RustyOsiSingleValueAcseListenerIsoStack::<R, W>::new(copp_responder).await.map_err(to_mms_error(""))?;
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

        let mms_listener = RustyMmsListenerIsoStack::<R, W>::new(acse_listener).await.map_err(to_mms_error(""))?;
        let mms_responder = mms_listener.responder().await.map_err(to_mms_error(""))?;
        let mms_connection = mms_responder.accept().await.map_err(to_mms_error(""))?;

        let (mms_reader, mms_writer) = mms_connection.split().await.map_err(to_mms_error(""))?;
        let (sender, receiver) = self.data_pump.register_responder(mms_reader, mms_writer).await;

        Ok(RustyMmsResponderService::new(sender, receiver))
    }
}

#[async_trait]
pub trait MmsInitiatorService: Send + Sync {
    async fn identify(&mut self) -> Result<Identity, MmsServiceError>;

    async fn get_name_list(&mut self, object_class: MmsObjectClass, object_scope: MmsObjectScope, continue_after: Option<String>) -> Result<NameList, MmsServiceError>;
    async fn get_variable_access_attributes(&mut self, object_name: MmsObjectName) -> Result<VariableAccessAttributes, MmsServiceError>;

    async fn define_named_variable_list(&mut self, variable_list_name: MmsObjectName, list_of_variables: Vec<ListOfVariablesItem>) -> Result<(), MmsServiceError>;
    async fn get_named_variable_list_attributes(&mut self, variable_list_name: MmsObjectName) -> Result<NamedVariableListAttributes, MmsServiceError>;
    async fn delete_named_variable_list(&mut self, scope_of_delete: MmsServiceDeleteObjectScope) -> Result<(i32 /* Number Matched */, i32 /* Number Deleted */), MmsServiceError>;

    async fn read(&mut self, specification: MmsVariableAccessSpecification) -> Result<Vec<MmsServiceAccessResult>, MmsServiceError>;
    async fn write(&mut self, specification: MmsVariableAccessSpecification, values: Vec<MmsServiceData>) -> Result<Vec<MmsWriteResult>, MmsServiceError>;

    async fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsServiceAccessResult>) -> Result<(), MmsServiceError>;
    async fn receive_information_report(&mut self) -> Result<InformationReportMmsServiceMessage, MmsServiceError>;
}

#[async_trait]
pub trait MmsResponderService: Send + Sync {
    async fn receive_message(&mut self) -> Result<MmsServiceMessage, MmsServiceError>;
    async fn send_information_report(&mut self, variable_access_specification: MmsVariableAccessSpecification, access_results: Vec<MmsServiceAccessResult>) -> Result<(), MmsServiceError>;
}

#[derive(Clone)]
pub struct RustyMmsInitiatorService {
    sender_queue: mpsc::UnboundedSender<MmsServiceDataPumpReaderType>,
    receiver_queue: Arc<Mutex<mpsc::UnboundedReceiver<Result<MmsMessage, MmsError>>>>,
}

impl RustyMmsInitiatorService {
    pub(crate) fn new(sender_queue: mpsc::UnboundedSender<MmsServiceDataPumpReaderType>, receiver_queue: mpsc::UnboundedReceiver<Result<MmsMessage, MmsError>>) -> Self {
        Self { sender_queue, receiver_queue: Arc::new(Mutex::new(receiver_queue)) }
    }
}

#[async_trait]
impl MmsInitiatorService for RustyMmsInitiatorService {
    async fn identify(&mut self) -> Result<Identity, MmsServiceError> {
        let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
        let dpt = MmsServiceDataPumpReaderType::Confirmed(MmsConfirmedRequest::Identify, packet_sender);
        self.sender_queue.send(dpt).map_err(to_mms_error("Failed to queue MMS request."))?;
        let response = packet_receiver.recv().await;
        match response {
            Some(Ok(MmsConfirmedResponse::Identify { vendor_name, model_name, revision, abstract_syntaxes })) => Ok(Identity { vendor_name, model_name, revision, abstract_syntaxes }),
            Some(Ok(_)) => Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
            None => Err(MmsServiceError::ProtocolError("Connection Closed".into())),
            Some(Err(e)) => Err(e),
        }
    }

    async fn get_name_list(&mut self, object_class: MmsObjectClass, object_scope: MmsObjectScope, continue_after: Option<String>) -> Result<NameList, MmsServiceError> {
        let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
        let dpt = MmsServiceDataPumpReaderType::Confirmed(MmsConfirmedRequest::GetNameList { object_class, object_scope, continue_after }, packet_sender);
        self.sender_queue.send(dpt).map_err(to_mms_error("Failed to queue MMS request."))?;
        let response = packet_receiver.recv().await;
        match response {
            Some(Ok(MmsConfirmedResponse::GetNameList { list_of_identifiers, more_follows })) => Ok(NameList { identifiers: list_of_identifiers, more_follows: more_follows.unwrap_or(true) }),
            Some(Ok(_)) => Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
            None => Err(MmsServiceError::ProtocolError("Connection Closed".into())),
            Some(Err(e)) => Err(e),
        }
    }

    async fn get_variable_access_attributes(&mut self, object_name: MmsObjectName) -> Result<VariableAccessAttributes, MmsServiceError> {
        let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
        let dpt = MmsServiceDataPumpReaderType::Confirmed(MmsConfirmedRequest::GetVariableAccessAttributes { object_name }, packet_sender);
        self.sender_queue.send(dpt).map_err(to_mms_error("Failed to queue MMS request."))?;
        let response = packet_receiver.recv().await;
        match response {
            Some(Ok(MmsConfirmedResponse::GetVariableAccessAttributes { deletable, type_description })) => {
                Ok(VariableAccessAttributes { deletable, type_description: convert_low_level_data_types_to_high_level_data_types(&type_description)? })
            }
            Some(Ok(_)) => Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
            None => Err(MmsServiceError::ProtocolError("Connection Closed".into())),
            Some(Err(e)) => Err(e),
        }
    }

    async fn define_named_variable_list(&mut self, variable_list_name: MmsObjectName, list_of_variables: Vec<ListOfVariablesItem>) -> Result<(), MmsServiceError> {
        let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
        let dpt = MmsServiceDataPumpReaderType::Confirmed(MmsConfirmedRequest::DefineNamedVariableList { variable_list_name, list_of_variables }, packet_sender);
        self.sender_queue.send(dpt).map_err(to_mms_error("Failed to queue MMS request."))?;
        let response = packet_receiver.recv().await;
        match response {
            Some(Ok(MmsConfirmedResponse::DefineNamedVariableList {})) => Ok(()),
            Some(Ok(_)) => Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
            None => Err(MmsServiceError::ProtocolError("Connection Closed".into())),
            Some(Err(e)) => Err(e),
        }
    }

    async fn get_named_variable_list_attributes(&mut self, variable_list_name: MmsObjectName) -> Result<NamedVariableListAttributes, MmsServiceError> {
        let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
        let dpt = MmsServiceDataPumpReaderType::Confirmed(MmsConfirmedRequest::GetNamedVariableListAttributes { object_name: variable_list_name }, packet_sender);
        self.sender_queue.send(dpt).map_err(to_mms_error("Failed to queue MMS request."))?;
        let response = packet_receiver.recv().await;
        match response {
            Some(Ok(MmsConfirmedResponse::GetNamedVariableListAttributes { deletable, list_of_variables })) => Ok(NamedVariableListAttributes { deletable, list_of_variables }),
            Some(Ok(_)) => Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
            None => Err(MmsServiceError::ProtocolError("Connection Closed".into())),
            Some(Err(e)) => Err(e),
        }
    }

    async fn delete_named_variable_list(&mut self, scope_of_delete: MmsServiceDeleteObjectScope) -> Result<(i32, i32), MmsServiceError> {
        let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
        let dpt = MmsServiceDataPumpReaderType::Confirmed(
            match scope_of_delete {
                MmsServiceDeleteObjectScope::Specific(mms_object_names) => MmsConfirmedRequest::DeleteNamedVariableList { scope_of_delete: Some(MmsScope::Specific), list_of_variable_list_names: Some(mms_object_names), domain_name: None },
                MmsServiceDeleteObjectScope::AaSpecific => MmsConfirmedRequest::DeleteNamedVariableList { scope_of_delete: Some(MmsScope::AaSpecific), list_of_variable_list_names: None, domain_name: None },
                MmsServiceDeleteObjectScope::Domain(domain_name) => MmsConfirmedRequest::DeleteNamedVariableList { scope_of_delete: Some(MmsScope::Domain), list_of_variable_list_names: None, domain_name: Some(domain_name) },
                MmsServiceDeleteObjectScope::Vmd => MmsConfirmedRequest::DeleteNamedVariableList { scope_of_delete: Some(MmsScope::Vmd), list_of_variable_list_names: None, domain_name: None },
            },
            packet_sender,
        );
        self.sender_queue.send(dpt).map_err(to_mms_error("Failed to queue MMS request."))?;
        let response = packet_receiver.recv().await;
        match response {
            Some(Ok(MmsConfirmedResponse::DeleteNamedVariableList { number_matched, number_deleted })) => {
                Ok((BigInt::from_signed_bytes_be(&number_matched).try_into().map_err(to_mms_error(""))?, BigInt::from_signed_bytes_be(&number_deleted).try_into().map_err(to_mms_error(""))?))
            }
            Some(Ok(_)) => Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
            None => Err(MmsServiceError::ProtocolError("Connection Closed".into())),
            Some(Err(e)) => Err(e),
        }
    }

    async fn read(&mut self, specification: MmsVariableAccessSpecification) -> Result<Vec<MmsServiceAccessResult>, MmsServiceError> {
        let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
        let dpt = MmsServiceDataPumpReaderType::Confirmed(MmsConfirmedRequest::Read { specification_with_result: Some(false), variable_access_specification: specification }, packet_sender);
        self.sender_queue.send(dpt).map_err(to_mms_error("Failed to queue MMS request."))?;
        let response = packet_receiver.recv().await;
        match response {
            Some(Ok(MmsConfirmedResponse::Read { variable_access_specification: _, access_results })) => Ok(access_results
                .into_iter()
                .map(|x| match x {
                    MmsAccessResult::Success(mms_data) => Ok(MmsServiceAccessResult::Success(convert_low_level_data_to_high_level_data(&mms_data)?)),
                    MmsAccessResult::Failure(mms_access_error) => Ok(MmsServiceAccessResult::Failure(mms_access_error)),
                })
                .collect::<Result<Vec<MmsServiceAccessResult>, MmsServiceError>>()?),
            Some(Ok(_)) => Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
            None => Err(MmsServiceError::ProtocolError("Connection Closed".into())),
            Some(Err(e)) => Err(e),
        }
    }

    async fn write(&mut self, specification: MmsVariableAccessSpecification, values: Vec<MmsServiceData>) -> Result<Vec<MmsWriteResult>, MmsServiceError> {
        let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
        let dpt = MmsServiceDataPumpReaderType::Confirmed(
            MmsConfirmedRequest::Write { variable_access_specification: specification, list_of_data: values.iter().map(|x| convert_high_level_data_to_low_level_data(x)).collect::<Result<Vec<MmsData>, MmsError>>()? },
            packet_sender,
        );
        self.sender_queue.send(dpt).map_err(to_mms_error("Failed to queue MMS request."))?;
        let response = packet_receiver.recv().await;
        match response {
            Some(Ok(MmsConfirmedResponse::Write { write_results })) => Ok(write_results),
            Some(Ok(_)) => Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
            None => Err(MmsServiceError::ProtocolError("Connection Closed".into())),
            Some(Err(e)) => Err(e),
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
        self.sender_queue.send(MmsServiceDataPumpReaderType::Unconfirmed(rusty_mms::MmsUnconfirmedService::InformationReport { variable_access_specification, access_results })).map_err(to_mms_error("Failed to send message."))?;
        Ok(())
    }

    async fn receive_information_report(&mut self) -> Result<InformationReportMmsServiceMessage, MmsServiceError> {
        let value = match self.receiver_queue.lock().await.recv().await {
            Some(Ok(MmsMessage::Unconfirmed { unconfirmed_service })) => unconfirmed_service,
            Some(Ok(x)) => {
                error!("Unexpected Message: {:?}", x);
                return Err(MmsServiceError::ProtocolError("Unexpected Message. The message has been logged.".into()));
            }
            Some(Err(x)) => return Err(MmsServiceError::ProtocolStackError(x)),
            None => return Err(MmsServiceError::ProtocolError("Connection Closed".into())),
        };
        let message = match value {
            rusty_mms::MmsUnconfirmedService::InformationReport { variable_access_specification, access_results } => InformationReportMmsServiceMessage {
                variable_access_specification,
                access_results: access_results
                    .into_iter()
                    .map(|x| match x {
                        MmsAccessResult::Success(mms_data) => Ok(MmsServiceAccessResult::Success(convert_low_level_data_to_high_level_data(&mms_data)?)),
                        MmsAccessResult::Failure(mms_access_error) => Ok(MmsServiceAccessResult::Failure(mms_access_error)),
                    })
                    .collect::<Result<Vec<MmsServiceAccessResult>, MmsServiceError>>()?,
            },
        };
        Ok(message)
    }
}

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
    use crate::MmsResponderService;
    use crate::data::{
        MmsServiceAccessResult, MmsServiceData, MmsServiceDataFloat, MmsServiceDeleteObjectScope, MmsServiceTypeDescription, MmsServiceTypeDescriptionComponent, MmsServiceTypeSpecification, NameList, NamedVariableListAttributes,
        VariableAccessAttributes,
    };
    use crate::error::to_mms_error;
    use crate::{MmsInitiatorService, datapump::process_bindings};
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use anyhow::anyhow;
    use der_parser::Oid;
    use num_bigint::{BigInt, BigUint};
    use rand::random_range;
    use rusty_mms::{ListOfVariablesItem, MmsAccessError, MmsBasicObjectClass, MmsObjectClass, MmsObjectName, MmsObjectScope, MmsVariableAccessSpecification, MmsWriteResult, VariableSpecification};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktWriter};
    use tokio::{join, sync::Mutex};
    use tracing_test::traced_test;

    use crate::{Identity, MmsServiceConnectionParameters, MmsServiceDataPump, RustyMmsServiceFactory, RustyTpktClientConnectionFactory, RustyTpktServerConnectionFactory, error::MmsServiceError, message::MmsServiceMessage};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_a_large_number_of_operations() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = RustyTpktClientConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new(address);
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_client_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
        );

        let mut client = client_results?;
        let mut server = server_results?;

        let client_task = tokio::task::spawn(async move {
            for _ in 1..10000 {
                client.identify().await?;
            }
            Ok::<(), MmsServiceError>(())
        });
        let server_task = tokio::task::spawn(async move {
            for _ in 1..10000 {
                let value = match server.receive_message().await {
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

        let (client_task_result, server_task_result) = join!(client_task, server_task);
        client_task_result??;
        server_task_result?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_identify_operation() -> Result<(), anyhow::Error> {
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = RustyTpktClientConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new(address);
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_client_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
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
        let port: u16 = random_range(20000..30000);
        let address = format!("127.0.0.1:{}", port).parse().map_err(to_mms_error("Test Failed"))?;

        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = RustyTpktClientConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new(address);
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_client_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
        );

        let client = client_results?;
        let mut server = server_results?;

        let client_task = tokio::task::spawn(async move { client.clone().get_name_list(MmsObjectClass::Basic(MmsBasicObjectClass::Domain), MmsObjectScope::Vmd, Some("Some Thing".into())).await });
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

        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = RustyTpktClientConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new(address);
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_client_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
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

        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = RustyTpktClientConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new(address);
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_client_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
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

        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = RustyTpktClientConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new(address);
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_client_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
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

        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = RustyTpktClientConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new(address);
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_client_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
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

        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = RustyTpktClientConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new(address);
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_client_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
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

        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = RustyTpktClientConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new(address);
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_client_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
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

        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                // Allow the server to start listening first.
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = RustyTpktClientConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new(address);
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_client_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = RustyTpktServerConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::listen(address).await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
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
