use async_trait::async_trait;
use der_parser::Oid;
use futures::{StreamExt, stream::FuturesUnordered};
use num_bigint::ToBigInt;
use rusty_acse::{
    AcseRequestInformation, AcseResponseInformation, AeQualifier, ApTitle, AssociateResult, AssociateSourceDiagnostic, AssociateSourceDiagnosticUserCategory, RustyOsiSingleValueAcseInitiatorIsoStack, RustyOsiSingleValueAcseListenerIsoStack,
};
use rusty_copp::{CoppConnectionInformation, RustyCoppInitiatorIsoStack, RustyCoppListenerIsoStack};
use rusty_cosp::{CospConnectionInformation, RustyCospInitiatorIsoStack, RustyCospListenerIsoStack};
use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection};
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{
        Mutex,
        mpsc::{self, UnboundedSender},
    },
    time::timeout,
};
use tracing::warn;

use rusty_mms::{
    MmsConfirmedRequest, MmsConfirmedResponse, MmsConnection, MmsData, MmsError, MmsInitiator, MmsListener, MmsMessage, MmsReader, MmsRecvResult, MmsRequestInformation, MmsResponder, MmsUnconfirmedService, MmsWriter,
    RustyMmsInitiatorIsoStack, RustyMmsListenerIsoStack, parameters::{ParameterSupportOption, ServiceSupportOption},
};
use rusty_tpkt::{TcpTpktConnection, TcpTpktServer, TpktConnection, TpktReader, TpktWriter};

use crate::{
    api::{
        DefineNamedVariableListMmsServiceMessage, DeleteNamedVariableListMmsServiceMessage, GetNameListMmsServiceMessage, GetNamedVariableListAttributesMmsServiceMessage, GetVariableAccessAttributesMmsServiceMessage,
        IdentifyMmsServiceMessage, Identity, InformationReportMmsServiceMessage, MmsInitiatorService, MmsServiceData, MmsServiceError, MmsServiceMessage, ReadMmsServiceMessage, WriteMmsServiceMessage,
    },
    error::to_mms_error,
};

pub mod api;
pub(crate) mod error;

fn convert_high_level_data_to_low_level_data(service_data: &MmsServiceData) -> Result<MmsData, MmsError> {
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
        MmsServiceData::Unsigned(big_uint) => Ok(MmsData::Unsigned(
            big_uint.to_bigint().ok_or_else(|| MmsError::InternalError("This is a bug. Please contact the project team.".into()))?.to_signed_bytes_be(),
        )),
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

fn convert_low_level_data_to_high_level_data(service_data: &MmsData) -> Result<MmsServiceData, MmsError> {
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

// Send queue should also hold for max outstanding requests

struct MmsServiceDataPumpBinding {
    reader: Pin<Box<dyn Future<Output = ()> + Send>>,
    queue: mpsc::UnboundedSender<Result<MmsMessage, MmsError>>,
}

pub struct MmsServiceDataPump {
    running: Arc<AtomicBool>,
    bindings: Arc<Mutex<Vec<Pin<Box<dyn Future<Output = ()> + Send>>>>>,
}

pub enum MmsServiceDataPumpReaderType {
    Confirmed(MmsConfirmedRequest, UnboundedSender<Result<MmsConfirmedResponse, MmsServiceError>>),
    Unconfirmed(MmsUnconfirmedService),
}

impl MmsServiceDataPump {
    fn new(running: Arc<AtomicBool>, bindings: Arc<Mutex<Vec<Pin<Box<dyn Future<Output = ()> + Send>>>>>) -> MmsServiceDataPump {
        MmsServiceDataPump { running, bindings }
    }

    pub async fn register_initiator(&self, reader: impl MmsReader + 'static, writer: impl MmsWriter + 'static) -> (mpsc::UnboundedSender<MmsServiceDataPumpReaderType>, mpsc::UnboundedReceiver<Result<MmsMessage, MmsError>>) {
        let (sender, inbound_queue) = mpsc::unbounded_channel();
        let (outbound_queue, receiver) = mpsc::unbounded_channel();
        self.bindings.lock().await.push(Box::pin(process_initiator_binding(reader, writer, inbound_queue, outbound_queue)));
        (sender, receiver)
    }

    pub async fn register_responder(&self, reader: impl MmsReader + 'static, writer: impl MmsWriter + 'static) -> (mpsc::UnboundedSender<MmsMessage>, mpsc::UnboundedReceiver<MmsServiceMessage>) {
        let (sender, inbound_queue) = mpsc::unbounded_channel();
        let (outbound_queue, receiver) = mpsc::unbounded_channel();
        self.bindings.lock().await.push(Box::pin(process_responder_binding(reader, writer, sender.clone(), inbound_queue, outbound_queue)));
        (sender, receiver)
    }
}

async fn write_wait(writer: &mut impl MmsWriter, message: &mut VecDeque<MmsMessage>) -> Result<(), MmsError> {
    writer.send(message).await?;
    tokio::time::sleep(Duration::from_millis(10000)).await;
    Ok(())
}

async fn process_initiator_binding(mut reader: impl MmsReader, mut writer: impl MmsWriter, mut inbound_queue: mpsc::UnboundedReceiver<MmsServiceDataPumpReaderType>, outbound_queue: mpsc::UnboundedSender<Result<MmsMessage, MmsError>>) {
    let mut confirmed_request_counter = 0u32;
    let mut confirmed_requests = HashMap::new();
    let mut buffer = VecDeque::new();
    let mut inactive_timeout = Instant::now() + Duration::from_mins(15);

    loop {
        let reader_messages = reader.recv();

        tokio::pin!(reader_messages);

        tokio::select! {
            _ = write_wait(&mut writer, &mut buffer) => (),
            x = inbound_queue.recv() => {
                match x {
                    Some(MmsServiceDataPumpReaderType::Unconfirmed(message)) => {
                        buffer.push_back(MmsMessage::Unconfirmed { unconfirmed_service: message });
                    },
                    Some(MmsServiceDataPumpReaderType::Confirmed(message_data, return_queue)) => {
                        let reqeust_id = confirmed_request_counter;
                        confirmed_request_counter += 1;

                        if let Some(_) = confirmed_requests.insert(reqeust_id, return_queue) {
                            warn!("Overlapping Requests Detected");
                            break;
                        };

                        buffer.push_back(MmsMessage::ConfirmedRequest { invocation_id: reqeust_id.to_be_bytes().to_vec(), request: message_data });
                    },
                    None => {
                        break;
                    },
                }
            },
            x = &mut reader_messages => {
                match x {
                    Ok(MmsRecvResult::Message(MmsMessage::ConfirmedResponse { invocation_id, response })) => {
                        let b = match invocation_id.as_slice().try_into().map_err(to_mms_error("")) {
                            Ok(x) => x,
                            Err(e) => {
                                warn!("Failed to convert invocation id: {:?}", e);
                                break;
                            },
                        };
                        let request_id = u32::from_be_bytes(b);
                        match confirmed_requests.remove(&request_id) {
                            Some(v) => {
                                v.send(Ok(response));
                            },
                            None => {
                                warn!("Got a reqeust id for a value that was not pending: {:?}", request_id)
                            },
                        }
                    },
                    Ok(MmsRecvResult::Message(MmsMessage::Unconfirmed { unconfirmed_service })) => {
                        outbound_queue.send(Ok(MmsMessage::Unconfirmed { unconfirmed_service }));
                    },
                    Ok(MmsRecvResult::Message(m)) => {
                        warn!("Initiator got an unsupported message: {:?}", m);
                        break;
                    },
                    Ok(MmsRecvResult::Closed) => {
                        warn!("Connection closed");
                        break;
                    },
                    Err(e) => {
                        warn!("Failed to read from buffer: {:?}", e);
                        break;
                    },
                }
            },
            else => {
                break;
            }
        }
    }
}

async fn process_request(request: MmsConfirmedRequest, invocation_id: u32, mut external_outbound_queue: mpsc::UnboundedSender<MmsMessage>) -> Result<MmsServiceMessage, MmsServiceError> {
    match request {
        MmsConfirmedRequest::GetNameList { object_class, object_scope, continue_after } => Ok(MmsServiceMessage::GetNameList(GetNameListMmsServiceMessage::new(
            invocation_id,
            object_class,
            object_scope,
            continue_after,
            external_outbound_queue.clone(),
        ))),
        MmsConfirmedRequest::Identify => Ok(MmsServiceMessage::Identify(IdentifyMmsServiceMessage::new(invocation_id, external_outbound_queue.clone()))),
        MmsConfirmedRequest::Read {
            specification_with_result,
            variable_access_specification,
        } => Ok(MmsServiceMessage::Read(ReadMmsServiceMessage::new(
            invocation_id,
            variable_access_specification,
            specification_with_result,
            external_outbound_queue.clone(),
        ))),
        MmsConfirmedRequest::Write { variable_access_specification, list_of_data } => Ok(MmsServiceMessage::Write(WriteMmsServiceMessage::new(
            invocation_id,
            variable_access_specification,
            list_of_data,
            external_outbound_queue.clone(),
        )?)),
        MmsConfirmedRequest::GetVariableAccessAttributes { object_name } => Ok(MmsServiceMessage::GetVariableAccessAttributes(GetVariableAccessAttributesMmsServiceMessage::new(
            invocation_id,
            object_name,
            external_outbound_queue.clone(),
        ))),
        MmsConfirmedRequest::DefineNamedVariableList { variable_list_name, list_of_variables } => Ok(MmsServiceMessage::DefineNamedVariableList(DefineNamedVariableListMmsServiceMessage::new(
            invocation_id,
            variable_list_name,
            list_of_variables,
            external_outbound_queue.clone(),
        ))),
        MmsConfirmedRequest::GetNamedVariableListAttributes { object_name } => Ok(MmsServiceMessage::GetNamedVariableListAttributes(GetNamedVariableListAttributesMmsServiceMessage::new(
            invocation_id,
            object_name,
            external_outbound_queue.clone(),
        ))),
        MmsConfirmedRequest::DeleteNamedVariableList {
            scope_of_delete,
            list_of_variable_list_names,
            domain_name,
        } => Ok(MmsServiceMessage::DeleteNamedVariableList(DeleteNamedVariableListMmsServiceMessage::new(
            invocation_id,
            scope_of_delete,
            list_of_variable_list_names,
            domain_name,
            external_outbound_queue.clone(),
        ))),
    }
}

async fn process_responder_binding(
    mut reader: impl MmsReader,
    mut writer: impl MmsWriter,
    mut external_outbound_queue: mpsc::UnboundedSender<MmsMessage>,
    mut inbound_queue: mpsc::UnboundedReceiver<MmsMessage>,
    outbound_queue: mpsc::UnboundedSender<MmsServiceMessage>,
) {
    let mut confirmed_request_counter = 0u32;
    let mut buffer = VecDeque::new();
    let mut inactive_timeout = Instant::now() + Duration::from_mins(15);

    let mut write_buffer = false;
    loop {
        let reader_messages = reader.recv();

        tokio::pin!(reader_messages);

        tokio::select! {
            _ = write_wait(&mut writer, &mut buffer) => (),
            x = inbound_queue.recv() => {
                match x {
                    Some(x) => {
                        buffer.push_back(x);
                    },
                    None => {
                        break;
                    },
                }
            },
            x = &mut reader_messages => {
                match x {
                    Ok(MmsRecvResult::Message(MmsMessage::ConfirmedRequest { invocation_id, request })) => {
                        let b = match invocation_id.as_slice().try_into().map_err(to_mms_error("")) {
                            Ok(x) => x,
                            Err(e) => {
                                warn!("Failed to convert invocation id: {:?}", e);
                                break;
                            },
                        };
                        let invocation_id = u32::from_be_bytes(b);
                        let value = match process_request(request, invocation_id, external_outbound_queue.clone()).await {
                            Ok(x) => outbound_queue.send(x),
                            Err(_) => todo!(),
                        };
                    },
                    Ok(MmsRecvResult::Message(MmsMessage::Unconfirmed { unconfirmed_service: MmsUnconfirmedService::InformationReport { variable_access_specification, access_results } })) => {
                        outbound_queue.send(MmsServiceMessage::InformationReport(InformationReportMmsServiceMessage { variable_access_specification, access_results } ));
                    },
                    Ok(MmsRecvResult::Message(m)) => {
                        warn!("Responder got an unsupported message: {:?}", m);
                        break;
                    },
                    Ok(MmsRecvResult::Closed) => {
                        warn!("Connection closed");
                        break;
                    },
                    Err(e) => {
                        warn!("Failed to read from buffer: {:?}", e);
                        break;
                    },
                }
            }
            else => {
                break;
            }
        }

        if write_buffer || !buffer.is_empty() {
            write_buffer = write_buffer || !buffer.is_empty();
            match timeout(Duration::from_nanos(100), writer.send(&mut buffer)).await {
                Ok(Err(e)) => {
                    warn!("Failed to send data to client: {:?}", e);
                    break;
                }
                Ok(Ok(())) => write_buffer = false,
                Err(_) => (),
            }
        }
    }
}

pub async fn process_bindings(running: Arc<AtomicBool>, bindings: Arc<Mutex<Vec<Pin<Box<dyn Future<Output = ()> + Send>>>>>) {
    let mut current_bindings = FuturesUnordered::new();

    while running.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let new_bindings: Vec<_> = { bindings.lock().await.drain(..).collect() };
        for binding in new_bindings {
            current_bindings.push(binding);
        }
        match timeout(Duration::from_secs(1), current_bindings.next()).await {
            Ok(_) => (),
            Err(_) => (),
        }
    }
}

pub trait TpktClientConnectionFactory<T: TpktConnection, R: TpktReader, W: TpktWriter> {
    fn create_connection<'a>(&mut self) -> impl std::future::Future<Output = Result<impl TpktConnection + 'a, MmsServiceError>> + Send;
}

pub trait TpktServerConnectionFactory<T: TpktConnection, R: TpktReader, W: TpktWriter> {
    fn create_connection<'a>(&mut self) -> impl std::future::Future<Output = Result<impl TpktConnection + 'a, MmsServiceError>> + Send;
}

struct MmsServiceConnectionParameters {
    called_tsap_id: Option<Vec<u8>>,
    calling_tsap_id: Option<Vec<u8>>,

    called_session_selector: Option<Vec<u8>>,
    calling_session_selector: Option<Vec<u8>>,

    called_presentation_selector: Option<Vec<u8>>,
    calling_presentation_selector: Option<Vec<u8>>,

    called_ap_title: Option<Oid<'static>>,
    called_ae_qualifier: Option<Vec<u8>>,
    called_ap_invocation_identifier: Option<Vec<u8>>,
    called_ae_invocation_identifier: Option<Vec<u8>>,

    calling_ap_title: Option<Oid<'static>>,
    calling_ae_qualifier: Option<Vec<u8>>,
    calling_ap_invocation_identifier: Option<Vec<u8>>,
    calling_ae_invocation_identifier: Option<Vec<u8>>,

    proposed_max_serv_outstanding_calling: i16,
    proposed_max_serv_outstanding_called: i16,
    proposed_data_structure_nesting_level: Option<i8>,
    propsed_parameter_cbb: Vec<ParameterSupportOption>,
    services_supported_calling: Vec<ServiceSupportOption>,
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
            ],
        }
    }
}

pub struct TA<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> {
    _tpkt_connection: PhantomData<T>,
    _tpkt_reader: PhantomData<R>,
    _tpkt_writer: PhantomData<W>,
}

impl<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> TA<T, R, W> {
    pub fn new() -> TA<T, R, W> {
        TA {
            _tpkt_connection: PhantomData,
            _tpkt_reader: PhantomData,
            _tpkt_writer: PhantomData,
        }
    }
}

impl<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> TpktClientConnectionFactory<T, R, W> for TA<T, R, W> {
    async fn create_connection<'a>(&mut self) -> Result<impl TpktConnection + 'a, MmsServiceError> {
        TcpTpktConnection::connect("127.0.0.1:8102".parse().map_err(to_mms_error(""))?).await.map_err(to_mms_error(""))
    }
}

pub struct TB<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> {
    server: TcpTpktServer,
    _tpkt_reader: PhantomData<R>,
    _tpkt_writer: PhantomData<W>,
    _tpkt_connection: PhantomData<T>,
}

impl<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> TB<T, R, W> {
    pub async fn new() -> Result<TB<T, R, W>, MmsServiceError> {
        Ok(TB {
            server: TcpTpktServer::listen("127.0.0.1:8102".parse().map_err(to_mms_error(""))?).await.map_err(to_mms_error(""))?,
            _tpkt_reader: PhantomData,
            _tpkt_writer: PhantomData,
            _tpkt_connection: PhantomData,
        })
    }
}

impl<T: TpktConnection + 'static, R: TpktReader + 'static, W: TpktWriter + 'static> TpktServerConnectionFactory<T, R, W> for TB<T, R, W> {
    async fn create_connection<'a>(&mut self) -> Result<impl TpktConnection + 'a, MmsServiceError> {
        Ok(self.server.accept().await.map_err(to_mms_error(""))?.0)
    }
}

pub struct RustyMmsInitiatorService {
    sender_queue: mpsc::UnboundedSender<MmsServiceDataPumpReaderType>,
    receiver_queue: mpsc::UnboundedReceiver<Result<MmsMessage, MmsError>>,
}
#[async_trait]
impl MmsInitiatorService for RustyMmsInitiatorService {
    async fn identify(&mut self) -> Result<api::Identity, MmsServiceError> {
        let (s, mut r) = mpsc::unbounded_channel();
        let dpt = MmsServiceDataPumpReaderType::Confirmed(MmsConfirmedRequest::Identify, s);
        self.sender_queue.send(dpt).map_err(to_mms_error("Failed to queue MMS request."))?;
        let response = r.recv().await;
        match response {
            Some(Ok(MmsConfirmedResponse::Identify {
                vendor_name,
                model_name,
                revision,
                abstract_syntaxes,
            })) => Ok(Identity {
                vendor_name,
                model_name,
                revision,
                abstract_syntaxes,
            }),
            Some(Ok(_)) => Err(MmsServiceError::ProtocolError("Unexpected payload received.".into())),
            None => Err(MmsServiceError::ProtocolError("Connection Closed".into())),
            Some(Err(e)) => Err(e),
        }
    }

    async fn get_name_list(&mut self, object_class: rusty_mms::MmsObjectClass, object_scope: rusty_mms::MmsObjectScope, continue_after: Option<String>) -> Result<api::NameList, MmsServiceError> {
        todo!()
    }

    async fn get_variable_access_attributes(&mut self, object_name: rusty_mms::MmsObjectName) -> Result<api::VariableAccessAttributes, MmsServiceError> {
        todo!()
    }

    async fn define_named_variable_list(
        &mut self,
        variable_list_name: rusty_mms::MmsObjectName,
        list_of_variables: Vec<rusty_mms::ListOfVariablesItem>,
    ) -> Result<(Option<rusty_mms::MmsVariableAccessSpecification>, Vec<rusty_mms::MmsAccessResult>), MmsServiceError> {
        todo!()
    }

    async fn get_named_variable_list_attributes(&mut self, variable_list_name: rusty_mms::MmsObjectName) -> Result<(Option<rusty_mms::MmsVariableAccessSpecification>, Vec<rusty_mms::MmsAccessResult>), MmsServiceError> {
        todo!()
    }

    async fn delete_named_variable_list(&mut self, variable_list_name: rusty_mms::MmsObjectName) -> Result<(Option<rusty_mms::MmsVariableAccessSpecification>, Vec<rusty_mms::MmsAccessResult>), MmsServiceError> {
        todo!()
    }

    async fn read(&mut self, specification: rusty_mms::MmsVariableAccessSpecification) -> Result<(Option<rusty_mms::MmsVariableAccessSpecification>, Vec<rusty_mms::MmsAccessResult>), MmsServiceError> {
        todo!()
    }

    async fn write(&mut self, specification: rusty_mms::MmsVariableAccessSpecification, values: Vec<MmsServiceData>) -> Result<rusty_mms::MmsWriteResult, MmsServiceError> {
        todo!()
    }

    async fn send_information_report(&mut self, variable_access_specification: rusty_mms::MmsVariableAccessSpecification, access_results: Vec<rusty_mms::MmsAccessResult>) -> Result<(), MmsServiceError> {
        todo!()
    }

    async fn receive_information_report(&mut self) -> Result<InformationReportMmsServiceMessage, MmsServiceError> {
        todo!()
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
        RustyMmsServiceFactory {
            data_pump,
            _tpkt_connection: PhantomData,
            _tpkt_reader: PhantomData,
            _tpkt_writer: PhantomData,
        }
    }

    async fn create_connection(
        &mut self,
        tpkt_connection_factory: &mut impl TpktClientConnectionFactory<T, R, W>,
        parameters: MmsServiceConnectionParameters,
    ) -> Result<(tokio::sync::mpsc::UnboundedSender<MmsServiceDataPumpReaderType>, tokio::sync::mpsc::UnboundedReceiver<Result<MmsMessage, MmsError>>), MmsServiceError> {
        let tpkt_connection = tpkt_connection_factory.create_connection().await?;

        let cotp_connection_info = CotpConnectInformation {
            called_tsap_id: parameters.called_tsap_id,
            calling_tsap_id: parameters.calling_tsap_id,
            ..Default::default()
        };
        let cotp_connection = TcpCotpConnection::<R, W>::initiate(tpkt_connection, cotp_connection_info).await.map_err(to_mms_error("Failed to create COTP Connection"))?;

        let cosp_connection_info = CospConnectionInformation {
            called_session_selector: parameters.called_session_selector,
            calling_session_selector: parameters.calling_session_selector,
            ..Default::default()
        };
        let cosp_initiator = RustyCospInitiatorIsoStack::<R, W>::new(cotp_connection, cosp_connection_info).await.map_err(to_mms_error("Failed to create COSP Connection"))?;

        let copp_connection_info = CoppConnectionInformation {
            called_presentation_selector: parameters.called_presentation_selector,
            calling_presentation_selector: parameters.calling_presentation_selector,
        };
        let copp_initiator = RustyCoppInitiatorIsoStack::<R, W>::new(cosp_initiator, copp_connection_info);

        let acse_connection_info = AcseRequestInformation {
            application_context_name: Oid::from(&[1, 0, 9506, 2, 1]).map_err(to_mms_error("Failed to create MMS Application Context Name"))?,
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
        let (a, b) = self.data_pump.register_initiator(mms_reader, mms_writer).await;

        Ok((a, b))
    }

    async fn create_server_connection(
        &mut self,
        tpkt_connection_factory: &mut impl TpktServerConnectionFactory<T, R, W>,
        parameters: MmsServiceConnectionParameters,
    ) -> Result<(tokio::sync::mpsc::UnboundedSender<MmsMessage>, tokio::sync::mpsc::UnboundedReceiver<MmsServiceMessage>), MmsServiceError> {
        let tpkt_connection = tpkt_connection_factory.create_connection().await?;

        let cotp_connection_info = CotpAcceptInformation { ..Default::default() };
        let (cotp_listener, _) = TcpCotpAcceptor::<R, W>::new(tpkt_connection).await.map_err(to_mms_error("Failed to create COTP Server"))?;
        let cotp_connection = cotp_listener.accept(cotp_connection_info).await.map_err(to_mms_error(""))?;

        let (cosp_listener, _) = RustyCospListenerIsoStack::<R, W>::new(cotp_connection).await.map_err(to_mms_error("Failed to create COSP Connection"))?;

        let copp_connection_info = CoppConnectionInformation {
            called_presentation_selector: parameters.called_presentation_selector,
            calling_presentation_selector: parameters.calling_presentation_selector,
        };
        let (copp_responder, _) = RustyCoppListenerIsoStack::<R, W>::new(cosp_listener).await.map_err(to_mms_error(""))?;

        let (mut acse_listener, acse_request_info) = RustyOsiSingleValueAcseListenerIsoStack::<R, W>::new(copp_responder).await.map_err(to_mms_error(""))?;
        acse_listener.set_response(Some(AcseResponseInformation {
            application_context_name: Oid::from(&[1, 0, 9506, 2, 1]).map_err(to_mms_error(""))?,
            associate_result: AssociateResult::Accepted,
            associate_source_diagnostic: AssociateSourceDiagnostic::User(AssociateSourceDiagnosticUserCategory::Null),
            responding_ap_title: acse_request_info.called_ap_title,
            responding_ae_qualifier: acse_request_info.called_ae_qualifier,
            responding_ap_invocation_identifier: acse_request_info.called_ap_invocation_identifier,
            responding_ae_invocation_identifier: acse_request_info.called_ae_invocation_identifier,
            implementation_information: None,
        }));

        let (mms_listener, _) = RustyMmsListenerIsoStack::<R, W>::new(acse_listener).await.map_err(to_mms_error(""))?;
        let mms_responder = mms_listener.responder().await.map_err(to_mms_error(""))?;
        let mms_connection = mms_responder.accept().await.map_err(to_mms_error(""))?;

        let (mms_reader, mms_writer) = mms_connection.split().await.map_err(to_mms_error(""))?;
        let (a, b) = self.data_pump.register_responder(mms_reader, mms_writer).await;

        Ok((a, b))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use rusty_mms::{MmsConfirmedRequest, MmsConfirmedResponse, MmsMessage};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktWriter};
    use tokio::{
        join,
        sync::{Mutex, mpsc},
    };
    use tracing_test::traced_test;

    use crate::{
        MmsServiceConnectionParameters, MmsServiceDataPump, MmsServiceDataPumpReaderType, RustyMmsServiceFactory, TA, TB,
        api::{IdentifyMmsServiceMessage, Identity, MmsServiceError, MmsServiceMessage},
        error::to_mms_error,
        process_bindings,
    };

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn main() -> Result<(), anyhow::Error> {
        let running = Arc::new(AtomicBool::new(true));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));

        let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

        let (client_results, server_results) = join!(
            async {
                tokio::time::sleep(Duration::from_millis(1)).await;
                let mut tpkt_client_factory = TA::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new();
                let mut client_factory = RustyMmsServiceFactory::new(data_pump.clone());
                client_factory.create_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
            },
            async {
                let mut tpkt_server_factory = TB::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new().await?;
                let mut server_factory = RustyMmsServiceFactory::new(data_pump.clone());
                server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
            }
        );

        let (client_send_queue, mut client_receive_queue) = client_results?;
        let (server_send_queue, mut server_receive_queue) = server_results?;

        let m = client_send_queue.clone();

        let (s, r) = mpsc::unbounded_channel();
        let (t1, t2) = join!(
            tokio::task::spawn(async move {
                for _ in 1..10000 {
                    client_send_queue
                        .clone()
                        .send(MmsServiceDataPumpReaderType::Confirmed(MmsConfirmedRequest::Identify, s.clone()))
                        .map_err(to_mms_error(""))
                        .expect("");
                }
            }),
            tokio::task::spawn(async move {
                for _ in 1..10000 {
                    let value = match server_receive_queue.recv().await {
                        Some(x) => x,
                        None => {
                            break;
                        }
                    };
                    if let MmsServiceMessage::Identify(message) = value {
                        message
                            .respond(Identity {
                                vendor_name: "Yo".into(),
                                model_name: "There".into(),
                                revision: "Fool".into(),
                                abstract_syntaxes: None,
                            })
                            .await
                            .expect("")
                    }
                }
            })
        );
        t1?;
        t2?;

        Ok(())
    }
}

// async fn create_connection(running: Arc<AtomicBool>) -> Result<(), MmsServiceError> {
//     let bindings = Arc::new(Mutex::new(Vec::new()));
//     tokio::task::spawn(process_bindings(running.clone(), bindings.clone()));
//     let data_pump = Arc::new(MmsServiceDataPump::new(running.clone(), bindings.clone()));

//     let (client, server) = tokio::join!(
//         async {
//             tokio::time::sleep(Duration::from_millis(1)).await;
//             let mut tpkt_client_factory = TA::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new();
//             let mut client_factory = RustyMmsInitiatorServiceFactory::new(data_pump.clone());
//             client_factory.create_connection(&mut tpkt_client_factory, MmsServiceConnectionParameters::default()).await
//         },
//         async {
//             let mut tpkt_server_factory = TB::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::new().await?;
//             let mut server_factory = RustyMmsInitiatorServiceFactory::new(data_pump.clone());
//             server_factory.create_server_connection(&mut tpkt_server_factory, MmsServiceConnectionParameters::default()).await
//         }
//     );
//     let (client_send_queue, client_recv_queue) = client?;
//     let (server_send_queue, server_recv_queue) = server?;

//     Ok((client_send_queue, client_recv_queue, server_send_queue, server_recv_queue))
// }

// impl<R: TpktReader, W: TpktWriter> RustyMmsInitiatorService<R, W> {
// }

// impl<R: TpktReader, W: TpktWriter> MmsInitiatorService for RustyMmsInitiatorService<R, W> {
//     async fn idemtify(&mut self) -> Result<api::Identity, api::MmsServiceError> {
//         let lock = self.writer.lock().await;
//         lock.rea

//         todo!()
//     }

//     async fn get_name_list(&mut self, object_class: rusty_mms::MmsObjectClass, object_scope: rusty_mms::MmsObjectScope, continue_after: Option<String>) -> Result<api::NameList, api::MmsServiceError> {
//         todo!()
//     }

//     async fn get_variable_access_attributes(&mut self, object_name: rusty_mms::MmsObjectName) -> Result<api::VariableAccessAttributes, api::MmsServiceError> {
//         todo!()
//     }

//     async fn define_named_variable_list(
//         &mut self,
//         variable_list_name: rusty_mms::MmsObjectName,
//         list_of_variables: Vec<rusty_mms::ListOfVariablesItem>,
//     ) -> Result<(Option<rusty_mms::MmsVariableAccessSpecification>, Vec<rusty_mms::MmsAccessResult>), api::MmsServiceError> {
//         todo!()
//     }

//     async fn get_named_variable_list_attributes(&mut self, variable_list_name: rusty_mms::MmsObjectName) -> Result<(Option<rusty_mms::MmsVariableAccessSpecification>, Vec<rusty_mms::MmsAccessResult>), api::MmsServiceError> {
//         todo!()
//     }

//     async fn delete_named_variable_list(&mut self, variable_list_name: rusty_mms::MmsObjectName) -> Result<(Option<rusty_mms::MmsVariableAccessSpecification>, Vec<rusty_mms::MmsAccessResult>), api::MmsServiceError> {
//         todo!()
//     }

//     async fn read(&mut self, specification: rusty_mms::MmsVariableAccessSpecification) -> Result<(Option<rusty_mms::MmsVariableAccessSpecification>, Vec<rusty_mms::MmsAccessResult>), api::MmsServiceError> {
//         todo!()
//     }

//     async fn write(&mut self, specification: rusty_mms::MmsVariableAccessSpecification, values: Vec<api::MmsServiceData>) -> Result<rusty_mms::MmsWriteResult, api::MmsServiceError> {
//         todo!()
//     }

//     async fn information_report(variable_access_specification: rusty_mms::MmsVariableAccessSpecification, access_results: Vec<rusty_mms::MmsAccessResult>) -> Result<(), api::MmsServiceError> {
//         todo!()
//     }
// }
