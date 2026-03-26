use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use num_bigint::BigInt;
use rusty_mms::{MmsConfirmedRequest, MmsConfirmedResponse, MmsError, MmsMessage, MmsReader, MmsRecvResult, MmsScope, MmsUnconfirmedService, MmsWriter};
use tokio::{
    sync::{
        Mutex,
        mpsc::{self, UnboundedSender},
    },
    time::timeout,
};
use tracing::warn;

use crate::{
    data::{InformationReportMmsServiceMessage, MmsServiceAccessResult, MmsServiceDeleteObjectScope, convert_low_level_data_to_high_level_data},
    error::{MmsServiceError, to_mms_error},
    message::{
        DefineNamedVariableListMmsServiceMessage, DeleteNamedVariableListMmsServiceMessage, GetNameListMmsServiceMessage, GetNamedVariableListAttributesMmsServiceMessage, GetVariableAccessAttributesMmsServiceMessage,
        IdentifyMmsServiceMessage, MmsServiceMessage, ReadMmsServiceMessage, WriteMmsServiceMessage,
    },
};

// TODO Send queue should also hold for max outstanding requests
pub enum MmsServiceDataPumpReaderType {
    Confirmed(MmsConfirmedRequest, UnboundedSender<Result<MmsConfirmedResponse, MmsServiceError>>),
    Unconfirmed(MmsUnconfirmedService),
}

pub struct MmsServiceDataPump {
    _running: Arc<AtomicBool>,
    bindings: Arc<Mutex<Vec<Pin<Box<dyn Future<Output = ()> + Send>>>>>,
}

impl MmsServiceDataPump {
    pub fn new(running: Arc<AtomicBool>, bindings: Arc<Mutex<Vec<Pin<Box<dyn Future<Output = ()> + Send>>>>>) -> MmsServiceDataPump {
        MmsServiceDataPump { _running: running, bindings }
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
                                match v.send(Ok(response)) {
                                    Ok(()) => (),
                                    Err(e) => {
                                        warn!("Failed to send message: {:?}", e);
                                        break;
                                    },
                                }
                            },
                            None => {
                                warn!("Got a reqeust id for a value that was not pending: {:?}", request_id)
                            },
                        }
                    },
                    Ok(MmsRecvResult::Message(MmsMessage::Unconfirmed { unconfirmed_service })) => {
                        match outbound_queue.send(Ok(MmsMessage::Unconfirmed { unconfirmed_service })) {
                            Ok(()) => (),
                            Err(e) => {
                                warn!("Failed to send message: {:?}", e);
                                break;
                            },
                        }
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

async fn process_request(request: MmsConfirmedRequest, invocation_id: u32, external_outbound_queue: mpsc::UnboundedSender<MmsMessage>) -> Result<MmsServiceMessage, MmsServiceError> {
    match request {
        MmsConfirmedRequest::GetNameList { object_class, object_scope, continue_after } => {
            Ok(MmsServiceMessage::GetNameList(GetNameListMmsServiceMessage::new(invocation_id, object_class, object_scope, continue_after, external_outbound_queue.clone())))
        }
        MmsConfirmedRequest::Identify => Ok(MmsServiceMessage::Identify(IdentifyMmsServiceMessage::new(invocation_id, external_outbound_queue.clone()))),
        MmsConfirmedRequest::Read { specification_with_result, variable_access_specification } => {
            Ok(MmsServiceMessage::Read(ReadMmsServiceMessage::new(invocation_id, variable_access_specification, specification_with_result, external_outbound_queue.clone())))
        }
        MmsConfirmedRequest::Write { variable_access_specification, list_of_data } => Ok(MmsServiceMessage::Write(WriteMmsServiceMessage::new(invocation_id, variable_access_specification, list_of_data, external_outbound_queue.clone())?)),
        MmsConfirmedRequest::GetVariableAccessAttributes { object_name } => Ok(MmsServiceMessage::GetVariableAccessAttributes(GetVariableAccessAttributesMmsServiceMessage::new(invocation_id, object_name, external_outbound_queue.clone()))),
        MmsConfirmedRequest::DefineNamedVariableList { variable_list_name, list_of_variables } => {
            Ok(MmsServiceMessage::DefineNamedVariableList(DefineNamedVariableListMmsServiceMessage::new(invocation_id, variable_list_name, list_of_variables, external_outbound_queue.clone())))
        }
        MmsConfirmedRequest::GetNamedVariableListAttributes { object_name } => {
            Ok(MmsServiceMessage::GetNamedVariableListAttributes(GetNamedVariableListAttributesMmsServiceMessage::new(invocation_id, object_name, external_outbound_queue.clone())))
        }
        MmsConfirmedRequest::DeleteNamedVariableList { scope_of_delete, list_of_variable_list_names, domain_name } => match (scope_of_delete, list_of_variable_list_names, domain_name) {
            (None, Some(variables), None) => Ok(MmsServiceMessage::DeleteNamedVariableList(DeleteNamedVariableListMmsServiceMessage::new(invocation_id, MmsServiceDeleteObjectScope::Specific(variables), external_outbound_queue.clone()))),
            (Some(MmsScope::Specific), Some(variables), None) => {
                Ok(MmsServiceMessage::DeleteNamedVariableList(DeleteNamedVariableListMmsServiceMessage::new(invocation_id, MmsServiceDeleteObjectScope::Specific(variables), external_outbound_queue.clone())))
            }
            (Some(MmsScope::AaSpecific), None, None) => Ok(MmsServiceMessage::DeleteNamedVariableList(DeleteNamedVariableListMmsServiceMessage::new(invocation_id, MmsServiceDeleteObjectScope::AaSpecific, external_outbound_queue.clone()))),
            (Some(MmsScope::Vmd), None, None) => Ok(MmsServiceMessage::DeleteNamedVariableList(DeleteNamedVariableListMmsServiceMessage::new(invocation_id, MmsServiceDeleteObjectScope::Vmd, external_outbound_queue.clone()))),
            (Some(MmsScope::Domain), None, Some(domain_name)) => {
                Ok(MmsServiceMessage::DeleteNamedVariableList(DeleteNamedVariableListMmsServiceMessage::new(invocation_id, MmsServiceDeleteObjectScope::Domain(domain_name), external_outbound_queue.clone())))
            }
            (x, y, z) => Err(MmsServiceError::ProtocolError(format!("Non-standard scope {:?}, {:?}, {:?}", x, y, z))),
        },
    }
}

async fn process_responder_binding(
    mut reader: impl MmsReader,
    mut writer: impl MmsWriter,
    external_outbound_queue: mpsc::UnboundedSender<MmsMessage>,
    mut inbound_queue: mpsc::UnboundedReceiver<MmsMessage>,
    outbound_queue: mpsc::UnboundedSender<MmsServiceMessage>,
) {
    let mut buffer = VecDeque::new();

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
                        let invocation_id: u32 = match BigInt::from_signed_bytes_be(&invocation_id).try_into() {
                            Ok(x) => x,
                            Err(e) => {
                                warn!("Failed to convert invocation id: {:?}", e);
                                break;
                            },
                        };
                        let send_result = match process_request(request, invocation_id, external_outbound_queue.clone()).await {
                            Ok(x) => outbound_queue.send(x),
                            Err(e) => {
                                warn!("Failed to process message: {:?}", e);
                                break;
                            },
                        };
                        match send_result {
                            Ok(()) => (),
                            Err(e) => {
                                warn!("Failed to send message: {:?}", e);
                                break;
                            },
                        }
                    },
                    Ok(MmsRecvResult::Message(MmsMessage::Unconfirmed { unconfirmed_service: MmsUnconfirmedService::InformationReport { variable_access_specification, access_results } })) => {
                        let access_results = access_results.into_iter().map(|x| match x {
                            rusty_mms::MmsAccessResult::Success(mms_data) => Ok(MmsServiceAccessResult::Success(convert_low_level_data_to_high_level_data(&mms_data)?)),
                            rusty_mms::MmsAccessResult::Failure(mms_access_error) => Ok(MmsServiceAccessResult::Failure(mms_access_error)),
                        }).collect::<Result<Vec<MmsServiceAccessResult>, MmsServiceError>>();

                        let access_results = match access_results {
                            Ok(x) => x,
                            Err(e) => {
                                warn!("Failed to convert message: {:?}", e);
                                break;
                            },
                        };

                        match outbound_queue.send(MmsServiceMessage::InformationReport(InformationReportMmsServiceMessage { variable_access_specification, access_results })) {
                            Ok(()) => (),
                            Err(e) => {
                                warn!("Failed to send message: {:?}", e);
                                break;
                            },
                        };
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
