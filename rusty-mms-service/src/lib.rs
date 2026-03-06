use der_parser::nom::Map;
use num_bigint::{ToBigInt, ToBigUint};
use std::{collections::HashMap, convert::identity, ops::Deref, sync::Arc, time::Duration};
use tokio::{
    join,
    sync::{Mutex, Notify, futures, mpsc},
    time::error::Elapsed,
};

use rusty_mms::{MmsConfirmedRequest, MmsConfirmedResponse, MmsData, MmsError, MmsMessage, MmsReader, MmsRecvResult, MmsWriter, RustyMmsConnection, RustyMmsConnectionIsoStack, RustyMmsReaderIsoStack, RustyMmsWriterIsoStack};
use rusty_tpkt::{TpktConnection, TpktReader, TpktWriter};

use crate::api::{MmsInitiatorService, MmsServiceData};

pub mod api;
pub(crate) mod error;

enum MmsTxRxWorkerEvent {
    Close,
    ConfirmedReqeust { request: MmsConfirmedRequest, sender: mpsc::UnboundedSender<Result<MmsConfirmedResponse, MmsError>> },
}

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
            Ok(MmsData::Array(low_level_data))
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
        MmsServiceData::FloatingPoint(value) => Ok({
            MmsData::FloatingPoint(value.get_raw_data().clone())
        }),
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

struct EventPollItem {}

async fn mms_transceiver_worker(event_queue: mpsc::Receiver<MmsTxRxWorkerEvent>, reader: RustyMmsReaderIsoStack<impl TpktReader>) {
    // We will allow these to wrap. It is unlikely that 4B messages can be sent before the earlier ones timeout.
    // let mut sequence_number_counter: u32 = 0;

    // loop {
    //     tokio::select! {
    //         Some(x) 
    //     }
    // }
}

async fn mms_reader_worker(mut reader: RustyMmsReaderIsoStack<impl TpktReader>, mut message_queue: mpsc::UnboundedSender<Result<MmsMessage, MmsError>>) {
    loop {
        match reader.recv().await {
            Ok(MmsRecvResult::Message(message)) => message_queue.send(Ok(message)),
            Ok(MmsRecvResult::Closed) => return,
            Err(e) => {
                message_queue.send(Err(e));
                return;
            }
        };
    }
}

async fn mms_sender_worker(mut writer: RustyMmsWriterIsoStack<impl TpktWriter>, mut event_queue: mpsc::UnboundedReceiver<MmsMessage>) {
    loop {
        match event_queue.recv().await {
            Some(x) => {
                if let Err(e) = writer.send(x).await {
                    // TODO Log some kind of sane error.
                    event_queue.close();
                }
            },
            None => return,
        };
    }
}

async fn mms_receiver_worker(mut reader: RustyMmsReaderIsoStack<impl TpktReader>, mut event_queue: mpsc::Sender<MmsTxRxWorkerEvent>) {
    // loop {
    //     let received_value = reader.recv().await;

    //     let event_poll = tokio::time::timeout(Duration::from_millis(1), event_queue.recv()).await;
    //     match event_poll {
    //         Ok(Some(x)) => {
    //             writer.send(x);
    //         }
    //         Ok(None) => return,
    //         Err(_) => {
    //             // If comms is failing we can spend to on the send rather than servicing the queue as this is the blocker.
    //             if let Err(_) = tokio::time::timeout(Duration::from_millis(1), writer.continue_send()).await {
    //                 // TODO Log with some kind of de-dup or metric
    //             }
    //         }
    //     };
    // }
}

// pub struct RustyMmsInitiatorService<R: TpktReader, W: TpktWriter> {
//     reader: Arc<Mutex<RustyMmsReaderIsoStack<R>>>,
//     writer: Arc<Mutex<RustyMmsWriterIsoStack<W>>>,
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
