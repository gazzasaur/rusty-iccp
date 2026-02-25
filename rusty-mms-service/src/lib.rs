use std::{convert::identity, ops::Deref, sync::Arc, time::Duration};
use tokio::sync::{Mutex, Notify, mpsc};

use rusty_mms::{MmsConfirmedResponse, MmsReader, RustyMmsConnection, RustyMmsConnectionIsoStack, RustyMmsReaderIsoStack, RustyMmsWriterIsoStack};
use rusty_tpkt::{TpktConnection, TpktReader, TpktWriter};

use crate::api::MmsInitiatorService;

pub mod api;

enum MmsReceiveWorkerResult {}

struct MmsReceiveWorkerConfirmedReqeust {
    notify: Notify,
    value: Arc<Mutex<Option<MmsConfirmedResponse>>>,
}

enum MmsReceiveWorkerEvent {}

struct EventPollItem {
    
}

async fn mms_receive_worker(reader: RustyMmsReaderIsoStack<impl TpktReader>, writer: RustyMmsWriterIsoStack<impl TpktWriter>, mut event_queue: mpsc::Receiver<MmsReceiveWorkerEvent>) {
    loop {
        let event_poll = tokio::time::timeout(Duration::from_millis(1), event_queue.recv()).await;
        let event = match event_poll {
            Ok(Some(x)) => x,
            Ok(None) => return,
            Err(_) => continue,
        };
    }
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
