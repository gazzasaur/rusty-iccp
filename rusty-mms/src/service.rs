use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use der_parser::Oid;
use rusty_acse::OsiSingleValueAcseConnection;
use rusty_acse::{OsiSingleValueAcseInitiator, OsiSingleValueAcseListener, OsiSingleValueAcseReader, OsiSingleValueAcseResponder, OsiSingleValueAcseWriter};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{Mutex, mpsc};

use crate::MmsVariableAccessSpecification;
use crate::pdu::{ConfirmedMmsPduType, MmsPduType, ReadRequestPdu};
use crate::{
    MmsConnection, MmsError, MmsInitiator, MmsListener, MmsResponder,
    error::to_mms_error,
    parameters::{ParameterSupportOption, ParameterSupportOptions, ServiceSupportOption, ServiceSupportOptions},
    pdu::{InitRequestResponseDetails, InitiateRequestPdu, InitiateResponsePdu},
};

pub struct MmsRequestInformation {
    pub local_detail_calling: Option<i32>,
    pub proposed_max_serv_outstanding_calling: i16,
    pub proposed_max_serv_outstanding_called: i16,
    pub proposed_data_structure_nesting_level: Option<i8>,

    pub proposed_version_number: i16,
    pub propsed_parameter_cbb: Vec<ParameterSupportOption>,
    pub services_supported_calling: Vec<ServiceSupportOption>,
}

impl Default for MmsRequestInformation {
    fn default() -> Self {
        Self {
            local_detail_calling: None,
            proposed_max_serv_outstanding_calling: 10,
            proposed_max_serv_outstanding_called: 10,
            proposed_data_structure_nesting_level: None,
            proposed_version_number: Default::default(),
            propsed_parameter_cbb: vec![
                ParameterSupportOption::Str1,
                ParameterSupportOption::Str2,
                ParameterSupportOption::Vnam,
                ParameterSupportOption::Valt,
                ParameterSupportOption::Vlis,
            ],
            services_supported_calling: vec![
                ServiceSupportOption::GetNameList,
                ServiceSupportOption::Identify,
                ServiceSupportOption::Read,
                ServiceSupportOption::Write,
                ServiceSupportOption::GetVariableAccessAttributes,
                ServiceSupportOption::GetNamedVariableListAttribute,
                ServiceSupportOption::DefineNamedVariableList,
                ServiceSupportOption::DeleteNamedVariableList,
                ServiceSupportOption::InformationReport,
            ],
        }
    }
}

pub struct RustyMmsInitiator<T: OsiSingleValueAcseInitiator, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> {
    acse_initiator: T,
    acse_reader: PhantomData<R>,
    acse_writer: PhantomData<W>,
    options: MmsRequestInformation,
}

impl<T: OsiSingleValueAcseInitiator, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> RustyMmsInitiator<T, R, W> {
    pub fn new(acse_initiator: impl OsiSingleValueAcseInitiator, options: MmsRequestInformation) -> RustyMmsInitiator<impl OsiSingleValueAcseInitiator, impl OsiSingleValueAcseReader, impl OsiSingleValueAcseWriter> {
        RustyMmsInitiator {
            acse_initiator,
            acse_reader: PhantomData::<R>,
            acse_writer: PhantomData::<W>,
            options,
        }
    }
}

impl<T: OsiSingleValueAcseInitiator, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> MmsInitiator for RustyMmsInitiator<T, R, W> {
    async fn initiate(self) -> Result<impl MmsConnection, MmsError> {
        let pdu = InitiateRequestPdu::new(
            self.options.local_detail_calling,
            self.options.proposed_max_serv_outstanding_calling,
            self.options.proposed_max_serv_outstanding_called,
            self.options.proposed_data_structure_nesting_level,
            InitRequestResponseDetails {
                proposed_version_number: self.options.proposed_version_number,
                propsed_parameter_cbb: ParameterSupportOptions { options: self.options.propsed_parameter_cbb },
                services_supported_calling: ServiceSupportOptions {
                    options: self.options.services_supported_calling,
                },
            },
        );
        let request_data = pdu.serialise()?;

        let (acse_connection, response, user_data) = self
            .acse_initiator
            .initiate(Oid::from(&[1, 0, 9506, 2, 1]).map_err(to_mms_error("Failed to create MMS OID. This is a bug."))?.to_owned(), request_data)
            .await
            .map_err(to_mms_error("Failed yo initiate MMS connection"))?;
        let response = InitiateResponsePdu::parse(user_data)?;

        let (acse_reader, acse_writer) = acse_connection.split().await.map_err(|e| MmsError::ProtocolError(format!("Failed to initiate MMS connection: {:?}", e)))?;

        Ok(RustyMmsConnection::<R, W>::new(acse_reader, acse_writer))
    }
}

pub struct RustyMmsListener<T: OsiSingleValueAcseResponder, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> {
    acse_responder: T,
    _r: PhantomData<R>,
    _w: PhantomData<W>,
}

impl<T: OsiSingleValueAcseResponder, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> RustyMmsListener<T, R, W> {
    pub async fn new(acse_listener: impl OsiSingleValueAcseListener) -> Result<(RustyMmsListener<impl OsiSingleValueAcseResponder, impl OsiSingleValueAcseReader, impl OsiSingleValueAcseWriter>, MmsRequestInformation), MmsError> {
        let (acse_responder, init_data) = acse_listener.responder().await.map_err(to_mms_error("Failed to create ACSE association for MMS response"))?;
        let request = InitiateRequestPdu::parse(init_data)?;

        Ok((
            RustyMmsListener {
                acse_responder,
                _r: PhantomData::<R>,
                _w: PhantomData::<W>,
            },
            MmsRequestInformation::default(),
        ))
    }
}

impl<T: OsiSingleValueAcseResponder, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> MmsListener for RustyMmsListener<T, R, W> {
    async fn responder(self) -> Result<impl MmsResponder, MmsError> {
        Ok(RustyMmsResponder {
            acse_responder: self.acse_responder,
            _r: PhantomData::<R>,
            _w: PhantomData::<W>,
        })
    }
}

pub struct RustyMmsResponder<T: OsiSingleValueAcseResponder, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> {
    acse_responder: T,
    _r: PhantomData<R>,
    _w: PhantomData<W>,
}

impl<T: OsiSingleValueAcseResponder, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> MmsResponder for RustyMmsResponder<T, R, W> {
    async fn accept(self) -> Result<impl MmsConnection, MmsError> {
        let repsonse = InitiateResponsePdu::new(
            None,
            10,
            11,
            Some(12),
            InitRequestResponseDetails {
                proposed_version_number: 1,
                propsed_parameter_cbb: ParameterSupportOptions {
                    options: vec![
                        ParameterSupportOption::Str1,
                        ParameterSupportOption::Str2,
                        ParameterSupportOption::Vnam,
                        // ParameterSupportOption::Valt, Optional, not implemented for now.
                        ParameterSupportOption::Vlis,
                    ],
                },
                services_supported_calling: ServiceSupportOptions {
                    options: vec![
                        ServiceSupportOption::GetNameList,
                        ServiceSupportOption::Identify,
                        ServiceSupportOption::Read,
                        ServiceSupportOption::Write,
                        ServiceSupportOption::GetVariableAccessAttributes,
                        ServiceSupportOption::GetNamedVariableListAttribute,
                        ServiceSupportOption::DefineNamedVariableList,
                        ServiceSupportOption::DeleteNamedVariableList,
                        ServiceSupportOption::InformationReport,
                    ],
                },
            },
        );
        let acse_connection = self.acse_responder.accept(repsonse.serialise()?).await.map_err(|e| MmsError::ProtocolError(format!("Failed to initiate MMS connection: {:?}", e)))?;
        let (acse_reader, acse_writer) = acse_connection.split().await.map_err(|e| MmsError::ProtocolError(format!("Failed to initiate MMS connection: {:?}", e)))?;
        Ok(RustyMmsConnection::<R, W>::new(acse_reader, acse_writer))
    }
}

struct RustyMmsConnectionInternal<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> {
    acse_reader: R,
    acse_writer: W,

    pending: HashMap<u32, Receiver<Result<MmsPduType, MmsError>>>
}

impl<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> RustyMmsConnectionInternal<R, W> {
    fn new(acse_reader: R, acse_writer: W) -> Self {
        Self { acse_reader, acse_writer, pending: HashMap::new() }
    }
}

pub struct RustyMmsConnection<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> {
    invocation_id: AtomicU32,
    internal: Arc<Mutex<RustyMmsConnectionInternal<R, W>>>
}

impl<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> RustyMmsConnection<R, W> {
    pub fn new(acse_reader: impl OsiSingleValueAcseReader, acse_writer: impl OsiSingleValueAcseWriter) -> RustyMmsConnection<impl OsiSingleValueAcseReader, impl OsiSingleValueAcseWriter> {
        RustyMmsConnection { invocation_id: AtomicU32::new(1), internal: Arc::new(Mutex::new(RustyMmsConnectionInternal::new(acse_reader, acse_writer))) }
    }
}

impl<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> MmsConnection for RustyMmsConnection<R, W> {
    async fn read(&mut self, access_specifications: Vec<MmsVariableAccessSpecification>) -> Result<Vec<crate::MmsAccessResult>, MmsError> {
        let read_request_pdu = ReadRequestPdu {

        };

        let invocation_id = self.invocation_id.fetch_add(1, Ordering::Acquire);
        let (inbound_sender, inbound_receiver) = mpsc::channel::<Result<MmsPduType, MmsError>>(1);
        

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_serialises_parameter_support_options_empty() -> Result<(), anyhow::Error> {
        Ok(())
    }
}
