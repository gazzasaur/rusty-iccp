use std::marker::PhantomData;

use der_parser::Oid;
use rusty_acse::{AcseError, OsiSingleValueAcseInitiator, OsiSingleValueAcseListener, OsiSingleValueAcseReader, OsiSingleValueAcseResponder, OsiSingleValueAcseWriter};

use crate::{
    MmsConnection, MmsError, MmsInitiator, MmsListener, MmsReader, MmsResponder, MmsWriter, error::to_mms_error, parameters::{ParameterSupportOption, ParameterSupportOptions, ServiceSupportOption, ServiceSupportOptions}, pdu::{InitRequestDetails, InitiateRequestPdu}
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
            InitRequestDetails {
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
        Ok(RustyMmsConnection::<R, W> {
            _r: PhantomData, _w: PhantomData
        })
    }
}

pub struct RustyMmsListener<T: OsiSingleValueAcseResponder, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> {
    _t: PhantomData<T>,
    _r: PhantomData<R>,
    _w: PhantomData<W>,
}

impl<T: OsiSingleValueAcseResponder, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> RustyMmsListener<T, R, W> {
    pub async fn new(acse_listener: impl OsiSingleValueAcseListener) -> Result<(RustyMmsListener<impl OsiSingleValueAcseResponder, impl OsiSingleValueAcseReader, impl OsiSingleValueAcseWriter>, MmsRequestInformation), AcseError> {
        acse_listener.responder().await?;
        
        Ok((RustyMmsListener { _t: PhantomData::<T>, _r: PhantomData::<R>, _w: PhantomData::<W> }, MmsRequestInformation::default()))
    }
}



impl<T: OsiSingleValueAcseResponder, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> MmsListener for RustyMmsListener<T, R, W> {
    async fn responder(self) -> Result<impl MmsResponder, MmsError> {
        Err::<RustyMmsResponder<T, R, W>, MmsError>(MmsError::InternalError("Nah".into()))
    }
}

pub struct RustyMmsResponder<T: OsiSingleValueAcseResponder, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> {
    _t: PhantomData<T>,
    _r: PhantomData<R>,
    _w: PhantomData<W>,
}

impl<T: OsiSingleValueAcseResponder, R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> MmsResponder for RustyMmsResponder<T, R, W> {
    async fn accept(self) -> Result<impl MmsConnection, MmsError> {
        Err::<RustyMmsConnection<R, W>, MmsError>(MmsError::InternalError("Nah".into()))
    }
}

pub struct RustyMmsConnection<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> {
    _r: PhantomData<R>,
    _w: PhantomData<W>,
}

impl<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> MmsConnection for RustyMmsConnection<R, W> {
    async fn split(self) -> Result<(impl MmsReader, impl MmsWriter), MmsError> {
        Err::<(RustyMmsReader<R>, RustyMmsWriter<W>), MmsError>(MmsError::InternalError("Nah".into()))
    }
}

pub struct RustyMmsReader<R: OsiSingleValueAcseReader> {
    _r: PhantomData<R>
}

impl<R: OsiSingleValueAcseReader> MmsReader for RustyMmsReader<R> {
    async fn recv(&mut self) -> Result<crate::MmsRecvResult, MmsError> {
        todo!()
    }
}

pub struct RustyMmsWriter<W: OsiSingleValueAcseWriter> {
    _w: PhantomData<W>
}

impl<W: OsiSingleValueAcseWriter> MmsWriter for RustyMmsWriter<W> {
    async fn send(&mut self, data: crate::MmsMessage) -> Result<(), MmsError> {
        todo!()
    }

    async fn continue_send(&mut self) -> Result<(), MmsError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::parameters::ParameterSupportOption;

    use super::*;

    #[test]
    fn it_serialises_parameter_support_options_empty() -> Result<(), anyhow::Error> {
        Ok(())
    }
}
