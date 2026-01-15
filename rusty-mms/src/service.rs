use std::marker::PhantomData;

use der_parser::Oid;
use der_parser::asn1_rs::Any;
use der_parser::ber::{BerObject, BerObjectContent, BitStringObject, Length, parse_ber_any};
use der_parser::der::{Class, Header, Tag};
use rusty_acse::{AcseRecvResult, OsiSingleValueAcseConnection};
use rusty_acse::{OsiSingleValueAcseInitiator, OsiSingleValueAcseListener, OsiSingleValueAcseReader, OsiSingleValueAcseResponder, OsiSingleValueAcseWriter};
use tracing::warn;

use crate::parsers::{process_constructed_data, process_mms_string};
use crate::pdu::common::expect_value;
use crate::pdu::confirmedrequest::{confirmed_request_to_ber, parse_confirmed_request};
use crate::pdu::confirmedresponse::confirmed_response_to_ber;
use crate::pdu::initiaterequest::{InitRequestResponseDetails, InitiateRequestPdu};
use crate::pdu::initiateresponse::InitiateResponsePdu;
use crate::pdu::readrequest::read_request_to_ber;
use crate::{ListOfVariablesItem, MmsConnection, MmsData, MmsMessage, MmsObjectName, MmsReader, MmsRecvResult, MmsVariableAccessSpecification, MmsWriter, VariableSpecification};
use crate::{
    MmsError, MmsInitiator, MmsListener, MmsResponder,
    error::to_mms_error,
    parameters::{ParameterSupportOption, ParameterSupportOptions, ServiceSupportOption, ServiceSupportOptions},
};

impl MmsObjectName {
    // Tecnically only a-zA-Z0-9 and $ and _ with no more than 32 char. We leave that to a higher layer to validate
    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        match &self {
            MmsObjectName::VmdSpecific(name) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)), BerObjectContent::VisibleString(&name.as_str())),
            MmsObjectName::DomainSpecific(domain, name) => BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
                BerObjectContent::Sequence(vec![
                    BerObject::from_obj(BerObjectContent::VisibleString(&domain.as_str())),
                    BerObject::from_obj(BerObjectContent::VisibleString(&name.as_str())),
                ]),
            ),
            MmsObjectName::AaSpecific(name) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(2), Length::Definite(0)), BerObjectContent::VisibleString(&name.as_str())),
        }
    }

    pub(crate) fn parse(pdu: &str, data: &[u8]) -> Result<MmsObjectName, MmsError> {
        let error_message = format!("Failed to parse ObjectName on {}", pdu);
        let (_, npm_object) = parse_ber_any(data).map_err(to_mms_error(error_message.as_str()))?;
        match npm_object.header.raw_tag() {
            Some([128]) => Ok(MmsObjectName::VmdSpecific(process_mms_string(&npm_object, error_message.as_str())?)),
            Some([161]) => {
                let values = process_constructed_data(npm_object.data).map_err(to_mms_error(&error_message))?;
                let mut values_iter = values.iter();
                let domain = expect_value(pdu, "ObjectName", values_iter.next())?;
                let name = expect_value(pdu, "ObjectName", values_iter.next())?;
                Ok(MmsObjectName::DomainSpecific(process_mms_string(domain, &error_message)?, process_mms_string(name, &error_message)?))
            }
            Some([130]) => Ok(MmsObjectName::AaSpecific(process_mms_string(&npm_object, error_message.as_str())?)),
            x => Err(MmsError::ProtocolError(error_message)),
        }
    }
}

impl MmsVariableAccessSpecification {
    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        match &self {
            MmsVariableAccessSpecification::ListOfVariables(list_of_variable_items) => BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
                BerObjectContent::Sequence(list_of_variable_items.iter().map(|i| i.to_ber()).collect()),
            ),
            MmsVariableAccessSpecification::VariableListName(mms_object_name) => {
                BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)), BerObjectContent::Sequence(vec![mms_object_name.to_ber()]))
            }
        }
    }

    pub(crate) fn parse(pdu_name: &str, data: &[u8]) -> Result<MmsVariableAccessSpecification, MmsError> {
        let items = process_constructed_data(data).map_err(to_mms_error(format!("Failed to parse Variable Access Specification on {:?}", pdu_name).as_str()))?;
        if items.len() != 1 {
            return Err(MmsError::ProtocolError(format!("Expected one item on variable access specification but got {}", items.len())));
        }
        match items[0].header.raw_tag() {
            Some([160]) => {
                let mut variables = vec![];
                for variable_ber in process_constructed_data(items[0].data).map_err(to_mms_error(format!("Failed to parse Variable Access Specification on {:?}", pdu_name).as_str()))? {
                    variables.push(ListOfVariablesItem::parse(&variable_ber, pdu_name)?);
                }
                return Ok(MmsVariableAccessSpecification::ListOfVariables(variables));
            }
            Some([161]) => {
                let mms_object = MmsObjectName::parse(pdu_name, items[0].data)?;
                return Ok(MmsVariableAccessSpecification::VariableListName(mms_object));
            }
            Some(x) => return Err(MmsError::InternalError(format!("Unsupported variable type found {:?} on {:?}", x, pdu_name))),
            None => return Err(MmsError::InternalError(format!("No variable found in payload: {:?}", pdu_name))),
        }
    }
}

impl ListOfVariablesItem {
    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        BerObject::from_seq(vec![self.variable_specification.to_ber()])
    }

    pub(crate) fn parse(item: &Any<'_>, error_message: &str) -> Result<ListOfVariablesItem, MmsError> {
        let mut variable_specification = None;

        for item in process_constructed_data(item.data).map_err(to_mms_error(error_message))? {
            match item.header.raw_tag() {
                Some([160]) => variable_specification = Some(VariableSpecification::parse(item.data)?),
                x => warn!("Ignoring unknown variable specification: {:?}", x),
            }
        }
        let variable_specification = expect_value(error_message, "Variable Specification", variable_specification)?;
        Ok(ListOfVariablesItem { variable_specification })
    }
}

impl VariableSpecification {
    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        match &self {
            VariableSpecification::Name(mms_object_name) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)), BerObjectContent::Sequence(vec![mms_object_name.to_ber()])),
            VariableSpecification::Invalidated => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(4), Length::Definite(0)), BerObjectContent::Null),
        }
    }

    pub(crate) fn parse(data: &[u8]) -> Result<VariableSpecification, MmsError> {
        let (_, variable_spec_ber) = parse_ber_any(data).map_err(to_mms_error("Failed to parse Variable Specification"))?;
        match variable_spec_ber.header.raw_tag() {
            Some([128]) => Ok(VariableSpecification::Name(MmsObjectName::parse("", data)?)),
            Some([161]) => Ok(VariableSpecification::Name(MmsObjectName::parse("", data)?)),
            Some([130]) => Ok(VariableSpecification::Name(MmsObjectName::parse("", data)?)),
            Some([132]) => Ok(VariableSpecification::Invalidated),
            x => Err(MmsError::ProtocolError(format!("Unknown Variable Specification: {:?}", x))),
        }
    }
}

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

impl MmsData {
    pub(crate) fn serialise(&self, str1: bool, str2: bool) -> Result<BerObject<'_>, MmsError> {
        let payload = match &self {
            MmsData::Array(mms_array_items) if str1 => {
                let mut mms_array_data = vec![];
                for mms_array_item in mms_array_items {
                    mms_array_data.push(mms_array_item.serialise(str1, str2)?)
                }
                BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)), BerObjectContent::Sequence(mms_array_data))
            }
            MmsData::Array(_) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(1), Length::Definite(0)), BerObjectContent::Null),

            MmsData::Structure(mms_array_items) if str2 => {
                let mut mms_array_data = vec![];
                for mms_array_item in mms_array_items {
                    mms_array_data.push(mms_array_item.serialise(str1, str2)?)
                }
                BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(2), Length::Definite(0)), BerObjectContent::Sequence(mms_array_data))
            }
            MmsData::Structure(_) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(2), Length::Definite(0)), BerObjectContent::Null),

            MmsData::Boolean(value) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(3), Length::Definite(0)), BerObjectContent::Boolean(*value)),
            MmsData::BitString(padding, bit_data) => BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, false, Tag::from(4), Length::Definite(0)),
                BerObjectContent::BitString(*padding, BitStringObject { data: &bit_data }),
            ),
            MmsData::Integer(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(5), Length::Definite(0)), BerObjectContent::Integer(&object_data)),
            MmsData::Unsigned(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(6), Length::Definite(0)), BerObjectContent::Integer(&object_data)),
            MmsData::FloatingPoint(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(7), Length::Definite(0)), BerObjectContent::OctetString(&object_data)),
            MmsData::OctetString(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(8), Length::Definite(0)), BerObjectContent::OctetString(&object_data)),
            MmsData::VisibleString(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(5), Length::Definite(0)), BerObjectContent::VisibleString(&object_data)),
            MmsData::GeneralizedTime(instant) => todo!(),
            MmsData::BinaryTime(items) => todo!(),
            MmsData::Bcd(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(13), Length::Definite(0)), BerObjectContent::Integer(&object_data)),
            MmsData::BooleanArray(paddibg, object_data) => BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, false, Tag::from(14), Length::Definite(0)),
                BerObjectContent::BitString(*paddibg, BitStringObject { data: &object_data }),
            ),
            MmsData::ObjectId(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(15), Length::Definite(0)), BerObjectContent::OID(object_data.to_owned())),
            MmsData::MmsString(object_data) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(16), Length::Definite(0)), BerObjectContent::VisibleString(&object_data)),
        };
        Ok(payload)
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
        let acse_connection = self
            .acse_responder
            .accept(repsonse.serialise()?)
            .await
            .map_err(|e| MmsError::ProtocolError(format!("Failed to initiate MMS connection: {:?}", e)))?;
        let (acse_reader, acse_writer) = acse_connection.split().await.map_err(|e| MmsError::ProtocolError(format!("Failed to initiate MMS connection: {:?}", e)))?;
        Ok(RustyMmsConnection::<R, W>::new(acse_reader, acse_writer))
    }
}

pub struct RustyMmsConnection<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> {
    acse_reader: R,
    acse_writer: W,
}

impl<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> RustyMmsConnection<R, W> {
    pub fn new(acse_reader: impl OsiSingleValueAcseReader, acse_writer: impl OsiSingleValueAcseWriter) -> RustyMmsConnection<impl OsiSingleValueAcseReader, impl OsiSingleValueAcseWriter> {
        RustyMmsConnection { acse_reader, acse_writer }
    }
}

impl<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> MmsConnection for RustyMmsConnection<R, W> {
    async fn split(self) -> Result<(impl MmsReader, impl MmsWriter), MmsError> {
        Ok((RustyMmsReader::new(self.acse_reader), RustyMmsWriter::new(self.acse_writer)))
    }
}

pub struct RustyMmsReader<R: OsiSingleValueAcseReader> {
    acse_reader: R,
}

impl<R: OsiSingleValueAcseReader> RustyMmsReader<R> {
    fn new(acse_reader: R) -> Self {
        RustyMmsReader { acse_reader }
    }
}

impl<R: OsiSingleValueAcseReader> MmsReader for RustyMmsReader<R> {
    async fn recv(&mut self) -> Result<MmsRecvResult, MmsError> {
        loop {
            let result = self.acse_reader.recv().await?;
            match result {
                AcseRecvResult::Closed => return Ok(MmsRecvResult::Closed),
                AcseRecvResult::Data(data) => {
                    let (_, message) = parse_ber_any(&data).map_err(to_mms_error("Failed to parse MMS message"))?;
                    match message.header.raw_tag() {
                        Some([160]) => return Ok(MmsRecvResult::Message(parse_confirmed_request(message)?)),
                        x => warn!("Failed to parse unknown MMS PDU: {:?}", x),
                    }
                }
            };
        }
    }
}

pub struct RustyMmsWriter<W: OsiSingleValueAcseWriter> {
    acse_writer: W,
}

impl<R: OsiSingleValueAcseWriter> RustyMmsWriter<R> {
    fn new(acse_writer: R) -> Self {
        RustyMmsWriter { acse_writer }
    }
}

impl<W: OsiSingleValueAcseWriter> MmsWriter for RustyMmsWriter<W> {
    async fn send(&mut self, message: MmsMessage) -> Result<(), MmsError> {
        let data = match message {
            MmsMessage::ConfirmedRequest { invocation_id, request } => confirmed_request_to_ber(&invocation_id, &request).to_vec(),
            MmsMessage::ConfirmedResponse { invocation_id, response } => confirmed_response_to_ber(&invocation_id, &response)?.to_vec(),
            x => todo!("Cannot send MMS message: {:?}", x),
        };
        self.acse_writer.send(data.map_err(to_mms_error("Failed to serialise message"))?).await?;
        Ok(())
    }
}

// impl<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> RustyMmsResponderConnection<R, W> {
//     pub fn new(acse_reader: impl OsiSingleValueAcseReader, acse_writer: impl OsiSingleValueAcseWriter) -> RustyMmsResponderConnection<impl OsiSingleValueAcseReader, impl OsiSingleValueAcseWriter> {
//         RustyMmsResponderConnection {
//             internal: Arc::new(Mutex::new(RustyMmsConnectionInternal::new(acse_reader, acse_writer))),
//         }
//     }
// }

// impl<R: OsiSingleValueAcseReader, W: OsiSingleValueAcseWriter> MmsConnection for MmsConnection<R, W> {
//     async fn recv(&mut self) -> Result<crate::MmsResponderRecvResult, MmsError> {
//         let acse_user_data = self.internal.lock().await.acse_reader.recv().await.map_err(|e| MmsError::ProtocolStackError(e))?;
//         let user_data = match acse_user_data {
//             AcseRecvResult::Closed => return Ok(MmsResponderRecvResult::Closed),
//             AcseRecvResult::Data(user_data) => user_data,
//         };
//         let (_, mms_pdu) = parse_ber_any(&user_data).map_err(|e| MmsError::ProtocolError(format!("Failed to parse MMS PDU: {:?}", e)))?;

//         match mms_pdu.header.raw_tag() {
//             Some(&[160]) => {
//                 let mut invocation_id = None;
//                 let mut mms_payload = None;

//                 for item in process_constructed_data(mms_pdu.data).map_err(to_mms_error("Failed to parse Confirmed Request PDU"))? {
//                     match item.header.raw_tag() {
//                         Some(&[2]) => invocation_id = Some(process_mms_integer_32_content(&item, "DSA")?),
//                         Some(&[164]) => mms_payload = Some(ConfirmedMmsPduType::ReadRequestPduType(ReadRequestPdu::parse(&item)?)),
//                         x => warn!("Failed to parse unknown MMS Confirmed Request Item: {:?}", x)
//                     }
//                 }

//                 let invocation_id = expect_value("ConfirmedRequest", "InvocationId", invocation_id)?;
//                 let mms_payload = expect_value("ConfirmedRequest", "MmsPayload", mms_payload)?;

//                 return Ok(MmsResponderRecvResult::Pdu(MmsPduType::ConfirmedRequestPduType(ConfirmedMmsPdu {
//                     invocation_id,
//                     payload: mms_payload,
//                 })));
//             },
//             x => warn!("Failed to parse unknown MMS PDU: {:?}", x)
//         }
//         return Err(MmsError::ProtocolError("failed to recv MMS payload".into()))
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_serialises_parameter_support_options_empty() -> Result<(), anyhow::Error> {
        Ok(())
    }
}
