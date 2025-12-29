use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length, parse_ber_any},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsError, MmsVariableAccessSpecification,
    error::to_mms_error,
    parameters::{ParameterSupportOptions, ParameterSupportOptionsBerObject, ServiceSupportOptions, ServiceSupportOptionsBerObject},
    parsers::{process_constructed_data, process_integer_content, process_mms_boolean_content, process_mms_integer_8_content, process_mms_integer_16_content, process_mms_integer_32_content, process_mms_parameter_support_options, process_mms_service_support_option},
};

#[repr(u8)]
pub(crate) enum MmsPduType {
    ConfirmedRequestPduType(ConfirmedMmsPdu) = 0,
    ConfirmedResponsePduType = 1,
    ConfirmedErrorPduType = 2,

    UnconfirmedPduType = 3,

    RejectPduType = 4,
    CancelRequestPduType = 5,
    CancelResponsePduType = 6,
    CancelErrorPduType = 7,

    InitiateRequestPduType(InitiateRequestPdu) = 8,
    InitiateResponsePduType(InitiateResponsePdu) = 9,
    InitiateErrorPduType = 10,

    ConcludeRequestPduType = 11,
    ConcludeResponsePduType = 12,
    ConcludeErrorPduType = 13,
}

pub(crate) struct ConfirmedMmsPdu {
    pub(crate) invocation_id: i32,
    pub(crate) payload: ConfirmedMmsPduType,
}

#[repr(u8)]
pub(crate) enum ConfirmedMmsPduType {
    ReadRequestPduType(ReadRequestPdu) = 1,
}

pub(crate) struct InitiateRequestPdu {
    local_detail_calling: Option<i32>,
    proposed_max_serv_outstanding_calling: i16,
    proposed_max_serv_outstanding_called: i16,
    proposed_data_structure_nesting_level: Option<i8>,
    init_request_details: InitRequestResponseDetails,
}

pub(crate) struct InitRequestResponseDetails {
    pub proposed_version_number: i16,
    pub propsed_parameter_cbb: ParameterSupportOptions,
    pub services_supported_calling: ServiceSupportOptions,
}

impl InitiateRequestPdu {
    pub(crate) fn new(
        local_detail_calling: Option<i32>,
        proposed_max_serv_outstanding_calling: i16,
        proposed_max_serv_outstanding_called: i16,
        proposed_data_structure_nesting_level: Option<i8>,
        init_request_details: InitRequestResponseDetails,
    ) -> Self {
        Self {
            local_detail_calling,
            proposed_max_serv_outstanding_calling,
            proposed_max_serv_outstanding_called,
            proposed_data_structure_nesting_level,
            init_request_details,
        }
    }

    pub(crate) fn serialise(self) -> Result<Vec<u8>, MmsError> {
        let local_detail_calling = self.local_detail_calling.map(|x| x.to_be_bytes());
        let proposed_max_serv_outstanding_calling = self.proposed_max_serv_outstanding_calling.to_be_bytes();
        let proposed_max_serv_outstanding_called = self.proposed_max_serv_outstanding_called.to_be_bytes();
        let proposed_data_structure_nesting_level = self.proposed_data_structure_nesting_level.map(|x| x.to_be_bytes());
        let propsed_parameter_cbb = ParameterSupportOptionsBerObject::new(self.init_request_details.propsed_parameter_cbb);
        let services_supported_calling = ServiceSupportOptionsBerObject::new(self.init_request_details.services_supported_calling);

        BerObject::from_header_and_content(
            Header::new(Class::ContextSpecific, true, Tag::from(8), Length::Definite(0)),
            BerObjectContent::Sequence(
                vec![
                    local_detail_calling
                        .as_ref()
                        .map(|x| BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)), BerObjectContent::Integer(x))),
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, false, Tag::from(1), Length::Definite(0)),
                        BerObjectContent::Integer(&proposed_max_serv_outstanding_calling),
                    )),
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, false, Tag::from(2), Length::Definite(0)),
                        BerObjectContent::Integer(&proposed_max_serv_outstanding_called),
                    )),
                    proposed_data_structure_nesting_level
                        .as_ref()
                        .map(|x| BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(3), Length::Definite(0)), BerObjectContent::Integer(x))),
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(4), Length::Definite(0)),
                        BerObjectContent::Sequence(vec![
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)),
                                BerObjectContent::Integer(&self.init_request_details.proposed_version_number.to_be_bytes()),
                            ),
                            propsed_parameter_cbb.to_ber_object(Tag::from(1)),
                            services_supported_calling.to_ber_object(Tag::from(2)),
                        ]),
                    )),
                ]
                .into_iter()
                .filter_map(|i| i)
                .collect(),
            ),
        )
        .to_vec()
        .map_err(to_mms_error(""))
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<InitiateRequestPdu, MmsError> {
        let mut local_detail_calling = None;
        let mut proposed_max_serv_outstanding_calling = None;
        let mut proposed_max_serv_outstanding_called = None;
        let mut proposed_data_structure_nesting_level = None;
        let mut init_request_details = None;

        let (_, pdu) = der_parser::ber::parse_ber_any(&data).map_err(to_mms_error("Failed to parse MMS Init payload."))?;
        match pdu.header.raw_tag() {
            Some([168]) => {
                for item in &process_constructed_data(pdu.data).map_err(to_mms_error("Failed to parse MMS outer payload."))? {
                    match item.header.raw_tag() {
                        Some([128]) => local_detail_calling = Some(process_mms_integer_32_content(item, "Failed to parse local detail calling on MMS request")?),
                        Some([129]) => proposed_max_serv_outstanding_calling = Some(process_mms_integer_16_content(item, "Failed to parse proposed max serv outstanding calling on MMS request")?),
                        Some([130]) => proposed_max_serv_outstanding_called = Some(process_mms_integer_16_content(item, "Failed to parse proposed max serv outstanding called on MMS request")?),
                        Some([131]) => proposed_data_structure_nesting_level = Some(process_mms_integer_8_content(item, "Failed to parse process proposed data structure nesting level on MMS request")?),
                        Some([164]) => init_request_details = Some(InitRequestResponseDetails::parse("InitiateRequest", item)?),
                        x => warn!("Unknown MMS Request item {:?}", x),
                    }
                }
            }
            x => return Err(MmsError::InternalError(format!("Expected tag &[168] on MMS Init Request PDU but found {:?}", x))),
        }

        Ok(InitiateRequestPdu {
            local_detail_calling: local_detail_calling,
            proposed_max_serv_outstanding_calling: expect_value("InitiateRequest", "ProposedMaxServOutstandingCalling", proposed_max_serv_outstanding_calling)?,
            proposed_max_serv_outstanding_called: expect_value("InitiateRequest", "ProposedMaxServOutstandingCalled", proposed_max_serv_outstanding_called)?,
            proposed_data_structure_nesting_level: proposed_data_structure_nesting_level,
            init_request_details: expect_value("InitiateRequest", "InitRequestDetails", init_request_details)?,
        })
    }
}

pub(crate) struct InitiateResponsePdu {
    local_detail_calling: Option<i32>,
    negotiated_max_serv_outstanding_calling: i16,
    negotiated_max_serv_outstanding_called: i16,
    negotiated_data_structure_nesting_level: Option<i8>,
    init_response_details: InitRequestResponseDetails,
}

impl InitiateResponsePdu {
    pub(crate) fn new(
        local_detail_calling: Option<i32>,
        negotiated_max_serv_outstanding_calling: i16,
        negotiated_max_serv_outstanding_called: i16,
        negotiated_data_structure_nesting_level: Option<i8>,
        init_response_details: InitRequestResponseDetails,
    ) -> Self {
        Self {
            local_detail_calling,
            negotiated_max_serv_outstanding_calling,
            negotiated_max_serv_outstanding_called,
            negotiated_data_structure_nesting_level,
            init_response_details,
        }
    }

    pub(crate) fn serialise(self) -> Result<Vec<u8>, MmsError> {
        let local_detail_calling = self.local_detail_calling.map(|x| x.to_be_bytes());
        let negotiated_max_serv_outstanding_calling = self.negotiated_max_serv_outstanding_calling.to_be_bytes();
        let negotiated_max_serv_outstanding_called = self.negotiated_max_serv_outstanding_called.to_be_bytes();
        let negotiated_data_structure_nesting_level = self.negotiated_data_structure_nesting_level.map(|x| x.to_be_bytes());
        let negotiated_parameter_cbb = ParameterSupportOptionsBerObject::new(self.init_response_details.propsed_parameter_cbb);
        let services_supported_calling = ServiceSupportOptionsBerObject::new(self.init_response_details.services_supported_calling);

        BerObject::from_header_and_content(
            Header::new(Class::ContextSpecific, true, Tag::from(9), Length::Definite(0)),
            BerObjectContent::Sequence(
                vec![
                    local_detail_calling
                        .as_ref()
                        .map(|x| BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)), BerObjectContent::Integer(x))),
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, false, Tag::from(1), Length::Definite(0)),
                        BerObjectContent::Integer(&negotiated_max_serv_outstanding_calling),
                    )),
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, false, Tag::from(2), Length::Definite(0)),
                        BerObjectContent::Integer(&negotiated_max_serv_outstanding_called),
                    )),
                    negotiated_data_structure_nesting_level
                        .as_ref()
                        .map(|x| BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(3), Length::Definite(0)), BerObjectContent::Integer(x))),
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(4), Length::Definite(0)),
                        BerObjectContent::Sequence(vec![
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)),
                                BerObjectContent::Integer(&self.init_response_details.proposed_version_number.to_be_bytes()),
                            ),
                            negotiated_parameter_cbb.to_ber_object(Tag::from(1)),
                            services_supported_calling.to_ber_object(Tag::from(2)),
                        ]),
                    )),
                ]
                .into_iter()
                .filter_map(|i| i)
                .collect(),
            ),
        )
        .to_vec()
        .map_err(to_mms_error(""))
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<InitiateResponsePdu, MmsError> {
        let mut local_detail_calling = None;
        let mut negotiated_max_serv_outstanding_calling = None;
        let mut negotiated_max_serv_outstanding_called = None;
        let mut negotiated_data_structure_nesting_level = None;
        let mut init_response_details = None;

        let (_, pdu) = der_parser::ber::parse_ber_any(&data).map_err(to_mms_error("Failed to parse MMS Init payload."))?;
        match pdu.header.raw_tag() {
            Some([169]) => {
                for item in &process_constructed_data(pdu.data).map_err(to_mms_error("Failed to parse MMS outer payload."))? {
                    match item.header.raw_tag() {
                        Some([128]) => local_detail_calling = Some(process_mms_integer_32_content(item, "Failed to parse local detail calling on MMS response")?),
                        Some([129]) => negotiated_max_serv_outstanding_calling = Some(process_mms_integer_16_content(item, "Failed to parse negotiated max serv outstanding calling on MMS response")?),
                        Some([130]) => negotiated_max_serv_outstanding_called = Some(process_mms_integer_16_content(item, "Failed to parse negotiated max serv outstanding called on MMS response")?),
                        Some([131]) => negotiated_data_structure_nesting_level = Some(process_mms_integer_8_content(item, "Failed to parse process negotiated data structure nesting level on MMS response")?),
                        Some([164]) => init_response_details = Some(InitRequestResponseDetails::parse("InitiateRequest", item)?),
                        x => warn!("Unknown MMS Request item {:?}", x),
                    }
                }
            }
            x => return Err(MmsError::InternalError(format!("Expected tag &[169] on MMS Init Response PDU but found {:?}", x))),
        }

        Ok(InitiateResponsePdu {
            local_detail_calling: local_detail_calling,
            negotiated_max_serv_outstanding_calling: expect_value("InitiateResponse", "NegotiatedMaxServOutstandingCalling", negotiated_max_serv_outstanding_calling)?,
            negotiated_max_serv_outstanding_called: expect_value("InitiateResponse", "NegotiatedMaxServOutstandingCalled", negotiated_max_serv_outstanding_called)?,
            negotiated_data_structure_nesting_level: negotiated_data_structure_nesting_level,
            init_response_details: expect_value("InitiateResponse", "InitResponseDetails", init_response_details)?,
        })
    }
}

impl InitRequestResponseDetails {
    pub(crate) fn parse(pdu: &str, value: &Any<'_>) -> Result<InitRequestResponseDetails, MmsError> {
        let mut proposed_version_number = None;
        let mut propsed_parameter_cbb = None;
        let mut services_supported_calling = None;

        for item in &process_constructed_data(value.data).map_err(to_mms_error("Failed to parse MMS details payload."))? {
            match item.header.raw_tag() {
                Some([128]) => proposed_version_number = Some(process_mms_integer_16_content(item, "Failed to parse proposed version number on MMS request")?),
                Some([129]) => propsed_parameter_cbb = Some(process_mms_parameter_support_options(&item, "Failed to parse propsed parameter cbb on MMS request")?),
                Some([130]) => services_supported_calling = Some(process_mms_service_support_option(&item, "Failed to parse services supported calling on MMS request")?),
                x => warn!("Unknown MMS Request item {:?}", x),
            }
        }

        Ok(InitRequestResponseDetails {
            proposed_version_number: proposed_version_number.ok_or_else(|| MmsError::ProtocolError("".into()))?,
            propsed_parameter_cbb: expect_value((pdu.to_string() + ":InitRequestResponseDetails").as_str(), "ProposedParameterCBB", propsed_parameter_cbb)?,
            services_supported_calling: expect_value((pdu.to_string() + ":InitRequestResponseDetails").as_str(), "ServicesSupportedCalling", services_supported_calling)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ReadRequestPdu {
    pub(crate) specification_with_result: Option<bool>,
    pub(crate) variable_access_specification: MmsVariableAccessSpecification,
}

impl ReadRequestPdu {
    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        BerObject::from_header_and_content(
            Header::new(Class::ContextSpecific, true, Tag::from(4), Length::Definite(0)),
            BerObjectContent::Sequence(
                vec![
                    match &self.specification_with_result {
                        Some(specification_with_result) => Some(BerObject::from_header_and_content(
                            Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)),
                            BerObjectContent::Boolean(*specification_with_result),
                        )),
                        None => None,
                    },
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
                        BerObjectContent::Sequence(vec![self.variable_access_specification.to_ber()]),
                    )),
                ]
                .into_iter()
                .filter_map(|i| i)
                .collect(),
            ),
        )
    }

    pub(crate) fn parse(pdu: &Any<'_>) -> Result<ReadRequestPdu, MmsError> {
        let mut specification_with_result = None;
        let mut variable_access_specification = None;

        match pdu.header.raw_tag() {
            Some(&[164]) => {
                for item in process_constructed_data(pdu.data).map_err(to_mms_error("Failed to parse MMS Request PDU"))? {
                    match item.header.raw_tag() {
                        Some([80]) => specification_with_result = Some(process_mms_boolean_content(&item, "Failed to parse Specification With Result parameter on MMS Request PDU")?),
                        Some([161]) => variable_access_specification = Some(MmsVariableAccessSpecification::parse("Read Request PDU", item.data)?),
                        x => return Err(MmsError::ProtocolError(format!("Unsupported tag in MMS Read Request PDU: {:?}", x))),
                    }
                }
            }
            x => return Err(MmsError::ProtocolError(format!("Expected MMS Read Request PDU to have a tag of 164 a but {:?} was found", x))),
        };

        let variable_access_specification = variable_access_specification.ok_or_else(|| MmsError::ProtocolError("No Variable Access Specification on Request PDU".into()))?;
        Ok(ReadRequestPdu {
            specification_with_result,
            variable_access_specification,
        })
    }
}

pub(crate) struct ReadResponsePdu {}

pub(crate) fn expect_value<T>(pdu: &str, field: &str, value: Option<T>) -> Result<T, MmsError> {
    value.ok_or_else(|| MmsError::ProtocolError(format!("MMS Payload '{}' must container the field '{}' but was not found.", pdu, field)))
}
