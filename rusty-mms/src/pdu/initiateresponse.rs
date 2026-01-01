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
    parsers::{process_constructed_data, process_integer_content, process_mms_boolean_content, process_mms_integer_8_content, process_mms_integer_16_content, process_mms_integer_32_content, process_mms_parameter_support_options, process_mms_service_support_option}, pdu::{common::expect_value, initiaterequest::InitRequestResponseDetails},
};

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
