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
    parsers::{process_constructed_data, process_integer_content, process_mms_boolean_content, process_mms_integer_8_content, process_mms_integer_16_content, process_mms_integer_32_content, process_mms_parameter_support_options, process_mms_service_support_option}, pdu::common::expect_value,
};

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
