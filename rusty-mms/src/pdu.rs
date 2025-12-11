use der_parser::{
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};

use crate::{
    MmsError,
    error::to_mms_error,
    parameters::{ParameterSupportOptions, ParameterSupportOptionsBerObject, ServiceSupportOptions, ServiceSupportOptionsBerObject},
};

#[repr(u8)]
pub(crate) enum MmsPduType {
    ConfirmedRequestPduType() = 0,
    ConfirmedResponsePduType = 1,
    ConfirmedErrorPduType = 2,

    UnconfirmedPduType = 3,

    RejectPduType = 4,
    CancelRequestPduType = 5,
    CancelResponsePduType = 6,
    CancelErrorPduType = 7,

    InitiateRequestPduType(InitiateRequestPdu) = 8,
    InitiateResponsePduType = 9,
    InitiateErrorPduType = 10,

    ConcludeRequestPduType = 11,
    ConcludeResponsePduType = 12,
    ConcludeErrorPduType = 13,
}

pub(crate) struct InitiateRequestPdu {
    local_detail_calling: Option<i32>,
    proposed_max_serv_outstanding_calling: i16,
    proposed_max_serv_outstanding_called: i16,
    proposed_data_structure_nesting_level: Option<i8>,
    init_request_details: InitRequestDetails,
}

pub(crate) struct InitRequestDetails {
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
        init_request_details: InitRequestDetails,
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
                        Header::new(Class::ContextSpecific, false, Tag::from(4), Length::Definite(0)),
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
        // let local_detail_calling = None;
        // let proposed_max_serv_outstanding_calling = None;
        // let proposed_max_serv_outstanding_called = None;
        // let proposed_data_structure_nesting_level = None;
        // let init_request_details = None;

        let (_, pdu) = der_parser::ber::parse_ber_any(&data).map_err(to_mms_error("Failed to parse MMS Init payload."))?;
        match pdu.header.raw_tag() {
            Some(&[8]) => return Err(MmsError::InternalError("Must Implement".into())),
            x => return Err(MmsError::InternalError(format!("Expected tag &[8] on MMS Init PDU but found {:?}", x)))
        }
    }
}

pub(crate) struct InitiateResponsePdu {
    local_detail_calling: Option<i32>,
    negotiated_max_serv_outstanding_calling: i16,
    negotiated_max_serv_outstanding_called: i16,
    negotiated_data_structure_nesting_level: Option<i8>,
    init_response_details: InitResponseDetails,
}

pub(crate) struct InitResponseDetails {
    proposed_version_number: i16,
    propsed_parameter_cbb: ParameterSupportOptions,
    services_supported_calling: ServiceSupportOptions,
}
