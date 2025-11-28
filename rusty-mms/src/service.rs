use der_parser::{asn1_rs::Any, ber::BerObject, der::Header};
use rusty_copp::CoppResponder;

use crate::{MmsConnection, MmsError, MmsInitiator};

#[repr(u8)]
enum MmsPduType {
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

pub struct InitiateRequestPdu {
    local_detail_calling: Option<i32>,
    proposed_max_serv_outstanding_calling: i16,
    proposed_max_serv_outstanding_called: i16,
    proposed_data_structure_nesting_level: Option<i8>,
    init_request_details: InitRequestDetails,
}

pub struct InitRequestDetails {
    proposed_version_number: i16,
    propsed_parameter_cbb: ParameterSupportOptions,
    services_supported_calling: ServiceSupportOptions,
    additional_supported_calling: Option<AdditionalSupportOptions>, // Conditional csr, cspi
    additional_cbb_supported_calling: Option<AdditionalCbbSupportOptions>, // Conditional cspi
    privilege_class_identity_calling: Option<PrivilegeClassIdentityCalling>, // Conditional cspi
}

pub struct InitiateResponsePdu {
    local_detail_calling: Option<i32>,
    negotiated_max_serv_outstanding_calling: i16,
    negotiated_max_serv_outstanding_called: i16,
    negotiated_data_structure_nesting_level: Option<i8>,
    init_response_details: InitResponseDetails,
}

fn serialise_i32(tag: &[u8], value: i32) -> Any<'_> {
    BerObject::from_header_and_content(Header::new(, constructed, tag, length), content)
}

pub struct InitResponseDetails {
    proposed_version_number: i16,
    propsed_parameter_cbb: ParameterSupportOptions,
    services_supported_calling: ServiceSupportOptions,
    additional_supported_calling: Option<AdditionalSupportOptions>, // Conditional csr, cspi
    additional_cbb_supported_calling: Option<AdditionalCbbSupportOptions>, // Conditional cspi
    privilege_class_identity_calling: Option<PrivilegeClassIdentityCalling>, // Conditional cspi
}

pub struct ParameterSupportOptions {
}

pub struct ServiceSupportOptions {
}

pub struct AdditionalSupportOptions {
}

pub struct AdditionalCbbSupportOptions {
}

pub struct PrivilegeClassIdentityCalling {
}

// pub struct RustyMmsInitiator<T: CoppResponder> {
//     // fn initiate(self) -> impl std::future::Future<Output = Result<impl MmsConnection, MmsError>> + Send;
// }

// impl<T: CoppResponder> MmsInitiator for RustyMmsInitiator<T> {
//     async fn initiate(self) -> Result<impl MmsConnection, MmsError> {
//         todo!()
//     }
// }