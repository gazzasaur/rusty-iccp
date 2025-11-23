use std::fmt::Debug;

use der_parser::{
    asn1_rs::Any,
    ber::{BerObjectContent, BitStringObject, parse_ber_any, parse_ber_content, parse_ber_integer, parse_ber_oid},
    der::{Class, Tag},
    error::BerError,
    parse_ber,
};
use tracing::warn;

use crate::{AcseError, AcseRequestInformation, AcseResponseInformation, AeQualifier, ApTitle, AssociateResult, AssociateSourceDiagnostic};

pub(crate) fn to_acse_error<T: Debug>(message: &str) -> impl FnOnce(T) -> AcseError {
    move |error| AcseError::ProtocolError(format!("{}: {:?}", message, error))
}

pub(crate) fn process_request(data: &[u8]) -> Result<(AcseRequestInformation, Vec<u8>), AcseError> {
    let mut version = BitStringObject { data: &[0x80] }; // Default protocol version 1
    let mut application_context_name = None;
    let mut called_ap_title = None;
    let mut called_ae_qualifier = None;
    let mut called_ap_invocation_identifier = None;
    let mut called_ae_invocation_identifier = None;
    let mut calling_ap_title = None;
    let mut calling_ae_qualifier = None;
    let mut calling_ap_invocation_identifier = None;
    let mut calling_ae_invocation_identifier = None;
    let mut implementation_information = None;
    let mut payload_user_data = None;

    let (_, pdu) = parse_ber_any(&data).map_err(to_acse_error("Failed to parse ACSE Request"))?;
    pdu.header.assert_class(Class::Application).map_err(to_acse_error("Expected ACSE Request was not found"))?;
    pdu.header.assert_tag(Tag::from(0)).map_err(to_acse_error("Expected ACSE Request was not found"))?;
    pdu.header.assert_constructed().map_err(to_acse_error("Expected ACSE Request was not found"))?;
    let pdu_parts = process_constructed_data(pdu.data).map_err(to_acse_error("Could not deconstruct ACSE Request"))?;

    for pdu_part in pdu_parts {
        match pdu_part.header.raw_tag() {
            Some(&[128]) => version = process_bitstring(pdu_part, "Failed to extract protocol version from ACSE Request")?,
            Some(&[161]) => application_context_name = Some(parse_ber_oid(pdu_part.data).map_err(to_acse_error("Failed to parse Application Context Name in ACSE Request"))?.1),

            Some(&[162]) => called_ap_title = Some(process_ap_title(pdu_part, "Failed to parse Called AP Title in ACSE Request")?),
            Some(&[163]) => called_ae_qualifier = Some(process_ae_qualifier(pdu_part, "Failed to parse Called AE Title in ACSE Request")?),
            Some(&[164]) => called_ap_invocation_identifier = Some(process_integer(pdu_part.data, "Failed to parse Called AP Invocation Identifier in ACSE Request")?),
            Some(&[165]) => called_ae_invocation_identifier = Some(process_integer(pdu_part.data, "Failed to parse Called AE Invocation Identifier in ACSE Request")?),

            Some(&[166]) => calling_ap_title = Some(process_ap_title(pdu_part, "Failed to parse Calling AP Title in ACSE Request")?),
            Some(&[167]) => calling_ae_qualifier = Some(process_ae_qualifier(pdu_part, "Failed to parse Calling AE Title in ACSE Request")?),
            Some(&[168]) => calling_ap_invocation_identifier = Some(process_integer(pdu_part.data, "Failed to parse Calling AP Invocation Identifier in ACSE Request")?),
            Some(&[169]) => calling_ae_invocation_identifier = Some(process_integer(pdu_part.data, "Failed to parse Calling AE Invocation Identifier in ACSE Request")?),

            Some(&[157]) => implementation_information = Some(process_graphical_string(pdu_part, "Failed to parse Implementation Information in ACSE Request")?),
            Some(&[190]) => {
                for user_data_part in process_constructed_data(pdu_part.data).map_err(to_acse_error("Failed to deconstruct UserInformation on ACSE Request".into()))? {
                    match user_data_part.header.raw_tag() {
                        Some(&[40]) => {
                            for single_value_part in process_constructed_data(user_data_part.data).map_err(to_acse_error("Failed to deconstruct Single Value part in ACSE Request"))? {
                                let mut context_id = None;
                                match single_value_part.header.raw_tag() {
                                    Some(&[2]) => context_id = Some(process_integer_context(single_value_part, "Failed to parse context id from Single Value part in ACSE Request")?),
                                    Some(&[160]) => payload_user_data = Some(single_value_part.data.to_vec()),
                                    x => warn!("Unknown tag in ACSE Request User Data Single Value part: {:?}", x),
                                }
                                if let Some(cid) = context_id
                                    && cid != &[3]
                                {
                                    return Err(AcseError::ProtocolError(format!("Incorrect context id found for User Data in ACSE Request: Expected [3] but got {:?}", cid)));
                                }
                            }
                        }
                        x => warn!("Unknown tag in ACSE Request User Data: {:?}", x),
                    };
                }
            }
            x => warn!("Unexpected tag in ACSE Request: {:?}", x),
        }
    }

    if !version.is_set(0) {
        return Err(AcseError::ProtocolError("Unsupported ACSE version requested".into()));
    }
    let payload_user_data = match payload_user_data {
        Some(payload_user_data) => payload_user_data,
        None => return Err(AcseError::ProtocolError("No User Data found on ACSE Request".into())),
    };

    Ok((
        AcseRequestInformation {
            application_context_name: application_context_name
                .ok_or_else(|| AcseError::ProtocolError("No Application Context Name was present on the ACSE request".into()))?
                .as_oid_val()
                .map_err(to_acse_error("Failed to extract Application Context Name OID from ACSE Request"))?
                .to_owned(),
            called_ap_title,
            called_ae_qualifier,
            called_ap_invocation_identifier,
            called_ae_invocation_identifier,
            calling_ap_title,
            calling_ae_qualifier,
            calling_ap_invocation_identifier,
            calling_ae_invocation_identifier,
            implementation_information,
        },
        payload_user_data,
    ))
}

pub(crate) fn process_response(data: &[u8]) -> Result<(AcseResponseInformation, Vec<u8>), AcseError> {
    let mut version = BitStringObject { data: &[0x80] }; // Default protocol version 1
    let mut response_results = None;
    let mut response_diagnostics = None;
    let mut application_context_name = None;
    let mut responding_ap_title = None;
    let mut responding_ae_qualifier = None;
    let mut responding_ap_invocation_identifier = None;
    let mut responding_ae_invocation_identifier = None;
    let mut implementation_information = None;
    let mut payload_user_data = None;

    let (_, pdu) = parse_ber_any(&data).map_err(to_acse_error("Failed to parse ACSE Response"))?;
    pdu.header.assert_class(Class::Application).map_err(to_acse_error("Expected ACSE Response was not found"))?;
    pdu.header.assert_tag(Tag::from(1)).map_err(to_acse_error("Expected ACSE Response was not found"))?;
    pdu.header.assert_constructed().map_err(to_acse_error("Expected ACSE Response was not found"))?;
    let pdu_parts = process_constructed_data(pdu.data).map_err(to_acse_error("Could not deconstruct ACSE Response"))?;

    for pdu_part in pdu_parts {
        match pdu_part.header.raw_tag() {
            Some(&[128]) => version = process_bitstring(pdu_part, "Failed to extract protocol version from ACSE Response")?,
            Some(&[161]) => application_context_name = Some(parse_ber_oid(pdu_part.data).map_err(to_acse_error("Failed to parse Application Context Name in ACSE Response"))?.1),

            Some(&[162]) => response_results = Some(process_response_result(pdu_part.data, "Failed to parse Application Context Name in ACSE Response")?),
            Some(&[163]) => response_diagnostics = Some(process_response_diagnostics(pdu_part.data, "Failed to parse Application Context Name in ACSE Response")?),
            Some(&[164]) => responding_ap_title = Some(process_ap_title(pdu_part, "Failed to parse Called AP Title in ACSE Response")?),
            Some(&[165]) => responding_ae_qualifier = Some(process_ae_qualifier(pdu_part, "Failed to parse Called AE Title in ACSE Response")?),
            Some(&[166]) => responding_ap_invocation_identifier = Some(process_integer(pdu_part.data, "Failed to parse Called AP Invocation Identifier in ACSE Response")?),
            Some(&[167]) => responding_ae_invocation_identifier = Some(process_integer(pdu_part.data, "Failed to parse Called AE Invocation Identifier in ACSE Response")?),

            Some(&[157]) => implementation_information = Some(process_graphical_string(pdu_part, "Failed to parse Implementation Information in ACSE Response")?),
            Some(&[190]) => {
                for user_data_part in process_constructed_data(pdu_part.data).map_err(to_acse_error("Failed to deconstruct UserInformation on ACSE Response".into()))? {
                    match user_data_part.header.raw_tag() {
                        Some(&[40]) => {
                            for single_value_part in process_constructed_data(user_data_part.data).map_err(to_acse_error("Failed to deconstruct Single Value part in ACSE Response"))? {
                                let mut context_id = None;
                                match single_value_part.header.raw_tag() {
                                    Some(&[2]) => context_id = Some(process_integer_context(single_value_part, "Failed to parse context id from Single Value part in ACSE Response")?),
                                    Some(&[160]) => payload_user_data = Some(single_value_part.data.to_vec()),
                                    x => warn!("Unknown tag in ACSE Response User Data Single Value part: {:?}", x),
                                }
                                if let Some(cid) = context_id
                                    && cid != &[3]
                                {
                                    return Err(AcseError::ProtocolError(format!("Incorrect context id found for User Data in ACSE Response: Expected [3] but got {:?}", cid)));
                                }
                            }
                        }
                        x => warn!("Unknown tag in ACSE Response User Data: {:?}", x),
                    };
                }
            }
            x => warn!("Unexpected tag in ACSE Response: {:?}", x),
        }
    }

    if !version.is_set(0) {
        return Err(AcseError::ProtocolError("Unsupported ACSE version requested".into()));
    }
    let payload_user_data = match payload_user_data {
        Some(payload_user_data) => payload_user_data,
        None => return Err(AcseError::ProtocolError("No User Data found on ACSE Request".into())),
    };

    Ok((
        AcseResponseInformation {
            application_context_name: application_context_name
                .ok_or_else(|| AcseError::ProtocolError("No Application Context Name was present on the ACSE request".into()))?
                .as_oid_val()
                .map_err(to_acse_error("Failed to extract Application Context Name OID from ACSE Request"))?
                .to_owned(),
            associate_result: response_results.ok_or_else(|| AcseError::ProtocolError("No response result was found on ACSE Response".into()))?,
            associate_source_diagnostic: response_diagnostics.ok_or_else(|| AcseError::ProtocolError("No response diagnostics were found on ACSE Response".into()))?,
            responding_ap_title,
            responding_ae_qualifier,
            responding_ap_invocation_identifier,
            responding_ae_invocation_identifier,
            implementation_information,
        },
        payload_user_data,
    ))
}

pub(crate) fn process_constructed_data<'a>(data: &'a [u8]) -> Result<Vec<Any<'a>>, BerError> {
    let mut remaining = data;
    let mut results = vec![];

    while remaining.len() > 0 {
        let (rem, obj) = parse_ber_any(remaining)?;
        results.push(obj);
        remaining = rem;
    }
    Ok(results)
}

pub(crate) fn process_bitstring<'a>(npm_object: Any<'a>, error_message: &str) -> Result<BitStringObject<'a>, AcseError> {
    let (_, inner_object) = parse_ber_content(Tag::BitString)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_acse_error(error_message))?;

    match inner_object {
        BerObjectContent::BitString(_, value) => Ok(value),
        _ => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_integer<'a>(data: &[u8], error_message: &str) -> Result<Vec<u8>, AcseError> {
    let (_, inner_object) = parse_ber_integer(data).map_err(to_acse_error(error_message))?;

    match inner_object.content {
        BerObjectContent::Integer(value) => Ok(value.to_vec()),
        _ => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_integer_context<'a>(npm_object: Any<'a>, error_message: &str) -> Result<Vec<u8>, AcseError> {
    let (_, inner_object) = parse_ber_content(Tag::Integer)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_acse_error(error_message))?;

    match inner_object {
        BerObjectContent::Integer(value) => Ok(value.to_vec()),
        _ => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_graphical_string<'a>(npm_object: Any<'a>, error_message: &str) -> Result<String, AcseError> {
    let (_, inner_object) = parse_ber_content(Tag::GeneralString)(npm_object.data, &npm_object.header, npm_object.data.len()).map_err(to_acse_error(error_message))?;

    match inner_object {
        BerObjectContent::GeneralString(value) => Ok(value.to_owned()),
        _ => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_ap_title<'a>(npm_object: Any<'a>, error_message: &str) -> Result<ApTitle, AcseError> {
    let (_, ap_title) = parse_ber(npm_object.data).map_err(to_acse_error(error_message))?;

    match (ap_title.header.tag(), ap_title.content) {
        (Tag::Oid, BerObjectContent::OID(oid)) => Ok(ApTitle::Form2(oid.to_owned())),
        (_, _) => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_ae_qualifier<'a>(npm_object: Any<'a>, error_message: &str) -> Result<AeQualifier, AcseError> {
    let (_, ap_title) = parse_ber(npm_object.data).map_err(to_acse_error(error_message))?;

    match (ap_title.header.tag(), ap_title.content) {
        (Tag::Integer, BerObjectContent::Integer(qualifier)) => Ok(AeQualifier::Form2(qualifier.to_owned())),
        (_, _) => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_response_result<'a>(data: &[u8], error_message: &str) -> Result<AssociateResult, AcseError> {
    let (_, inner_object) = parse_ber_integer(data).map_err(to_acse_error(error_message))?;

    match inner_object.content {
        BerObjectContent::Integer(x) if x == &[0] => Ok(AssociateResult::Accepted),
        BerObjectContent::Integer(x) if x == &[1] => Ok(AssociateResult::RejectedPermanent),
        BerObjectContent::Integer(x) if x == &[2] => Ok(AssociateResult::RejectedTransient),
        BerObjectContent::Integer(x) => Ok(AssociateResult::Unknown(x.to_vec())),
        _ => Err(AcseError::ProtocolError(error_message.into())),
    }
}

pub(crate) fn process_response_diagnostics<'a>(data: &[u8], error_message: &str) -> Result<AssociateSourceDiagnostic, AcseError> {
    let (_, inner_object) = parse_ber_any(data).map_err(to_acse_error(error_message))?;
    let context_specific_code = process_integer(inner_object.data, error_message).map_err(to_acse_error(error_message))?;

    match (inner_object.header.raw_tag(), context_specific_code) {
        (Some(&[161]), x) if x == vec![0] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::Null)),
        (Some(&[161]), x) if x == vec![1] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::NoReasonGiven)),
        (Some(&[161]), x) if x == vec![2] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::ApplicationContextNameNotSupported)),
        (Some(&[161]), x) if x == vec![3] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::CallingApTitleNotRecognized)),
        (Some(&[161]), x) if x == vec![4] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::CallingApInvocationIdentifierNotRecognized)),
        (Some(&[161]), x) if x == vec![5] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::CallingAeQualifierNotRecognized)),
        (Some(&[161]), x) if x == vec![6] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::CallingAeInvocationIdentifierNotRecognized)),
        (Some(&[161]), x) if x == vec![7] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::CalledApTitleNotRecognized)),
        (Some(&[161]), x) if x == vec![8] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::CalledApInvocationIdentifierNotRecognized)),
        (Some(&[161]), x) if x == vec![9] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::CalledAeQualifierNotRecognized)),
        (Some(&[161]), x) if x == vec![10] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::CalledAeInvocationIdentifierNotRecognized)),
        (Some(&[161]), x) if x == vec![11] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::AuthenticationMechanismNameNotRecognized)),
        (Some(&[161]), x) if x == vec![12] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::AuthenticationMechanismNameRequired)),
        (Some(&[161]), x) if x == vec![13] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::AuthenticationFailure)),
        (Some(&[161]), x) if x == vec![14] => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::AuthenticationRequired)),
        (Some(&[161]), x) => Ok(AssociateSourceDiagnostic::User(crate::AssociateSourceDiagnosticUserCategory::Unknown(x))),
        (Some(&[162]), x) if x == vec![0] => Ok(AssociateSourceDiagnostic::Provider(crate::AssociateSourceDiagnosticProviderCategory::Null)),
        (Some(&[162]), x) if x == vec![0] => Ok(AssociateSourceDiagnostic::Provider(crate::AssociateSourceDiagnosticProviderCategory::NoReasonGiven)),
        (Some(&[162]), x) if x == vec![0] => Ok(AssociateSourceDiagnostic::Provider(crate::AssociateSourceDiagnosticProviderCategory::NoCommonAcseVersion)),
        (Some(x), _) => Ok(AssociateSourceDiagnostic::Unknown(x.to_vec())),
        _ => Err(AcseError::ProtocolError(error_message.into())),
    }
}
