use std::marker::PhantomData;

use der_parser::{
    asn1_rs::{Any, BitString, ToDer},
    ber::{
        BerObject, BerObjectContent, BitStringObject,
        Length::{self, Definite},
    },
    der::{
        Class::{self, ContextSpecific},
        Header, Tag,
    },
};
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
}

pub struct InitiateResponsePdu {
    local_detail_calling: Option<i32>,
    negotiated_max_serv_outstanding_calling: i16,
    negotiated_max_serv_outstanding_called: i16,
    negotiated_data_structure_nesting_level: Option<i8>,
    init_response_details: InitResponseDetails,
}

fn serialise_mms_i32(tag: &[u8], value: i32) -> BerObject<'_> {
    BerObject::from_header_and_content(Header::new(ContextSpecific, false, Tag::Integer, Definite(0)), der_parser::ber::BerObjectContent::EndOfContent)
}

pub struct InitResponseDetails {
    proposed_version_number: i16,
    propsed_parameter_cbb: ParameterSupportOptions,
    services_supported_calling: ServiceSupportOptions,
}

pub struct ParameterSupportOptions {
    pub options: Vec<ParameterSupportOption>,
}

pub enum ParameterSupportOption {
    Str1,
    Str2,
    Vnam,
    Valt,
    Vlist,
    Unsupported(u8),
}

pub struct ServiceSupportOptions {
    options: Vec<ServiceSupportOption>,
}

pub enum ServiceSupportOption {
    GetNameList,                   // Bit 1
    Identify,                      // Bit 2
    Read,                          // Bit 4
    Write,                         // Bit 5
    GetVariableAccessAttributes,   // Bit 6
    GetNamedVariableListAttribute, // Bit 7
    DefineNamedVariableList,       // Bit 11
    DeleteNamedVariableList,       // Bit 13
    InformationReport,             // Bit 79
    Unsupported(u8),
}

struct ServiceSupportOptionsBerObject<'a> {
    data: [u8; 10],
    ignored_bits: u8,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ServiceSupportOptionsBerObject<'a> {
    // 0b01101110 0b00011100 0b00000000 0b00000000 0b00000000 0b00000000 0b00000000 0b00000000 0b00000000 0b00000001
    fn new(service_support_options: ServiceSupportOptions) -> ServiceSupportOptionsBerObject<'a> {
        let mut obj = ServiceSupportOptionsBerObject {
            ignored_bits: 80,
            data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            _lifetime: PhantomData::<&'a ()>,
        };

        for option in service_support_options.options {
            match option {
                ServiceSupportOption::GetNameList => {
                    obj.ignored_bits = obj.ignored_bits.min(78);
                    obj.data[0] |= 0x40;
                }
                ServiceSupportOption::Identify => {
                    obj.ignored_bits = obj.ignored_bits.min(77);
                    obj.data[0] |= 0x20;
                }
                ServiceSupportOption::Read => {
                    obj.ignored_bits = obj.ignored_bits.min(75);
                    obj.data[0] |= 0x08;
                }
                ServiceSupportOption::Write => {
                    obj.ignored_bits = obj.ignored_bits.min(74);
                    obj.data[0] |= 0x40;
                }
                _ => (),
            }
        }

        obj
    }

    fn to_ber_object(&'a self, tag: Tag) -> BerObject<'a> {
        BerObject::from_header_and_content(
            Header::new(Class::ContextSpecific, false, tag, Length::Definite(0)),
            BerObjectContent::BitString(self.ignored_bits, BitStringObject { data: &self.data }),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn it_serialises_service_support_options2() -> Result<(), anyhow::Error> {
        match ServiceSupportOptionsBerObject::new(ServiceSupportOptions { options: vec![] }).to_ber_object(Tag::from(3)).content {
            BerObjectContent::BitString(_, bit_string_object) => {
                assert!(!bit_string_object.is_set(0));
                assert!(!bit_string_object.is_set(1));
                assert!(!bit_string_object.is_set(2));
                assert!(!bit_string_object.is_set(4));
                assert!(!bit_string_object.is_set(5));
                assert!(!bit_string_object.is_set(6));
                assert!(!bit_string_object.is_set(7));
                assert!(!bit_string_object.is_set(11));
                assert!(!bit_string_object.is_set(13));
                assert!(!bit_string_object.is_set(79));
            }
            x => return Err(anyhow::anyhow!("Expected bit string but got {:?}", x)),
        };

        match ServiceSupportOptionsBerObject::new(ServiceSupportOptions { options: vec![ServiceSupportOption::GetNameList] }).to_ber_object(Tag::from(3)).content {
            BerObjectContent::BitString(_, bit_string_object) => {
                assert!(!bit_string_object.is_set(0));
                assert!(bit_string_object.is_set(1));
                assert!(!bit_string_object.is_set(2));
                assert!(!bit_string_object.is_set(4));
                assert!(!bit_string_object.is_set(5));
                assert!(!bit_string_object.is_set(6));
                assert!(!bit_string_object.is_set(7));
                assert!(!bit_string_object.is_set(11));
                assert!(!bit_string_object.is_set(13));
                assert!(!bit_string_object.is_set(79));
            }
            x => return Err(anyhow::anyhow!("Expected bit string but got {:?}", x)),
        };

                match ServiceSupportOptionsBerObject::new(ServiceSupportOptions { options: vec![ServiceSupportOption::GetNameList] }).to_ber_object(Tag::from(3)).content {
            BerObjectContent::BitString(_, bit_string_object) => {
                assert!(!bit_string_object.is_set(0));
                assert!(bit_string_object.is_set(1));
                assert!(!bit_string_object.is_set(2));
                assert!(!bit_string_object.is_set(4));
                assert!(!bit_string_object.is_set(5));
                assert!(!bit_string_object.is_set(6));
                assert!(!bit_string_object.is_set(7));
                assert!(!bit_string_object.is_set(11));
                assert!(!bit_string_object.is_set(13));
                assert!(!bit_string_object.is_set(79));
            }
            x => return Err(anyhow::anyhow!("Expected bit string but got {:?}", x)),
        };

        Ok(())
    }
}
