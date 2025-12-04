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
    ignored_bits: usize,
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
                    obj.data[0] |= 0x04;
                }
                ServiceSupportOption::GetVariableAccessAttributes => {
                    obj.ignored_bits = obj.ignored_bits.min(73);
                    obj.data[0] |= 0x02;
                }
                ServiceSupportOption::GetNamedVariableListAttribute => {
                    obj.ignored_bits = obj.ignored_bits.min(72);
                    obj.data[0] |= 0x01;
                }
                ServiceSupportOption::DefineNamedVariableList => {
                    obj.ignored_bits = obj.ignored_bits.min(68);
                    obj.data[1] |= 0x10;
                }
                ServiceSupportOption::DeleteNamedVariableList => {
                    obj.ignored_bits = obj.ignored_bits.min(66);
                    obj.data[1] |= 0x04;
                }
                ServiceSupportOption::InformationReport => {
                    obj.ignored_bits = obj.ignored_bits.min(72);
                    obj.data[9] |= 0x01;
                }
                _ => (),
            }
        }

        obj
    }

    fn to_ber_object(&'a self, tag: Tag) -> BerObject<'a> {
        BerObject::from_header_and_content(
            Header::new(Class::ContextSpecific, false, tag, Length::Definite(0)),
            BerObjectContent::BitString(
                (self.ignored_bits % 8) as u8,
                BitStringObject {
                    data: &self.data[0..(10 - self.ignored_bits / 8)],
                },
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn it_serialises_service_support_options_empty() -> Result<(), anyhow::Error> {
        let subject = ServiceSupportOptionsBerObject::new(ServiceSupportOptions { options: vec![] });
        let subject_ber = subject.to_ber_object(Tag::from(3)).content;
        for test_bit in 1..100 {
            match &subject_ber {
                BerObjectContent::BitString(i, x) => assert!(!x.is_set(test_bit)),
                x => return Err(anyhow::anyhow!("Expected bit string but got {:?}", x)),
            }
        }
        assert_eq!(vec![131, 1, 0], subject.to_ber_object(Tag::from(3)).to_vec()?);

        Ok(())
    }

    #[test]
    fn it_serialises_service_support_options() -> Result<(), anyhow::Error> {
        let subject_bits = vec![
            (1, 6, vec![131u8, 2u8, 6u8, 64u8], ServiceSupportOption::GetNameList),
            (2, 5, vec![131u8, 2u8, 5u8, 32u8], ServiceSupportOption::Identify),
            (4, 3, vec![131u8, 2u8, 3u8, 8u8], ServiceSupportOption::Read),
            (5, 2, vec![131u8, 2u8, 2u8, 4u8], ServiceSupportOption::Write),
            (6, 1, vec![131u8, 2u8, 1u8, 2u8], ServiceSupportOption::GetVariableAccessAttributes),
            (7, 0, vec![131u8, 2u8, 0u8, 1u8], ServiceSupportOption::GetNamedVariableListAttribute),
            (11, 4, vec![131u8, 3u8, 4u8, 0u8, 16u8], ServiceSupportOption::DefineNamedVariableList),
            (13, 2, vec![131u8, 3u8, 2u8, 0u8, 4u8], ServiceSupportOption::DeleteNamedVariableList),
            (79, 0, vec![131u8, 3u8, 2u8, 0u8, 4u8], ServiceSupportOption::InformationReport),
        ];

        for (subject_bit, expected_ignored_bits, expected_serilised_form, subject_option) in subject_bits {
            let subject = ServiceSupportOptionsBerObject::new(ServiceSupportOptions { options: vec![subject_option] });
            let subject_ber = subject.to_ber_object(Tag::from(3)).content;
            for test_bit in 1..100 {
                match &subject_ber {
                    BerObjectContent::BitString(i, x) if test_bit == subject_bit => {
                        assert!(x.is_set(test_bit));
                        assert_eq!(*i as usize, expected_ignored_bits);
                        assert_eq!(&expected_serilised_form, &subject.to_ber_object(Tag::from(3)).to_vec()?);
                    }
                    BerObjectContent::BitString(i, x) if test_bit != subject_bit => assert!(!x.is_set(test_bit)),
                    x => return Err(anyhow::anyhow!("Expected bit string but got {:?}", x)),
                }
            }
        }

        Ok(())
    }
}
