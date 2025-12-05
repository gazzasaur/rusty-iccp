use std::marker::PhantomData;

use der_parser::{
    ber::{
        BerObject, BerObjectContent, BitStringObject,
        Length::{self, Definite},
    },
    der::{
        Class::{self, ContextSpecific},
        Header, Tag,
    },
};

use crate::MmsError;

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

impl InitiateRequestPdu {
    pub fn new(local_detail_calling: Option<i32>, proposed_max_serv_outstanding_calling: i16, proposed_max_serv_outstanding_called: i16, proposed_data_structure_nesting_level: Option<i8>, init_request_details: InitRequestDetails) -> Self {
        Self {
            local_detail_calling,
            proposed_max_serv_outstanding_calling,
            proposed_max_serv_outstanding_called,
            proposed_data_structure_nesting_level,
            init_request_details,
        }
    }

    pub fn serialise(self) -> Result<Vec<u8>, MmsError> {
        let local_detail_calling = self.local_detail_calling.map(|x| x.to_be_bytes());
        let proposed_max_serv_outstanding_calling = self.proposed_max_serv_outstanding_calling.to_be_bytes();
        let proposed_max_serv_outstanding_called = self.proposed_max_serv_outstanding_called.to_be_bytes();
        let proposed_data_structure_nesting_level = self.proposed_data_structure_nesting_level.map(|x| x.to_be_bytes());

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
                ]
                .into_iter()
                .filter_map(|i| i)
                .collect(),
            ),
        );
        Ok(vec![])
    }
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
    Str1, // Bit 0
    Str2, // Bit 1
    Vnam, // Bit 2
    Valt, // Bit 3
    Vlis, // Bit 7
    Unsupported(u8),
}

struct ParameterSupportOptionsBerObject<'a> {
    data: [u8; 1],
    ignored_bits: usize,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ParameterSupportOptionsBerObject<'a> {
    fn new(parameter_support_options: ParameterSupportOptions) -> ParameterSupportOptionsBerObject<'a> {
        let mut obj = ParameterSupportOptionsBerObject {
            ignored_bits: 8,
            data: [0],
            _lifetime: PhantomData::<&'a ()>,
        };

        for option in parameter_support_options.options {
            match option {
                ParameterSupportOption::Str1 => {
                    obj.ignored_bits = obj.ignored_bits.min(7);
                    obj.data[0] |= 0x80;
                }
                ParameterSupportOption::Str2 => {
                    obj.ignored_bits = obj.ignored_bits.min(6);
                    obj.data[0] |= 0x40;
                }
                ParameterSupportOption::Vnam => {
                    obj.ignored_bits = obj.ignored_bits.min(5);
                    obj.data[0] |= 0x20;
                }
                ParameterSupportOption::Valt => {
                    obj.ignored_bits = obj.ignored_bits.min(4);
                    obj.data[0] |= 0x10;
                }
                ParameterSupportOption::Vlis => {
                    obj.ignored_bits = obj.ignored_bits.min(0);
                    obj.data[0] |= 0x01;
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
                    data: &self.data[0..(1 - self.ignored_bits / 8)],
                },
            ),
        )
    }
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
                    obj.ignored_bits = obj.ignored_bits.min(0);
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
    fn it_serialises_parameter_support_options_empty() -> Result<(), anyhow::Error> {
        let subject = ParameterSupportOptionsBerObject::new(ParameterSupportOptions { options: vec![] });
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
    fn it_serialises_parameter_support_options() -> Result<(), anyhow::Error> {
        let subject_bits = vec![
            (0, 7, vec![131u8, 2u8, 7u8, 128u8], ParameterSupportOption::Str1),
            (1, 6, vec![131u8, 2u8, 6u8, 64u8], ParameterSupportOption::Str2),
            (2, 5, vec![131u8, 2u8, 5u8, 32u8], ParameterSupportOption::Vnam),
            (3, 4, vec![131u8, 2u8, 4u8, 16u8], ParameterSupportOption::Valt),
            (7, 0, vec![131u8, 2u8, 0u8, 1u8], ParameterSupportOption::Vlis),
        ];

        for (subject_bit, expected_ignored_bits, expected_serilised_form, subject_option) in subject_bits {
            let subject = ParameterSupportOptionsBerObject::new(ParameterSupportOptions { options: vec![subject_option] });
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

    #[test]
    fn it_serialises_parameter_support_option_multiple() -> Result<(), anyhow::Error> {
        assert_eq!(
            vec![131, 2, 0, 129],
            ParameterSupportOptionsBerObject::new(ParameterSupportOptions {
                options: vec![ParameterSupportOption::Str1, ParameterSupportOption::Vlis]
            })
            .to_ber_object(Tag::from(3))
            .to_vec()?
        );

        Ok(())
    }

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
            (79, 0, vec![131u8, 11u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8], ServiceSupportOption::InformationReport),
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

    #[test]
    fn it_serialises_service_support_option_multiple() -> Result<(), anyhow::Error> {
        assert_eq!(
            vec![131, 11, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ServiceSupportOptionsBerObject::new(ServiceSupportOptions {
                options: vec![ServiceSupportOption::InformationReport, ServiceSupportOption::Read]
            })
            .to_ber_object(Tag::from(3))
            .to_vec()?
        );
        assert_eq!(
            vec![131, 2, 2, 12],
            ServiceSupportOptionsBerObject::new(ServiceSupportOptions {
                options: vec![ServiceSupportOption::Write, ServiceSupportOption::Read]
            })
            .to_ber_object(Tag::from(3))
            .to_vec()?
        );

        Ok(())
    }
}
