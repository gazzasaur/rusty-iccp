use std::marker::PhantomData;

use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, BitStringObject, Length, parse_ber_content},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsBasicObjectClass, MmsError, MmsObjectClass, MmsObjectScope,
    error::to_mms_error,
    parsers::{process_constructed_data, process_mms_string},
};

pub(crate) struct ParameterSupportOptions {
    pub options: Vec<ParameterSupportOption>,
}

#[derive(Clone, Copy)]
pub enum ParameterSupportOption {
    Str1, // Bit 0
    Str2, // Bit 1
    Vnam, // Bit 2
    Valt, // Bit 3
    Vlis, // Bit 7
    Unsupported(u8),
}

pub(crate) struct ParameterSupportOptionsBerObject<'a> {
    data: [u8; 1],
    ignored_bits: usize,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ParameterSupportOptionsBerObject<'a> {
    pub(crate) fn new(parameter_support_options: ParameterSupportOptions) -> ParameterSupportOptionsBerObject<'a> {
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

    pub(crate) fn to_ber_object(&'a self, tag: Tag) -> BerObject<'a> {
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

pub(crate) struct ServiceSupportOptions {
    pub options: Vec<ServiceSupportOption>,
}

#[derive(Clone, Copy)]
pub enum ServiceSupportOption {
    GetNameList,                   // Bit 1
    Identify,                      // Bit 2
    Read,                          // Bit 4
    Write,                         // Bit 5
    GetVariableAccessAttributes,   // Bit 6
    DefineNamedVariableList,       // Bit 11
    GetNamedVariableListAttribute, // Bit 12
    DeleteNamedVariableList,       // Bit 13
    InformationReport,             // Bit 79
    Unsupported(u8),
}

pub(crate) struct ServiceSupportOptionsBerObject<'a> {
    data: [u8; 10],
    ignored_bits: usize,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ServiceSupportOptionsBerObject<'a> {
    pub(crate) fn new(service_support_options: ServiceSupportOptions) -> ServiceSupportOptionsBerObject<'a> {
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
                ServiceSupportOption::DefineNamedVariableList => {
                    obj.ignored_bits = obj.ignored_bits.min(68);
                    obj.data[1] |= 0x10;
                }
                ServiceSupportOption::GetNamedVariableListAttribute => {
                    obj.ignored_bits = obj.ignored_bits.min(67);
                    obj.data[1] |= 0x08;
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

    pub(crate) fn to_ber_object(&'a self, tag: Tag) -> BerObject<'a> {
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

impl MmsObjectClass {
    pub(crate) fn parse(_context: &str, value: &Any<'_>) -> Result<MmsObjectClass, MmsError> {
        match value.header.raw_tag() {
            Some([160]) => {
                let constructed_data = process_constructed_data(value.data).map_err(to_mms_error("Failed to parse MMS Object Class"))?;
                let data = constructed_data.last().ok_or_else(|| MmsError::ProtocolError("No content in MMS Object Class".into()))?;
                let basic_object_class = MmsBasicObjectClass::parse(data)?;
                Ok(MmsObjectClass::Basic(basic_object_class))
            }
            x => {
                warn!("Unsupported MMS Object Class tag: {:?}", x);
                Err(MmsError::ProtocolError(format!("Unsupported MMS Object Class tag: {:?}", x)))
            }
        }
    }

    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        match self {
            MmsObjectClass::Basic(mms_basic_object_class) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)), BerObjectContent::Integer(mms_basic_object_class.to_ber())),
        }
    }
}

impl MmsBasicObjectClass {
    pub(crate) fn parse(value: &Any<'_>) -> Result<MmsBasicObjectClass, MmsError> {
        if value.header.raw_tag() != Some(&[128]) {
            return Err(MmsError::ProtocolError(format!("MMS Basic Object Class has an unsupported tag {:?}", value.header.raw_tag())));
        }

        match value.data {
            [0] => Ok(MmsBasicObjectClass::NamedVariable),
            [2] => Ok(MmsBasicObjectClass::NamedVariableList),
            [3] => Ok(MmsBasicObjectClass::NamedType),
            [4] => Ok(MmsBasicObjectClass::Semaphore),
            [5] => Ok(MmsBasicObjectClass::EventCondition),
            [6] => Ok(MmsBasicObjectClass::EventAction),
            [7] => Ok(MmsBasicObjectClass::EventEnrollment),
            [8] => Ok(MmsBasicObjectClass::Journal),
            [9] => Ok(MmsBasicObjectClass::Domain),
            [10] => Ok(MmsBasicObjectClass::ProgramInvocation),
            [11] => Ok(MmsBasicObjectClass::OperatorStation),
            [12] => Ok(MmsBasicObjectClass::DataExchange),
            [13] => Ok(MmsBasicObjectClass::AccessControlList),
            x => Err(MmsError::ProtocolError(format!("Unsupported MMS Basic Object Class tag: {:?}", x))),
        }
    }

    pub(crate) fn to_ber(&self) -> &[u8] {
        match self {
            MmsBasicObjectClass::NamedVariable => &[0],
            // 1 (Scattered Access is not supported as the vsca option is not supported)
            MmsBasicObjectClass::NamedVariableList => &[2],
            MmsBasicObjectClass::NamedType => &[3],
            MmsBasicObjectClass::Semaphore => &[4],
            MmsBasicObjectClass::EventCondition => &[5],
            MmsBasicObjectClass::EventAction => &[6],
            MmsBasicObjectClass::EventEnrollment => &[7],
            MmsBasicObjectClass::Journal => &[8],
            MmsBasicObjectClass::Domain => &[9],
            MmsBasicObjectClass::ProgramInvocation => &[10],
            MmsBasicObjectClass::OperatorStation => &[11],
            MmsBasicObjectClass::DataExchange => &[12],
            MmsBasicObjectClass::AccessControlList => &[13],
        }
    }
}

impl MmsObjectScope {
    pub(crate) fn parse(value: &Any<'_>) -> Result<MmsObjectScope, MmsError> {
        match value.header.raw_tag() {
            Some([128]) => Ok(MmsObjectScope::Vmd),
            Some([129]) => {
                let domain_name = process_mms_string(value, "Failed to parse Domain Name in MMS Object Scope")?;
                Ok(MmsObjectScope::Domain(domain_name))
            }
            Some([130]) => Ok(MmsObjectScope::Aa),
            x => {
                warn!("Unsupported MMS Object Scope tag: {:?}", x);
                Err(MmsError::ProtocolError(format!("Unsupported MMS Object Scope tag: {:?}", x)))
            }
        }
    }

    pub(crate) fn to_ber(&self) -> BerObject<'_> {
        match self {
            MmsObjectScope::Vmd => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)), BerObjectContent::Null),
            MmsObjectScope::Domain(domain_name) => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(1), Length::Definite(0)), BerObjectContent::VisibleString(domain_name.as_str())),
            MmsObjectScope::Aa => BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(2), Length::Definite(0)), BerObjectContent::Null),
        }
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
                BerObjectContent::BitString(_, x) => assert!(!x.is_set(test_bit)),
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
                    BerObjectContent::BitString(_, x) if test_bit != subject_bit => assert!(!x.is_set(test_bit)),
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
                BerObjectContent::BitString(_, x) => assert!(!x.is_set(test_bit)),
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
            (11, 4, vec![131u8, 3u8, 4u8, 0u8, 16u8], ServiceSupportOption::DefineNamedVariableList),
            (12, 3, vec![131u8, 3u8, 3u8, 0u8, 8u8], ServiceSupportOption::GetNamedVariableListAttribute),
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
                    BerObjectContent::BitString(_, x) if test_bit != subject_bit => assert!(!x.is_set(test_bit)),
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
