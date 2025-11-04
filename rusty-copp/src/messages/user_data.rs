use der_parser::{
    Oid,
    asn1_rs::Any,
    ber::BerObject,
    der::{Class, Header, Tag},
    error::BerError,
};

#[derive(Debug)]
pub enum UserData {
    // SimplyEncoded(Vec<u8>),
    FullyEncoded(Vec<PresentationDataValueList>),
}

impl UserData {
    pub(crate) fn to_ber(&self) -> BerObject {
        match &self {
            UserData::FullyEncoded(presentation_data_value_lists) => {
                let mut pdv_lists = vec![];
                for presentation_data_value_list in presentation_data_value_lists {
                    pdv_lists.push(presentation_data_value_list.to_ber());
                }
                der_parser::ber::BerObject::from_header_and_content(
                    Header::new(Class::Application, true, Tag::from(1), der_parser::ber::Length::Definite(0)),
                    der_parser::ber::BerObjectContent::Sequence(pdv_lists),
                )
            }
        }
    }

    pub(crate) fn parse<'a>(ber_object: Any<'a>) -> Result<UserData, BerError> {
        match ber_object.header.raw_tag() {
            // TODO Change the error to return something meaningful.
            _ => todo!(),
        }
        // Ok(UserData::FullyEncoded(vec![]))
    }
}

// Technically SingleAsn1Type is only allowed if there is one PDV. But We do not restrict this here.
#[derive(Debug)]
pub struct PresentationDataValueList {
    pub transfer_syntax_name: Option<Oid<'static>>,
    pub presentation_context_identifier: Vec<u8>,
    pub presentation_data_values: PresentationDataValues,
}

impl PresentationDataValueList {
    pub(crate) fn to_ber(&self) -> BerObject {
        let mut object_content = vec![];
        if let Some(transfer_syntax_name) = &self.transfer_syntax_name {
            object_content.push(der_parser::ber::BerObject::from_obj(der_parser::ber::BerObjectContent::OID(transfer_syntax_name.clone())));
        }
        object_content.push(der_parser::ber::BerObject::from_obj(der_parser::ber::BerObjectContent::Integer(&self.presentation_context_identifier)));
        object_content.push(self.presentation_data_values.to_ber());

        der_parser::ber::BerObject::from_seq(object_content)
    }
}

// Technically SingleAsn1Type is only allowed if there is one PDV. But We do not restrict this here.
#[derive(Debug)]
pub enum PresentationDataValues {
    SingleAsn1Type(Vec<u8>),
    OctetAligned(Vec<u8>),
    Arbitrary(Vec<u8>),
}

impl PresentationDataValues {
    pub(crate) fn to_ber(&self) -> BerObject {
        match &self {
            PresentationDataValues::SingleAsn1Type(data) => der_parser::ber::BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, true, Tag::from(0), der_parser::ber::Length::Definite(0)),
                der_parser::ber::BerObjectContent::OctetString(data),
            ),
            PresentationDataValues::OctetAligned(data) => {
                der_parser::ber::BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(1), der_parser::ber::Length::Definite(0)), der_parser::ber::BerObjectContent::OctetString(data))
            }
            PresentationDataValues::Arbitrary(data) => {
                der_parser::ber::BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(2), der_parser::ber::Length::Definite(0)), der_parser::ber::BerObjectContent::OctetString(data))
            }
        }
    }
}
