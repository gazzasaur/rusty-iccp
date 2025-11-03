use der_parser::{
    asn1_rs::{Any, BitString, OctetString, Sequence}, ber::{BerObject, BerObjectContent}, der::{Class, Header, Tag}, error::BerError, num_bigint::{BigInt, Sign}, Oid
};
use tracing::warn;

use crate::{CoppError, messages::parsers::process_constructed_data};

#[derive(Debug)]
pub(crate) enum UserData {
    // SimplyEncoded(Vec<u8>),
    FullyEncoded(Vec<PresentationDataValue>),
}

// Technically SingleAsn1Type is only allowed if there is one PDV. But We do not restrict this here.
#[derive(Debug)]
pub(crate) enum PresentationDataValueData {
    SingleAsn1Type(BerObjectContent<'static>),
    OctetAligned(BerObjectContent<'static>),
    Arbitrary(BerObjectContent<'static>),
}

#[derive(Debug)]
pub(crate) struct PresentationDataValue {
    transfer_syntax_name: Option<Oid<'static>>,
    presentation_context_identifier: Vec<u8>,
    presentation_data_values: PresentationDataValueData,
}

impl UserData {
    pub (crate) fn serialise(&self) -> Result<Vec<u8>, CoppError> {
        // TODO
        Ok(vec![])
    }

    pub(crate) fn parse<'a>(ber_object: Any<'a>) -> Result<UserData, BerError> {
        match ber_object.header.raw_tag() {
            // TODO Change the error to return something meaning ful.
            _ => todo!(),
        }
        // Ok(UserData::FullyEncoded(vec![]))
    }

    pub(crate) fn to_ber<'a>(&'a self) -> Result<BerObject<'a>, BerError> {
        let content = match self {
            UserData::FullyEncoded(x) => BerObject::from_seq(
                x.iter()
                    .map(|f| {
                        BerObject::from_seq(vec![der_parser::ber::BerObject::from_header_and_content(
                            Header::new(Class::ContextSpecific, true, Tag::from(0), der_parser::ber::Length::Definite(0)),
                            der_parser::ber::BerObjectContent::Integer(f.presentation_context_identifier.as_slice()),
                        )])
                    })
                    .collect(),
            ),
        };
        Ok(content)
    }
}
