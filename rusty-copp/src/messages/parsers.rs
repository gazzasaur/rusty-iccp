use der_parser::{
    Oid,
    asn1_rs::Any,
    ber::{BerObjectContent, BitStringObject, parse_ber_any},
    der::{Class, Tag},
    error::BerError,
};

use crate::{PresentationContext, PresentationContextResult, PresentationContextResultCause, PresentationContextResultType, PresentationContextType};

#[derive(Debug)]
pub(crate) enum PresentationMode {
    Normal,
    X410,
    Unknown,
}

impl From<&[u8]> for PresentationMode {
    fn from(value: &[u8]) -> Self {
        match value {
            &[0] => PresentationMode::X410,
            &[1] => PresentationMode::Normal,
            _ => PresentationMode::Unknown,
        }
    }
}

#[derive(Debug)]
pub(crate) enum Protocol {
    Version1,
    Unknown(Vec<u8>),
}

pub(crate) fn process_bitstring<'a>(npm_object: Any<'a>) -> Result<Option<BitStringObject<'a>>, BerError> {
    let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::BitString)(npm_object.data, &npm_object.header, npm_object.data.len())?;
    match inner_object {
        BerObjectContent::BitString(_, value) => Ok(Some(value)),
        _ => Ok(None),
    }
}

pub(crate) fn process_octetstring<'a>(npm_object: Any<'a>) -> Result<Option<Vec<u8>>, BerError> {
    let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::OctetString)(npm_object.data, &npm_object.header, npm_object.data.len())?;
    match inner_object {
        BerObjectContent::OctetString(value) => Ok(Some(value.to_vec())),
        _ => Ok(None),
    }
}

pub(crate) fn process_integer<'a>(npm_object: Any<'a>) -> Result<Option<Vec<u8>>, BerError> {
    let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::Integer)(npm_object.data, &npm_object.header, npm_object.data.len())?;
    match inner_object {
        BerObjectContent::Integer(value) => Ok(Some(value.to_vec())),
        _ => Ok(None),
    }
}

pub(crate) fn process_context_result<'a>(npm_object: Any<'a>) -> Result<PresentationContextResultCause, BerError> {
    match process_integer(npm_object)? {
        Some(x) if x == vec![0] => Ok(PresentationContextResultCause::Acceptance),
        Some(x) if x == vec![1] => Ok(PresentationContextResultCause::UserRejection),
        Some(x) if x == vec![2] => Ok(PresentationContextResultCause::ProviderRejection),
        _ => Ok(PresentationContextResultCause::Unknown),
    }
}

pub(crate) fn process_oid<'a>(npm_object: Any<'a>) -> Result<Option<Oid<'static>>, BerError> {
    let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::Oid)(npm_object.data, &npm_object.header, npm_object.data.len())?;
    match inner_object {
        BerObjectContent::OID(value) => Ok(Some(value.to_owned())),
        _ => Ok(None),
    }
}
pub(crate) fn process_protocol<'a>(npm_object: Any<'a>) -> Result<Option<Protocol>, BerError> {
    match process_bitstring(npm_object)? {
        Some(value) if value.is_set(0) => Ok(Some(Protocol::Version1)),
        Some(value) => Ok(Some(Protocol::Unknown(value.data.to_vec()))),
        None => Ok(None),
    }
}

pub(crate) fn process_transfer_syntaxt_list<'a>(data: &'a [u8]) -> Result<Vec<Oid<'static>>, BerError> {
    let mut res = vec![];
    for item in process_constructed_data(data)? {
        match process_oid(item)? {
            Some(oid) => res.push(oid),
            None => (),
        }
    }
    Ok(res)
}

pub(crate) fn process_presentation_context<'a>(npm_objects: Vec<Any<'a>>) -> Result<PresentationContext, BerError> {
    let mut id = None;
    let mut abstract_syntax_name = None;
    let mut transfer_syntax_name_list = None;

    for npm_object in npm_objects {
        match npm_object.header.raw_tag() {
            Some(&[2]) => id = process_integer(npm_object)?,
            Some(&[6]) => abstract_syntax_name = process_oid(npm_object)?,
            Some(&[48]) => transfer_syntax_name_list = Some(process_transfer_syntaxt_list(npm_object.data)?),
            _ => (),
        };
    }
    Ok(PresentationContext {
        indentifier: id.ok_or_else(|| BerError::BerValueError)?,
        abstract_syntax_name: abstract_syntax_name.ok_or_else(|| BerError::BerValueError)?,
        transfer_syntax_name_list: transfer_syntax_name_list.ok_or_else(|| BerError::BerValueError)?,
    })
}

pub(crate) fn process_presentation_result_context<'a>(npm_objects: Vec<Any<'a>>) -> Result<PresentationContextResult, BerError> {
    let mut result = PresentationContextResultCause::Unknown;
    let mut transfer_syntax_name = None;

    for npm_object in npm_objects {
        match npm_object.header.raw_tag() {
            Some(&[0]) => result = process_context_result(npm_object)?,
            Some(&[1]) => transfer_syntax_name = process_oid(npm_object)?,
            // Some(&[2]) => provider_reason = Some(process_transfer_syntaxt_list(npm_object.data)?), TODO
            _ => (),
        };
    }
    Ok(PresentationContextResult {
        result,
        transfer_syntax_name,
        provider_reason: None, // TODO Provider Reason
    })
}

pub(crate) fn process_presentation_context_list<'a>(data: &'a [u8]) -> Result<PresentationContextType, BerError> {
    let mut context_definition_list = vec![];
    for context_item in process_constructed_data(data)? {
        context_item.header.assert_constructed()?;
        context_item.header.assert_tag(Tag::Sequence)?;
        context_item.header.assert_class(Class::Universal)?;

        context_definition_list.push(process_presentation_context(process_constructed_data(context_item.data)?)?);
    }
    Ok(PresentationContextType::ContextDefinitionList(context_definition_list))
}

pub(crate) fn process_presentation_context_result_list<'a>(data: &'a [u8]) -> Result<PresentationContextResultType, BerError> {
    let mut context_definition_list = vec![];
    for context_item in process_constructed_data(data)? {
        context_item.header.assert_constructed()?;
        context_item.header.assert_tag(Tag::Sequence)?;
        context_item.header.assert_class(Class::Universal)?;

        context_definition_list.push(process_presentation_result_context(process_constructed_data(context_item.data)?)?);
    }
    Ok(PresentationContextResultType::ContextDefinitionList(context_definition_list))
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
