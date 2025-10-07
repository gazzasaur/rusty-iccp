use der_parser::{
    asn1_rs::{Any, BitString, OctetString},
    ber::{BerObjectContent, BitStringObject},
    der::Tag,
    error::BerError,
};

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
pub(crate) enum ConnectMessageParameter {
    Mode(PresentationMode),
    NormalModeParameters(Vec<NormalModeParameter>),
    Unknown,
}

#[derive(Debug)]
pub(crate) enum FunctionalUnit {
    ContextManagement,
    Restoration,
}

#[derive(Debug)]
pub(crate) enum Protocol {
    Version1,
    Unknown(Vec<u8>),
}

#[derive(Debug)]
pub(crate) enum NormalModeParameter {
    Protocol(Protocol),
    CallingPresentationSelector(Vec<u8>),
    CalledPresentationSelector(Vec<u8>),
    FunctionalUnits(Vec<FunctionalUnit>),
}

pub(crate) fn process_implicit_bitstring_or_skip<'a>(raw_tag: &[u8], remainder: &'a [u8], npm_object: Any<'a>) -> Result<(&'a [u8], Any<'a>, Option<BitStringObject<'a>>), BerError> {
    let mut res = None;
    if let Some(x) = npm_object.header.raw_tag()
        && raw_tag == x
    {
        let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::BitString)(npm_object.data, &npm_object.header, npm_object.data.len())?;
        if let BerObjectContent::BitString(_, value) = inner_object {
            res.replace(value);
        };
        let (remainder, npm_object) = der_parser::ber::parse_ber_any(remainder)?;
        Ok((remainder, npm_object, res))
    } else {
        Ok((remainder, npm_object, res))
    }
}

pub(crate) fn process_implicit_octetstring_or_skip<'a>(raw_tag: &[u8], remainder: &'a [u8], npm_object: Any<'a>) -> Result<(&'a [u8], Any<'a>, Option<&'a [u8]>), BerError> {
    let mut res = None;
    if let Some(x) = npm_object.header.raw_tag()
        && raw_tag == x
    {
        let (_, inner_object) = der_parser::ber::parse_ber_content(Tag::OctetString)(npm_object.data, &npm_object.header, npm_object.data.len())?;
        if let BerObjectContent::OctetString(value) = inner_object {
            res.replace(value);
        };
        let (remainder, npm_object) = der_parser::ber::parse_ber_any(remainder)?;
        Ok((remainder, npm_object, res))
    } else {
        Ok((remainder, npm_object, res))
    }
}

pub(crate) fn process_protocol_or_skip<'a>(remainder: &'a [u8], npm_object: Any<'a>) -> Result<(&'a [u8], Any<'a>, Option<Protocol>), BerError> {
    let mut res = None;
    let (remainder, npm_object, value) = process_implicit_bitstring_or_skip(&[128], remainder, npm_object)?;
    match value {
        Some(value) if value.is_set(0) => res = Some(Protocol::Version1),
        Some(value) => res = Some(Protocol::Unknown(value.data.to_vec())),
        None => (),
    };
    Ok((remainder, npm_object, res))
}

pub(crate) fn process_calling_selector_or_skip<'a>(remainder: &'a [u8], npm_object: Any<'a>) -> Result<(&'a [u8], Any<'a>, Option<Vec<u8>>), BerError> {
    let mut res: Option<_> = None;
    let (remainder, npm_object, value) = process_implicit_octetstring_or_skip(&[129], remainder, npm_object)?;
    match value {
        Some(value) => res.replace(value.to_vec()),
        None => None,
    };
    Ok((remainder, npm_object, res))
}

pub(crate) fn process_called_selector_or_skip<'a>(remainder: &'a [u8], npm_object: Any<'a>) -> Result<(&'a [u8], Any<'a>, Option<Vec<u8>>), BerError> {
    let mut res = None;
    let (remainder, npm_object, value) = process_implicit_octetstring_or_skip(&[130], remainder, npm_object)?;
    match value {
        Some(value) => res.replace(value.to_vec()),
        None => None,
    };
    Ok((remainder, npm_object, res))
}

pub(crate) fn process_unknown_and_skip<'a>(raw_tag: &'_ [u8], remainder: &'a [u8], npm_object: Any<'a>) -> Result<(&'a [u8], Any<'a>, Vec<NormalModeParameter>), BerError> {
    if let Some(x) = npm_object.header.raw_tag()
        && x == raw_tag
    {
        let (remainder, npm_object) = der_parser::ber::parse_ber_any(remainder)?;
        Ok((remainder, npm_object, vec![]))
    } else {
        Ok((remainder, npm_object, vec![]))
    }
}
