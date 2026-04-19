use der_parser::{
    der::{Class, Header, Tag},
};

use crate::{
    CoppError, EventIdentifier, ProviderReason, error::protocol_error,
    messages::parsers::process_integer,
};

#[derive(Debug)]
pub(crate) struct AbortProviderMessage {
    provider_reason: Option<ProviderReason>,
    event_identifier: Option<EventIdentifier>,
}

impl AbortProviderMessage {
    pub(crate) fn new(provider_reason: Option<ProviderReason>, event_identifier: Option<EventIdentifier>) -> Self {
        Self { provider_reason, event_identifier }
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<AbortProviderMessage, CoppError> {
        let mut provider_reason = None; // a.k.a abort reason
        let mut event_identifier = None;

        // This destructively processes the payload directly into the accept message in a single pass. No retrun is required.
        der_parser::ber::parse_ber_set_of_v(|data| {
            let (abort_message_remainder, object) = der_parser::ber::parse_ber_any(data)?;

            match object.header.raw_tag() {
                Some(&[128]) => provider_reason = process_integer(object)?,
                Some(&[129]) => event_identifier = process_integer(object)?,
                _ => (),
            };
            Ok((abort_message_remainder, 0))
        })(&data)
        .map_err(|e| protocol_error("sd", e))?;

        Ok(AbortProviderMessage { provider_reason: provider_reason.map(|x| x[..].into()), event_identifier: event_identifier.map(|x| x[..].into()) })
    }

    pub(crate) fn to_error(self) -> CoppError {
        CoppError::ProviderAborted(self.provider_reason, self.event_identifier)
    }

    pub(crate) fn serialise(&self) -> Result<Vec<u8>, CoppError> {
        let provider_reason: Option<Vec<u8>> = match &self.provider_reason {
            Some(x) => Some(x.into()),
            None => None,
        };
        let provider_reason_ber = match &provider_reason {
            Some(x) => Some(der_parser::ber::BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), der_parser::ber::Length::Definite(0)), der_parser::ber::BerObjectContent::Integer(&x))),
            None => None,
        };

        let event_identifier: Option<Vec<u8>> = match &self.event_identifier {
            Some(x) => Some(x.into()),
            None => None,
        };
        let event_identifier_ber = match &event_identifier {
            Some(x) => Some(der_parser::ber::BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(1), der_parser::ber::Length::Definite(0)), der_parser::ber::BerObjectContent::Integer(&x))),
            None => None,
        };

        Ok(der_parser::ber::BerObject::from_header_and_content(
            Header::new(Class::ContextSpecific, true, Tag::from(30), der_parser::ber::Length::Definite(0)),
            der_parser::ber::BerObjectContent::Sequence(vec![provider_reason_ber, event_identifier_ber].into_iter().filter_map(|f| f).collect()),
        )
        .to_vec()
        .map_err(|e| CoppError::InternalError(e.to_string()))?)
    }
}
