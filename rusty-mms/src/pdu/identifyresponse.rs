use der_parser::{
    Oid,
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};

use crate::{MmsConfirmedResponse, MmsError, error::to_mms_error, parsers::process_constructed_data};

pub(crate) fn parse_identify_response(payload: &Any<'_>) -> Result<MmsConfirmedResponse, MmsError> {
    let mut vendor_name = None;
    let mut model_name = None;
    let mut revision = None;
    // let mut abstract_syntaxes = None; TODO

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Identify Response PDU"))? {
        match item.header.raw_tag() {
            Some([128]) => vendor_name = Some(String::from_utf8_lossy(item.data).to_string()),
            Some([129]) => model_name = Some(String::from_utf8_lossy(item.data).to_string()),
            Some([130]) => revision = Some(String::from_utf8_lossy(item.data).to_string()),
            x => todo!(), // Warn
        }
    }

    Ok(MmsConfirmedResponse::Identify {
        vendor_name: vendor_name.ok_or_else(|| MmsError::ProtocolError("Failed to find vendor name on identify request".into()))?,
        model_name: model_name.ok_or_else(|| MmsError::ProtocolError("Failed to find model name on identify request".into()))?,
        revision: revision.ok_or_else(|| MmsError::ProtocolError("Failed to find revision on identify request".into()))?,
        abstract_syntaxes: None,
    })
}

pub(crate) fn identify_response_to_ber<'a>(vendor_name: &'a str, model_name: &'a str, revision: &'a str, application_syntaxes: &Option<Vec<Oid<'_>>>) -> BerObject<'a> {
    BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(2), Length::Definite(0)),
        BerObjectContent::Sequence(vec![
            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)), BerObjectContent::OctetString(vendor_name.as_bytes())),
            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(1), Length::Definite(0)), BerObjectContent::OctetString(model_name.as_bytes())),
            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(2), Length::Definite(0)), BerObjectContent::OctetString(revision.as_bytes())),
            if let Some(syntaxes) = application_syntaxes {
                BerObject::from_header_and_content(
                    Header::new(Class::ContextSpecific, true, Tag::from(3), Length::Definite(0)),
                    BerObjectContent::Sequence(
                        syntaxes
                            .into_iter()
                            .map(|oid| BerObject::from_header_and_content(Header::new(Class::Universal, false, Tag::Oid, Length::Definite(0)), BerObjectContent::OID(oid.to_owned())))
                            .collect(),
                    ),
                )
            } else {
                BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(3), Length::Definite(0)), BerObjectContent::Sequence(vec![]))
            },
        ]),
    )
}
