use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    MmsConfirmedResponse, MmsError, error::to_mms_error,
    parsers::{process_constructed_data, process_mms_boolean_content, process_mms_string},
};

pub(crate) fn parse_get_name_list_response(payload: &Any<'_>) -> Result<MmsConfirmedResponse, MmsError> {
    let mut list_of_identifiers = vec![];
    let mut more_follows = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Get Name List Response PDU"))? {
        match item.header.raw_tag() {
            Some([160]) => {
                list_of_identifiers = process_constructed_data(item.data)
                    .map_err(to_mms_error("Failed to parse List of Identifiers in Get Name List Response PDU"))?
                    .into_iter()
                    .map(|x| process_mms_string(&x, "Failed to parse Identifier in Get Name List Response PDU"))
                    .collect::<Result<Vec<_>, _>>()?;
            }
            Some([129]) => {
                more_follows = Some(process_mms_boolean_content(&item, "Failed to parse More Follows in Get Name List Response PDU")?);
            }
            x => warn!("Unsupported tag in MMS Get Name List Response PDU: {:?}", x),
        }
    }

    Ok(MmsConfirmedResponse::GetNameList { list_of_identifiers, more_follows })
}

pub(crate) fn get_name_list_response_to_ber<'a>(list_of_identifiers: &'a Vec<String>, more_follows: &'a Option<bool>) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
        BerObjectContent::Sequence(
            vec![
                Some(BerObject::from_header_and_content(
                    Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
                    BerObjectContent::Sequence(
                        list_of_identifiers
                            .iter()
                            .map(|id| BerObject::from_header_and_content(Header::new(Class::Universal, false, Tag::VisibleString, Length::Definite(0)), BerObjectContent::VisibleString(id.as_str())))
                            .collect(),
                    ),
                )),
                more_follows
                    .as_ref()
                    .map(|mf| BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(1), Length::Definite(0)), BerObjectContent::Boolean(*mf))),
            ]
            .into_iter()
            .filter_map(|i| i)
            .collect(),
        ),
    ))
}
