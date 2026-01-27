use der_parser::{
    asn1_rs::Any,
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};

use crate::{MmsConfirmedRequest, MmsError, MmsObjectName, MmsScope};

pub(crate) fn parse_delete_named_variable_list_reqeust(payload: &Any<'_>) -> Result<MmsConfirmedRequest, MmsError> {
    let object_name = MmsObjectName::parse("MMS GetNamedVariableListAttributes", payload.data)?;
    Ok(MmsConfirmedRequest::DeleteNamedVariableList {
        scope_of_delete: None,
        list_of_variable_list_names: None,
        domain_name: None,
    })
}

pub(crate) fn delete_named_variable_list_reqeust_to_ber<'a>(scope_of_delete: &Option<MmsScope>, list_of_variable_list_names: &'a Option<Vec<MmsObjectName>>, domain: &'a Option<String>) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(13), Length::Definite(0)),
        BerObjectContent::Sequence(
            vec![
                match scope_of_delete {
                    Some(scope_of_delete) => Some(scope_of_delete.to_ber(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)))),
                    None => None,
                },
                match list_of_variable_list_names {
                    Some(items) => Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
                        BerObjectContent::Sequence({
                            let mut list = vec![];
                            for item in items {
                                list.push(item.to_ber());
                            }
                            list
                        }),
                    )),
                    None => None,
                },
                match domain {
                    Some(domain) => Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(2), Length::Definite(0)),
                        BerObjectContent::VisibleString(domain),
                    )),
                    None => None,
                },
            ]
            .into_iter()
            .filter_map(|x| x)
            .collect(),
        ),
    ))
}
