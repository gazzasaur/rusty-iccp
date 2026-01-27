use der_parser::{
    asn1_rs::{Any, ToDer},
    ber::{BerObject, BerObjectContent, Length},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{ListOfVariablesItem, MmsConfirmedRequest, MmsError, MmsObjectName, MmsScope, error::to_mms_error, parsers::{process_constructed_data, process_integer_content, process_mms_string}};

pub(crate) fn parse_delete_named_variable_list_reqeust(payload: &Any<'_>) -> Result<MmsConfirmedRequest, MmsError> {
    let mut scope_of_delete = None;
    let mut list_of_variable_list_names = None;
    let mut domain_name = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse DeleteNamedVariableList"))? {
        match item.header.raw_tag() {
            Some([128]) => scope_of_delete = Some(MmsScope::parse(&item)?),
            Some([161]) => list_of_variable_list_names = Some({
                let mut list = vec![];
                for variable_name in process_constructed_data(item.data).map_err(to_mms_error("Failed to parse List of Variable List Names on DeleteNamedVariableList"))? {
                    list.push(MmsObjectName::parse("DeleteNamedVariableList", &variable_name.to_der_vec().map_err(to_mms_error("Failed to process ObjectName on DeleteNamedVariableList"))?)?);
                }
                list
            }),
            Some([130]) => domain_name = Some(process_mms_string(&item, "Failedd to process Domain on DeleteNamedVariableList")?),
            x => warn!("Unknown item on DeleteNamedVariableList: {:?}", x),
        };
    }

    Ok(MmsConfirmedRequest::DeleteNamedVariableList {
        scope_of_delete,
        list_of_variable_list_names,
        domain_name,
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
                        Header::new(Class::ContextSpecific, false, Tag::from(2), Length::Definite(0)),
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
