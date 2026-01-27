use std::{collections::VecDeque, rc::Rc};

use der_parser::{
    asn1_rs::{Any, ToDer},
    ber::{BerObject, BerObjectContent, Length, parse_ber_any},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{
    ListOfVariablesItem, MmsConfirmedResponse, MmsError, MmsTypeDescription,
    error::to_mms_error,
    parsers::{process_constructed_data, process_mms_boolean_content},
};

pub(crate) fn parse_get_named_variable_list_attributes_response(payload: &Any<'_>) -> Result<MmsConfirmedResponse, MmsError> {
    let mut deletable = None;
    let mut list_of_variables = None;

    for item in process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS Get Variable Access Attributes PDU"))? {
        match item.header.raw_tag() {
            Some([128]) => {
                deletable = Some(process_mms_boolean_content(&item, "Get Variable Access Attributes Response PDU - Deletable Flag")?);
            }
            Some([161]) => {
                list_of_variables = {
                    let items = process_constructed_data(item.data).map_err(to_mms_error("Failed to parse MMS DefineNamedVariableList PDU"))?;
                    let mut items_iter = items.iter();

                    let variable_specifications_payload = items_iter
                        .next()
                        .ok_or_else(|| MmsError::ProtocolError("Failed to parse MMS DefineNamedVariableList PDU - No Variable Specifications found".into()))?;
                    let mut variable_specifications = vec![];
                    for variable_specifications_item in process_constructed_data(variable_specifications_payload.data).map_err(to_mms_error("Failed to parse MMS DefineNamedVariableList PDU - Failed to parse Variable Specifications"))? {
                        let variable_specifications_item_data = variable_specifications_item.to_der_vec()
                            .map_err(to_mms_error("Failed to parse MMS DefineNamedVariableList PDU - Failed to parse Variable Specification"))?;
                        let (_, unwrapped_variable_specifications_item) =
                            parse_ber_any(&variable_specifications_item_data).map_err(to_mms_error("Failed to parse MMS DefineNamedVariableList PDU - Failed to parse List Of Variables Item Sequence"))?;
                        variable_specifications.push(ListOfVariablesItem::parse(
                            &unwrapped_variable_specifications_item,
                            "Failed to parse MMS DefineNamedVariableList PDU - Failed to parse List Of Variables Item",
                        )?);
                    }

                    Some(variable_specifications)
                }
            }
            x => warn!("Unsupported tag in MMS Get Variable Access Attributes Response PDU: {:?}", x),
        }
    }

    let deletable = deletable.ok_or_else(|| MmsError::ProtocolError("No Deletable Flag on Get Variable Access Attributes Response PDU".into()))?;
    let list_of_variables = list_of_variables.ok_or_else(|| MmsError::ProtocolError("No Deletable Flag on Get Variable Access Attributes Response PDU".into()))?;

    Ok(MmsConfirmedResponse::GetNamedVariableListAttributes { deletable, list_of_variables: vec![] })
}

pub(crate) fn get_named_variable_list_attributes_response_to_ber<'a>(deletable: bool, list_of_variables: &'a [ListOfVariablesItem]) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(12), Length::Definite(0)),
        BerObjectContent::Sequence(vec![
            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, false, Tag::from(0), Length::Definite(0)), BerObjectContent::Boolean(deletable)),
            BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, true, Tag::from(1), Length::Definite(0)),
                BerObjectContent::Sequence({
                    let mut list = vec![];
                    for variable in list_of_variables.iter() {
                        list.push(variable.to_ber());
                    }
                    list
                }),
            ),
        ]),
    ))
}
