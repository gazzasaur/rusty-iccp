use der_parser::{
    asn1_rs::{Any, ToDer},
    ber::{BerObject, BerObjectContent, Length, parse_ber_any},
    der::{Class, Header, Tag},
};
use tracing::warn;

use crate::{ListOfVariablesItem, MmsConfirmedRequest, MmsError, MmsObjectName, VariableSpecification, error::to_mms_error, parsers::process_constructed_data};

pub(crate) fn parse_define_named_variable_list_reqeust(payload: &Any<'_>) -> Result<MmsConfirmedRequest, MmsError> {
    // Order Matters Here
    let items = process_constructed_data(payload.data).map_err(to_mms_error("Failed to parse MMS DefineNamedVariableList PDU"))?;
    let mut items_iter = items.iter();

    let object_name_payload = items_iter.next().ok_or_else(|| MmsError::ProtocolError("Failed to parse MMS DefineNamedVariableList PDU - No Object Name found".into()))?;
    let object_name_data = object_name_payload.to_der_vec().map_err(to_mms_error("Failed to parse MMS DefineNamedVariableList PDU - Failed to parse Object Name"))?;
    let object_name = MmsObjectName::parse("MMS DefineNamedVariableList", &object_name_data)?;

    let variable_specifications_payload = items_iter
        .next()
        .ok_or_else(|| MmsError::ProtocolError("Failed to parse MMS DefineNamedVariableList PDU - No Variable Specifications found".into()))?;
    let mut variable_specifications = vec![];
    for variable_specifications_item in process_constructed_data(variable_specifications_payload.data).map_err(to_mms_error("Failed to parse MMS DefineNamedVariableList PDU - Failed to parse Variable Specifications"))? {
        let variable_specifications_item_data = variable_specifications_item
            .to_der_vec()
            .map_err(to_mms_error("Failed to parse MMS DefineNamedVariableList PDU - Failed to parse Variable Specification"))?;
        let (_, unwrapped_variable_specifications_item) = parse_ber_any(&variable_specifications_item_data).map_err(to_mms_error("Failed to parse MMS DefineNamedVariableList PDU - Failed to parse List Of Variables Item Sequence"))?;
        variable_specifications.push(ListOfVariablesItem::parse(
            &unwrapped_variable_specifications_item,
            "Failed to parse MMS DefineNamedVariableList PDU - Failed to parse List Of Variables Item",
        )?);
    }

    Ok(MmsConfirmedRequest::DefineNamedVariableList {
        variable_list_name: object_name,
        list_of_variables: variable_specifications,
    })
}

pub(crate) fn define_named_variable_list_reqeust_to_ber<'a>(object_name: &'a MmsObjectName, variable_specifications: &'a [ListOfVariablesItem]) -> Result<BerObject<'a>, MmsError> {
    Ok(BerObject::from_header_and_content(
        Header::new(Class::ContextSpecific, true, Tag::from(11), Length::Definite(0)),
        BerObjectContent::Sequence(vec![
            object_name.to_ber(),
            BerObject::from_header_and_content(
                Header::new(Class::ContextSpecific, true, Tag::from(0), Length::Definite(0)),
                BerObjectContent::Sequence({
                    let mut list = vec![];

                    for variable_specification in variable_specifications {
                        list.push(variable_specification.to_ber());
                    }

                    list
                }),
            ),
        ]),
    ))
}
