
pub(crate) struct GetNameListRequestPdu {
    object_class: ObjectClass,
    proposed_max_serv_outstanding_calling: i16,
    proposed_max_serv_outstanding_called: i16,
    proposed_data_structure_nesting_level: Option<i8>,
    init_request_details: InitRequestResponseDetails,
}