use crate::packet::{
    connection_confirm::ConnectionConfirm,
    connection_request::ConnectionRequest,
    data_transfer::DataTransfer,
    disconnect_request::DisconnectRequest,
    tpdu_error::TpduError,
};

#[derive(Debug, PartialEq)]
pub(crate) enum TransportProtocolDataUnit {
    CR(ConnectionRequest),
    CC(ConnectionConfirm),
    DR(DisconnectRequest),
    DT(DataTransfer),
    ER(TpduError),
}
