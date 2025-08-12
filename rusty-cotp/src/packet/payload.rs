use crate::packet::{
    connection_confirm::{CONNECTION_CONFIRM_CODE, ConnectionConfirm},
    connection_request::{CONNECTION_REQUEST_CODE, ConnectionRequest},
    data_transfer::{DATA_TRANSFER_CODE, DataTransfer},
    disconnect_request::{DISCONNECT_REQUEST_CODE, DisconnectRequest},
    tpdu_error::{TPDU_ERROR_CODE, TpduError},
};

#[derive(Debug, PartialEq)]
pub enum TransportProtocolDataUnit {
    CR(ConnectionRequest),
    CC(ConnectionConfirm),
    DR(DisconnectRequest),
    DT(DataTransfer),
    ER(TpduError),
}

impl TransportProtocolDataUnit {
    pub fn get_code(tpdu: &Self) -> u8 {
        match tpdu {
            Self::CR(_) => CONNECTION_REQUEST_CODE,
            Self::CC(_) => CONNECTION_CONFIRM_CODE,
            Self::DR(_) => DISCONNECT_REQUEST_CODE,
            Self::DT(_) => DATA_TRANSFER_CODE,
            Self::ER(_) => TPDU_ERROR_CODE,
        }
    }
}
