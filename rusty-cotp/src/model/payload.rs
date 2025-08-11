use crate::model::connection_request::{CONNECTION_REQUEST_CODE, ConnectionRequest};

pub const CONNECTION_CONFIRM_CODE: u8 = 0xD0u8;
pub const DISCONNECT_REQUEST_CODE: u8 = 0x90u8;
pub const DATA_CODE: u8 = 0xF0u8;
pub const ERROR_CODE: u8 = 0x70u8;

#[derive(Debug, PartialEq)]
pub enum TransportProtocolDataUnit {
    CR(ConnectionRequest),
    CC(ConnectionConfirm),
    DR(DisconnectRequest),
    DT(Data),
    ER(TpduError),
}

impl TransportProtocolDataUnit {
    pub fn get_code(tpdu: &Self) -> u8 {
        match tpdu {
            Self::CR(_) => CONNECTION_REQUEST_CODE,
            Self::CC(_) => CONNECTION_CONFIRM_CODE,
            Self::DR(_) => DISCONNECT_REQUEST_CODE,
            Self::DT(_) => DATA_CODE,
            Self::ER(_) => ERROR_CODE,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ConnectionConfirm {}

#[derive(Debug, PartialEq)]
pub struct DisconnectRequest {}

#[derive(Debug, PartialEq)]
pub struct Data {}

#[derive(Debug, PartialEq)]
pub struct TpduError {}
