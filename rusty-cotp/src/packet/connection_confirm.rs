use crate::packet::parameter::{ConnectionClass, ConnectionOption, CotpParameter};

pub const CONNECTION_CONFIRM_CODE: u8 = 0xD0u8;

#[derive(Debug, PartialEq)]
pub struct ConnectionConfirm {
    credit: u8,
    source_reference: u16,
    destination_reference: u16,
    preferred_class: ConnectionClass,
    options: Vec<ConnectionOption>,
    parameters: Vec<CotpParameter>,
    user_data: Vec<u8>,
}

impl ConnectionConfirm {
    pub fn new(credit: u8, source_reference: u16, destination_reference: u16, preferred_class: ConnectionClass, options: Vec<ConnectionOption>, parameters: Vec<CotpParameter>, user_data: &[u8]) -> Self {
        Self {
            credit,
            source_reference,
            destination_reference,
            preferred_class,
            options,
            parameters,
            user_data: user_data.into(),
        }
    }

    pub fn credit(&self) -> u8 {
        self.credit
    }

    pub fn source_reference(&self) -> u16 {
        self.source_reference
    }

    pub fn destination_reference(&self) -> u16 {
        self.destination_reference
    }

    pub fn preferred_class(&self) -> &ConnectionClass {
        &self.preferred_class
    }

    pub fn options(&self) -> &[ConnectionOption] {
        &self.options
    }

    pub fn parameters(&self) -> &[CotpParameter] {
        &self.parameters
    }

    pub fn user_data(&self) -> &[u8] {
        &self.user_data
    }
}
