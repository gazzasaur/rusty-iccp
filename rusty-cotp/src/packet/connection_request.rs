use crate::packet::parameters::{ConnectionClass, ConnectionOption, CotpParameter};

pub const CONNECTION_REQUEST_CODE: u8 = 0xE0u8;

#[derive(Debug, PartialEq)]
pub(crate) struct ConnectionRequest {
    credit: u8,
    source_reference: u16,
    destination_reference: u16,
    preferred_class: ConnectionClass,
    options: Vec<ConnectionOption>,
    parameters: Vec<CotpParameter>,
    user_data: Vec<u8>,
}

impl ConnectionRequest {
    pub(crate) fn new(credit: u8, source_reference: u16, destination_reference: u16, preferred_class: ConnectionClass, options: Vec<ConnectionOption>, parameters: Vec<CotpParameter>, user_data: &[u8]) -> Self {
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

    pub(crate) fn credit(&self) -> u8 {
        self.credit
    }

    pub(crate) fn source_reference(&self) -> u16 {
        self.source_reference
    }

    pub(crate) fn destination_reference(&self) -> u16 {
        self.destination_reference
    }

    pub(crate) fn preferred_class(&self) -> &ConnectionClass {
        &self.preferred_class
    }

    pub(crate) fn options(&self) -> &[ConnectionOption] {
        &self.options
    }

    pub(crate) fn parameters(&self) -> &[CotpParameter] {
        &self.parameters
    }

    pub(crate) fn user_data(&self) -> &[u8] {
        &self.user_data
    }
}
