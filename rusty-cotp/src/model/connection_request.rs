use crate::model::parameter::CotpParameter;

pub const CONNECTION_REQUEST_CODE: u8 = 0xE0u8;

#[derive(Debug, PartialEq)]
pub struct ConnectionRequest {
    source_reference: u16,
    destination_reference: u16,
    preferred_class: ConnectionClass,
    options: Vec<ConnectionOption>,
    parameters: Vec<CotpParameter>,
    user_data: Vec<u8>,
}

impl ConnectionRequest {
    pub fn new(source_reference: u16, destination_reference: u16, preferred_class: ConnectionClass, options: Vec<ConnectionOption>, parameters: Vec<CotpParameter>, user_data: &[u8]) -> Self {
        Self {
            source_reference,
            destination_reference,
            preferred_class,
            options,
            parameters,
            user_data: user_data.into(),
        }
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

#[derive(Debug, PartialEq)]
pub enum ConnectionClass {
    Class0,
    Unknown(u8),
}

impl From<u8> for ConnectionClass {
    fn from(value: u8) -> Self {
        match value {
            0 => ConnectionClass::Class0,
            x => Self::Unknown(x),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ConnectionOption {
    Unknown(u8),
}

impl ConnectionOption {
    pub fn from(connection_options: u8) -> Vec<Self> {
        (0..8)
            .filter_map(|i| match connection_options & (1 << i) {
                x if x != 0 => Some(ConnectionOption::Unknown(i)),
                _ => None,
            })
            .collect()
    }
}
