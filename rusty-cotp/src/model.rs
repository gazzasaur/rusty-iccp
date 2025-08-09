pub const CONNECTION_REQUEST_CODE: u8 = 0xE0u8;
pub const CONNECTION_CONFIRM_CODE: u8 = 0xD0u8;
pub const DISCONNECT_REQUEST_CODE: u8 = 0x90u8;
pub const DATA_CODE: u8 = 0xF0u8;
pub const ERROR_CODE: u8 = 0x70u8;

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

pub struct ConnectionRequest {
    source_reference: u16,
    destination_reference: u16,
    preferred_class: ConnectionClass,
    options: Vec<ConnectionOption>,
    parameters: Vec<CotpParameter>,
    user_data: Vec<u8>,
}

impl ConnectionRequest {
    pub fn new(
        source_reference: u16,
        destination_reference: u16,
        preferred_class: ConnectionClass,
        options: Vec<ConnectionOption>,
        parameters: Vec<CotpParameter>,
        user_data: &[u8],
    ) -> TransportProtocolDataUnit {
        TransportProtocolDataUnit::CR(Self {
            source_reference,
            destination_reference,
            preferred_class,
            options,
            parameters,
            user_data: user_data.into(),
        })
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

pub enum ConnectionOption {
    Unknown(u8),
}

pub fn parse_connection_options(connection_options: u8) -> Vec<ConnectionOption> {
    vec![ConnectionOption::Unknown(connection_options)]
}

pub struct ConnectionConfirm {}

pub struct DisconnectRequest {}

pub struct Data {}

pub struct TpduError {}

pub enum CotpParameter {
    TpduLengthParameter(TpduLength),
    UnknownParameter(u8),
}

pub enum TpduLength {
    Size128,
    Size256,
    Size512,
    Size1024,
    Size2048,
    Size4096,
    Size8192,
    Unknown(u8),
}

impl From<u8> for TpduLength {
    fn from(value: u8) -> Self {
        match value {
            0b00000111 => Self::Size128,
            0b00001000 => Self::Size256,
            0b00001001 => Self::Size512,
            0b00001010 => Self::Size1024,
            0b00001011 => Self::Size2048,
            0b00001100 => Self::Size4096,
            0b00001101 => Self::Size8192,
            x => Self::Unknown(x),
        }
    }
}
