#[derive(Debug, PartialEq)]
pub enum ConnectionOption {
    Unknown(u8),
}

impl ConnectionOption {
    pub fn from(connection_options: u8) -> Vec<Self> {
        (0..8)
            .filter_map(|i| match connection_options & (1 << i) {
                x if x != 0 => Some(ConnectionOption::Unknown(i + 1)),
                _ => None,
            })
            .collect()
    }
}

#[derive(Debug, PartialEq)]
pub enum ConnectionClass {
    Class0,
    Class1,
    Class2,
    Class3,
    Class4,
    Unknown(u8),
}

impl From<u8> for ConnectionClass {
    fn from(value: u8) -> Self {
        match value {
            0 => ConnectionClass::Class0,
            1 => ConnectionClass::Class1,
            2 => ConnectionClass::Class2,
            3 => ConnectionClass::Class3,
            4 => ConnectionClass::Class4,
            x => Self::Unknown(x),
        }
    }
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub enum CotpParameter {
    AlternativeClassParameter(Vec<ConnectionClass>),
    TpduLengthParameter(TpduLength),
    UnknownParameter(u8, Vec<u8>),
}
