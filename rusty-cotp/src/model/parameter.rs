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
    TpduLengthParameter(TpduLength),
    UnknownParameter(u8),
}
