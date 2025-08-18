use std::collections::VecDeque;

pub const CONNECT_ACCEPT_PARAMETER_CODE: u8 = 5;
pub const PROTOCOL_OPTIONS_PARAMETER_CODE: u8 = 19;
pub const VERSION_NUMBER_PARAMETER_CODE: u8 = 22;

pub enum ParameterType {
    ConnectAcceptItem(ConnectAcceptParameterGroup),
}

pub struct ConnectAcceptParameterGroup {
    protocol_options: ProtocolOptions,
    version_number: VersionNumber,
}

impl From<ConnectAcceptParameterGroup> for Vec<u8> {
    fn from(value: ConnectAcceptParameterGroup) -> Self {
        let mut buffer: VecDeque<u8> = VecDeque::new();
        <VecDeque<u8> as Extend<u8>>::extend::<Vec<u8>>(&mut buffer, value.protocol_options.into());
        <VecDeque<u8> as Extend<u8>>::extend::<Vec<u8>>(&mut buffer, value.version_number.into());
        Vec::from(buffer)
    }
}

pub struct ProtocolOptions {
    extended_concatenated_spdu_support: bool,
}

impl ProtocolOptions {
    pub fn new(extended_concatenated_spdu_support: bool) -> Self {
        Self { extended_concatenated_spdu_support }
    }
}

impl From<ProtocolOptions> for Vec<u8> {
    fn from(value: ProtocolOptions) -> Self {
        let payload_value = match value.extended_concatenated_spdu_support {
            true => 1,
            false => 0,
        };
        vec![PROTOCOL_OPTIONS_PARAMETER_CODE, 1u8, payload_value]
    }
}

pub enum VersionNumber {
    Version1,
    Version2,
    Unknown(u8),
}

impl From<VersionNumber> for Vec<u8> {
    fn from(value: VersionNumber) -> Self {
        let version_flag = match value {
            VersionNumber::Version1 => 0x01,
            VersionNumber::Version2 => 0x02,
            VersionNumber::Unknown(x) => x,
        };
        vec![VERSION_NUMBER_PARAMETER_CODE, 1u8, version_flag]
    }
}
