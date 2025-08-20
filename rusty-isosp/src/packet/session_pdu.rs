use bitfield::bitfield;

pub const CONNECT_ACCEPT_PARAMETER_CODE: u8 = 5;
pub const PROTOCOL_OPTIONS_PARAMETER_CODE: u8 = 19;
pub const VERSION_NUMBER_PARAMETER_CODE: u8 = 22;

pub type ConnectSessionPdu = SessionPdu<13>;

pub struct SessionPdu<const T: u8> {
    pdu_parameters: Vec<PduParameter>,
}

impl<const T: u8> SessionPdu<T> {
    pub fn new(pdu_parameters: Vec<PduParameter>) -> Self {
        Self { pdu_parameters }
    }
    
    pub fn code() -> u8 {
        T
    }
    
    pub fn pdu_parameters(&self) -> &[PduParameter] {
        &self.pdu_parameters
    }
}

pub enum PduParameter {
    Group(ParameterGroup),
    Single(Parameter),
    Unknown(u8, Vec<u8>),
}

pub enum ParameterGroup {
    ConnectAcceptItem(Vec<Parameter>),
}

pub enum Parameter {
    ProtocolOptionsParameter(ProtocolOptions),
    VersionNumberParameter(SupportedVersions),
    TsduMaximumSizeParameter(TsduMaximumSize),
    SessionUserRequirements(SessionUserRequirements),
    UserData(Vec<u8>),              // Techincally a parameter group. But it parses like a parameter.
    ExtendedUserData(Vec<u8>),      // Techincally a parameter group. But it parses like a parameter.
    DataOverflow(u8),
    Unknown(u8, Vec<u8>),
}

bitfield! {
    pub struct ProtocolOptions(u8);

    extended_concatenated_spdu_support, _ : 0;
    reserved, _ : 7, 1;
}

bitfield! {
    pub struct SupportedVersions(u8);

    version1, _ : 0;
    version2, _ : 1;
    reserved2, _ : 7, 2;
}

impl Default for SupportedVersions {
    fn default() -> Self {
        Self(0x01)
    }
}

bitfield! {
    pub struct TsduMaximumSize(u32);

    initiator, _ : 15, 0;
    responder, _ : 16, 31;
}

bitfield! {
    pub struct SessionUserRequirements(u16);

    half_duplex, _ : 0;
    full_duplex, _ : 1;
    expedited, _ : 2;
    minor_synchronize, _ : 3;
    major_synchronize, _ : 4;
    resynchronize, _ : 5;
    activity_management, _ : 6;
    negotiated_release, _ : 7;
    capability_data, _ : 8;
    exceptions, _ : 9;
    typed_data, _ : 10;
    reserved, _ : 15, 11;
}

impl Default for SessionUserRequirements {
    fn default() -> Self {
        Self(0x0349) // Default as per X.225
    }
}