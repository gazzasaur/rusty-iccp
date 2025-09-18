use bitfield::bitfield;
use strum::IntoStaticStr;

use crate::api::CospError;

#[derive(Debug, IntoStaticStr)]
pub(crate) enum SessionPduParameter {
    // We are treating the PDU tpyes as parameters as their tags do not conflict and they follow the same encoding rules.
    // The main difference is that the order of concatenation is not determined by the tag. So serialize and deserialize is different.
    Connect(Vec<SessionPduParameter>),
    OverflowAccept(Vec<SessionPduParameter>),
    ConnectDataOverflow(Vec<SessionPduParameter>),
    Accept(Vec<SessionPduParameter>),
    GiveTokens(),
    DataTransfer(Vec<SessionPduParameter>),

    ConnectAcceptItemParameter(Vec<SessionPduParameter>),

    ProtocolOptionsParameter(ProtocolOptionsField),
    TsduMaximumSizeParameter(TsduMaximumSizeField),
    VersionNumberParameter(VersionNumberField),
    // ReasonCodeParameter(ReasonCode), TODO
    SessionUserRequirementsParameter(SessionUserRequirementsField),
    UserDataParameter(Vec<u8>),
    ExtendedUserDataParameter(Vec<u8>),
    DataOverflowParameter(DataOverflowField),
    EnclosureParameter(EnclosureField),

    Unknown,
}

// ---
// Utilities

pub(crate) fn encode_length(length: usize) -> Result<Vec<u8>, CospError> {
    if length > u16::MAX as usize {
        Err(CospError::InternalError(format!("Parameter length is greater than max length {}", length)).into())
    } else if length < 255 {
        Ok(vec![length as u8])
    } else {
        let length_bytes = (length as u16).to_be_bytes();
        Ok(vec![0xFF, length_bytes[0], length_bytes[1]])
    }
}

#[macro_export]
macro_rules! serialise_parameter_value {
    ($code: expr, $parameter_value: expr) => {{
        let mut buffer: VecDeque<u8> = VecDeque::new();

        let encoded_value = $parameter_value.to_be_bytes();

        buffer.push_back($code);
        buffer.extend(encode_length(encoded_value.len())?);
        buffer.extend(encoded_value);

        Result::<Vec<u8>, CospError>::Ok(buffer.drain(..).collect())
    }};
}

// ---
// Protocol Options

bitfield! {
    pub(crate) struct ProtocolOptionsField(u8);

    impl new;
    impl Debug;

    pub(crate) extended_concatenated_spdu_support, _ : 0;
    pub(crate) reserved, _ : 7, 1;
}

// ---
// TSDU Maximum Size

bitfield! {
    pub(crate) struct TsduMaximumSizeField(u32);

    impl new;
    impl Debug;

    u16;
    pub(crate) to_initiator, _ : 15, 0;
    pub(crate) to_responder, _ : 31, 16;
}

// ---
// Version Number

bitfield! {
    pub(crate) struct VersionNumberField(u8);

    impl new;
    impl Debug;

    pub(crate) version1, _ : 0;
    pub(crate) version2, _ : 1;
    pub(crate) reserved, _ : 7, 2;
}

// ---
// Reason Code

// TODO
// #[derive(Debug, IntoStaticStr)]
// pub(crate) enum ReasonCode {
//     RejectionByCalledSsUser,
//     RejectionByCalledSsUserDueToTemporaryCongestion,
//     RejectionByCalledSsUserWithData(Vec<u8>),
//     SessionSelectorUnknown,
//     SsUserNotAttachedToSsap,
//     SpmCongestionAtConnectTime,
//     ProposedProtocolVersionsNotSupported,
//     RejectionByTheSpm,
//     RejectionByTheSpm2,
//     Unknown(u8),
// }

// impl ReasonCode {
//     pub(crate) fn new(code: u8, user_data: &[u8]) -> Self {
//         match code {
//             0 => ReasonCode::RejectionByCalledSsUser,
//             1 => ReasonCode::RejectionByCalledSsUserDueToTemporaryCongestion,
//             2 => ReasonCode::RejectionByCalledSsUserWithData(user_data.to_vec()),
//             129 => ReasonCode::SessionSelectorUnknown,
//             130 => ReasonCode::SsUserNotAttachedToSsap,
//             131 => ReasonCode::SpmCongestionAtConnectTime,
//             132 => ReasonCode::ProposedProtocolVersionsNotSupported,
//             133 => ReasonCode::RejectionByTheSpm,
//             134 => ReasonCode::RejectionByTheSpm2,
//             x => ReasonCode::Unknown(x),
//         }
//     }
// }

// impl TryFrom<&ReasonCode> for Vec<u8> {
//     type Error = CospError;

//     fn try_from(value: &ReasonCode) -> Result<Self, Self::Error> {
//         let mut buffer = VecDeque::new();

//         let code = match value {
//             ReasonCode::RejectionByCalledSsUser => 0,
//             ReasonCode::RejectionByCalledSsUserDueToTemporaryCongestion => 1,
//             ReasonCode::RejectionByCalledSsUserWithData(_) => 2,
//             ReasonCode::SessionSelectorUnknown => 129,
//             ReasonCode::SsUserNotAttachedToSsap => 130,
//             ReasonCode::SpmCongestionAtConnectTime => 131,
//             ReasonCode::ProposedProtocolVersionsNotSupported => 132,
//             ReasonCode::RejectionByTheSpm => 133,
//             ReasonCode::RejectionByTheSpm2 => 134,
//             ReasonCode::Unknown(code) => *code,
//         };

//         let empty_vec = vec![];
//         let user_data = match value {
//             ReasonCode::RejectionByCalledSsUserWithData(user_data) => user_data,
//             _ => &empty_vec,
//         };

//         buffer.push_back(REASON_CODE_PARAMETER_CODE);
//         buffer.extend(encode_length(1 + user_data.len())?);
//         buffer.push_back(code);
//         buffer.extend(user_data);

//         Ok(buffer.into_iter().collect())
//     }
// }

// ---
// Session User Requirements

bitfield! {
    pub(crate) struct SessionUserRequirementsField(u16);

    impl new;
    impl Debug;

    pub(crate) half_duplex, _ : 0;
    pub(crate) full_duplex, _ : 1;
    pub(crate) expedited, _ : 2;
    pub(crate) minor_synchronize, _ : 3;
    pub(crate) major_synchronize, _ : 4;
    pub(crate) resynchronize, _ : 5;
    pub(crate) activity_management, _ : 6;
    pub(crate) negotiated_release, _ : 7;
    pub(crate) capability_data, _ : 8;
    pub(crate) exceptions, _ : 9;
    pub(crate) typed_data, _ : 10;
    pub(crate) reserved, _ : 15, 11;
}

impl Clone for SessionUserRequirementsField {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Copy for SessionUserRequirementsField {}

impl Default for SessionUserRequirementsField {
    fn default() -> Self {
        Self(0x0349) // Default as per X.225
    }
}

// ---
// Data Overflow Field

bitfield! {
    #[derive(Debug)]
    pub(crate) struct DataOverflowField(u8);

    pub(crate) more_data, _ : 0; // The only valid value is true
    pub(crate) reserved, _ : 7, 1;
}

impl Clone for DataOverflowField {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Copy for DataOverflowField {}

impl Default for DataOverflowField {
    fn default() -> Self {
        Self(0x01)
    }
}

// --
// Enclosure Field

bitfield! {
    #[derive(Debug)]
    pub(crate) struct EnclosureField(u8);

    pub(crate) begining, _ : 0; // The only valid value is false
    pub(crate) end, _ : 1;
    pub(crate) reserved, _ : 7, 2;
}

impl Clone for EnclosureField {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Copy for EnclosureField {}

impl Default for EnclosureField {
    fn default() -> Self {
        Self(0x02)
    }
}
