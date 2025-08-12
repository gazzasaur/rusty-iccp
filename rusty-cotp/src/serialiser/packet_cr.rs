use crate::{
    error::CotpError,
    packet::{
        connection_request::{CONNECTION_REQUEST_CODE, ConnectionRequest},
        parameter::{ConnectionClass, CotpParameter, TpduLength},
    },
};

pub fn serialise_connection_request(data: &ConnectionRequest) -> Result<Vec<u8>, CotpError> {
    if data.preferred_class() != &ConnectionClass::Class0 {
        return Err(CotpError::ProtocolError(format!("Unsupported class {:?}. Only Class 0 is supported by this package.", data.preferred_class()).into()));
    }
    if data.user_data().len() != 0 {
        return Err(CotpError::ProtocolError("User data is not supported on Class 0 connections requests.".into()));
    }
    if data.parameters().len() > 1 {
        return Err(CotpError::ProtocolError("Only a single parameter specifying TPDU length is supported.".into()));
    }
    if data.parameters().len() == 1 {
        match data.parameters().get(0) {
            Some(&CotpParameter::TpduLengthParameter(TpduLength::Size128)) => (),
            Some(&CotpParameter::TpduLengthParameter(TpduLength::Size256)) => (),
            Some(&CotpParameter::TpduLengthParameter(TpduLength::Size512)) => (),
            Some(&CotpParameter::TpduLengthParameter(TpduLength::Size1024)) => (),
            Some(&CotpParameter::TpduLengthParameter(TpduLength::Size2048)) => (),
            Some(&CotpParameter::TpduLengthParameter(TpduLength::Size4096)) => return Err(CotpError::ProtocolError("Unsupported payload 4096 length for Class 0.".into())),
            Some(&CotpParameter::TpduLengthParameter(TpduLength::Size8192)) => return Err(CotpError::ProtocolError("Unsupported payload 8192 length for Class 0.".into())),
            Some(&CotpParameter::TpduLengthParameter(TpduLength::Unknown(x))) => return Err(CotpError::ProtocolError(format!("Unknown oayload size requested: {}", x).into())),
            x => return Err(CotpError::ProtocolError(format!("UnkUnsupported Parameter: {:?}", x).into())),
        }
        ()
    }

    let mut buffer = Vec::new();
    buffer.push(CONNECTION_REQUEST_CODE);

    Ok(buffer)
}
