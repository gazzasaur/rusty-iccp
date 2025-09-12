use crate::{
    api::CotpError,
    packet::{
        connection_confirm::{CONNECTION_CONFIRM_CODE, ConnectionConfirm},
        parameters::{ConnectionClass, ConnectionOption, CotpParameter, TpduSize},
    },
    serialiser::params::serialise_parameters,
};

pub fn serialise_connection_confirm(data: &ConnectionConfirm) -> Result<Vec<u8>, CotpError> {
    if data.preferred_class() != &ConnectionClass::Class0 {
        return Err(CotpError::ProtocolError(format!("Unsupported class {:?}. Only Class 0 is supported by this package.", data.preferred_class()).into()));
    }
    if data.user_data().len() != 0 {
        return Err(CotpError::ProtocolError("User data is not supported on Class 0 connection confirms.".into()));
    }
    if data.parameters().len() > 1 {
        return Err(CotpError::ProtocolError("Only a single parameter specifying TPDU length is supported.".into()));
    }
    if data.parameters().len() == 1 {
        match data.parameters().get(0) {
            Some(&CotpParameter::TpduLengthParameter(TpduSize::Size128)) => (),
            Some(&CotpParameter::TpduLengthParameter(TpduSize::Size256)) => (),
            Some(&CotpParameter::TpduLengthParameter(TpduSize::Size512)) => (),
            Some(&CotpParameter::TpduLengthParameter(TpduSize::Size1024)) => (),
            Some(&CotpParameter::TpduLengthParameter(TpduSize::Size2048)) => (),
            Some(&CotpParameter::TpduLengthParameter(TpduSize::Size4096)) => return Err(CotpError::ProtocolError("Unsupported payload 4096 length for Class 0.".into())),
            Some(&CotpParameter::TpduLengthParameter(TpduSize::Size8192)) => return Err(CotpError::ProtocolError("Unsupported payload 8192 length for Class 0.".into())),
            Some(&CotpParameter::TpduLengthParameter(TpduSize::Unknown(x))) => return Err(CotpError::ProtocolError(format!("Unknown oayload size requested: {}", x).into())),
            x => return Err(CotpError::ProtocolError(format!("Unsupported Parameter: {:?}", x).into())),
        }
    }

    let params = serialise_parameters(data.parameters())?;

    let header_field_length = 6 + params.len();
    if header_field_length > 254 {
        // 0xFF is reserved.
        return Err(CotpError::ProtocolError(format!("The given packet is too big. The maximum is 254 but got {}.", header_field_length).into()));
    }

    let data_class_field: u8 = <&ConnectionClass as Into<u8>>::into(data.preferred_class()) << 4;
    let data_options_field: u8 = serialise_connection_options(data.options())?;

    let mut buffer = Vec::new();
    buffer.push(header_field_length as u8);
    buffer.push(CONNECTION_CONFIRM_CODE | data.credit());
    buffer.extend(data.destination_reference().to_be_bytes());
    buffer.extend(data.source_reference().to_be_bytes());
    buffer.push(data_class_field | data_options_field);
    buffer.extend(params);

    Ok(buffer)
}

pub fn serialise_connection_options(options: &[ConnectionOption]) -> Result<u8, CotpError> {
    let mut options_field = 0u8;
    for option in options {
        options_field = options_field | option.into()?
    }
    return Ok(options_field);
}

#[cfg(test)]
mod tests {
    use super::*;

    use tracing_test::traced_test;

    use crate::{
        packet::{parameters::ConnectionClass, payload::TransportProtocolDataUnit},
        serialiser::packet::serialise,
    };

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_happy() -> Result<(), anyhow::Error> {
        assert_eq!(
            serialise(&TransportProtocolDataUnit::CC(ConnectionConfirm::new(0, 0, 0, ConnectionClass::Class0, vec![], vec![], &[])))?,
            hex::decode("06D00000000000")?.as_slice()
        );
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_alternative_classes_happy() -> Result<(), anyhow::Error> {
        assert_eq!(
            serialise(&TransportProtocolDataUnit::CC(ConnectionConfirm::new(
                1,
                0,
                0,
                ConnectionClass::Class0,
                vec![ConnectionOption::Unknown(1), ConnectionOption::Unknown(3)],
                vec![],
                &[],
            )))?,
            hex::decode("06D10000000005")?.as_slice()
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_alternative_classes_sad() -> Result<(), anyhow::Error> {
        match serialise(&TransportProtocolDataUnit::CC(ConnectionConfirm::new(
            0,
            0,
            0,
            ConnectionClass::Class4,
            vec![ConnectionOption::Unknown(1), ConnectionOption::Unknown(3)],
            vec![],
            &[],
        ))) {
            Ok(_) => assert!(false, "Expected this to result in an error"),
            Err(CotpError::ProtocolError(message)) => assert_eq!("Unsupported class Class4. Only Class 0 is supported by this package.", message),
            _ => assert!(false, "Unexpected failure result."),
        };
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_parameters_happy() -> Result<(), anyhow::Error> {
        match serialise(&TransportProtocolDataUnit::CC(ConnectionConfirm::new(
            0,
            0,
            0,
            ConnectionClass::Class0,
            vec![],
            vec![CotpParameter::UnknownParameter(0xAB, vec![0x48, 0x65, 0x6C, 0x6C, 0x6F])],
            &[],
        ))) {
            Ok(_) => assert!(false, "Expected this to result in an error"),
            Err(CotpError::ProtocolError(message)) => assert_eq!("Unsupported Parameter: Some(UnknownParameter(171, [72, 101, 108, 108, 111]))", message),
            _ => assert!(false, "Unexpected failure result."),
        };
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_userdata_sad() -> Result<(), anyhow::Error> {
        match serialise(&TransportProtocolDataUnit::CC(ConnectionConfirm::new(0, 0, 0, ConnectionClass::Class0, vec![], vec![], &[1, 2, 3]))) {
            Ok(_) => assert!(false, "Expected this to result in an error"),
            Err(CotpError::ProtocolError(message)) => assert_eq!("User data is not supported on Class 0 connection confirms.", message),
            _ => assert!(false, "Unexpected failure result."),
        };
        Ok(())
    }
}
