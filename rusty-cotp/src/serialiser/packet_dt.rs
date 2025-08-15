use crate::{
    api::CotpError,
    packet::{
        connection_request::{ConnectionRequest, CONNECTION_REQUEST_CODE}, data_transfer::DataTransfer, parameter::{ConnectionClass, ConnectionOption, CotpParameter, TpduSize}
    },
    serialiser::params::serialise_parameters,
};

// pub fn serialise_data_transfer(data: &DataTransfer) -> Result<Vec<u8>, CotpError> {
    
// }

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
        packet::{parameter::ConnectionClass, payload::TransportProtocolDataUnit},
        serialiser::packet::TransportProtocolDataUnitSerialiser,
    };

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitSerialiser::new();

        assert_eq!(
            subject.serialise(&TransportProtocolDataUnit::CR(ConnectionRequest::new(0, 0, 0, ConnectionClass::Class0, vec![], vec![], &[])))?,
            hex::decode("06E00000000000")?.as_slice()
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_alternative_classes_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitSerialiser::new();

        assert_eq!(
            subject.serialise(&TransportProtocolDataUnit::CR(ConnectionRequest::new(
                0,
                0,
                0,
                ConnectionClass::Class0,
                vec![ConnectionOption::Unknown(1), ConnectionOption::Unknown(3)],
                vec![],
                &[],
            )))?,
            hex::decode("06E00000000005")?.as_slice()
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_alternative_classes_sad() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitSerialiser::new();

        match subject.serialise(&TransportProtocolDataUnit::CR(ConnectionRequest::new(
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
        let subject = TransportProtocolDataUnitSerialiser::new();

        match subject.serialise(&TransportProtocolDataUnit::CR(ConnectionRequest::new(
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
        let subject = TransportProtocolDataUnitSerialiser::new();

        match subject.serialise(&TransportProtocolDataUnit::CR(ConnectionRequest::new(0, 0, 0, ConnectionClass::Class0, vec![], vec![], &[1, 2, 3]))) {
            Ok(_) => assert!(false, "Expected this to result in an error"),
            Err(CotpError::ProtocolError(message)) => assert_eq!("User data is not supported on Class 0 connection requests.", message),
            _ => assert!(false, "Unexpected failure result."),
        };
        Ok(())
    }
}
