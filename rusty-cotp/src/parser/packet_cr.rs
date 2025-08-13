use crate::{
    error::CotpError,
    packet::{connection_request::ConnectionRequest, parameter::ConnectionOption, payload::TransportProtocolDataUnit},
    parser::{common::parse_u16, params::parse_parameters},
};

pub fn parse_connection_request(header_data: &[u8], user_data: &[u8]) -> Result<TransportProtocolDataUnit, CotpError> {
    if header_data.len() < 5 {
        return Err(CotpError::ProtocolError(format!("At least 5 bytes are required to parse the payload but got {}", header_data.len())).into());
    }

    let destination_reference = parse_u16(&header_data[0..2])?;
    let source_reference = parse_u16(&header_data[2..4])?;
    let preferred_class = (header_data[4] & 0xF0) >> 4;
    let request_options = header_data[4] & 0x0F;
    let variable_part = &header_data[5..];

    let parameters = parse_parameters(variable_part)?;

    Ok(TransportProtocolDataUnit::CR(ConnectionRequest::new(
        source_reference,
        destination_reference,
        preferred_class.into(),
        ConnectionOption::from(request_options),
        parameters,
        &user_data,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    use tracing_test::traced_test;

    use crate::{
        packet::{
            parameter::{ConnectionClass, CotpParameter, TpduSize},
            payload::TransportProtocolDataUnit,
        },
        parser::packet::TransportProtocolDataUnitParser,
    };

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            subject.parse(hex::decode("06E00000000000")?.as_slice())?,
            TransportProtocolDataUnit::CR(ConnectionRequest::new(0, 0, ConnectionClass::Class0, vec![], vec![], &[]))
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_alternative_classes_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            subject.parse(hex::decode("06E00000000045")?.as_slice())?,
            TransportProtocolDataUnit::CR(ConnectionRequest::new(0, 0, ConnectionClass::Class4, vec![ConnectionOption::Unknown(1), ConnectionOption::Unknown(3)], vec![], &[]))
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_parameters_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            subject.parse(hex::decode("0DE00000000000AB0548656C6C6F")?.as_slice())?,
            TransportProtocolDataUnit::CR(ConnectionRequest::new(
                0,
                0,
                ConnectionClass::Class0,
                vec![],
                vec![CotpParameter::UnknownParameter(0xAB, vec![0x48, 0x65, 0x6C, 0x6C, 0x6F])],
                &[]
            ))
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_multiple_parameters_with_userdata_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            subject.parse(hex::decode("15E00000000000C00108C703001030AB0548656C6C6F010203")?.as_slice())?,
            TransportProtocolDataUnit::CR(ConnectionRequest::new(
                0,
                0,
                ConnectionClass::Class0,
                vec![],
                vec![
                    CotpParameter::TpduLengthParameter(TpduSize::Size256),
                    CotpParameter::AlternativeClassParameter(vec![ConnectionClass::Class0, ConnectionClass::Class1, ConnectionClass::Class3]),
                    CotpParameter::UnknownParameter(0xAB, vec![0x48, 0x65, 0x6C, 0x6C, 0x6F])
                ],
                &[1, 2, 3]
            ))
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_userdata_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            // Not striclty legal having userdata on class 0, but eh.
            subject.parse(hex::decode("06E00000000000010203")?.as_slice())?,
            TransportProtocolDataUnit::CR(ConnectionRequest::new(0, 0, ConnectionClass::Class0, vec![], vec![], &[1, 2, 3]))
        );

        Ok(())
    }
}
