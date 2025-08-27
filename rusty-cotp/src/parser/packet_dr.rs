use crate::{
    api::CotpError,
    packet::{disconnect_request::DisconnectRequest, payload::TransportProtocolDataUnit},
    parser::{common::parse_u16, params::parse_parameters},
};

pub fn parse_disconnect_request(header_data: &[u8], user_data: &[u8]) -> Result<TransportProtocolDataUnit, CotpError> {
    if header_data.len() < 5 {
        return Err(CotpError::ProtocolError(format!("At least 5 bytes are required to parse the payload but got {}", header_data.len())).into());
    }

    let destination_reference = parse_u16(&header_data[0..2])?;
    let source_reference = parse_u16(&header_data[2..4])?;
    let reason = header_data[4];
    let variable_part = &header_data[5..];

    let parameters = parse_parameters(variable_part)?;

    Ok(TransportProtocolDataUnit::DR(DisconnectRequest::new(source_reference, destination_reference, reason.into(), parameters, &user_data)))
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

        assert_eq!(subject.parse(hex::decode("06800000000000")?.as_slice())?, TransportProtocolDataUnit::DR(DisconnectRequest::new(0, 0, 0.into(), vec![], &[])));

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_alternative_classes_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(subject.parse(hex::decode("06800000000080")?.as_slice())?, TransportProtocolDataUnit::DR(DisconnectRequest::new(0, 0, 128.into(), vec![], &[])));

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_parameters_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            subject.parse(hex::decode("0D8000000000C8AB0548656C6C6F")?.as_slice())?,
            TransportProtocolDataUnit::DR(DisconnectRequest::new(0, 0, 200.into(), vec![CotpParameter::UnknownParameter(0xAB, vec![0x48, 0x65, 0x6C, 0x6C, 0x6F])], &[]))
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_multiple_parameters_with_userdata_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            subject.parse(hex::decode("15800000000014C00108C703001030AB0548656C6C6F010203")?.as_slice())?,
            TransportProtocolDataUnit::DR(DisconnectRequest::new(
                0,
                0,
                20.into(),
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
            subject.parse(hex::decode("0680000000008c010203")?.as_slice())?,
            TransportProtocolDataUnit::DR(DisconnectRequest::new(0, 0, 140.into(), vec![], &[1, 2, 3]))
        );

        Ok(())
    }
}
