use crate::{
    api::CotpError,
    packet::{payload::TransportProtocolDataUnit, tpdu_error::TpduError},
    parser::{common::parse_u16, params::parse_parameters},
};

pub fn parse_tpdu_error(header_data: &[u8]) -> Result<TransportProtocolDataUnit, CotpError> {
    if header_data.len() < 3 {
        return Err(CotpError::ProtocolError(format!("At least 3 bytes are required to parse the payload but got {}", header_data.len())).into());
    }

    let destination_reference = parse_u16(&header_data[0..2])?;
    let reason = header_data[2];
    let variable_part = &header_data[3..];

    let parameters = parse_parameters(variable_part)?;

    Ok(TransportProtocolDataUnit::ER(TpduError::new(destination_reference, reason.into(), parameters)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use tracing_test::traced_test;

    use crate::{
        packet::{parameter::CotpParameter, payload::TransportProtocolDataUnit},
        parser::packet::TransportProtocolDataUnitParser,
    };

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(subject.parse(hex::decode("0470000001")?.as_slice())?, TransportProtocolDataUnit::ER(TpduError::new(0, 1.into(), vec![])));

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_parameters_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            subject.parse(hex::decode("0B700000C8AB0548656C6C6F")?.as_slice())?,
            TransportProtocolDataUnit::ER(TpduError::new(0, 200.into(), vec![CotpParameter::UnknownParameter(0xAB, vec![0x48, 0x65, 0x6C, 0x6C, 0x6F])]))
        );

        Ok(())
    }
}
