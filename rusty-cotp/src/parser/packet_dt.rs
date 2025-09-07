use crate::{
    api::CotpError,
    packet::{data_transfer::DataTransfer, payload::TransportProtocolDataUnit},
};

pub(crate) fn parse_data_transfer(header_data: &[u8], user_data: &[u8]) -> Result<TransportProtocolDataUnit, CotpError> {
    if header_data.len() < 1 {
        return Err(CotpError::ProtocolError(format!("At least 1 bytes are required to parse the payload but got {}", header_data.len())).into());
    }
    if header_data.len() > 1 {
        return Err(CotpError::ProtocolError(format!("Data transfer only supports a 1 byte field on class 0 but got {}", header_data.len())).into());
    }

    let end_of_transmission = (header_data[0] & 0x80) != 0;
    Ok(TransportProtocolDataUnit::DT(DataTransfer::new(end_of_transmission, user_data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use tracing_test::traced_test;

    use crate::{packet::payload::TransportProtocolDataUnit, parser::packet::TransportProtocolDataUnitParser};

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(subject.parse(hex::decode("02F08000000000")?.as_slice())?, TransportProtocolDataUnit::DT(DataTransfer::new(true, &[0, 0, 0, 0])));
        assert_eq!(subject.parse(hex::decode("02F000")?.as_slice())?, TransportProtocolDataUnit::DT(DataTransfer::new(false, &[])));

        Ok(())
    }
}
