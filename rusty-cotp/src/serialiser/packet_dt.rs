use crate::{
    api::CotpError,
    packet::{
        connection_request::{ConnectionRequest, CONNECTION_REQUEST_CODE}, data_transfer::{DataTransfer, DATA_TRANSFER_CODE}, parameter::{ConnectionClass, ConnectionOption, CotpParameter, TpduSize}
    },
    serialiser::params::serialise_parameters,
};

pub fn serialise_data_transfer(data: &DataTransfer) -> Result<Vec<u8>, CotpError> {
    let mut buffer = Vec::new();
    buffer.push(2);
    buffer.push(DATA_TRANSFER_CODE);
    match data.end_of_transmission() {
        true => buffer.push(0x80),
        false => buffer.push(0x00),
    }
    buffer.extend(data.user_data());
    Ok(buffer)
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
            subject.serialise(&TransportProtocolDataUnit::DT(DataTransfer::new(false, &[1, 2, 3])))?,
            hex::decode("02F000010203")?.as_slice()
        );
        assert_eq!(
            subject.serialise(&TransportProtocolDataUnit::DT(DataTransfer::new(true, &[3, 2, 1])))?,
            hex::decode("02F080030201")?.as_slice()
        );

        Ok(())
    }
}
