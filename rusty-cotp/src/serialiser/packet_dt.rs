use crate::{
    api::CotpError,
    packet::data_transfer::{DATA_TRANSFER_CODE, DataTransfer},
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

    use crate::{packet::payload::TransportProtocolDataUnit, serialiser::packet::serialise};

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_happy() -> Result<(), anyhow::Error> {
        assert_eq!(serialise(&TransportProtocolDataUnit::DT(DataTransfer::new(false, &[1, 2, 3])))?, hex::decode("02F000010203")?.as_slice());
        assert_eq!(serialise(&TransportProtocolDataUnit::DT(DataTransfer::new(true, &[3, 2, 1])))?, hex::decode("02F080030201")?.as_slice());

        Ok(())
    }
}
