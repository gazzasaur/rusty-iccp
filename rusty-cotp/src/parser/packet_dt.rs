/**
 * MIT License
 *
 * Copyright (c) 2025 gazzasaur
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

use crate::{
    api::CotpError,
    packet::{data_transfer::DataTransfer, payload::TransportProtocolDataUnit},
};

pub fn parse_data_transfer(header_data: &[u8], user_data: &[u8]) -> Result<TransportProtocolDataUnit, CotpError> {
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
