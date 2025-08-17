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

    use crate::{packet::payload::TransportProtocolDataUnit, serialiser::packet::TransportProtocolDataUnitSerialiser};

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitSerialiser::new();

        assert_eq!(subject.serialise(&TransportProtocolDataUnit::DT(DataTransfer::new(false, &[1, 2, 3])))?, hex::decode("02F000010203")?.as_slice());
        assert_eq!(subject.serialise(&TransportProtocolDataUnit::DT(DataTransfer::new(true, &[3, 2, 1])))?, hex::decode("02F080030201")?.as_slice());

        Ok(())
    }
}
