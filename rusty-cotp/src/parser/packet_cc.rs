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
    packet::{connection_confirm::ConnectionConfirm, parameter::ConnectionOption, payload::TransportProtocolDataUnit},
    parser::{common::parse_u16, params::parse_parameters},
};

pub fn parse_create_confirm(credit: u8, header_data: &[u8], user_data: &[u8]) -> Result<TransportProtocolDataUnit, CotpError> {
    if header_data.len() < 5 {
        return Err(CotpError::ProtocolError(format!("At least 5 bytes are required to parse the payload but got {}", header_data.len())).into());
    }

    let destination_reference = parse_u16(&header_data[0..2])?;
    let source_reference = parse_u16(&header_data[2..4])?;
    let preferred_class = (header_data[4] & 0xF0) >> 4;
    let request_options = header_data[4] & 0x0F;
    let variable_part = &header_data[5..];

    let parameters = parse_parameters(variable_part)?;

    Ok(TransportProtocolDataUnit::CC(ConnectionConfirm::new(
        credit,
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
            subject.parse(hex::decode("06D00000000000")?.as_slice())?,
            TransportProtocolDataUnit::CC(ConnectionConfirm::new(0, 0, 0, ConnectionClass::Class0, vec![], vec![], &[]))
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_alternative_classes_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            subject.parse(hex::decode("06D10000000045")?.as_slice())?,
            TransportProtocolDataUnit::CC(ConnectionConfirm::new(1, 0, 0, ConnectionClass::Class4, vec![ConnectionOption::Unknown(1), ConnectionOption::Unknown(3)], vec![], &[]))
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn parse_payloads_with_parameters_happy() -> Result<(), anyhow::Error> {
        let subject = TransportProtocolDataUnitParser::new();

        assert_eq!(
            subject.parse(hex::decode("0DD50000000000AB0548656C6C6F")?.as_slice())?,
            TransportProtocolDataUnit::CC(ConnectionConfirm::new(
                5,
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
            subject.parse(hex::decode("15DA0000000000C00108C703001030AB0548656C6C6F010203")?.as_slice())?,
            TransportProtocolDataUnit::CC(ConnectionConfirm::new(
                0x0A,
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
            subject.parse(hex::decode("06D00000000000010203")?.as_slice())?,
            TransportProtocolDataUnit::CC(ConnectionConfirm::new(0, 0, 0, ConnectionClass::Class0, vec![], vec![], &[1, 2, 3]))
        );

        Ok(())
    }
}
