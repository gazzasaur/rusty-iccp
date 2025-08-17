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
    packet::{
        connection_confirm::CONNECTION_CONFIRM_CODE, connection_request::CONNECTION_REQUEST_CODE, data_transfer::DATA_TRANSFER_CODE, disconnect_request::DISCONNECT_REQUEST_CODE, payload::TransportProtocolDataUnit,
        tpdu_error::TPDU_ERROR_CODE,
    },
    parser::{packet_cc::parse_create_confirm, packet_cr::parse_connection_request, packet_dr::parse_disconnect_request, packet_dt::parse_data_transfer, packet_er::parse_tpdu_error},
};

pub struct TransportProtocolDataUnitParser {}

impl TransportProtocolDataUnitParser {
    pub fn new() -> Self {
        TransportProtocolDataUnitParser {}
    }

    pub fn parse(&self, data: &[u8]) -> Result<TransportProtocolDataUnit, CotpError> {
        let buffer_length = data.len();
        if buffer_length < 2 {
            return Err(CotpError::ProtocolError(format!("Invalid payload data. Need at least 2 bytes but only {} bytes was received.", buffer_length)));
        }

        let header_length = data[0] as usize;
        if header_length < 2 || header_length > 254 {
            return Err(CotpError::ProtocolError(format!("Invalid header length value. The value must be greater than 1 and less that 255 but was {}.", header_length)));
        }

        if buffer_length < header_length + 1 {
            return Err(CotpError::ProtocolError(format!(
                "The buffer length {} cannot fit the required payload with a header length of {}",
                buffer_length, header_length
            )));
        }

        let class_code = data[1] & 0xF0u8;
        let credit = data[1] & 0x0Fu8;

        match (data[1], class_code, credit) {
            (_, CONNECTION_REQUEST_CODE, 0x00u8) => parse_connection_request(credit, &data[2..(header_length + 1)], &data[(header_length + 1)..]),
            (_, CONNECTION_CONFIRM_CODE, _) => parse_create_confirm(credit, &data[2..(header_length + 1)], &data[(header_length + 1)..]),
            (DISCONNECT_REQUEST_CODE, _, _) => parse_disconnect_request(&data[2..(header_length + 1)], &data[(header_length + 1)..]),
            (DATA_TRANSFER_CODE, _, _) => parse_data_transfer(&data[2..(header_length + 1)], &data[(header_length + 1)..]),
            (TPDU_ERROR_CODE, _, _) => parse_tpdu_error(&data[2..(header_length + 1)]),
            _ => return Err(CotpError::ProtocolError(format!("Unsupported class code was receiveed: {}", class_code).into())),
        }
    }
}

// Tests are in individual packet parsers.
