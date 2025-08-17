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
    packet::payload::TransportProtocolDataUnit,
    serialiser::{packet_cc::serialise_connection_confirm, packet_cr::serialise_connection_request, packet_dt::serialise_data_transfer},
};

pub struct TransportProtocolDataUnitSerialiser {}

impl TransportProtocolDataUnitSerialiser {
    pub fn new() -> Self {
        TransportProtocolDataUnitSerialiser {}
    }

    pub fn serialise(&self, data: &TransportProtocolDataUnit) -> Result<Vec<u8>, CotpError> {
        match data {
            TransportProtocolDataUnit::CR(x) => serialise_connection_request(&x),
            TransportProtocolDataUnit::CC(x) => serialise_connection_confirm(&x),
            TransportProtocolDataUnit::DT(x) => serialise_data_transfer(&x),
            _ => return Err(CotpError::ProtocolError(format!("Unsupported tpdu: {:?}", data).into())),
        }
    }
}
