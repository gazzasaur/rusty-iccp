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

use bytes::BytesMut;

use crate::api::TpktError;

pub const HEADER_LENGTH: usize = 4;
pub const TPKT_MAGIC_START_NUMBER: u8 = 0x03u8;
pub const MAX_PACKET_LENGTH: usize = 2usize.pow(16) - 1;
pub const MAX_PAYLOAD_LENGTH: usize = MAX_PACKET_LENGTH - HEADER_LENGTH;

pub struct TpktSerialiser {}

impl TpktSerialiser {
    pub fn new() -> Self {
        Self {}
    }

    pub fn serialise(&self, data: &[u8]) -> Result<BytesMut, TpktError> {
        if data.len() > MAX_PAYLOAD_LENGTH {
            return Err(TpktError::ProtocolError(format!("TPKT user data must be less than or equal to {} but was {}", MAX_PAYLOAD_LENGTH, data.len())));
        }
        let packet_length = ((data.len() + HEADER_LENGTH) as u16).to_be_bytes();
        let mut send_buffer = BytesMut::with_capacity(4 + data.len());
        send_buffer.extend_from_slice(&[0x03u8, 0x00u8]);
        send_buffer.extend_from_slice(&packet_length);
        send_buffer.extend_from_slice(&data);
        Ok(send_buffer)
    }
}
