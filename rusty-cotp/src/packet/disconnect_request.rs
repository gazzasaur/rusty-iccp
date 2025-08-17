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

use crate::packet::parameter::CotpParameter;

pub const DISCONNECT_REQUEST_CODE: u8 = 0x81u8;

#[derive(Debug, PartialEq)]
pub struct DisconnectRequest {
    source_reference: u16,
    destination_reference: u16,
    reason: DisconnectReason,
    parameters: Vec<CotpParameter>,
    user_data: Vec<u8>,
}

impl DisconnectRequest {
    pub fn new(source_reference: u16, destination_reference: u16, reason: DisconnectReason, parameters: Vec<CotpParameter>, user_data: &[u8]) -> Self {
        Self {
            source_reference,
            destination_reference,
            reason,
            parameters,
            user_data: user_data.into(),
        }
    }

    pub fn source_reference(&self) -> u16 {
        self.source_reference
    }

    pub fn destination_reference(&self) -> u16 {
        self.destination_reference
    }

    pub fn reason(&self) -> &DisconnectReason {
        &self.reason
    }

    pub fn parameters(&self) -> &[CotpParameter] {
        &self.parameters
    }

    pub fn user_data(&self) -> &[u8] {
        &self.user_data
    }
}

#[derive(Debug, PartialEq)]
pub enum DisconnectReason {
    ReasonNotSpecified,
    CongestionAtTsap,
    NotAttachedToTsap,
    AddressUnknown,

    NormalDisconnect,
    CongestionAtConnectionRequestTime,
    ConnectionNegotiationFailed,
    DuplicateSourceReferenceDetected,
    MismatchedEeferences,
    ProtocolError,
    NotUsed134,
    ReferenceOverflow,
    ConnectionRequestRefused,
    NotUsed137,
    HeaderOrParameterLengthInvalid,

    Unkown(u8),
}

impl From<u8> for DisconnectReason {
    fn from(value: u8) -> Self {
        match value {
            0 => DisconnectReason::ReasonNotSpecified,
            1 => DisconnectReason::CongestionAtTsap,
            2 => DisconnectReason::NotAttachedToTsap,
            3 => DisconnectReason::AddressUnknown,
            128 => DisconnectReason::NormalDisconnect,
            129 => DisconnectReason::CongestionAtConnectionRequestTime,
            130 => DisconnectReason::ConnectionNegotiationFailed,
            131 => DisconnectReason::DuplicateSourceReferenceDetected,
            132 => DisconnectReason::MismatchedEeferences,
            133 => DisconnectReason::ProtocolError,
            134 => DisconnectReason::NotUsed134,
            135 => DisconnectReason::ReferenceOverflow,
            136 => DisconnectReason::ConnectionRequestRefused,
            137 => DisconnectReason::NotUsed137,
            138 => DisconnectReason::HeaderOrParameterLengthInvalid,
            x => DisconnectReason::Unkown(x),
        }
    }
}
