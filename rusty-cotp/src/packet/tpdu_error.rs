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

pub const TPDU_ERROR_CODE: u8 = 0x70u8;

#[derive(Debug, PartialEq)]
pub struct TpduError {
    destination_reference: u16,
    reason: RejectCause,
    parameters: Vec<CotpParameter>,
}

impl TpduError {
    pub fn new(destination_reference: u16, reason: RejectCause, parameters: Vec<CotpParameter>) -> Self {
        Self { destination_reference, reason, parameters }
    }

    pub fn destination_reference(&self) -> u16 {
        self.destination_reference
    }

    pub fn reason(&self) -> &RejectCause {
        &self.reason
    }

    pub fn parameters(&self) -> &[CotpParameter] {
        &self.parameters
    }
}

#[derive(Debug, PartialEq)]
pub enum RejectCause {
    ReasonNotSpecified,
    InvalidParameterCode,
    InvalidTpduType,
    InvalidParameterValue,
    Unkown(u8),
}

impl From<u8> for RejectCause {
    fn from(value: u8) -> Self {
        match value {
            0 => RejectCause::ReasonNotSpecified,
            1 => RejectCause::InvalidParameterCode,
            2 => RejectCause::InvalidTpduType,
            3 => RejectCause::InvalidParameterValue,
            x => RejectCause::Unkown(x),
        }
    }
}
