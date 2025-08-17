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

use crate::api::CotpError;

pub const TPDU_SIZE_PARAMETER_CODE: u8 = 0b11000000;
pub const ALTERNATIVE_CLASS_PARAMETER_CODE: u8 = 0b11000111;

#[derive(Debug, PartialEq)]
pub enum ConnectionOption {
    Unknown(u8),
}

impl ConnectionOption {
    pub fn from(connection_options: u8) -> Vec<Self> {
        (0..8)
            .filter_map(|i| match connection_options & (1 << i) {
                x if x != 0 => Some(ConnectionOption::Unknown(i + 1)),
                _ => None,
            })
            .collect()
    }

    pub fn into(&self) -> Result<u8, CotpError> {
        match self {
            ConnectionOption::Unknown(0) => Ok(0),
            ConnectionOption::Unknown(x) if *x > 8 => Err(CotpError::InternalError(format!("An unknown connection option was detected. This is likely a bug: {}", *x))),
            ConnectionOption::Unknown(x) => Ok(1 << (*x - 1)),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ConnectionClass {
    Class0,
    Class1,
    Class2,
    Class3,
    Class4,
    Unknown(u8),
}

impl From<u8> for ConnectionClass {
    fn from(value: u8) -> Self {
        match value {
            0 => ConnectionClass::Class0,
            1 => ConnectionClass::Class1,
            2 => ConnectionClass::Class2,
            3 => ConnectionClass::Class3,
            4 => ConnectionClass::Class4,
            x => Self::Unknown(x),
        }
    }
}

impl From<&ConnectionClass> for u8 {
    fn from(value: &ConnectionClass) -> Self {
        match value {
            ConnectionClass::Class0 => 0,
            ConnectionClass::Class1 => 1,
            ConnectionClass::Class2 => 2,
            ConnectionClass::Class3 => 3,
            ConnectionClass::Class4 => 4,
            ConnectionClass::Unknown(x) => *x,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum TpduSize {
    Size128,
    Size256,
    Size512,
    Size1024,
    Size2048,
    Size4096,
    Size8192,
    Unknown(u8),
}

impl From<u8> for TpduSize {
    fn from(value: u8) -> Self {
        match value {
            0b00000111 => Self::Size128,
            0b00001000 => Self::Size256,
            0b00001001 => Self::Size512,
            0b00001010 => Self::Size1024,
            0b00001011 => Self::Size2048,
            0b00001100 => Self::Size4096,
            0b00001101 => Self::Size8192,
            x => Self::Unknown(x),
        }
    }
}

impl From<&TpduSize> for u8 {
    fn from(value: &TpduSize) -> Self {
        match value {
            TpduSize::Size128 => 0b00000111,
            TpduSize::Size256 => 0b00001000,
            TpduSize::Size512 => 0b00001001,
            TpduSize::Size1024 => 0b00001010,
            TpduSize::Size2048 => 0b00001011,
            TpduSize::Size4096 => 0b00001100,
            TpduSize::Size8192 => 0b00001101,
            TpduSize::Unknown(x) => *x,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CotpParameter {
    AlternativeClassParameter(Vec<ConnectionClass>),
    TpduLengthParameter(TpduSize),
    UnknownParameter(u8, Vec<u8>),
}
