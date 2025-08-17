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

use crate::packet::parameter::{ConnectionClass, ConnectionOption, CotpParameter};

pub const CONNECTION_REQUEST_CODE: u8 = 0xE0u8;

#[derive(Debug, PartialEq)]
pub struct ConnectionRequest {
    credit: u8,
    source_reference: u16,
    destination_reference: u16,
    preferred_class: ConnectionClass,
    options: Vec<ConnectionOption>,
    parameters: Vec<CotpParameter>,
    user_data: Vec<u8>,
}

impl ConnectionRequest {
    pub fn new(credit: u8, source_reference: u16, destination_reference: u16, preferred_class: ConnectionClass, options: Vec<ConnectionOption>, parameters: Vec<CotpParameter>, user_data: &[u8]) -> Self {
        Self {
            credit,
            source_reference,
            destination_reference,
            preferred_class,
            options,
            parameters,
            user_data: user_data.into(),
        }
    }

    pub fn credit(&self) -> u8 {
        self.credit
    }

    pub fn source_reference(&self) -> u16 {
        self.source_reference
    }

    pub fn destination_reference(&self) -> u16 {
        self.destination_reference
    }

    pub fn preferred_class(&self) -> &ConnectionClass {
        &self.preferred_class
    }

    pub fn options(&self) -> &[ConnectionOption] {
        &self.options
    }

    pub fn parameters(&self) -> &[CotpParameter] {
        &self.parameters
    }

    pub fn user_data(&self) -> &[u8] {
        &self.user_data
    }
}
