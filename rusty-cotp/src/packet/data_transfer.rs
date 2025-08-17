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

pub const DATA_TRANSFER_CODE: u8 = 0xF0u8;

#[derive(Debug, PartialEq)]
pub struct DataTransfer {
    end_of_transmission: bool,
    user_data: Vec<u8>,
}

impl DataTransfer {
    pub fn new(end_of_transmission: bool, user_data: &[u8]) -> Self {
        Self {
            end_of_transmission,
            user_data: user_data.into(),
        }
    }

    pub fn end_of_transmission(&self) -> bool {
        self.end_of_transmission
    }

    pub fn user_data(&self) -> &[u8] {
        &self.user_data
    }
}
