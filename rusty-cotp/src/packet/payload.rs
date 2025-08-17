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

use crate::packet::{
    connection_confirm::{CONNECTION_CONFIRM_CODE, ConnectionConfirm},
    connection_request::{CONNECTION_REQUEST_CODE, ConnectionRequest},
    data_transfer::{DATA_TRANSFER_CODE, DataTransfer},
    disconnect_request::{DISCONNECT_REQUEST_CODE, DisconnectRequest},
    tpdu_error::{TPDU_ERROR_CODE, TpduError},
};

#[derive(Debug, PartialEq)]
pub enum TransportProtocolDataUnit {
    CR(ConnectionRequest),
    CC(ConnectionConfirm),
    DR(DisconnectRequest),
    DT(DataTransfer),
    ER(TpduError),
}

impl TransportProtocolDataUnit {
    pub fn get_code(tpdu: &Self) -> u8 {
        match tpdu {
            Self::CR(_) => CONNECTION_REQUEST_CODE,
            Self::CC(_) => CONNECTION_CONFIRM_CODE,
            Self::DR(_) => DISCONNECT_REQUEST_CODE,
            Self::DT(_) => DATA_TRANSFER_CODE,
            Self::ER(_) => TPDU_ERROR_CODE,
        }
    }
}
