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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TpktError {
    #[error("Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("Error: {}", .0)]
    InternalError(String),
}

pub enum TpktRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait TpktService<T> {
    fn create_server<'a>(address: T) -> impl std::future::Future<Output = Result<impl 'a + TpktServer<T> + Send, TpktError>> + Send;
    fn connect<'a>(address: T) -> impl std::future::Future<Output = Result<impl 'a + TpktConnection<T> + Send, TpktError>> + Send;
}

pub trait TpktServer<T> {
    fn accept<'a>(&self) -> impl std::future::Future<Output = Result<impl 'a + TpktConnection<T> + Send, TpktError>> + Send;
}

pub trait TpktConnection<T> {
    fn remote_host(&self) -> T;
    fn split<'a>(connection: Self) -> impl std::future::Future<Output = Result<(impl 'a + TpktReader<T> + Send, impl 'a + TpktWriter<T> + Send), TpktError>> + Send;
}

pub trait TpktReader<T> {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<TpktRecvResult, TpktError>> + Send;
}

pub trait TpktWriter<T> {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), TpktError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), TpktError>> + Send;
}
