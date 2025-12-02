use rusty_copp::CoppError;
use thiserror::Error;

/**
 * This MMS stack is designed to be used with ICCP. It supports the following.
 * 
 * Parameter CBB
 * - str1
 * - str2
 * - vnam
 * - vatl
 * - vlis
 * 
 * VMD Support
 * - GetNameList
 * - Identify
 *    
 * Variable Access
 * - Read
 * - Write
 * - Information Report
 * - GetVariableAccessAttributes
 * - DefineNamedVariableList
 * - GetNamedVariableListAttribute
 * - DeleteNamedVariableList
 */

#[derive(Error, Debug)]
pub enum MmsError {
    #[error("MMS Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("MMS over ACSE Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] CoppError),

    #[error("MMS IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("MMS Error: {}", .0)]
    InternalError(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsRecvResult {
    Closed,
    Data(MmsMessage),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmsMessage {
    ConfirmedRequest,
    InitiateRequest,
    InitiateResponse,
}

pub trait MmsInitiator: Send {
    fn initiate(self) -> impl std::future::Future<Output = Result<impl MmsConnection, MmsError>> + Send;
}

pub trait MmsListener: Send {
    fn responder(self) -> impl std::future::Future<Output = Result<impl MmsResponder, MmsError>> + Send;
}

pub trait MmsResponder: Send {
    fn accept(self) -> impl std::future::Future<Output = Result<impl MmsConnection, MmsError>> + Send;
}

pub trait MmsConnection: Send {
    fn split(self) -> impl std::future::Future<Output = Result<(impl MmsReader, impl MmsWriter), MmsError>> + Send;
}

pub trait MmsReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<MmsRecvResult, MmsError>> + Send;
}

pub trait MmsWriter: Send {
    fn send(&mut self, data: MmsMessage) -> impl std::future::Future<Output = Result<(), MmsError>> + Send;
    fn continue_send(&mut self) -> impl std::future::Future<Output = Result<(), MmsError>> + Send;
}
