use std::collections::VecDeque;

use rusty_tpkt::{ProtocolInformation, TpktError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CotpError {
    #[error("COTP Protocol Error - {}", .0)]
    ProtocolError(String),

    #[error("COTP over TPKT Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] TpktError),

    #[error("COTP IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    #[error("COTP Error: {}", .0)]
    InternalError(String),
}

#[derive(PartialEq, Clone, Debug)]
pub struct CotpProtocolInformation {
    initiator_reference: u16,
    responder_reference: u16,
    calling_tsap_id: Option<Vec<u8>>,
    called_tsap_id: Option<Vec<u8>>,
}

impl CotpProtocolInformation {
    pub(crate) fn new(initiator_reference: u16, responder_reference: u16, calling_tsap_id: Option<Vec<u8>>, called_tsap_id: Option<Vec<u8>>) -> Self {
        CotpProtocolInformation { initiator_reference, responder_reference, calling_tsap_id, called_tsap_id }
    }

    pub fn initiator(calling_tsap_id: Option<Vec<u8>>, called_tsap_id: Option<Vec<u8>>) -> Self {
        CotpProtocolInformation { initiator_reference: rand::random(), responder_reference: 0, calling_tsap_id, called_tsap_id }
    }

    pub fn responder(self) -> Self {
        CotpProtocolInformation { initiator_reference: self.initiator_reference, responder_reference: rand::random(), calling_tsap_id: self.calling_tsap_id.clone(), called_tsap_id: self.calling_tsap_id.clone() }
    }

    pub fn initiator_reference(&self) -> u16 {
        self.initiator_reference
    }

    /// This will be 0 for the first request from the initiator.
    pub fn responder_reference(&self) -> u16 {
        self.responder_reference
    }

    pub fn calling_tsap_id(&self) -> Option<&Vec<u8>> {
        self.calling_tsap_id.as_ref()
    }

    pub fn called_tsap_id(&self) -> Option<&Vec<u8>> {
        self.called_tsap_id.as_ref()
    }
}

impl ProtocolInformation for CotpProtocolInformation {}

pub enum CotpRecvResult {
    Closed,
    Data(Vec<u8>),
}

pub trait CotpResponder: Send {
    fn accept(self, options: CotpProtocolInformation) -> impl std::future::Future<Output = Result<impl CotpConnection, CotpError>> + Send;
}

pub trait CotpConnection: Send {
    fn get_protocol_infomation_list(&self) -> &Vec<Box<dyn ProtocolInformation>>;

    fn split(self) -> impl std::future::Future<Output = Result<(impl CotpReader, impl CotpWriter), CotpError>> + Send;
}

pub trait CotpReader: Send {
    fn recv(&mut self) -> impl std::future::Future<Output = Result<CotpRecvResult, CotpError>> + Send;
}

pub trait CotpWriter: Send {
    fn send(&mut self, input: &mut VecDeque<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CotpError>> + Send;
}
