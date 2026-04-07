use std::collections::VecDeque;

use rusty_tpkt::{ProtocolInformation, TpktError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CotpError {
    /// Indicates issues with parsing of incoming packets or protocol violations with input user data.
    #[error("COTP Protocol Error - {}", .0)]
    ProtocolError(String),

    /// Indicates issues with lower layers.
    #[error("COTP over TPKT Protocol Stack Error - {}", .0)]
    ProtocolStackError(#[from] TpktError),

    /// Indicates issues with the underlying TCP socket or hardware.
    #[error("COTP IO Error: {:?}", .0)]
    IoError(#[from] std::io::Error),

    /// Usually indicates a bug or an unhandled error condition.
    #[error("COTP Error: {}", .0)]
    InternalError(String),
}

/// Provides a set of parameters used to tune timers or prevent the runaway consumption or resources due to a malicious client.
#[derive(PartialEq, Clone, Debug)]
pub struct CotpConnectionParameters {
    /// A limit on the reassembled payload. If this is exceeded, an error will be raised on the read operation.
    ///
    /// Defaults to 1MB for payload plus a 1024 byte overhead to account for headers. Only applies to inbound data.
    pub max_reassembled_payload_size: usize,
}

impl Default for CotpConnectionParameters {
    fn default() -> Self {
        Self { max_reassembled_payload_size: 1024*1024 + 1024 }
    }
}

/// Captures information about a COTP connection allowing it to be used later for connection negotiation.
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

    /// Used to specify information used by the COTP service during the initiator phase. This generates a random initiator and set the responder reference to 0.
    pub fn initiator(calling_tsap_id: Option<Vec<u8>>, called_tsap_id: Option<Vec<u8>>) -> Self {
        CotpProtocolInformation { initiator_reference: rand::random(), responder_reference: 0, calling_tsap_id, called_tsap_id }
    }

    /// Convert initiator information received by a connection request to responder information. This generates a random responder reference.
    pub fn responder(self) -> Self {
        CotpProtocolInformation { initiator_reference: self.initiator_reference, responder_reference: rand::random(), calling_tsap_id: self.calling_tsap_id.clone(), called_tsap_id: self.calling_tsap_id.clone() }
    }

    /// The initiator reference. As this supports Class 0 only, the reference is informational.
    pub fn initiator_reference(&self) -> u16 {
        self.initiator_reference
    }

    /// The responder reference. As this supports Class 0 only, the reference is informational.
    ///
    /// This will be 0 for information received from the initiator.
    pub fn responder_reference(&self) -> u16 {
        self.responder_reference
    }

    /// The Transport Id of the caller. Similar to a TCP port except it is not ephemeral for the calling party.
    pub fn calling_tsap_id(&self) -> Option<&Vec<u8>> {
        self.calling_tsap_id.as_ref()
    }

    /// The Transport Id of the called host. Similar to a TCP port.
    pub fn called_tsap_id(&self) -> Option<&Vec<u8>> {
        self.called_tsap_id.as_ref()
    }
}

impl ProtocolInformation for CotpProtocolInformation {}

/// Provides a mechnism to respond with negotiated values suring the connect phase.
pub trait CotpResponder: Send {
    /// Accepts a connection with the given parameters.
    ///
    /// This the CotpResponder is dropped the connection will be closed.
    fn accept(self, options: CotpProtocolInformation) -> impl std::future::Future<Output = Result<impl CotpConnection, CotpError>> + Send;
}

/// A trait representing a COTP connection.
pub trait CotpConnection: Send {
    /// Gets the information regarding the protocols that have been negotiated during the connect phase.
    fn get_protocol_infomation_list(&self) -> &Vec<Box<dyn ProtocolInformation>>;

    /// Splits a connection into reader and writer components. This must be done before the connection is used.
    fn split(self) -> impl std::future::Future<Output = Result<(impl CotpReader, impl CotpWriter), CotpError>> + Send;
}

/// A trait representing the read half of COTP connection.
pub trait CotpReader: Send {
    /// Reads from a COTP connection. There are three outcomes.
    /// * Some(data) - Data was read.
    /// * None - The underlying connection was closed normally.
    /// * TpktError - May indicate a packet was malformed, there was an IO error or some other internal failure occurred.
    ///
    /// This operation is cancel safe.
    fn recv(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, CotpError>> + Send;
}

/// A trait representing the write half of COTP connection.
pub trait CotpWriter: Send {
    /// Writes to a COTP connection. This uses a VedDeque as a buffer. This is to ensure the operation is cancel safe so long as the buffer is not dropped while it has data.
    ///
    /// This operation is cancel safe as long as the data in the input buffer is not dropped.
    /// The Veque is intended to be used as a FIFO buffer stored on the caller and reused.
    fn send(&mut self, input: &mut VecDeque<Vec<u8>>) -> impl std::future::Future<Output = Result<(), CotpError>> + Send;
}
