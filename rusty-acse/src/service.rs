use std::marker::PhantomData;

use rusty_copp::{CoppInitiator, CoppReader, CoppWriter, PresentationContextType, UserData};

use crate::{AcseConnection, AcseError, AcseInitiator, AcseReader, AcseRequestInformation, AcseResponseInformation, AcseWriter};

pub struct RustyAcseInitiator<T: CoppInitiator, R: CoppReader, W: CoppWriter> {
    copp_initiator: T,
    copp_reader: PhantomData<R>,
    copp_writer: PhantomData<W>,
    options: AcseRequestInformation,
}

impl<T: CoppInitiator, R: CoppReader, W: CoppWriter> RustyAcseInitiator<T, R, W> {
    pub fn new(copp_initiator: impl CoppInitiator, options: AcseRequestInformation) -> RustyAcseInitiator<impl CoppInitiator, impl CoppReader, impl CoppWriter> {
        RustyAcseInitiator {
            copp_initiator,
            copp_reader: PhantomData::<R>,
            copp_writer: PhantomData::<W>,
            options,
        }
    }
}

impl<T: CoppInitiator, R: CoppReader, W: CoppWriter> AcseInitiator for RustyAcseInitiator<T, R, W> {
    async fn initiate(self, presentation_contexts: PresentationContextType, user_data: Vec<u8>) -> Result<(impl crate::AcseConnection, AcseResponseInformation, UserData), crate::AcseError> {
        self.copp_initiator.initiate(presentation_contexts, user_data)
        Err::<(RustyAcseConnection, AcseResponseInformation, UserData), crate::AcseError>(AcseError::InternalError("Not implemented".to_string()))
    }
}

pub struct RustyAcseConnection {}

impl AcseConnection for RustyAcseConnection {
    async fn split(self) -> Result<(impl crate::AcseReader, impl crate::AcseWriter), AcseError> {
        Err::<(RustyAcseReader, RustyAcseWriter), crate::AcseError>(AcseError::InternalError("Not implemented".to_string()))
    }
}

pub struct RustyAcseReader {}

impl AcseReader for RustyAcseReader {
    async fn recv(&mut self) -> Result<crate::AcseRecvResult, AcseError> {
        Err(AcseError::InternalError("Not implemented".to_string()))
    }
}

pub struct RustyAcseWriter {}

impl AcseWriter for RustyAcseWriter {
    async fn send(&mut self, data: UserData) -> Result<(), AcseError> {
        Err(AcseError::InternalError("Not implemented".to_string()))
    }

    async fn continue_send(&mut self) -> Result<(), AcseError> {
        Err(AcseError::InternalError("Not implemented".to_string()))
    }
}
