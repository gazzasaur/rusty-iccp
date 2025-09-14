use crate::{api::CospError, common::TsduMaximumSize, packet::parameters::SessionPduParameter};

pub(crate) struct OverflowAcceptMessage {
    maximum_size_to_responder: TsduMaximumSize,
}

impl OverflowAcceptMessage {
    pub(crate) fn new(maximum_size_to_responder: TsduMaximumSize) -> Self {
        Self { maximum_size_to_responder }
    }

    pub(crate) fn maximum_size_to_responder(&self) -> &TsduMaximumSize {
        &self.maximum_size_to_responder
    }

    pub(crate) fn from_parameters(parameters: &[SessionPduParameter]) -> Result<Self, CospError> {
        let mut version_number = None;
        let mut maximum_size_to_responder = TsduMaximumSize::Unlimited;

        // Not minding about order or duplicates.
        for parameter in parameters {
            match parameter {
                SessionPduParameter::VersionNumberParameter(supported_versions) => version_number = Some(supported_versions),
                SessionPduParameter::TsduMaximumSizeParameter(tsdu_maximum_size) => maximum_size_to_responder = TsduMaximumSize::Size(tsdu_maximum_size.to_responder()),
                _ => (), // Ignore everything else.
            };
        }
        match version_number {
            Some(version) if version.version2() => (),
            Some(version) if version.version1() => return Err(CospError::ProtocolError("Only version 2 is supported but version 1 was requested by the server on accept.".into())),
            Some(_) => return Err(CospError::ProtocolError("Only version 2 is supported but not was requested by the server on accept.".into())),
            None => return Err(CospError::ProtocolError("Only version 2 is supported but version 1 was implied by the server on accept.".into())),
        }

        Ok(OverflowAcceptMessage { maximum_size_to_responder })
    }
}
