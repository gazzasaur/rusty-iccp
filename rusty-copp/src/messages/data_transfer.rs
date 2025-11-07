use der_parser::ber::parse_ber_any;

use crate::{
    CoppError,
    messages::user_data::UserData,
};

#[derive(Debug)]
pub(crate) struct DataTransferMessage {
    user_data: UserData,
}

impl DataTransferMessage {
    pub(crate) fn new(user_data: UserData) -> Self {
        Self { user_data }
    }

    pub(crate) fn parse(data: Vec<u8>) -> Result<DataTransferMessage, CoppError> {
        let user_data = UserData::parse(parse_ber_any(&data).map_err(|e| CoppError::ProtocolError(e.to_string()))?.1).map_err(|e| CoppError::ProtocolError(e.to_string()))?;
        Ok(DataTransferMessage { user_data })
    }

    // TODO Support for default context
    pub(crate) fn serialise(&self) -> Result<Vec<u8>, CoppError> {
        self.user_data.to_ber().to_vec().map_err(|e| CoppError::ProtocolError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use crate::{PresentationContextResult, PresentationContextResultCause};

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_parse_accept() -> Result<(), anyhow::Error> {
        // let subject = DataTransferMessage::new(
        //     None,
        // );
        // let data = subject.serialise()?;
        // let result = DataTransferMessage::parse(data)?;
        // assert_eq!(result.responding_presentation_selector(), Some(&vec![4u8]));

        Ok(())
    }
}
