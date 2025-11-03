use der_parser::{
    ber::{BitStringObject, parse_ber_tagged_implicit_g},
    der::{Class, Header, Tag},
};

use crate::{
    error::protocol_error, messages::{parsers::{process_constructed_data, process_octetstring, process_presentation_context_list, process_protocol, PresentationMode, Protocol}, user_data::UserData}, CoppError, PresentationContextResultType
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
        let mut user_data = None;

        // This destructively processes the payload directly into the accept message in a single pass. No retrun is required.
        der_parser::ber::parse_ber_set_of_v(|data| {
            let (data_transfer_message_remainder, object) = der_parser::ber::parse_ber_any(data)?;

            let (_, data_transfer_message_remainder) = match object.header.raw_tag() {
                Some(&[161]) => {
                    // let pdv_data = vec![];
                    let pdv_list = process_constructed_data(object.data)?;
                    for pdv in pdv_list {
                        match pdv.header.raw_tag() {
                            x => todo!("Test {:?}", x)
                        }
                    }
                    // user_data = Some(user_data_bytes);
                    (&[] as &[u8], 0)
                }
                _ => (&[] as &[u8], 0),
            };
            Ok((&[] as &[u8], 0))
        })(&data)
        .map_err(|e| protocol_error("Failed to parse data transfer user data", e))?;

        // TODO Simply Encoded
        let user_data = match user_data {
            Some(user_data) => user_data,
            None => return Err(CoppError::ProtocolError("A payload was received with no or unsupported user data".into())),
        };

        Ok(DataTransferMessage { user_data })
    }

    // TODO Support for default context
    pub(crate) fn serialise(&self) -> Result<Vec<u8>, CoppError> {
        Ok(self.user_data.serialise()?)
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
