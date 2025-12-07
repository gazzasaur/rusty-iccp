use std::marker::PhantomData;

use der_parser::{
    Oid,
    ber::{BerObject, BerObjectContent, BitStringObject},
    der::{Class, Header, Tag},
};
use rusty_copp::CoppConnection;
use rusty_copp::{CoppError, CoppInitiator, CoppListener, CoppReader, CoppResponder, CoppWriter, PresentationContext, PresentationContextType, PresentationDataValueList, PresentationDataValues, UserData};

use crate::{
    AcseError, AcseRecvResult, AcseRequestInformation, AcseResponseInformation, AeQualifier, ApTitle, AssociateResult, AssociateSourceDiagnostic, AssociateSourceDiagnosticProviderCategory, AssociateSourceDiagnosticUserCategory,
    OsiSingleValueAcseConnection, OsiSingleValueAcseInitiator, OsiSingleValueAcseListener, OsiSingleValueAcseReader, OsiSingleValueAcseResponder, OsiSingleValueAcseWriter,
    messages::parsers::{process_request, process_response, to_acse_error},
};

pub struct RustyOsiSingleValueAcseInitiator<T: CoppInitiator, R: CoppReader, W: CoppWriter> {
    copp_initiator: T,
    copp_reader: PhantomData<R>,
    copp_writer: PhantomData<W>,
    options: AcseRequestInformation,
}

impl<T: CoppInitiator, R: CoppReader, W: CoppWriter> RustyOsiSingleValueAcseInitiator<T, R, W> {
    pub fn new(copp_initiator: impl CoppInitiator, options: AcseRequestInformation) -> RustyOsiSingleValueAcseInitiator<impl CoppInitiator, impl CoppReader, impl CoppWriter> {
        RustyOsiSingleValueAcseInitiator {
            copp_initiator,
            copp_reader: PhantomData::<R>,
            copp_writer: PhantomData::<W>,
            options,
        }
    }
}

impl<T: CoppInitiator, R: CoppReader, W: CoppWriter> OsiSingleValueAcseInitiator for RustyOsiSingleValueAcseInitiator<T, R, W> {
    async fn initiate(self, abstract_syntax_name: Oid<'static>, user_data: Vec<u8>) -> Result<(impl OsiSingleValueAcseConnection, AcseResponseInformation, Vec<u8>), AcseError> {
        let (copp_connection, received_user_data) = self
            .copp_initiator
            .initiate(
                PresentationContextType::ContextDefinitionList(vec![
                    // ACSE
                    PresentationContext {
                        indentifier: vec![1],
                        abstract_syntax_name: Oid::from(&[2, 2, 1, 0, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?,
                        transfer_syntax_name_list: vec![Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?],
                    },
                    // Requested BER Encoded Protocol
                    PresentationContext {
                        indentifier: vec![3],
                        abstract_syntax_name: abstract_syntax_name,
                        transfer_syntax_name_list: vec![Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?],
                    },
                ]),
                Some(UserData::FullyEncoded(vec![PresentationDataValueList {
                    transfer_syntax_name: None,
                    presentation_context_identifier: vec![0x01],
                    presentation_data_values: PresentationDataValues::SingleAsn1Type(self.options.serialise(&Some(user_data))?),
                }])),
            )
            .await?;
        let (copp_reader, copp_writer) = copp_connection.split().await?;
        let (acse_response, acse_response_data) = match received_user_data {
            Some(UserData::FullyEncoded(pdvs)) => {
                if pdvs.len() > 1 {
                    return Err(AcseError::ProtocolError(format!("Expecting a single PDV on ACSE Response but found {}", pdvs.len())));
                }
                match pdvs.first() {
                    Some(pdv) => {
                        if pdv.presentation_context_identifier != vec![1] {
                            return Err(AcseError::ProtocolError(format!("Expecting a context id of [1] on ACSE Response but found {:?}", pdv.presentation_context_identifier)));
                        }
                        match &pdv.presentation_data_values {
                            PresentationDataValues::SingleAsn1Type(response_user_data) => process_response(response_user_data)?,
                        }
                    }
                    None => return Err(AcseError::ProtocolError("No PDV was found on ACSE Response".into())),
                }
            }
            None => return Err(AcseError::ProtocolError("No user data was found on ACSE Response".into())),
        };
        Ok((RustyAcseConnection { copp_reader, copp_writer }, acse_response, acse_response_data))
    }
}

pub struct RustyOsiSingleValueAcseListener<T: CoppResponder, R: CoppReader, W: CoppWriter> {
    copp_responder: T,
    copp_reader: PhantomData<R>,
    copp_writer: PhantomData<W>,
    response: Option<AcseResponseInformation>,
    acse_user_data: Vec<u8>,
}

impl<T: CoppResponder, R: CoppReader, W: CoppWriter> RustyOsiSingleValueAcseListener<T, R, W> {
    pub async fn new(copp_listener: impl CoppListener) -> Result<(RustyOsiSingleValueAcseListener<impl CoppResponder, impl CoppReader, impl CoppWriter>, AcseRequestInformation), AcseError> {
        let (copp_responder, copp_options) = copp_listener.responder().await?;
        let copp_presentation_data_list = match copp_options {
            Some(UserData::FullyEncoded(x)) => x,
            None => return Err(AcseError::ProtocolError("COPP did not provide and data in the initiate payload".into())),
        };
        if copp_presentation_data_list.len() != 1 {
            return Err(AcseError::ProtocolError(format!("Expected 1 COPP but found {}", copp_presentation_data_list.len())));
        }
        let copp_presentation_data = match copp_presentation_data_list.first() {
            Some(x) => x,
            None => return Err(AcseError::ProtocolError("Expected 1 COPP but did not find any".into())),
        };
        match &copp_presentation_data.transfer_syntax_name {
            Some(x) if x == &Oid::from(&[2, 1, 1]).map_err(to_acse_error("Failed to parse BAR transfer syntax."))? => (),
            Some(x) => return Err(AcseError::ProtocolError(format!("Unsupported transfer syntax: {}", x))),
            None => (),
        }
        if copp_presentation_data.presentation_context_identifier != &[1] {
            return Err(AcseError::ProtocolError(format!(
                "Unexpected presentation contact id on COPP ACES Payload: Expecting &[1] but found {:?}",
                copp_presentation_data.presentation_context_identifier
            )));
        }
        let (request, acse_user_data) = match &copp_presentation_data.presentation_data_values {
            PresentationDataValues::SingleAsn1Type(data) => process_request(data)?,
        };
        Ok((
            RustyOsiSingleValueAcseListener {
                copp_responder,
                copp_reader: PhantomData::<R>,
                copp_writer: PhantomData::<W>,
                response: None,
                acse_user_data,
            },
            request,
        ))
    }
    
    pub fn set_response(&mut self, response: Option<AcseResponseInformation>) {
        self.response = response;
    }

}

impl<T: CoppResponder, R: CoppReader, W: CoppWriter> OsiSingleValueAcseListener for RustyOsiSingleValueAcseListener<T, R, W> {
    async fn responder(self) -> Result<(impl OsiSingleValueAcseResponder, Vec<u8>), AcseError> {
        match self.response {
            Some(response) => Ok((RustyOsiSingleValueAcseResponder::<T, R, W>::new(self.copp_responder, response), self.acse_user_data)),
            None => Err(AcseError::ProtocolError("No ACSE response information was provided".into())),
        }
    }
}

pub struct RustyOsiSingleValueAcseResponder<T: CoppResponder, R: CoppReader, W: CoppWriter> {
    copp_responder: T,
    copp_reader: PhantomData<R>,
    copp_writer: PhantomData<W>,
    response: AcseResponseInformation,
}

impl<T: CoppResponder, R: CoppReader, W: CoppWriter> RustyOsiSingleValueAcseResponder<T, R, W> {
    pub fn new(copp_responder: T, response: AcseResponseInformation) -> Self {
        RustyOsiSingleValueAcseResponder {
            copp_responder,
            copp_reader: PhantomData,
            copp_writer: PhantomData,
            response,
        }
    }
}

impl<T: CoppResponder, R: CoppReader, W: CoppWriter> OsiSingleValueAcseResponder for RustyOsiSingleValueAcseResponder<T, R, W> {
    async fn accept(self, user_data: Vec<u8>) -> Result<impl OsiSingleValueAcseConnection, AcseError> {
        let acse_data = self.response.serialise(&Some(user_data))?;
        let copp_connection = self
            .copp_responder
            .accept(Some(UserData::FullyEncoded(vec![PresentationDataValueList {
                transfer_syntax_name: None,
                presentation_context_identifier: vec![1],
                presentation_data_values: PresentationDataValues::SingleAsn1Type(acse_data),
            }])))
            .await?;
        let (copp_reader, copp_writer) = copp_connection.split().await?;
        Ok(RustyAcseConnection { copp_reader, copp_writer })
    }
}

pub struct RustyAcseConnection<R: CoppReader, W: CoppWriter> {
    copp_reader: R,
    copp_writer: W,
}

impl<R: CoppReader, W: CoppWriter> OsiSingleValueAcseConnection for RustyAcseConnection<R, W> {
    async fn split(self) -> Result<(impl OsiSingleValueAcseReader, impl OsiSingleValueAcseWriter), AcseError> {
        Ok((RustyOsiSingleValueAcseReader::new(self.copp_reader), RustyOsiSingleValueAcseWriter::new(self.copp_writer)))
    }
}

pub struct RustyOsiSingleValueAcseReader<R: CoppReader> {
    copp_reader: R,
}

impl<R: CoppReader> RustyOsiSingleValueAcseReader<R> {
    pub fn new(copp_reader: R) -> Self {
        Self { copp_reader }
    }
}

impl<R: CoppReader> OsiSingleValueAcseReader for RustyOsiSingleValueAcseReader<R> {
    async fn recv(&mut self) -> Result<AcseRecvResult, AcseError> {
        let copp_recv_result = self.copp_reader.recv().await?;
        match copp_recv_result {
            rusty_copp::CoppRecvResult::Closed => return Ok(AcseRecvResult::Closed),
            rusty_copp::CoppRecvResult::Data(user_data) => match user_data {
                UserData::FullyEncoded(presentation_data_value_lists) => {
                    if presentation_data_value_lists.len() > 1 {
                        return Err(AcseError::ProtocolError(format!("Expected one PDV value on ACSE read but found {}", presentation_data_value_lists.len())));
                    }
                    match presentation_data_value_lists.first() {
                        Some(x) => {
                            if x.presentation_context_identifier != vec![3] {
                                return Err(AcseError::ProtocolError(format!("Expected a context id of 3 on ACSE read but was {:?}", x.presentation_context_identifier)));
                            }
                            match &x.presentation_data_values {
                                PresentationDataValues::SingleAsn1Type(data) => return Ok(AcseRecvResult::Data(data.to_vec())),
                            }
                        }
                        None => return Err(AcseError::ProtocolError("Expected one PDV value on ACSE read but did not find any".into())),
                    }
                }
            },
        }
    }
}

pub struct RustyOsiSingleValueAcseWriter<W: CoppWriter> {
    copp_writer: W,
}

impl<W: CoppWriter> RustyOsiSingleValueAcseWriter<W> {
    pub fn new(copp_writer: W) -> Self {
        Self { copp_writer }
    }
}

impl<W: CoppWriter> OsiSingleValueAcseWriter for RustyOsiSingleValueAcseWriter<W> {
    async fn send(&mut self, data: Vec<u8>) -> Result<(), AcseError> {
        Ok(self
            .copp_writer
            .send(&UserData::FullyEncoded(vec![PresentationDataValueList {
                transfer_syntax_name: None,
                presentation_context_identifier: vec![3],
                presentation_data_values: PresentationDataValues::SingleAsn1Type(data),
            }]))
            .await?)
    }

    async fn continue_send(&mut self) -> Result<(), AcseError> {
        Ok(self.copp_writer.continue_send().await?)
    }
}

impl AcseRequestInformation {
    pub fn serialise(&self, user_data: &Option<Vec<u8>>) -> Result<Vec<u8>, AcseError> {
        // There is a bug that prevents creating a tag with a value of 30. Instead we create the header from a raw tag.
        // https://github.com/rusticata/der-parser/issues/89
        let user_data_structure = user_data
            .iter()
            .map(|v| {
                BerObject::from_header_and_content(
                    Header::new(Class::ContextSpecific, true, Tag::from(0), der_parser::ber::Length::Definite(0)),
                    der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                        Header::new(Class::Universal, true, Tag::from(8), der_parser::ber::Length::Definite(0)),
                        der_parser::ber::BerObjectContent::Sequence(vec![
                            BerObject::from_header_and_content(Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)), BerObjectContent::Integer(&[3])),
                            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(0), der_parser::ber::Length::Definite(0)), BerObjectContent::OctetString(v)),
                        ]),
                    )]),
                )
            })
            .last();
        let user_data_length = match &user_data_structure {
            Some(x) => x.to_vec().map_err(to_acse_error("Failed to serialise ACSE Request User Data"))?.len(),
            None => 0,
        };

        let payload = BerObject::from_header_and_content(
            Header::new(Class::Application, true, Tag::from(0), der_parser::ber::Length::Definite(0)),
            der_parser::ber::BerObjectContent::Sequence(
                vec![
                    // Version Default 1 - Not really needed, but we will put it anyway
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, false, Tag::from(0), der_parser::ber::Length::Definite(0)),
                        BerObjectContent::BitString(7, BitStringObject { data: &[0x80] }),
                    )),
                    // Application Context Name
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(1), der_parser::ber::Length::Definite(0)),
                        der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                            Header::new(Class::Universal, false, Tag::Oid, der_parser::ber::Length::Definite(0)),
                            BerObjectContent::OID(self.application_context_name.clone()),
                        )]),
                    )),
                    // Called AP Title
                    self.called_ap_title
                        .iter()
                        .map(|ap_title| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(2), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Oid, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::OID(match ap_title {
                                        ApTitle::Form2(oid) => oid.to_owned(),
                                    }),
                                )]),
                            )
                        })
                        .last(),
                    // Called AE Qualifier
                    self.called_ae_qualifier
                        .iter()
                        .map(|ae_qualifier| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(3), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::Integer(match ae_qualifier {
                                        AeQualifier::Form2(value) => value,
                                    }),
                                )]),
                            )
                        })
                        .last(),
                    // Called AP InvocationIdentifier
                    self.called_ap_invocation_identifier
                        .iter()
                        .map(|ap_invocation_id| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(4), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::Integer(ap_invocation_id),
                                )]),
                            )
                        })
                        .last(),
                    // Called AE InvocationIdentifier
                    self.called_ae_invocation_identifier
                        .iter()
                        .map(|ae_invocation_id| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(5), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::Integer(ae_invocation_id),
                                )]),
                            )
                        })
                        .last(),
                    // Calling AP Title
                    self.calling_ap_title
                        .iter()
                        .map(|ap_title| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(6), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Oid, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::OID(match ap_title {
                                        ApTitle::Form2(oid) => oid.to_owned(),
                                    }),
                                )]),
                            )
                        })
                        .last(),
                    // Calling AE Qualifier
                    self.calling_ae_qualifier
                        .iter()
                        .map(|ae_qualifier| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(7), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::Integer(match ae_qualifier {
                                        AeQualifier::Form2(value) => value,
                                    }),
                                )]),
                            )
                        })
                        .last(),
                    // Calling AP InvocationIdentifier
                    self.calling_ap_invocation_identifier
                        .iter()
                        .map(|ap_invocation_id| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(8), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::Integer(ap_invocation_id),
                                )]),
                            )
                        })
                        .last(),
                    // Calling AE InvocationIdentifier
                    self.calling_ae_invocation_identifier
                        .iter()
                        .map(|ae_invocation_id| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(9), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::Integer(ae_invocation_id),
                                )]),
                            )
                        })
                        .last(),
                    // Implementation Information
                    self.implementation_information
                        .iter()
                        .map(|implementation_information| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, false, Tag::from(29), der_parser::ber::Length::Definite(0)),
                                BerObjectContent::GraphicString(implementation_information),
                            )
                        })
                        .last(),
                    // User Information
                    user_data_structure,
                ]
                .iter()
                .filter_map(|v| v.to_owned())
                .collect(),
            ),
        );
        let mut data = payload.to_vec().map_err(to_acse_error("Failed to serialise Application Request Information"))?;
        let tl = data.len();
        if user_data_length > 0 {
            data[tl - user_data_length] = 0xbe;
        }
        Ok(data)
    }
}

impl AcseResponseInformation {
    pub fn serialise(&self, user_data: &Option<Vec<u8>>) -> Result<Vec<u8>, AcseError> {
        // There is a bug that prevents creating a tag with a value of 30. Instead we create the header from a raw tag.
        // https://github.com/rusticata/der-parser/issues/89
        let user_data_structure = user_data
            .iter()
            .map(|v| {
                BerObject::from_header_and_content(
                    Header::new(Class::ContextSpecific, true, Tag::from(0), der_parser::ber::Length::Definite(0)),
                    der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                        Header::new(Class::Universal, true, Tag::from(8), der_parser::ber::Length::Definite(0)),
                        der_parser::ber::BerObjectContent::Sequence(vec![
                            BerObject::from_header_and_content(Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)), BerObjectContent::Integer(&[3])),
                            BerObject::from_header_and_content(Header::new(Class::ContextSpecific, true, Tag::from(0), der_parser::ber::Length::Definite(0)), BerObjectContent::OctetString(v)),
                        ]),
                    )]),
                )
            })
            .last();
        let user_data_length = match &user_data_structure {
            Some(x) => x.to_vec().map_err(to_acse_error("Failed to serialise ACSE Request User Data"))?.len(),
            None => 0,
        };

        let payload = BerObject::from_header_and_content(
            Header::new(Class::Application, true, Tag::from(1), der_parser::ber::Length::Definite(0)),
            der_parser::ber::BerObjectContent::Sequence(
                vec![
                    // Version Default 1 - No need to specify
                    // Application Context Name
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(1), der_parser::ber::Length::Definite(0)),
                        der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                            Header::new(Class::Universal, false, Tag::Oid, der_parser::ber::Length::Definite(0)),
                            BerObjectContent::OID(self.application_context_name.clone()),
                        )]),
                    )),
                    // Result
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(2), der_parser::ber::Length::Definite(0)),
                        der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                            Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                            match &self.associate_result {
                                AssociateResult::Accepted => BerObjectContent::Integer(&[0]),
                                AssociateResult::RejectedPermanent => BerObjectContent::Integer(&[1]),
                                AssociateResult::RejectedTransient => BerObjectContent::Integer(&[2]),
                                AssociateResult::Unknown(x) => BerObjectContent::Integer(&x),
                            },
                        )]),
                    )),
                    // Result Diagnostic
                    Some(BerObject::from_header_and_content(
                        Header::new(Class::ContextSpecific, true, Tag::from(3), der_parser::ber::Length::Definite(0)),
                        der_parser::ber::BerObjectContent::Sequence(vec![match &self.associate_source_diagnostic {
                            AssociateSourceDiagnostic::User(category) => BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(1), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    der_parser::ber::BerObjectContent::Integer(match category {
                                        AssociateSourceDiagnosticUserCategory::Null => &[0],
                                        AssociateSourceDiagnosticUserCategory::NoReasonGiven => &[1],
                                        AssociateSourceDiagnosticUserCategory::ApplicationContextNameNotSupported => &[2],
                                        AssociateSourceDiagnosticUserCategory::CallingApTitleNotRecognized => &[3],
                                        AssociateSourceDiagnosticUserCategory::CallingApInvocationIdentifierNotRecognized => &[4],
                                        AssociateSourceDiagnosticUserCategory::CallingAeQualifierNotRecognized => &[5],
                                        AssociateSourceDiagnosticUserCategory::CallingAeInvocationIdentifierNotRecognized => &[6],
                                        AssociateSourceDiagnosticUserCategory::CalledApTitleNotRecognized => &[7],
                                        AssociateSourceDiagnosticUserCategory::CalledApInvocationIdentifierNotRecognized => &[8],
                                        AssociateSourceDiagnosticUserCategory::CalledAeQualifierNotRecognized => &[9],
                                        AssociateSourceDiagnosticUserCategory::CalledAeInvocationIdentifierNotRecognized => &[10],
                                        AssociateSourceDiagnosticUserCategory::AuthenticationMechanismNameNotRecognized => &[11],
                                        AssociateSourceDiagnosticUserCategory::AuthenticationMechanismNameRequired => &[12],
                                        AssociateSourceDiagnosticUserCategory::AuthenticationFailure => &[13],
                                        AssociateSourceDiagnosticUserCategory::AuthenticationRequired => &[14],
                                        AssociateSourceDiagnosticUserCategory::Unknown(value) => &value,
                                    }),
                                )]),
                            ),
                            AssociateSourceDiagnostic::Provider(category) => BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(1), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    der_parser::ber::BerObjectContent::Integer(match category {
                                        AssociateSourceDiagnosticProviderCategory::Null => &[0],
                                        AssociateSourceDiagnosticProviderCategory::NoReasonGiven => &[1],
                                        AssociateSourceDiagnosticProviderCategory::NoCommonAcseVersion => &[2],
                                        AssociateSourceDiagnosticProviderCategory::Unknown(value) => &value,
                                    }),
                                )]),
                            ),
                            AssociateSourceDiagnostic::Unknown(_) => return Err(AcseError::InternalError("Cannot serialise Unknown diagnostic on ACSE Response".into())),
                        }]),
                    )),
                    // Called AP Title
                    self.responding_ap_title
                        .iter()
                        .map(|ap_title| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(4), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Oid, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::OID(match ap_title {
                                        ApTitle::Form2(oid) => oid.to_owned(),
                                    }),
                                )]),
                            )
                        })
                        .last(),
                    // Called AE Qualifier
                    self.responding_ae_qualifier
                        .iter()
                        .map(|ae_qualifier| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(5), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::Integer(match ae_qualifier {
                                        AeQualifier::Form2(value) => value,
                                    }),
                                )]),
                            )
                        })
                        .last(),
                    // Called AP InvocationIdentifier
                    self.responding_ap_invocation_identifier
                        .iter()
                        .map(|ap_invocation_id| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(6), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::Integer(ap_invocation_id),
                                )]),
                            )
                        })
                        .last(),
                    // Called AE InvocationIdentifier
                    self.responding_ae_invocation_identifier
                        .iter()
                        .map(|ae_invocation_id| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, true, Tag::from(7), der_parser::ber::Length::Definite(0)),
                                der_parser::ber::BerObjectContent::Sequence(vec![BerObject::from_header_and_content(
                                    Header::new(Class::Universal, false, Tag::Integer, der_parser::ber::Length::Definite(0)),
                                    BerObjectContent::Integer(ae_invocation_id),
                                )]),
                            )
                        })
                        .last(),
                    // Implementation Information
                    self.implementation_information
                        .iter()
                        .map(|implementation_information| {
                            BerObject::from_header_and_content(
                                Header::new(Class::ContextSpecific, false, Tag::from(29), der_parser::ber::Length::Definite(0)),
                                BerObjectContent::GraphicString(implementation_information),
                            )
                        })
                        .last(),
                    // User Information
                    user_data_structure,
                ]
                .iter()
                .filter_map(|v| v.to_owned())
                .collect(),
            ),
        );
        let mut data = payload.to_vec().map_err(to_acse_error("Failed to serialise Application Request Information"))?;
        let tl = data.len();
        if user_data_length > 0 {
            data[tl - user_data_length] = 0xbe;
        }
        Ok(data)
    }
}
