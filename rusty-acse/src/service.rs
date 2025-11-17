use std::marker::PhantomData;

use der_parser::{
    Oid,
    ber::{BerObject, BerObjectContent},
    der::{Class, Header, Tag},
};
use rusty_copp::{CoppError, CoppInitiator, CoppReader, CoppWriter, PresentationContext, PresentationContextType, PresentationDataValueList, PresentationDataValues, UserData};

use crate::{
    AcseError, AcseRequestInformation, AcseResponseInformation, AeQualifier, ApTitle, AssociateResult, AssociateSourceDiagnostic, OsiSingleValueAcseConnection, OsiSingleValueAcseInitiator, OsiSingleValueAcseReader,
    OsiSingleValueAcseWriter, messages::parsers::to_acse_error,
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
        self.copp_initiator
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
        Ok((
            RustyAcseConnection::<R, W> {
                copp_reader: PhantomData::<R>,
                copp_writer: PhantomData::<W>,
            },
            AcseResponseInformation {
                application_context_name: self.options.application_context_name,
                associate_result: AssociateResult::Accepted,
                associate_source_diagnostic: AssociateSourceDiagnostic::Provider,
                responding_ap_title: self.options.called_ap_title,
                responding_ae_qualifier: self.options.called_ae_qualifier,
                responding_ap_invocation_identifier: self.options.called_ap_invocation_identifier,
                responding_ae_invocation_identifier: self.options.calling_ae_invocation_identifier,
                implementation_information: None,
            },
            vec![],
        ))
    }
}

pub struct RustyAcseConnection<R: CoppReader, W: CoppWriter> {
    copp_reader: PhantomData<R>,
    copp_writer: PhantomData<W>,
}

impl<R: CoppReader, W: CoppWriter> OsiSingleValueAcseConnection for RustyAcseConnection<R, W> {
    async fn split(self) -> Result<(impl OsiSingleValueAcseReader, impl OsiSingleValueAcseWriter), AcseError> {
        Err::<(RustyOsiSingleValueAcseReader<R>, RustyOsiSingleValueAcseWriter<W>), crate::AcseError>(AcseError::InternalError("Not implemented".to_string()))
    }
}

pub struct RustyOsiSingleValueAcseReader<R: CoppReader> {
    copp_reader: PhantomData<R>,
}

impl<R: CoppReader> OsiSingleValueAcseReader for RustyOsiSingleValueAcseReader<R> {
    async fn recv(&mut self) -> Result<crate::AcseRecvResult, AcseError> {
        Err(AcseError::InternalError("Not implemented".to_string()))
    }
}

pub struct RustyOsiSingleValueAcseWriter<W: CoppWriter> {
    copp_writer: PhantomData<W>,
}

impl<W: CoppWriter> OsiSingleValueAcseWriter for RustyOsiSingleValueAcseWriter<W> {
    async fn send(&mut self, data: Vec<u8>) -> Result<(), AcseError> {
        Err(AcseError::InternalError("Not implemented".to_string()))
    }

    async fn continue_send(&mut self) -> Result<(), AcseError> {
        Err(AcseError::InternalError("Not implemented".to_string()))
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
                    // Version Default 1 - No need to specify
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
