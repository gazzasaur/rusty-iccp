pub mod api;
pub(crate) mod error;
pub(crate) mod parameters;
pub(crate) mod parsers;
pub(crate) mod pdu;
pub mod service;

use std::marker::PhantomData;

pub use api::*;
use rusty_acse::{
    AcseRequestInformation, AcseResponseInformation, AssociateResult, AssociateSourceDiagnostic, AssociateSourceDiagnosticUserCategory, RustyOsiSingleValueAcseInitiatorIsoStack, RustyOsiSingleValueAcseListenerIsoStack,
    RustyOsiSingleValueAcseReaderIsoStack, RustyOsiSingleValueAcseResponderIsoStack, RustyOsiSingleValueAcseWriterIsoStack,
};
use rusty_copp::{CoppConnectionInformation, RustyCoppInitiatorIsoStack, RustyCoppListenerIsoStack};
use rusty_cosp::{CospConnectionInformation, TcpCospInitiator, TcpCospListener};
use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
use rusty_tpkt::{TpktConnection, TpktReader, TpktWriter};
pub use service::*;

use crate::error::to_mms_error;

pub type RustyMmsConnectionIsoStack<R, W> = RustyMmsConnection<RustyOsiSingleValueAcseReaderIsoStack<R>, RustyOsiSingleValueAcseWriterIsoStack<W>>;
pub type RustyMmsInitiatorIsoStack<R, W> = RustyMmsInitiator<RustyOsiSingleValueAcseInitiatorIsoStack<R, W>, RustyOsiSingleValueAcseReaderIsoStack<R>, RustyOsiSingleValueAcseWriterIsoStack<W>>;
pub type RustyMmsListenerIsoStack<R, W> = RustyMmsListener<RustyOsiSingleValueAcseResponderIsoStack<R, W>, RustyOsiSingleValueAcseReaderIsoStack<R>, RustyOsiSingleValueAcseWriterIsoStack<W>>;
pub type RustyMmsResponderIsoStack<R, W> = RustyMmsResponder<RustyOsiSingleValueAcseResponderIsoStack<R, W>, RustyOsiSingleValueAcseReaderIsoStack<R>, RustyOsiSingleValueAcseWriterIsoStack<W>>;

pub struct OsiMmsInitiatorConnectionFactory<T: TpktConnection, R: TpktReader, W: TpktWriter> {
    _tpkt_connection: PhantomData<T>,
    _tpkt_reader: PhantomData<R>,
    _tpkt_writer: PhantomData<W>,
}

impl<T: TpktConnection, R: TpktReader, W: TpktWriter> OsiMmsInitiatorConnectionFactory<T, R, W> {
    pub async fn connect(
        tpkt_connection: T,
        cotp_information: CotpConnectInformation,
        cosp_information: CospConnectionInformation,
        copp_information: CoppConnectionInformation,
        acse_information: AcseRequestInformation,
        mms_information: MmsRequestInformation,
    ) -> Result<impl MmsConnection, MmsError> {
        let cotp_client = TcpCotpConnection::<R, W>::initiate(tpkt_connection, cotp_information)
            .await
            .map_err(to_mms_error("Failed to establish a COTP connection when creating an MMS association"))?;
        let cosp_client = TcpCospInitiator::<TcpCotpReader<R>, TcpCotpWriter<W>>::new(cotp_client, cosp_information)
            .await
            .map_err(to_mms_error("Failed to establish a COSP connection when creating an MMS association"))?;
        let copp_client = RustyCoppInitiatorIsoStack::<R, W>::new(cosp_client, copp_information);
        let acse_client = RustyOsiSingleValueAcseInitiatorIsoStack::<R, W>::new(copp_client, acse_information);
        let mms_client = RustyMmsInitiatorIsoStack::<R, W>::new(acse_client, mms_information);
        mms_client.initiate().await
    }
}

pub struct OsiMmsMirrorResponderConnectionFactory<T: TpktConnection, R: TpktReader, W: TpktWriter> {
    _tpkt_connection: PhantomData<T>,
    _tpkt_reader: PhantomData<R>,
    _tpkt_writer: PhantomData<W>,
}

impl<T: TpktConnection, R: TpktReader, W: TpktWriter> OsiMmsMirrorResponderConnectionFactory<T, R, W> {
    pub async fn accept(tpkt_connection: T) -> Result<impl MmsConnection, MmsError> {
        let (cotp_listener, _) = TcpCotpAcceptor::<R, W>::new(tpkt_connection).await.map_err(to_mms_error("Failed to create COTP connection when creating an MMS association"))?;
        let cotp_connection = cotp_listener
            .accept(CotpAcceptInformation::default())
            .await
            .map_err(to_mms_error("Failed to create a COSP connection when creating an MMS association"))?;
        let (cosp_listener, _) = TcpCospListener::<TcpCotpReader<R>, TcpCotpWriter<W>>::new(cotp_connection)
            .await
            .map_err(to_mms_error("Failed to create a COSP connection when creating an MMS association"))?;
        let (copp_listener, _) = RustyCoppListenerIsoStack::<R, W>::new(cosp_listener).await.map_err(to_mms_error("Failed to create COPP listener"))?;
        let (mut acse_listener, acse_request_information) = RustyOsiSingleValueAcseListenerIsoStack::<R, W>::new(copp_listener)
            .await
            .map_err(to_mms_error("Failed to create a COPP connection when creating an MMS association"))?;
        acse_listener.set_response(Some(AcseResponseInformation {
            application_context_name: acse_request_information.application_context_name, // TODO: Should verify it is MMS
            associate_result: AssociateResult::Accepted,
            associate_source_diagnostic: AssociateSourceDiagnostic::User(AssociateSourceDiagnosticUserCategory::Null),
            responding_ap_title: acse_request_information.called_ap_title,
            responding_ae_qualifier: acse_request_information.called_ae_qualifier,
            responding_ap_invocation_identifier: acse_request_information.called_ap_invocation_identifier,
            responding_ae_invocation_identifier: acse_request_information.called_ae_invocation_identifier,
            implementation_information: None,
        }));
        let (mms_listener, _) = RustyMmsListenerIsoStack::<R, W>::new(acse_listener).await?;
        let mms_responder = mms_listener.responder().await?;
        mms_responder.accept().await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use der_parser::{Oid, num_bigint::BigInt};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    use tokio::{join, time::sleep};
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_works() -> Result<(), anyhow::Error> {
        let test_address = "127.0.0.1:10002".parse()?;
        let client_path = async {
            tokio::time::sleep(Duration::from_millis(1)).await; // Give the server time to start
            let tpkt_client = TcpTpktConnection::connect(test_address).await?;
            let connection = OsiMmsInitiatorConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::connect(
                tpkt_client,
                CotpConnectInformation::default(),
                CospConnectionInformation::default(),
                CoppConnectionInformation::default(),
                AcseRequestInformation {
                    application_context_name: Oid::from(&[1, 2, 3])?,
                    ..Default::default()
                },
                MmsRequestInformation::default(),
            )
            .await?;

            Ok(connection)
        };
        let server_path = async {
            let tpkt_server = TcpTpktServer::listen(test_address).await?;
            let (tpkt_connection, _) = tpkt_server.accept().await?;
            let connection = OsiMmsMirrorResponderConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::accept(tpkt_connection).await?;

            Ok(connection)
        };

        let (copp_client, copp_server): (Result<_, anyhow::Error>, Result<_, anyhow::Error>) = join!(client_path, server_path);
        let mms_server = copp_server?;
        let mms_client = copp_client?;

        let (mut mms_client_reader, mut mms_client_writer) = mms_client.split().await?;
        let (mut mms_server_reader, mut mms_server_writer) = mms_server.split().await?;

        mms_client_writer
            .send(MmsMessage::ConfirmedRequest {
                invocation_id: BigInt::from(1).to_signed_bytes_be(),
                request: MmsConfirmedRequest::Read {
                    specification_with_result: None,
                    variable_access_specification: MmsVariableAccessSpecification::ListOfVariables(vec![
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific("Hello".into())),
                        },
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific("Foo".into(), "Bar".into())),
                        },
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("There".into())),
                        },
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("Does not exist".into())),
                        },
                    ]),
                },
            })
            .await?;

        let request = mms_server_reader.recv().await?;
        let read_request = match request {
            MmsRecvResult::Message(message) => match message {
                MmsMessage::ConfirmedRequest { invocation_id, request } => match (invocation_id, request) {
                    (
                        id,
                        MmsConfirmedRequest::Read {
                            specification_with_result,
                            variable_access_specification,
                        },
                    ) if id == &[1] => variable_access_specification,
                    _ => panic!(),
                },
                _ => panic!(),
            },
            MmsRecvResult::Closed => panic!(),
        };
        assert_eq!(
            read_request,
            MmsVariableAccessSpecification::ListOfVariables(vec![
                ListOfVariablesItem {
                    variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific("Hello".into())),
                },
                ListOfVariablesItem {
                    variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific("Foo".into(), "Bar".into())),
                },
                ListOfVariablesItem {
                    variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("There".into())),
                },
                ListOfVariablesItem {
                    variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("Does not exist".into())),
                },
            ])
        );

        mms_server_writer
            .send(MmsMessage::ConfirmedResponse {
                invocation_id: BigInt::from(1).to_signed_bytes_be(),
                response: MmsConfirmedResponse::Read {
                    variable_access_specification: None,
                    access_results: vec![
                        MmsAccessResult::Success(MmsData::Boolean(true)),
                        MmsAccessResult::Success(MmsData::Integer(vec![0x12, 0x34])),
                        MmsAccessResult::Success(MmsData::Array(vec![MmsData::MmsString("Test".into()), MmsData::Unsigned(vec![0x02]), MmsData::Unsigned(vec![0x03])])),
                        MmsAccessResult::Failure(MmsAccessError::Unknown(vec![0x04])),
                    ],
                },
            })
            .await?;

        let client_read_result = mms_client_reader.recv().await?;
        assert_eq!(
            client_read_result,
            MmsRecvResult::Message(MmsMessage::ConfirmedResponse {
                invocation_id: BigInt::from(1).to_signed_bytes_be(),
                response: MmsConfirmedResponse::Read {
                    variable_access_specification: None,
                    access_results: vec![
                        MmsAccessResult::Success(MmsData::Boolean(true)),
                        MmsAccessResult::Success(MmsData::Integer(vec![0x12, 0x34])),
                        MmsAccessResult::Success(MmsData::Array(vec![MmsData::MmsString("Test".into()), MmsData::Unsigned(vec![0x02]), MmsData::Unsigned(vec![0x03])])),
                        MmsAccessResult::Failure(MmsAccessError::Unknown(vec![0x04])),
                    ],
                },
            })
        );

        mms_client_writer
            .send(MmsMessage::ConfirmedRequest {
                invocation_id: vec![2],
                request: MmsConfirmedRequest::Identify,
            })
            .await?;
        assert_eq!(
            mms_server_reader.recv().await?,
            MmsRecvResult::Message(MmsMessage::ConfirmedRequest {
                invocation_id: vec![2],
                request: MmsConfirmedRequest::Identify,
            })
        );
        mms_server_writer
            .send(MmsMessage::ConfirmedResponse {
                invocation_id: vec![2],
                response: MmsConfirmedResponse::Identify {
                    vendor_name: "Test Vendor".into(),
                    model_name: "Test Model".into(),
                    revision: "Test Revision".into(),
                    abstract_syntaxes: Some(vec![Oid::from(&[1, 2, 3, 4])?, Oid::from(&[4, 3, 2, 1])?]),
                },
            })
            .await?;
        match mms_client_reader.recv().await? {
            MmsRecvResult::Message(MmsMessage::ConfirmedResponse { invocation_id, response }) => {
                assert_eq!(invocation_id, vec![2]);
                assert_eq!(
                    response,
                    MmsConfirmedResponse::Identify {
                        vendor_name: "Test Vendor".into(),
                        model_name: "Test Model".into(),
                        revision: "Test Revision".into(),
                        abstract_syntaxes: Some(vec![Oid::from(&[1, 2, 3, 4])?, Oid::from(&[4, 3, 2, 1])?]),
                    }
                );
            }
            _ => panic!(),
        }

        mms_client_writer
            .send(MmsMessage::ConfirmedRequest {
                invocation_id: vec![3],
                request: MmsConfirmedRequest::Write {
                    variable_access_specification: MmsVariableAccessSpecification::ListOfVariables(vec![
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific("Hello".into())),
                        },
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific("Foo".into(), "Bar".into())),
                        },
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("There".into())),
                        },
                    ]),
                    list_of_data: vec![
                        MmsData::Boolean(true),
                        MmsData::Integer(vec![0x12, 0x34]),
                        MmsData::Array(vec![MmsData::MmsString("Test".into()), MmsData::Unsigned(vec![0x02]), MmsData::Unsigned(vec![0x03])]),
                    ],
                },
            })
            .await?;
        match mms_server_reader.recv().await? {
            MmsRecvResult::Message(MmsMessage::ConfirmedRequest { invocation_id, request }) => {
                assert_eq!(invocation_id, vec![3]);
                assert_eq!(
                    request,
                    MmsConfirmedRequest::Write {
                        variable_access_specification: MmsVariableAccessSpecification::ListOfVariables(vec![
                            ListOfVariablesItem {
                                variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific("Hello".into())),
                            },
                            ListOfVariablesItem {
                                variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific("Foo".into(), "Bar".into())),
                            },
                            ListOfVariablesItem {
                                variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("There".into())),
                            },
                        ]),
                        list_of_data: vec![
                            MmsData::Boolean(true),
                            MmsData::Integer(vec![0x12, 0x34]),
                            MmsData::Array(vec![MmsData::MmsString("Test".into()), MmsData::Unsigned(vec![0x02]), MmsData::Unsigned(vec![0x03])]),
                        ],
                    }
                );
            }
            _ => panic!(),
        };
        mms_server_writer
            .send(MmsMessage::ConfirmedResponse {
                invocation_id: vec![3],
                response: MmsConfirmedResponse::Write {
                    write_results: vec![MmsWriteResult::Success, MmsWriteResult::Success, MmsWriteResult::Failure(MmsAccessError::ObjectInvalidated)],
                },
            })
            .await?;
        match mms_client_reader.recv().await? {
            MmsRecvResult::Message(MmsMessage::ConfirmedResponse { invocation_id, response }) => {
                assert_eq!(invocation_id, vec![3]);
                assert_eq!(
                    response,
                    MmsConfirmedResponse::Write {
                        write_results: vec![MmsWriteResult::Success, MmsWriteResult::Success, MmsWriteResult::Failure(MmsAccessError::ObjectInvalidated)],
                    }
                );
            }
            _ => panic!(),
        };
        mms_server_writer
            .send(MmsMessage::Unconfirmed {
                unconfirmed_service: MmsUnconfirmedService::InformationReport {
                    variable_access_specification: MmsVariableAccessSpecification::ListOfVariables(vec![
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific("Hello".into())),
                        },
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific("Foo".into(), "Bar".into())),
                        },
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("There".into())),
                        },
                    ]),
                    access_results: vec![
                        MmsAccessResult::Success(MmsData::Boolean(true)),
                        MmsAccessResult::Success(MmsData::Integer(vec![0x12, 0x34])),
                        MmsAccessResult::Success(MmsData::Array(vec![MmsData::MmsString("Test".into()), MmsData::Unsigned(vec![0x02]), MmsData::Unsigned(vec![0x03])])),
                    ],
                },
            })
            .await?;
        match mms_client_reader.recv().await? {
            MmsRecvResult::Message(MmsMessage::Unconfirmed { unconfirmed_service }) => {
                assert_eq!(
                    unconfirmed_service,
                    MmsUnconfirmedService::InformationReport {
                        variable_access_specification: MmsVariableAccessSpecification::ListOfVariables(vec![
                            ListOfVariablesItem {
                                variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific("Hello".into())),
                            },
                            ListOfVariablesItem {
                                variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific("Foo".into(), "Bar".into())),
                            },
                            ListOfVariablesItem {
                                variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("There".into())),
                            },
                        ]),
                        access_results: vec![
                            MmsAccessResult::Success(MmsData::Boolean(true)),
                            MmsAccessResult::Success(MmsData::Integer(vec![0x12, 0x34])),
                            MmsAccessResult::Success(MmsData::Array(vec![MmsData::MmsString("Test".into()), MmsData::Unsigned(vec![0x02]), MmsData::Unsigned(vec![0x03])])),
                        ],
                    }
                );
            }
            _ => panic!(),
        };

        mms_client_writer
            .send(MmsMessage::ConfirmedRequest {
                invocation_id: vec![4],
                request: MmsConfirmedRequest::GetNameList {
                    object_class: MmsObjectClass::Basic(MmsBasicObjectClass::NamedVariableList),
                    object_scope: MmsObjectScope::Domain("Test Domain".into()),
                    continue_after: Some("AfterThisOne".into()),
                },
            })
            .await?;
        match mms_server_reader.recv().await? {
            MmsRecvResult::Message(MmsMessage::ConfirmedRequest { invocation_id, request }) => {
                assert_eq!(invocation_id, vec![4]);
                assert_eq!(
                    request,
                    MmsConfirmedRequest::GetNameList {
                        object_class: MmsObjectClass::Basic(MmsBasicObjectClass::NamedVariableList),
                        object_scope: MmsObjectScope::Domain("Test Domain".into()),
                        continue_after: Some("AfterThisOne".into()),
                    }
                );
            }
            _ => panic!(),
        }
        mms_server_writer
            .send(MmsMessage::ConfirmedResponse {
                invocation_id: vec![4],
                response: MmsConfirmedResponse::GetNameList {
                    list_of_identifiers: vec!["Test1".into(), "Test2".into(), "Test3".into()],
                    more_follows: Option::Some(true),
                },
            })
            .await?;
        match mms_client_reader.recv().await? {
            MmsRecvResult::Message(MmsMessage::ConfirmedResponse { invocation_id, response }) => {
                assert_eq!(invocation_id, vec![4]);
                assert_eq!(
                    response,
                    MmsConfirmedResponse::GetNameList {
                        list_of_identifiers: vec!["Test1".into(), "Test2".into(), "Test3".into()],
                        more_follows: Option::Some(true),
                    }
                );
            }
            _ => panic!(),
        }

        mms_client_writer
            .send(MmsMessage::ConfirmedRequest {
                invocation_id: vec![5],
                request: MmsConfirmedRequest::GetVariableAccessAttributes {
                    object_name: MmsObjectName::VmdSpecific("Test VMD".into()),
                },
            })
            .await?;
        match mms_server_reader.recv().await? {
            MmsRecvResult::Message(MmsMessage::ConfirmedRequest { invocation_id, request }) => {
                assert_eq!(invocation_id, vec![5]);
                assert_eq!(
                    request,
                    MmsConfirmedRequest::GetVariableAccessAttributes {
                        object_name: MmsObjectName::VmdSpecific("Test VMD".into())
                    }
                );
            }
            _ => panic!(),
        }
        mms_server_writer
            .send(MmsMessage::ConfirmedResponse {
                invocation_id: vec![5],
                response: MmsConfirmedResponse::GetVariableAccessAttributes {
                    deletable: true,
                    type_description: MmsTypeDescription::Structure {
                        packed: Some(true),
                        components: vec![
                            MmsTypeDescriptionComponent {
                                component_name: Some("Name1".into()),
                                component_type: MmsTypeSpecification::ObjectName(MmsObjectName::AaSpecific("TestDomain1".into())),
                            },
                            MmsTypeDescriptionComponent {
                                component_name: Some("Name2".into()),
                                component_type: MmsTypeSpecification::TypeDescription(MmsTypeDescription::OctetString(vec![10])),
                            },
                            MmsTypeDescriptionComponent {
                                component_name: None,
                                component_type: MmsTypeSpecification::TypeDescription(MmsTypeDescription::Array {
                                    packed: Some(false),
                                    number_of_elements: vec![100],
                                    element_type: Box::new(MmsTypeSpecification::TypeDescription(MmsTypeDescription::GeneralizedTime)),
                                }),
                            },
                        ],
                    },
                },
            })
            .await?;
        match mms_client_reader.recv().await? {
            MmsRecvResult::Message(MmsMessage::ConfirmedResponse { invocation_id, response }) => {
                assert_eq!(invocation_id, vec![5]);
                assert_eq!(
                    response,
                    MmsConfirmedResponse::GetVariableAccessAttributes {
                        deletable: true,
                        type_description: MmsTypeDescription::Structure {
                            packed: Some(true),
                            components: vec![
                                MmsTypeDescriptionComponent {
                                    component_name: Some("Name1".into()),
                                    component_type: MmsTypeSpecification::ObjectName(MmsObjectName::AaSpecific("TestDomain1".into())),
                                },
                                MmsTypeDescriptionComponent {
                                    component_name: Some("Name2".into()),
                                    component_type: MmsTypeSpecification::TypeDescription(MmsTypeDescription::OctetString(vec![10])),
                                },
                                MmsTypeDescriptionComponent {
                                    component_name: None,
                                    component_type: MmsTypeSpecification::TypeDescription(MmsTypeDescription::Array {
                                        packed: Some(false),
                                        number_of_elements: vec![100],
                                        element_type: Box::new(MmsTypeSpecification::TypeDescription(MmsTypeDescription::GeneralizedTime)),
                                    }),
                                },
                            ],
                        },
                    }
                );
            }
            _ => panic!(),
        }

        mms_client_writer
            .send(MmsMessage::ConfirmedRequest {
                invocation_id: vec![5],
                request: MmsConfirmedRequest::DefineNamedVariableList {
                    variable_list_name: MmsObjectName::VmdSpecific("Test VMD".into()),
                    list_of_variables: vec![
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("I".into())),
                        },
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific("Want".into(), "That".into())),
                        },
                        ListOfVariablesItem {
                            variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific("One".into())),
                        },
                    ],
                },
            })
            .await?;
        match mms_server_reader.recv().await? {
            MmsRecvResult::Message(MmsMessage::ConfirmedRequest { invocation_id, request }) => {
                assert_eq!(invocation_id, vec![5]);
                assert_eq!(
                    request,
                    MmsConfirmedRequest::DefineNamedVariableList {
                        variable_list_name: MmsObjectName::VmdSpecific("Test VMD".into()),
                        list_of_variables: vec![
                            ListOfVariablesItem {
                                variable_specification: VariableSpecification::Name(MmsObjectName::AaSpecific("I".into()))
                            },
                            ListOfVariablesItem {
                                variable_specification: VariableSpecification::Name(MmsObjectName::DomainSpecific("Want".into(), "That".into()))
                            },
                            ListOfVariablesItem {
                                variable_specification: VariableSpecification::Name(MmsObjectName::VmdSpecific("One".into()))
                            },
                        ],
                    }
                );
            }
            _ => panic!(),
        }

        sleep(Duration::from_millis(1000)).await;

        Ok(())
    }
}
