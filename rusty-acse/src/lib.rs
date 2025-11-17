pub(crate) mod api;
pub(crate) mod messages;
pub(crate) mod service;

pub use api::*;
use rusty_copp::{RustyCoppInitiatorIsoStack, RustyCoppReaderIsoStack, RustyCoppWriterIsoStack};
pub use service::*;

pub type RustyAcseReaderIsoStack<R> = RustyOsiSingleValueAcseReader<RustyCoppReaderIsoStack<R>>;
pub type RustyAcseWriterIsoStack<W> = RustyOsiSingleValueAcseWriter<RustyCoppWriterIsoStack<W>>;
pub type RustyAcseInitiatorIsoStack<R, W> = RustyOsiSingleValueAcseInitiator<RustyCoppInitiatorIsoStack<R, W>, RustyCoppReaderIsoStack<R>, RustyCoppWriterIsoStack<W>>;

#[cfg(test)]
mod tests {
    use der_parser::num_bigint::BigInt;
    use rusty_copp::CoppConnection;
    use rusty_copp::CoppListener;
    use rusty_copp::CoppResponder;
    use std::time::Duration;

    use der_parser::Oid;
    use rusty_copp::{CoppError, PresentationContextResult, PresentationContextResultCause, PresentationContextResultType, RustyCoppInitiator, RustyCoppListener, UserData};
    use rusty_cosp::{TcpCospInitiator, TcpCospListener, TcpCospReader, TcpCospResponder, TcpCospWriter};
    use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    use tokio::join;
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_create_connection() -> Result<(), anyhow::Error> {
        create_acse_connection_pair_with_options(
            AcseRequestInformation {
                application_context_name: Oid::from(&[1, 0, 9506, 2, 1])?,
                called_ap_title: Some(ApTitle::Form2(Oid::from(&[1, 2, 3, 4, 5])?)),
                called_ae_qualifier: Some(AeQualifier::Form2(vec![100])),
                called_ap_invocation_identifier: Some(vec![101]),
                called_ae_invocation_identifier: Some(vec![102]),
                calling_ap_title: Some(ApTitle::Form2(Oid::from(&[2, 2, 3, 4, 5])?)),
                calling_ae_qualifier: Some(AeQualifier::Form2(BigInt::from(200u32).to_signed_bytes_be())),
                calling_ap_invocation_identifier: Some(BigInt::from(201u32).to_signed_bytes_be()),
                calling_ae_invocation_identifier: Some(BigInt::from(202u32).to_signed_bytes_be()),
                implementation_information: Some("This Guy".into()),
            },
            None,
        )
        .await?;

        Ok(())
    }

    async fn create_acse_connection_pair_with_options(reqeust_options: AcseRequestInformation, accept_data: Option<UserData>) -> Result<(impl OsiSingleValueAcseConnection, impl CoppConnection), anyhow::Error> {
        // let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let test_address = "127.0.0.1:10002".parse()?;

        let connect_information = CotpConnectInformation::default();

        let client_path = async {
            tokio::time::sleep(Duration::from_millis(1)).await; // Give the server time to start
            let tpkt_client = TcpTpktConnection::connect(test_address).await?;
            let cotp_client = TcpCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_client, connect_information.clone()).await?;
            let cosp_client = TcpCospInitiator::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_client, Default::default()).await?;
            let copp_client = RustyCoppInitiator::<TcpCospInitiator<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>, TcpCospReader<TcpCotpReader<TcpTpktReader>>, TcpCospWriter<TcpCotpWriter<TcpTpktWriter>>>::new(
                cosp_client,
                Default::default(),
            );
            let acse_client = RustyAcseInitiatorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(copp_client, reqeust_options);
            Ok(acse_client.initiate(Oid::from(&[1, 0, 9506, 2, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?, vec![0xa8, 0x00]).await?)
        };
        let server_path = async {
            let tpkt_server = TcpTpktServer::listen(test_address).await?;
            let (tpkt_connection, _) = tpkt_server.accept().await?;
            let (cotp_server, _) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::new(tpkt_connection).await?;
            let cotp_connection = cotp_server.accept(CotpAcceptInformation::default()).await?;
            let (cosp_listener, _) = TcpCospListener::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_connection).await?;
            let (mut copp_listener, _) =
                RustyCoppListener::<TcpCospResponder<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>, TcpCospReader<TcpCotpReader<TcpTpktReader>>, TcpCospWriter<TcpCotpWriter<TcpTpktWriter>>>::new(cosp_listener).await?;
            copp_listener.with_context(Some(PresentationContextResultType::ContextDefinitionList(vec![
                PresentationContextResult {
                    result: PresentationContextResultCause::Acceptance,
                    transfer_syntax_name: Some(Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?),
                    provider_reason: None,
                },
                PresentationContextResult {
                    result: PresentationContextResultCause::Acceptance,
                    transfer_syntax_name: Some(Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?),
                    provider_reason: None,
                },
            ])));
            let (copp_responder, connect_user_data) = copp_listener.responder().await?;

            Ok((copp_responder.accept(accept_data.clone()).await?, connect_user_data))
        };

        let (copp_client, copp_server): (Result<_, anyhow::Error>, Result<_, anyhow::Error>) = join!(client_path, server_path);
        let (copp_client, accepted_data, user_data) = copp_client?;
        let (copp_server, connected_data) = copp_server?;

        // assert_eq!(accept_data, accepted_data);
        // assert_eq!(connect_data, connected_data);

        Ok((copp_client, copp_server))
    }
}
