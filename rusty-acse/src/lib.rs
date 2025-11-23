pub(crate) mod api;
pub(crate) mod messages;
pub(crate) mod service;

pub use api::*;
use rusty_copp::{RustyCoppInitiatorIsoStack, RustyCoppReaderIsoStack, RustyCoppResponderIsoStack, RustyCoppWriterIsoStack};
pub use service::*;

pub type RustyOsiSingleValueAcseReaderIsoStack<R> = RustyOsiSingleValueAcseReader<R>;
pub type RustyOsiSingleValueAcseWriterIsoStack<W> = RustyOsiSingleValueAcseWriter<W>;
pub type RustyOsiSingleValueAcseInitiatorIsoStack<R, W> = RustyOsiSingleValueAcseInitiator<RustyCoppInitiatorIsoStack<R, W>, RustyCoppReaderIsoStack<R>, RustyCoppWriterIsoStack<W>>;
pub type RustyOsiSingleValueAcseListenerIsoStack<R, W> = RustyOsiSingleValueAcseListener<RustyCoppResponderIsoStack<R, W>, RustyCoppReaderIsoStack<R>, RustyCoppWriterIsoStack<W>>;
pub type RustyOsiSingleValueAcseResponderIsoStack<R, W> = RustyOsiSingleValueAcseResponder<RustyCoppResponderIsoStack<R, W>, RustyCoppReaderIsoStack<R>, RustyCoppWriterIsoStack<W>>;

#[cfg(test)]
mod tests {
    use der_parser::num_bigint::BigInt;
    use std::time::Duration;

    use der_parser::Oid;
    use rusty_copp::{CoppError, RustyCoppInitiator, RustyCoppListener};
    use rusty_cosp::{TcpCospInitiator, TcpCospListener, TcpCospReader, TcpCospResponder, TcpCospWriter};
    use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    use tokio::join;
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_create_connection() -> Result<(), anyhow::Error> {
        let (client, server) = create_acse_connection_pair_with_options(
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
            AcseResponseInformation {
                associate_result: AssociateResult::Accepted,
                associate_source_diagnostic: AssociateSourceDiagnostic::User(AssociateSourceDiagnosticUserCategory::Null),
                application_context_name: Oid::from(&[1, 0, 9506, 2, 1])?,
                responding_ap_title: Some(ApTitle::Form2(Oid::from(&[1, 2, 3, 4, 5])?)),
                responding_ae_qualifier: Some(AeQualifier::Form2(vec![100])),
                responding_ap_invocation_identifier: Some(vec![101]),
                responding_ae_invocation_identifier: Some(vec![102]),
                implementation_information: Some("This Other Guy".into()),
            },
            vec![0xa8, 0x00],
            vec![0xa9, 0x00],
        )
        .await?;

        let (mut client_reader, mut client_writer) = client.split().await?;
        let (mut server_reader, mut server_writer) = server.split().await?;

        client_writer.send(vec![0xa0, 0x03, 0x02, 0x01, 0x01]).await?;
        assert_eq!(AcseRecvResult::Data(vec![160, 3, 2, 1, 1]), server_reader.recv().await?);

        server_writer.send(vec![0xa0, 0x03, 0x02, 0x01, 0x02]).await?;
        assert_eq!(AcseRecvResult::Data(vec![160, 3, 2, 1, 2]), client_reader.recv().await?);

        Ok(())
    }

    async fn create_acse_connection_pair_with_options(
        reqeust_options: AcseRequestInformation,
        response_options: AcseResponseInformation,
        connect_data: Vec<u8>,
        accept_data: Vec<u8>,
    ) -> Result<(impl OsiSingleValueAcseConnection, impl OsiSingleValueAcseConnection), anyhow::Error> {
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
            let acse_client = RustyOsiSingleValueAcseInitiatorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(copp_client, reqeust_options.clone());
            Ok(acse_client.initiate(Oid::from(&[1, 0, 9506, 2, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?, connect_data.clone()).await?)
        };
        let server_path = async {
            let tpkt_server = TcpTpktServer::listen(test_address).await?;
            let (tpkt_connection, _) = tpkt_server.accept().await?;
            let (cotp_server, _) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::new(tpkt_connection).await?;
            let cotp_connection = cotp_server.accept(CotpAcceptInformation::default()).await?;
            let (cosp_listener, _) = TcpCospListener::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_connection).await?;
            let (copp_listener, _) =
                RustyCoppListener::<TcpCospResponder<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>, TcpCospReader<TcpCotpReader<TcpTpktReader>>, TcpCospWriter<TcpCotpWriter<TcpTpktWriter>>>::new(cosp_listener).await?;
            let acse_listener = RustyOsiSingleValueAcseListenerIsoStack::<TcpTpktReader, TcpTpktWriter>::new(copp_listener).await?;
            let (acse_responder, received_request_information, received_connect_data) = acse_listener.responder(response_options.clone()).await?;

            Ok((acse_responder.accept(accept_data.clone()).await?, received_request_information, received_connect_data))
        };

        let (copp_client, copp_server): (Result<_, anyhow::Error>, Result<_, anyhow::Error>) = join!(client_path, server_path);
        let (copp_server, received_request_information, received_connect_data) = copp_server?;
        let (copp_client, received_response_information, received_accept_data) = copp_client?;

        assert_eq!(reqeust_options, received_request_information);
        assert_eq!(connect_data, received_connect_data);
        assert_eq!(response_options, received_response_information);
        assert_eq!(accept_data, received_accept_data);

        Ok((copp_client, copp_server))
    }
}
