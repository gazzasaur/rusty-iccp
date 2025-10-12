pub(crate) mod api;
pub(crate) mod error;
pub(crate) mod messages;
pub(crate) mod service;

pub use api::*;
pub use service::*;

#[cfg(test)]
mod tests {
    use std::{ops::Range, time::Duration};

    use der_parser::Oid;
    use rusty_cosp::{TcpCospInitiator, TcpCospListener, TcpCospReader, TcpCospResponder, TcpCospWriter};
    use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    use tokio::join;

    use super::*;

    #[tokio::test]
    async fn it_should_create_connection() -> Result<(), anyhow::Error> {
        let options = CoppConnectionInformation {
            calling_presentation_selector: Some(vec![0x00, 0x00, 0x00, 0x23]),
            called_presentation_selector: Some(vec![0x65, 0x00, 0x00, 0x00]),
            ..Default::default()
        };
        let presentation_contexts = vec![
            // ACSE
            PresentationContext {
                indentifier: vec![1],
                abstract_syntax_name: Oid::from(&[2, 2, 1, 0, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?,
                transfer_syntax_name_list: vec![Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?],
            },
            // MMS
            PresentationContext {
                indentifier: vec![3],
                abstract_syntax_name: Oid::from(&[1, 0, 9506, 2, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?,
                transfer_syntax_name_list: vec![Oid::from(&[2, 1, 1]).map_err(|e| CoppError::InternalError(e.to_string()))?],
            },
        ];
        let (_c, _s) = create_copp_connection_pair_with_options(Some(vec![0x30, 0x00]), options, None, presentation_contexts).await?;

        Ok(())
    }

    async fn create_copp_connection_pair_with_options(
        connect_data: Option<Vec<u8>>,
        options: CoppConnectionInformation,
        accept_data: Option<&[u8]>,
        contexts: Vec<PresentationContext>,
    ) -> Result<(impl CoppConnection, impl CoppConnection), anyhow::Error> {
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
                options,
            );
            Ok(copp_client.initiate(PresentationContextType::ContextDefinitionList(contexts), connect_data).await?)
        };
        let server_path = async {
            let tpkt_server = TcpTpktServer::listen(test_address).await?;
            let (tpkt_connection, _) = tpkt_server.accept().await?;
            let (cotp_server, _) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::new(tpkt_connection).await?;
            let cotp_connection = cotp_server.accept(CotpAcceptInformation::default()).await?;
            let (cosp_listener, _) = TcpCospListener::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_connection).await?;
            let (copp_listener, _) =
                RustyCoppListener::<TcpCospResponder<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>, TcpCospReader<TcpCotpReader<TcpTpktReader>>, TcpCospWriter<TcpCotpWriter<TcpTpktWriter>>>::new(cosp_listener).await?;
            let (copp_responder, _) = copp_listener.responder().await?;
            Ok(copp_responder.accept(accept_data).await?)
        };

        let (copp_client, copp_server): (Result<_, anyhow::Error>, Result<_, anyhow::Error>) = join!(client_path, server_path);
        let (copp_client, _) = copp_client?;
        let copp_server = copp_server?;

        Ok((copp_client, copp_server))
    }
}
