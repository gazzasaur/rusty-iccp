pub(crate) mod api;
pub(crate) mod service;

pub use api::*;
pub use service::*;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use rusty_cosp::{CospConnectionInformation, CospConnector, CospResponder, TcpCospConnector, TcpCospReader, TcpCospWriter};
    use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    use tokio::join;

    use super::*;

    #[tokio::test]
    async fn it_should_create_connection() -> Result<(), anyhow::Error> {
        let (_c, _s) = create_copp_connection_pair_with_options(None, Default::default(), None).await?;
        Ok(())
    }

    async fn create_copp_connection_pair_with_options(connect_data: Option<&[u8]>, options: CospConnectionInformation, accept_data: Option<&[u8]>) -> Result<(impl CoppConnection, impl CoppConnection), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        // let test_address = "127.0.0.1:10002".parse()?;

        let connect_information = CotpConnectInformation::default();

        let tpkt_listener = TcpTpktServer::listen(test_address).await?;
        let (tpkt_client, tpkt_server) = join!(TcpTpktConnection::connect(test_address), tpkt_listener.accept());

        let (cotp_initiator, cotp_acceptor) = join!(async { TcpCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_client?, connect_information.clone()).await }, async {
            let (acceptor, remote) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::respond(tpkt_server?.0).await?;
            assert_eq!(remote, connect_information);
            acceptor.accept(CotpAcceptInformation::default()).await
        });

        let cotp_client = cotp_initiator?;
        let cotp_server = cotp_acceptor?;
        let cosp_client_connector = TcpCospConnector::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_client).await?;
        let cosp_server_connector = TcpCospConnector::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_server).await?;

        let (cosp_client, cosp_server) = join!(async { cosp_client_connector.initiator(options.clone(), connect_data.map(|o| o.to_vec())).await }, async {
            let (acceptor, connection_information, user_data) = cosp_server_connector.responder().await?;
            assert_eq!(connect_data.map(|x| x.to_vec()), user_data);
            assert_eq!(connection_information.called_session_selector, options.called_session_selector);
            acceptor.accept(accept_data).await
        });

        let copp_client_connector = RustyCoppConnector::<TcpCospReader<TcpCotpReader<TcpTpktReader>>, TcpCospWriter<TcpCotpWriter<TcpTpktWriter>>>::new(cosp_client?.0).await?;
        let copp_server_connector = RustyCoppConnector::<TcpCospReader<TcpCotpReader<TcpTpktReader>>, TcpCospWriter<TcpCotpWriter<TcpTpktWriter>>>::new(cosp_server?).await?;

        let (copp_client_connection, _) = copp_client_connector.initiator(Default::default(), None).await?;
        let (copp_responder, _, _) = copp_server_connector.responder().await?;
        let copp_server_connection = copp_responder.accept(None).await?;

        Ok((copp_client_connection, copp_server_connection))
    }
}
