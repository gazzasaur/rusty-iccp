pub(crate) mod api;
pub(crate) mod service;
pub(crate) mod message;
pub(crate) mod serialise;

pub use api::*;
pub use service::*;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use std::{ops::Range, time::Duration};

    use anyhow::anyhow;
    use rusty_cosp::{CospConnectionInformation, CospError, CospInitiator, CospListener, CospResponder, TcpCospInitiator, TcpCospListener, TcpCospReader, TcpCospResponder, TcpCospWriter};
    use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    use tokio::join;

    use super::*;

    #[tokio::test]
    async fn it_should_create_connection() -> Result<(), anyhow::Error> {
        let (_c, _s) = create_copp_connection_pair_with_options(None, Default::default(), None).await?;
        
        Ok(())
    }

    async fn create_copp_connection_pair_with_options(connect_data: Option<Vec<u8>>, options: CospConnectionInformation, accept_data: Option<&[u8]>) -> Result<(impl CoppConnection, impl CoppConnection), anyhow::Error> {
        // let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let test_address = "127.0.0.1:10002".parse()?;

        let connect_information = CotpConnectInformation::default();

        let client_path = async {
            tokio::time::sleep(Duration::from_millis(1)).await; // Give the server time to start
            let tpkt_client = TcpTpktConnection::connect(test_address).await?;
            let cotp_client = TcpCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_client, connect_information.clone()).await?;
            let cosp_client = TcpCospInitiator::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_client, options.clone()).await?;
            let copp_client = RustyCoppInitiator::<TcpCospInitiator<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>, TcpCospReader<TcpCotpReader<TcpTpktReader>>, TcpCospWriter<TcpCotpWriter<TcpTpktWriter>>>::new(cosp_client, CoppConnectionInformation::default());
            Ok(copp_client.initiate(connect_data).await?)
        };
        let server_path = async {
            let tpkt_server = TcpTpktServer::listen(test_address).await?;
            let (tpkt_connection, _) = tpkt_server.accept().await?;
            let (cotp_server, _) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::new(tpkt_connection).await?;
            let cotp_connection = cotp_server.accept(CotpAcceptInformation::default()).await?;
            let (cosp_listener, _) = TcpCospListener::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_connection).await?;
            let (copp_listener, _) = RustyCoppListener::<TcpCospResponder<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>, TcpCospReader<TcpCotpReader<TcpTpktReader>>, TcpCospWriter<TcpCotpWriter<TcpTpktWriter>>>::new(cosp_listener).await?;
            let (copp_responder, _, _) = copp_listener.responder().await?;
            Ok(copp_responder.accept(accept_data).await?)
        };

        let (copp_client, copp_server): (Result<_, anyhow::Error>, Result<_, anyhow::Error>) = join!(client_path, server_path);
        let (copp_client, _) = copp_client?;
        let copp_server = copp_server?;

        Ok((copp_client, copp_server))
    }
}
