pub(crate) mod api;
pub(crate) mod service;

pub use api::*;
pub use service::*;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    // use std::ops::Range;

    // use rusty_cosp::{api::{CospConnectionInformation, CospConnector, CospResponder}, TcpCospConnection, TcpCospConnector};
    // use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
    // use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    // use tokio::join;

    // use super::*;

    // #[test]
    // fn create_connection() {
    // }

    // async fn create_cosp_connection_pair_with_options(
    //     connect_data: Option<&[u8]>,
    //     options: CoppConnectionInformation,
    //     accept_data: Option<&[u8]>,
    // ) -> Result<(RustyCoppConnection<impl CoppReader, impl CoppWriter>, impl CoppConnection), anyhow::Error> {
    //     let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
    //     // let test_address = "127.0.0.1:10002".parse()?;

    //     let connect_information = CotpConnectInformation::default();

    //     let tpkt_listener = TcpTpktServer::listen(test_address).await?;
    //     let (tpkt_client, tpkt_server) = join!(TcpTpktConnection::connect(test_address), tpkt_listener.accept());

    //     let (cotp_initiator, cotp_acceptor) = join!(async { TcpCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_client?, connect_information.clone()).await }, async {
    //         let (acceptor, remote) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::respond(tpkt_server?.0).await?;
    //         assert_eq!(remote, connect_information);
    //         acceptor.accept(CotpAcceptInformation::default()).await
    //     });

    //     let cotp_client = cotp_initiator?;
    //     let cotp_server = cotp_acceptor?;
    //     let cotp_client_connector = TcpCospConnector::new(cotp_client).await?;
    //     let cotp_server_connector = TcpCospConnector::new(cotp_server).await?;
    //     let connector = cotp_server_connector.initiator(options, user_data);

    //     let (cosp_client, cosp_server) = join!(
    //         async { TcpCospConnection::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::connect(cotp_client, CospConnectionInformation::default(), connect_data).await },
    //         async {
    //             let (acceptor, connection_information, user_data) = connector.responder().await?;
    //             assert_eq!(connect_data.map(|x| x.to_vec()), user_data);
    //             assert_eq!(connection_information.called_session_selector, None);
    //             acceptor.accept(accept_data).await
    //         }
    //     );

    //     let cosp_responder = RustyCoppConnector::new(cosp_server?).await?;

    //     Ok(())

    //     // Ok((cosp_client?.0, cosp_server?))
    // }
}
