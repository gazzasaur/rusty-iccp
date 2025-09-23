mod api;
mod message;
mod packet;
mod service;

pub use crate::api::*;
pub use crate::service::*;

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    use tokio::join;
    use tracing_test::traced_test;

    use crate::service::TcpCospConnector;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_negotiate_a_version_2_unlimited_size_connection() -> Result<(), anyhow::Error> {
        let (client_connection, server_connection) = create_cosp_connection_pair_with_options(None, CospConnectionInformation::default(), None).await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
        match server_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
        }
        server_writer.send(&[1, 2, 3, 4]).await?;
        match client_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_should_pass_small_connect_and_accept_data() -> Result<(), anyhow::Error> {
        let (client_connection, server_connection) = create_cosp_connection_pair_with_options(Some(&[5, 6, 7]), CospConnectionInformation::default(), Some(&[5, 4, 3])).await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
        match server_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
        }
        server_writer.send(&[1, 2, 3, 4]).await?;
        match client_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_should_pass_medium_connect_and_accept_data() -> Result<(), anyhow::Error> {
        let mut initial_connect_data = vec![0xabu8; 10240];
        rand::fill(initial_connect_data.as_mut_slice());

        let mut init_accept_data = vec![0x8; 65510];
        rand::fill(init_accept_data.as_mut_slice());

        let (client_connection, server_connection) = create_cosp_connection_pair_with_options(Some(initial_connect_data.as_slice()), CospConnectionInformation::default(), Some(init_accept_data.as_slice())).await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
        match server_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
        }
        server_writer.send(&[1, 2, 3, 4]).await?;
        match client_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
        }

        Ok(())
    }

    // TODO Need to fix Accept
    // TODO Need to take into account the mtu of the peer
    // TODO Need to DT a lot bigger data
    #[tokio::test]
    #[traced_test]
    async fn it_should_pass_jumbo_connect_and_accept_data() -> Result<(), anyhow::Error> {
        let mut initial_connect_data = vec![0x00u8; 10240 + 65520 + 65520 + 100];
        rand::fill(initial_connect_data.as_mut_slice());

        let mut init_accept_data = vec![0x00u8; 65510 + 65510 + 100];
        rand::fill(init_accept_data.as_mut_slice());

        let (client_connection, server_connection) = create_cosp_connection_pair_with_options(Some(initial_connect_data.as_slice()), CospConnectionInformation::default(), Some(init_accept_data.as_slice())).await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
        match server_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
        }
        server_writer.send(&[1, 2, 3, 4]).await?;
        match client_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_should_pass_and_honour_options() -> Result<(), anyhow::Error> {
        let mut initial_connect_data = vec![0x00u8; 10240 + 65520 + 65520 + 100];
        rand::fill(initial_connect_data.as_mut_slice());

        let mut init_accept_data = vec![0x00u8; 65510 + 65510 + 100];
        rand::fill(init_accept_data.as_mut_slice());

        let (client_connection, server_connection) = create_cosp_connection_pair_with_options(
            Some(initial_connect_data.as_slice()),
            CospConnectionInformation {
                tsdu_maximum_size: Some(512),
                calling_session_selector: Some(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
                called_session_selector: Some(vec![0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21]),
            },
            Some(init_accept_data.as_slice()),
        )
        .await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
        match server_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
        }
        server_writer.send(&[1, 2, 3, 4]).await?;
        match client_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
        }

        Ok(())
    }

    async fn create_cosp_connection_pair_with_options(connect_data: Option<&[u8]>, options: CospConnectionInformation, accept_data: Option<&[u8]>) -> Result<(impl CospConnection, impl CospConnection), anyhow::Error> {
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
        let cosp_client_connector = TcpCospInitiator::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_client, options.clone()).await?;
        let cosp_server_connector = TcpCospConnector::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_server).await?;

        let (cosp_client, cosp_server) = join!(async { cosp_client_connector.initiate(connect_data.map(|o| o.to_vec())).await }, async {
            let (acceptor, connection_information, user_data) = cosp_server_connector.responder().await?;
            assert_eq!(connect_data.map(|x| x.to_vec()), user_data);
            assert_eq!(connection_information.called_session_selector, options.called_session_selector);
            acceptor.accept(accept_data).await
        });

        Ok((cosp_client?.0, cosp_server?))
    }
}
