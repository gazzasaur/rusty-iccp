mod api;
mod packet;
mod parser;
mod serialiser;
mod service;

pub use crate::api::*;
pub use crate::service::*;

#[cfg(test)]
mod tests {
    use std::{ops::Range, time::Duration};

    use rand::RngCore;
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter, TpktReader, TpktWriter};
    use tokio::{join, time::timeout};
    use tracing_test::traced_test;

    use crate::api::{CotpConnectInformation, CotpConnection, CotpReader, CotpResponder, CotpWriter};

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_transfers_data() -> Result<(), anyhow::Error> {
        let (cotp_client, cotp_server) = create_cotp_connection_pair(None, None).await?;

        let (mut client_read, mut client_writer) = cotp_client.split().await?;
        let (mut server_read, mut server_writer) = cotp_server.split().await?;

        client_writer.send("ABCD".as_bytes()).await?;
        match server_read.recv().await? {
            api::CotpRecvResult::Closed => assert!(false, "Connection was unexpectedly closed."),
            api::CotpRecvResult::Data(items) => assert_eq!(items, "ABCD".as_bytes().to_vec()),
        }

        server_writer.send("EFGH".as_bytes()).await?;
        match client_read.recv().await? {
            api::CotpRecvResult::Closed => assert!(false, "Connection was unexpectedly closed."),
            api::CotpRecvResult::Data(items) => assert_eq!(items, "EFGH".as_bytes().to_vec()),
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_transfers_data_with_tsaps() -> Result<(), anyhow::Error> {
        let (cotp_client, cotp_server) = create_cotp_connection_pair(Some(vec![1u8, 2u8, 3u8]), Some(vec![4u8, 5u8, 6u8])).await?;

        let (mut client_read, mut client_writer) = cotp_client.split().await?;
        let (mut server_read, mut server_writer) = cotp_server.split().await?;

        client_writer.send("ABCD".as_bytes()).await?;
        match server_read.recv().await? {
            api::CotpRecvResult::Closed => assert!(false, "Connection was unexpectedly closed."),
            api::CotpRecvResult::Data(items) => assert_eq!(items, "ABCD".as_bytes().to_vec()),
        }

        server_writer.send("EFGH".as_bytes()).await?;
        match client_read.recv().await? {
            api::CotpRecvResult::Closed => assert!(false, "Connection was unexpectedly closed."),
            api::CotpRecvResult::Data(items) => assert_eq!(items, "EFGH".as_bytes().to_vec()),
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_transfers_data_over_multiple_segments() -> Result<(), anyhow::Error> {
        let (cotp_client, cotp_server) = create_cotp_connection_pair(None, None).await?;

        let (mut client_read, mut client_writer) = cotp_client.split().await?;
        let (mut server_read, mut server_writer) = cotp_server.split().await?;

        let mut over_buffer = [0u8; 100000];
        rand::rng().fill_bytes(&mut over_buffer[..]);

        for _ in 0..10 {
            client_writer.send(over_buffer.as_slice()).await?;
            match server_read.recv().await? {
                api::CotpRecvResult::Closed => assert!(false, "Connection was unexpectedly closed."),
                api::CotpRecvResult::Data(items) => assert_eq!(items, over_buffer.to_vec()),
            }

            server_writer.send(over_buffer.as_slice()).await?;
            match client_read.recv().await? {
                api::CotpRecvResult::Closed => assert!(false, "Connection was unexpectedly closed."),
                api::CotpRecvResult::Data(items) => assert_eq!(items, over_buffer.to_vec()),
            }
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_flushes_correctly() -> Result<(), anyhow::Error> {
        let (cotp_client, cotp_server) = create_cotp_connection_pair(None, None).await?;

        let (mut client_read, mut client_writer) = cotp_client.split().await?;
        let (mut server_read, mut server_writer) = cotp_server.split().await?;

        let mut over_buffer = [0u8; 1024];
        let mut data_buffer = Vec::new();
        for _ in 1..10000 {
            rand::rng().fill_bytes(&mut over_buffer[..]);
            data_buffer.extend_from_slice(&over_buffer);
        }

        match timeout(Duration::from_millis(100), client_writer.send(data_buffer.as_slice())).await {
            Ok(_) => assert!(false, "Expected the data to be too large for the buffer."),
            Err(_) => (),
        }
        loop {
            match timeout(Duration::from_millis(100), client_writer.continue_send()).await {
                Ok(_) => break,
                Err(_) => (),
            };
            match timeout(Duration::from_millis(100), server_read.recv()).await {
                Ok(_) => assert!(false, "Expected that all the payload was not yet send."),
                Err(_) => (),
            }
        }
        match server_read.recv().await? {
            api::CotpRecvResult::Closed => assert!(false, "Connection was unexpectedly closed."),
            api::CotpRecvResult::Data(items) => assert_eq!(items, data_buffer.to_vec()),
        }

        match timeout(Duration::from_millis(100), server_writer.send(data_buffer.as_slice())).await {
            Ok(_) => assert!(false, "Expected the data to be too large for the buffer."),
            Err(_) => (),
        }
        loop {
            match timeout(Duration::from_millis(100), server_writer.continue_send()).await {
                Ok(_) => break,
                Err(_) => (),
            };
            match timeout(Duration::from_millis(100), client_read.recv()).await {
                Ok(_) => assert!(false, "Expected that all the payload was not yet send."),
                Err(_) => (),
            }
        }
        match client_read.recv().await? {
            api::CotpRecvResult::Closed => assert!(false, "Connection was unexpectedly closed."),
            api::CotpRecvResult::Data(items) => assert_eq!(items, data_buffer.to_vec()),
        }

        Ok(())
    }

    async fn create_cotp_connection_pair(calling_tsap_id: Option<Vec<u8>>, called_tsap_id: Option<Vec<u8>>) -> Result<(TcpCotpConnection<impl TpktReader, impl TpktWriter>, impl CotpConnection), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;

        let tpkt_listener = TcpTpktServer::listen(test_address).await?;
        let (tpkt_client, tpkt_server) = join!(TcpTpktConnection::connect(test_address), tpkt_listener.accept());

        let connect_information = CotpConnectInformation {
            calling_tsap_id: calling_tsap_id.clone(),
            called_tsap_id: called_tsap_id.clone(),
            ..Default::default()
        };
        let accept_information = CotpAcceptInformation { ..Default::default() };

        let (cotp_initiator, cotp_acceptor) = join!(async { TcpCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_client?, connect_information.clone(),).await }, async {
            let (acceptor, remote) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::new(tpkt_server?.0).await?;
            assert_eq!(remote, connect_information);
            acceptor.accept(accept_information).await
        });

        let cotp_client = cotp_initiator?;
        let cotp_server = cotp_acceptor?;

        Ok((cotp_client, cotp_server))
    }
}
