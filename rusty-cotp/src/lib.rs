#![doc = include_str!("../README.md")]

mod api;
mod packet;
mod parser;
mod serialiser;
mod service;

pub use crate::api::*;
pub use crate::service::*;

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, ops::Range, time::Duration};

    use anyhow::anyhow;
    use rand::RngCore;
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter, TpktReader, TpktWriter};
    use tokio::{join, time::timeout};
    use tracing_test::traced_test;

    use crate::api::{CotpConnection, CotpProtocolInformation, CotpReader, CotpResponder, CotpWriter};

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_transfers_data() -> Result<(), anyhow::Error> {
        let (cotp_client, cotp_server) = create_cotp_connection_pair(None, None, Default::default()).await?;

        let (mut client_read, mut client_writer) = cotp_client.split().await?;
        let (mut server_read, mut server_writer) = cotp_server.split().await?;

        client_writer.send(&mut VecDeque::from(vec![b"ABCD".to_vec()])).await?;
        assert_eq!(server_read.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, "ABCD".as_bytes().to_vec());

        server_writer.send(&mut VecDeque::from(vec![b"EFGH".to_vec()])).await?;
        assert_eq!(client_read.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, "EFGH".as_bytes().to_vec());

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_transfers_data_with_tsaps() -> Result<(), anyhow::Error> {
        let (cotp_client, cotp_server) = create_cotp_connection_pair(Some(vec![1u8, 2u8, 3u8]), Some(vec![4u8, 5u8, 6u8]), Default::default()).await?;

        let (mut client_read, mut client_writer) = cotp_client.split().await?;
        let (mut server_read, mut server_writer) = cotp_server.split().await?;

        client_writer.send(&mut VecDeque::from(vec![b"ABCD".to_vec()])).await?;
        assert_eq!(server_read.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, "ABCD".as_bytes().to_vec());

        server_writer.send(&mut VecDeque::from(vec![b"EFGH".to_vec()])).await?;
        assert_eq!(client_read.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, "EFGH".as_bytes().to_vec());

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_transfers_data_over_multiple_segments() -> Result<(), anyhow::Error> {
        let (cotp_client, cotp_server) = create_cotp_connection_pair(None, None, Default::default()).await?;

        let (mut client_read, mut client_writer) = cotp_client.split().await?;
        let (mut server_read, mut server_writer) = cotp_server.split().await?;

        let mut over_buffer = [0u8; 100000];
        rand::rng().fill_bytes(&mut over_buffer[..]);

        for _ in 0..10 {
            client_writer.send(&mut VecDeque::from(vec![over_buffer.to_vec()])).await?;
            assert_eq!(server_read.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, over_buffer.to_vec());

            server_writer.send(&mut VecDeque::from(vec![over_buffer.to_vec()])).await?;
            assert_eq!(client_read.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, over_buffer.to_vec());
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_fails_on_max_reassembled_payload_exceeded() -> Result<(), anyhow::Error> {
        let (cotp_client, cotp_server) = create_cotp_connection_pair(None, None, Default::default()).await?;

        let (_, mut client_writer) = cotp_client.split().await?;
        let (mut server_read, _) = cotp_server.split().await?;

        let mut over_buffer = [0u8; 1024];
        let mut data_buffer = Vec::new();
        for _ in 1..10000 {
            rand::rng().fill_bytes(&mut over_buffer[..]);
            data_buffer.extend_from_slice(&over_buffer);
        }

        match timeout(Duration::from_millis(100), client_writer.send(&mut VecDeque::from(vec![data_buffer.to_vec()]))).await {
            Ok(_) => assert!(false, "Expected the data to be too large for the buffer."),
            Err(_) => (),
        }
        match timeout(Duration::from_millis(100), server_read.recv()).await {
            Ok(Ok(_)) => assert!(false, "Expected that all the payload was not yet send."),
            Ok(Err(e)) => {
                assert_eq!(format!("{e}"), "COTP Protocol Error - Reassembled payload size 1051130 exceeds maximum payload size 1049600");
                return Ok(());
            }
            Err(_) => assert!(false, "Expected to failed on buffer exceeded."),
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_flushes_correctly() -> Result<(), anyhow::Error> {
        let (cotp_client, cotp_server) = create_cotp_connection_pair(None, None, CotpConnectionParameters { max_reassembled_payload_size: 32 * 1024 * 1024 }).await?;

        let (mut client_read, mut client_writer) = cotp_client.split().await?;
        let (mut server_read, mut server_writer) = cotp_server.split().await?;

        let mut over_buffer = [0u8; 1024];
        let mut data_buffer = Vec::new();
        for _ in 1..10000 {
            rand::rng().fill_bytes(&mut over_buffer[..]);
            data_buffer.extend_from_slice(&over_buffer);
        }

        match timeout(Duration::from_millis(100), client_writer.send(&mut VecDeque::from(vec![data_buffer.to_vec()]))).await {
            Ok(_) => assert!(false, "Expected the data to be too large for the buffer."),
            Err(_) => (),
        }
        loop {
            match timeout(Duration::from_millis(100), client_writer.send(&mut VecDeque::new())).await {
                Ok(_) => break,
                Err(_) => (),
            };
            match timeout(Duration::from_millis(100), server_read.recv()).await {
                Ok(Ok(_)) => assert!(false, "Expected that all the payload was not yet send."),
                Ok(Err(e)) => return Err(e)?,
                Err(_) => (),
            }
        }
        assert_eq!(server_read.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, data_buffer.to_vec());
        match timeout(Duration::from_millis(100), server_writer.send(&mut VecDeque::from(vec![data_buffer.to_vec()]))).await {
            Ok(_) => assert!(false, "Expected the data to be too large for the buffer."),
            Err(_) => (),
        }
        loop {
            match timeout(Duration::from_millis(100), server_writer.send(&mut VecDeque::new())).await {
                Ok(_) => break,
                Err(_) => (),
            };
            match timeout(Duration::from_millis(100), client_read.recv()).await {
                Ok(_) => assert!(false, "Expected that all the payload was not yet send."),
                Err(_) => (),
            }
        }
        assert_eq!(client_read.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, data_buffer.to_vec());

        Ok(())
    }

    async fn create_cotp_connection_pair(
        calling_tsap_id: Option<Vec<u8>>,
        called_tsap_id: Option<Vec<u8>>,
        connection_parameters: CotpConnectionParameters,
    ) -> Result<(RustyCotpConnection<impl TpktReader, impl TpktWriter>, impl CotpConnection), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;

        let tpkt_listener = TcpTpktServer::listen(test_address).await?;
        let (tpkt_client, tpkt_server) = join!(TcpTpktConnection::connect(test_address), tpkt_listener.accept());

        let connect_information = CotpProtocolInformation::initiator(calling_tsap_id, called_tsap_id);

        let initiator_connection_parameters = connection_parameters.clone();
        let initiator_connect_information = connect_information.clone();
        let (cotp_initiator, cotp_acceptor) = join!(async move { RustyCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_client?, initiator_connect_information, initiator_connection_parameters).await }, async move {
            let (acceptor, remote) = RustyCotpResponder::<TcpTpktReader, TcpTpktWriter>::new(tpkt_server?, connection_parameters).await?;
            assert_eq!(remote, connect_information);
            acceptor.accept(connect_information).await
        });

        let cotp_client = cotp_initiator?;
        let cotp_server = cotp_acceptor?;

        Ok((cotp_client, cotp_server))
    }
}
