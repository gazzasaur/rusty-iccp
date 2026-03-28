#![doc = include_str!("../README.md")]

mod api;
mod parser;
mod serialiser;
mod service;

pub use crate::api::*;
pub use crate::service::*;

#[cfg(test)]
mod tests {

    use std::{
        any::Any,
        collections::VecDeque,
        io::ErrorKind,
        ops::{Deref, Range},
    };

    use anyhow::anyhow;
    use rand::RngCore;
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_txrx_sequential_payloads() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktServer::listen(test_address).await?;

        // This proves we can drop the connection after the split takes place.
        let (mut client_reader, mut client_writer, mut server_reader, mut server_writer) = {
            let client_connection = TcpTpktConnection::connect(test_address).await?;
            let server_connection = server.accept().await?;
            match (server_connection.get_protocol_infomation_list().get(0).ok_or_else(|| anyhow!("Test Failed"))?.deref() as &dyn Any).downcast_ref::<TcpTpktProtocolInformation>() {
                Some(info) => assert!(info.remote_address.to_string().starts_with("127.0.0.1:")),
                None => return Err(anyhow!("Test Failed")),
            };

            let (client_reader, client_writer) = client_connection.split().await?;
            let (server_reader, server_writer) = server_connection.split().await?;
            (client_reader, client_writer, server_reader, server_writer)
        };

        server_writer.send(&mut VecDeque::from_iter(vec![b"Hello".to_vec()])).await?;
        client_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        drop(server);

        for _ in 0..1000 {
            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"Hello"));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"Hello"));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;
        }

        // Drain connections so they can be gracefully shutdown.
        assert_eq!(server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(b"World"));
        assert_eq!(client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(b"Hello"));

        drop(server_writer);
        drop(server_reader);

        match client_reader.recv().await? {
            None => (),
            _ => return Err(anyhow!("Failed to close connection gracefully.")),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_txrx_concurrent_payloads() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktServer::listen(test_address).await?;

        let client_connection = TcpTpktConnection::connect(test_address).await?;
        let server_connection = server.accept().await?;

        match (client_connection.get_protocol_infomation_list().get(0).ok_or_else(|| anyhow!("Test Failed"))?.deref() as &dyn Any).downcast_ref::<TcpTpktProtocolInformation>() {
            Some(info) => assert!(info.remote_address.to_string().starts_with("127.0.0.1:")),
            None => return Err(anyhow!("Test Failed")),
        };
        match (server_connection.get_protocol_infomation_list().get(0).ok_or_else(|| anyhow!("Test Failed"))?.deref() as &dyn Any).downcast_ref::<TcpTpktProtocolInformation>() {
            Some(info) => assert!(info.remote_address.to_string().starts_with("127.0.0.1:")),
            None => return Err(anyhow!("Test Failed")),
        };

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(&mut VecDeque::from_iter(vec![b"Hello".to_vec()])).await?;
        server_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        drop(server);

        for _ in 0..1000 {
            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"Hello"));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"Hello"));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;
        }

        assert_eq!(client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(b"Hello"));
        assert_eq!(client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(b"World"));

        drop(client_writer);
        drop(client_reader);

        // Drain connections so they can be gracefully shutdown.
        match server_reader.recv().await? {
            None => (),
            _ => return Err(anyhow!("Failed to close connection gracefully.")),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_txrx_sequential_ungraceful_shutdown() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktServer::listen(test_address).await?;

        let client_connection = TcpTpktConnection::connect(test_address).await?;
        let server_connection = server.accept().await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(&mut VecDeque::from_iter(vec![b"Hello".to_vec()])).await?;
        client_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        drop(server);

        for _ in 0..1000 {
            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"Hello"));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"Hello"));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;
        }

        // Drain connections so they can be gracefully shutdown.
        assert_eq!(server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(b"World"));
        assert_eq!(client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(b"Hello"));

        drop(server_writer);
        drop(server_reader);

        match client_reader.recv().await? {
            None => (),
            _ => return Err(anyhow!("Failed to close connection gracefully.")),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_txrx_zero_byte_data() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktServer::listen(test_address).await?;

        let client_connection = TcpTpktConnection::connect(test_address).await?;
        let server_connection = server.accept().await?;

        drop(server);

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(&mut VecDeque::from_iter(vec![b"".to_vec()])).await?;
        client_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        for _ in 0..1000 {
            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b""));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b""));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;
        }

        // Drain connections so they can be gracefully shutdown.
        assert_eq!(server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(b"World"));
        assert_eq!(client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(b""));

        drop(server_writer);
        drop(server_reader);

        match client_reader.recv().await? {
            None => (),
            _ => return Err(anyhow!("Failed to close connection gracefully.")),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_txrx_max_byte_data() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktServer::listen(test_address).await?;

        let client_connection = TcpTpktConnection::connect(test_address).await?;
        let server_connection = server.accept().await?;

        drop(server);

        let mut buffer = [0u8; 65531];
        rand::rng().fill_bytes(&mut buffer[..]);

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(&mut VecDeque::from_iter(vec![buffer.to_vec()])).await?;
        client_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        for _ in 0..1000 {
            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(buffer));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(buffer));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;
        }

        // Drain connections so they can be gracefully shutdown.
        assert_eq!(server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(b"World"));
        assert_eq!(client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(buffer));

        drop(server_writer);
        drop(server_reader);

        match client_reader.recv().await? {
            None => (),
            _ => return Err(anyhow!("Failed to close connection gracefully.")),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_txrx_over_max_byte_data() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktServer::listen(test_address).await?;

        let client_connection = TcpTpktConnection::connect(test_address).await?;
        let server_connection = server.accept().await?;

        drop(server);

        let mut over_buffer = [0u8; 65532];
        rand::rng().fill_bytes(&mut over_buffer[..]);

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        match server_writer.send(&mut VecDeque::from_iter(vec![over_buffer.to_vec()])).await {
            Ok(_) => assert!(false, "This was expected to fail as it is over the max payload limit"),
            Err(TpktError::ProtocolError(x)) => assert_eq!(x, "TPKT user data must be less than or equal to 65531 but was 65532"),
            _ => return Err(anyhow!("Something unexpected happened")),
        };

        // Try again and lets keep going
        let mut buffer = [0u8; 65531];
        rand::rng().fill_bytes(&mut buffer[..]);
        server_writer.send(&mut VecDeque::from_iter(vec![buffer.to_vec()])).await?;
        client_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        for _ in 0..100 {
            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(buffer));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(buffer));
            server_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;

            let data = client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
            assert_eq!(data, Vec::from(b"World"));
            client_writer.send(&mut VecDeque::from(vec![data.to_vec()])).await?;
        }

        // Drain connections so they can be gracefully shutdown.
        assert_eq!(server_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(b"World"));
        assert_eq!(client_reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?, Vec::from(buffer));

        drop(server_writer);
        drop(server_reader);

        match client_reader.recv().await? {
            None => (),
            _ => return Err(anyhow!("Failed to close connection gracefully.")),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_no_open_socket() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;

        match TcpTpktConnection::connect(test_address).await {
            Ok(_) => assert!(false, "This was expected to fail as a socket was not opened."),
            Err(TpktError::IoError(x)) => assert_eq!(x.kind(), ErrorKind::ConnectionRefused),
            Err(x) => return Err(anyhow!("Something unexpected happened: {:?}", x)),
        };

        Ok(())
    }
}
