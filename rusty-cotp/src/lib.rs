pub mod api;
pub mod packet;
pub mod parser;
pub mod serialiser;
pub mod service;

#[cfg(test)]
mod tests {
    use std::{ops::Range, time::Duration};

    use rand::RngCore;
    use tokio::{join, time::timeout};
    use tracing_test::traced_test;

    use crate::{
        api::{CotpConnection, CotpReader, CotpServer, CotpService, CotpWriter},
        service::TcpCotpService,
    };

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_transfers_data() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;

        // Prove we can srop everything after the split.
        let (mut client_read, mut client_writer, mut server_read, mut server_writer) = {
            let listener = TcpCotpService::create_server(test_address).await?;
            let (client, server) = join!(TcpCotpService::connect(test_address, Default::default()), listener.accept());

            let (client_read, client_writer) = client?.split().await?;
            let (server_read, server_writer) = server?.split().await?;

            (client_read, client_writer, server_read, server_writer)
        };

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
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let listener = TcpCotpService::create_server(test_address).await?;
        let (client, server) = join!(TcpCotpService::connect(test_address, Default::default()), listener.accept());

        let (mut client_read, mut client_writer) = client?.split().await?;
        let (mut server_read, mut server_writer) = server?.split().await?;

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
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let listener = TcpCotpService::create_server(test_address).await?;
        let (client, server) = join!(TcpCotpService::connect(test_address, Default::default()), listener.accept());

        let (mut client_read, mut client_writer) = client?.split().await?;
        let (mut server_read, mut server_writer) = server?.split().await?;

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
}
