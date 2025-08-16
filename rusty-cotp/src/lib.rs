pub mod api;
pub mod packet;
pub mod parser;
pub mod serialiser;
pub mod service;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use std::{io, ops::Range};

    use rand::RngCore;
    use tokio::join;
    use tracing_test::traced_test;

    use crate::{
        api::{CotpConnection, CotpError, CotpReader, CotpServer, CotpService, CotpWriter},
        service::{TcpCotpConnection, TcpCotpReader, TcpCotpServer, TcpCotpService, TcpCotpWriter},
    };

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_transfers_data() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let listener = TcpCotpService::create_server(test_address).await?;
        let (client, server) = join!(TcpCotpService::connect(test_address), listener.accept());

        let (mut client_read, mut client_writer) = TcpCotpConnection::split(client?).await?;
        let (mut server_read, mut server_writer) = TcpCotpConnection::split(server?).await?;

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
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..20001)).parse()?;
        let listener = TcpCotpService::create_server(test_address).await?;
        let (client, server) = join!(TcpCotpService::connect(test_address), listener.accept());

        let (mut client_read, mut client_writer) = TcpCotpConnection::split(client?).await?;
        let (mut server_read, mut server_writer) = TcpCotpConnection::split(server?).await?;

        let mut over_buffer = [0u8; 100000];
        rand::rng().fill_bytes(&mut over_buffer[..]);

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

        Ok(())
    }
}
