pub mod api;
pub mod parser;
pub mod serialiser;
pub mod service;

pub use crate::api::*;
pub use crate::parser::*;
pub use crate::service::*;

#[cfg(test)]
mod tests {

    use std::{io::ErrorKind, ops::Range};

    use rand::RngCore;
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_txrx_sequential_payloads() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktService::create_server(test_address).await?;

        // This proves we can drop the connection after the split takes place.
        let (mut client_reader, mut client_writer, mut server_reader, mut server_writer) = {
            let client_connection = TcpTpktService::connect(test_address).await?;
            let server_connection = server.accept().await?;

            let (client_reader, client_writer) = client_connection.split().await?;
            let (server_reader, server_writer) = server_connection.split().await?;
            (client_reader, client_writer, server_reader, server_writer)
        };

        server_writer.send(b"Hello").await?;
        client_writer.send(b"World").await?;

        drop(server);

        for _ in 0..1000 {
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
        }

        // Drain connections so they can be gracefully shutdown.
        match server_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(b"World"));
            }
            _ => assert!(false, "Connection was unexpectedly closed"),
        }
        match client_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(b"Hello"));
            }
            _ => assert!(false, "Connection was unexpectedly closed"),
        }

        drop(server_writer);
        drop(server_reader);

        match client_reader.recv().await? {
            TpktRecvResult::Closed => (),
            _ => assert!(false, "Failed to close connection gracefully."),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_txrx_concurrent_payloads() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktService::create_server(test_address).await?;

        let client_connection = TcpTpktService::connect(test_address).await?;
        let server_connection = server.accept().await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(b"Hello").await?;
        server_writer.send(b"World").await?;

        drop(server);

        for _ in 0..1000 {
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => panic!("Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => panic!("Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => panic!("Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => panic!("Connection was unexpectedly closed"),
            }
        }

        match client_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(b"Hello"));
            }
            _ => panic!("Connection was unexpectedly closed"),
        }
        match client_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(b"World"));
            }
            _ => panic!("Connection was unexpectedly closed"),
        }

        drop(client_writer);
        drop(client_reader);

        // Drain connections so they can be gracefully shutdown.
        match server_reader.recv().await? {
            TpktRecvResult::Closed => (),
            _ => assert!(false, "Failed to close connection gracefully."),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_txrx_sequential_ungraceful_shutdown() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktService::create_server(test_address).await?;

        let client_connection = TcpTpktService::connect(test_address).await?;
        let server_connection = server.accept().await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(b"Hello").await?;
        client_writer.send(b"World").await?;

        drop(server);

        for _ in 0..1000 {
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
        }

        // Drain connections so they can be gracefully shutdown.
        match server_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(b"World"));
            }
            _ => assert!(false, "Connection was unexpectedly closed"),
        }
        match client_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(b"Hello"));
            }
            _ => assert!(false, "Connection was unexpectedly closed"),
        }

        drop(server_writer);
        drop(server_reader);

        match client_reader.recv().await? {
            TpktRecvResult::Closed => (),
            _ => assert!(false, "Failed to close connection gracefully."),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_txrx_zero_byte_data() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktService::create_server(test_address).await?;

        let client_connection = TcpTpktService::connect(test_address).await?;
        let server_connection = server.accept().await?;

        drop(server);

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(b"").await?;
        client_writer.send(b"World").await?;

        for _ in 0..1000 {
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b""));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b""));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
        }

        // Drain connections so they can be gracefully shutdown.
        match server_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(b"World"));
            }
            _ => assert!(false, "Connection was unexpectedly closed"),
        }
        match client_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(b""));
            }
            _ => assert!(false, "Connection was unexpectedly closed"),
        }

        drop(server_writer);
        drop(server_reader);

        match client_reader.recv().await? {
            TpktRecvResult::Closed => (),
            _ => assert!(false, "Failed to close connection gracefully."),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_txrx_max_byte_data() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktService::create_server(test_address).await?;

        let client_connection = TcpTpktService::connect(test_address).await?;
        let server_connection = server.accept().await?;

        drop(server);

        let mut buffer = [0u8; 65531];
        rand::rng().fill_bytes(&mut buffer[..]);

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(&buffer).await?;
        client_writer.send(b"World").await?;

        for _ in 0..1000 {
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(buffer));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(buffer));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
        }

        // Drain connections so they can be gracefully shutdown.
        match server_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(b"World"));
            }
            _ => assert!(false, "Connection was unexpectedly closed"),
        }
        match client_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(buffer));
            }
            _ => assert!(false, "Connection was unexpectedly closed"),
        }

        drop(server_writer);
        drop(server_reader);

        match client_reader.recv().await? {
            TpktRecvResult::Closed => (),
            _ => assert!(false, "Failed to close connection gracefully."),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_txrx_over_max_byte_data() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpTpktService::create_server(test_address).await?;

        let client_connection = TcpTpktService::connect(test_address).await?;
        let server_connection = server.accept().await?;

        drop(server);

        let mut over_buffer = [0u8; 65532];
        rand::rng().fill_bytes(&mut over_buffer[..]);

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        match server_writer.send(&over_buffer).await {
            Ok(_) => assert!(false, "This was expected to fail as it is over the max payload limit"),
            Err(TpktError::ProtocolError(x)) => assert_eq!(x, "TPKT user data must be less than or equal to 65531 but was 65532"),
            _ => assert!(false, "Something unexpected happened"),
        };

        // Try again and lets keep going
        let mut buffer = [0u8; 65531];
        rand::rng().fill_bytes(&mut buffer[..]);
        server_writer.send(&buffer).await?;
        client_writer.send(b"World").await?;

        for _ in 0..100 {
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(buffer));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(buffer));
                    server_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(x.as_slice()).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
        }

        // Drain connections so they can be gracefully shutdown.
        match server_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(b"World"));
            }
            _ => assert!(false, "Connection was unexpectedly closed"),
        }
        match client_reader.recv().await? {
            TpktRecvResult::Data(x) => {
                assert_eq!(x, Vec::from(buffer));
            }
            _ => assert!(false, "Connection was unexpectedly closed"),
        }

        drop(server_writer);
        drop(server_reader);

        match client_reader.recv().await? {
            TpktRecvResult::Closed => (),
            _ => assert!(false, "Failed to close connection gracefully."),
        };

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_no_open_socket() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;

        match TcpTpktService::connect(test_address).await {
            Ok(_) => assert!(false, "This was expected to fail as a socket was not opened."),
            Err(TpktError::IoError(x)) => assert_eq!(x.kind(), ErrorKind::ConnectionRefused),
            Err(x) => assert!(false, "Something unexpected happened: {:?}", x),
        };

        Ok(())
    }
}
