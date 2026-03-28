mod api;
mod parser;
mod serialiser;
mod service;

pub use crate::api::*;
pub use crate::service::*;

#[cfg(test)]
mod tests {

    use std::{collections::VecDeque, io::ErrorKind, net::SocketAddr, ops::Range};

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
            let (server_connection, remote_host) = server.accept().await?;
            assert!(remote_host.to_string().starts_with("127.0.0.1:"));

            let (client_reader, client_writer) = client_connection.split().await?;
            let (server_reader, server_writer) = server_connection.split().await?;
            (client_reader, client_writer, server_reader, server_writer)
        };

        server_writer.send(&mut VecDeque::from_iter(vec![b"Hello".to_vec()])).await?;
        client_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        drop(server);

        for _ in 0..1000 {
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(&mut VecDeque::from(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    client_writer.send(&mut VecDeque::from(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    server_writer.send(&mut VecDeque::from(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(&mut VecDeque::from(vec![x.to_vec()])).await?;
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
        let server = TcpTpktServer::listen(test_address).await?;

        let client_connection = TcpTpktConnection::connect(test_address).await?;
        let (server_connection, remote_host) = server.accept().await?;
        assert!(remote_host.to_string().starts_with("127.0.0.1:"));

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(&mut VecDeque::from_iter(vec![b"Hello".to_vec()])).await?;
        server_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        drop(server);

        for _ in 0..1000 {
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    client_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => panic!("Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => panic!("Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    server_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => panic!("Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
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
        let server = TcpTpktServer::listen(test_address).await?;

        let client_connection = TcpTpktConnection::connect(test_address).await?;
        let (server_connection, remote_host) = server.accept().await?;
        assert!(remote_host.to_string().starts_with("127.0.0.1:"));

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(&mut VecDeque::from_iter(vec![b"Hello".to_vec()])).await?;
        client_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        drop(server);

        for _ in 0..1000 {
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    client_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"Hello"));
                    server_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
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
        let server = TcpTpktServer::listen(test_address).await?;

        let client_connection = TcpTpktConnection::connect(test_address).await?;
        let (server_connection, remote_host) = server.accept().await?;
        assert!(remote_host.to_string().starts_with("127.0.0.1:"));

        drop(server);

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(&mut VecDeque::from_iter(vec![b"".to_vec()])).await?;
        client_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        for _ in 0..1000 {
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b""));
                    client_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b""));
                    server_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
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
        let server = TcpTpktServer::listen(test_address).await?;

        let client_connection = TcpTpktConnection::connect(test_address).await?;
        let (server_connection, remote_host) = server.accept().await?;
        assert!(remote_host.to_string().starts_with("127.0.0.1:"));

        drop(server);

        let mut buffer = [0u8; 65531];
        rand::rng().fill_bytes(&mut buffer[..]);

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        server_writer.send(&mut VecDeque::from_iter(vec![buffer.to_vec()])).await?;
        client_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        for _ in 0..1000 {
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(buffer));
                    client_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(buffer));
                    server_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
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
        let server = TcpTpktServer::listen(test_address).await?;

        let client_connection = TcpTpktConnection::connect(test_address).await?;
        let (server_connection, remote_host) = server.accept().await?;
        assert!(remote_host.to_string().starts_with("127.0.0.1:"));

        drop(server);

        let mut over_buffer = [0u8; 65532];
        rand::rng().fill_bytes(&mut over_buffer[..]);

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        match server_writer.send(&mut VecDeque::from_iter(vec![over_buffer.to_vec()])).await {
            Ok(_) => assert!(false, "This was expected to fail as it is over the max payload limit"),
            Err(TpktError::ProtocolError(x)) => assert_eq!(x, "TPKT user data must be less than or equal to 65531 but was 65532"),
            _ => assert!(false, "Something unexpected happened"),
        };

        // Try again and lets keep going
        let mut buffer = [0u8; 65531];
        rand::rng().fill_bytes(&mut buffer[..]);
        server_writer.send(&mut VecDeque::from_iter(vec![buffer.to_vec()])).await?;
        client_writer.send(&mut VecDeque::from_iter(vec![b"World".to_vec()])).await?;

        for _ in 0..100 {
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    server_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(buffer));
                    client_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match server_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(buffer));
                    server_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
                }
                _ => assert!(false, "Connection was unexpectedly closed"),
            }
            match client_reader.recv().await? {
                TpktRecvResult::Data(x) => {
                    assert_eq!(x, Vec::from(b"World"));
                    client_writer.send(&mut VecDeque::from_iter(vec![x.to_vec()])).await?;
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

        match TcpTpktConnection::connect(test_address).await {
            Ok(_) => assert!(false, "This was expected to fail as a socket was not opened."),
            Err(TpktError::IoError(x)) => assert_eq!(x.kind(), ErrorKind::ConnectionRefused),
            Err(x) => assert!(false, "Something unexpected happened: {:?}", x),
        };

        Ok(())
    }

    // The code below is being used as an example.

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    #[traced_test]
    async fn main() -> Result<(), anyhow::Error> {
        let test_address = "127.0.0.1:12345".parse()?;

        // Start the server first so it can open the port. We are using spawn so it starts running immediately.
        let server_connect_task = tokio::task::spawn(example_server(test_address));
        let client_connect_task = tokio::task::spawn(example_client(test_address));

        // Check for errors.
        client_connect_task.await??;
        server_connect_task.await??;

        Ok(())
    }

    async fn example_server(address: SocketAddr) -> Result<(), anyhow::Error> {
        // Create the server. It will start listening on the port.
        let server = TcpTpktServer::listen(address.clone()).await?;

        // Accept an incoming connection. This can be called in a loop to keep accepting connections.
        let (connection, _) = server.accept().await?;

        // Split the connection into read and write halves. This is often done for easy multi-tasking.
        let (mut reader, mut writer) = connection.split().await?;

        // Get data from the client.
        let data = match reader.recv().await? {
            TpktRecvResult::Closed => return Err(anyhow!("Connection Closed")),
            TpktRecvResult::Data(data) => data,
        };
        assert_eq!(data, "Hello from the client!".as_bytes().to_vec());

        // Send data to the client. This uses a buffer to ensure the operation is cancel safe. Store this buffer on your object an reuse it.
        let mut data = VecDeque::new();
        data.push_back("Hello from the server!".as_bytes().to_vec());
        while data.len() > 0 {
            writer.send(&mut data).await?;
        }

        // The connection will be closed when it is dropped.

        Ok(())
    }

    async fn example_client(address: SocketAddr) -> Result<(), anyhow::Error> {
        // Create the client connection. This will start a connection.
        let connection = TcpTpktConnection::connect(address).await?;

        // Split the connection into read and write halves. This is often done for easy multi-tasking.
        let (mut reader, mut writer) = connection.split().await?;

        // Send data to the server. This uses a buffer to ensure the operation is cancel safe. Store this buffer on your object an reuse it.
        let mut data = VecDeque::new();
        data.push_back("Hello from the client!".as_bytes().to_vec());
        while data.len() > 0 {
            writer.send(&mut data).await?;
        }

        // Get data from the server.
        let data = match reader.recv().await? {
            TpktRecvResult::Closed => return Err(anyhow!("Connection Closed")),
            TpktRecvResult::Data(data) => data,
        };
        assert_eq!(data, "Hello from the server!".as_bytes().to_vec());

        // The connection will be closed when it is dropped.

        Ok(())
    }
}
