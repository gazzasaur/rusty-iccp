use std::{collections::VecDeque, net::SocketAddr};

use anyhow::anyhow;
use rusty_tpkt::{TcpTpktConnection, TcpTpktServer, TpktConnection, TpktReader, TpktWriter};

#[tokio::main]
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
    let data = reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
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
    let data = reader.recv().await?.ok_or_else(|| anyhow!("Connection Closed"))?;
    assert_eq!(data, "Hello from the server!".as_bytes().to_vec());

    // The connection will be closed when it is dropped.

    Ok(())
}
