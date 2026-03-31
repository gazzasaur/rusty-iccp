# Rusty TPKT
A pure rust implementation of TPKT over TCP.

TPKT is a glue protocol between the ISO standard protocols and TCP (an IETF protocol).

This standard is known by many names:
* ITOT
* TPKT
* RFC 2126

This package is intended to be used in conjunction with a higher level protocol. For example:
* [rusty-mms-service](https://crates.io/crates/rusty-mms-service)

## Using this Library

#### Static Dispatch

This library uses static dispatch. TPKT is a very small slice in a large protocol stack. It is called very often. Static dispatch removes vtable lookups reducing call overhead. Static dispatch also allows the types to be resolved at compile time, giving the compiler greater scope to perform optimisations. This also makes it ideal for use in embedded devices.

The trade of is that static dispatch may be more difficult to work with in complex applications. The rusty-mms-service provides one example of going from a static dispatch to a dynamic dispatch environment without degrading performance.

#### Async and STD

This library uses async rust and std components. If using this in embedded systems, FreeRTOS may be required to provide and adaption layer between embedded hardware and this library.

#### Cancel Safety

Senc and Recv operations are cancel safe as long as the caller does not drop their buffer after cancel if it still contains data. It is safe to call Send and Recv anytime after cancellation.

## Conformance
This packet implements Class 0 functionality.

This allows most ISO protcols to be operated over this implementation of TPKT, normally using the 'kernel only' or 'core features' of higher layer protocols. Please refer to the conformance statement of the standard you are using to ensure all the features you require are offered given the comformance of this implementation.

## References
* [RFC 2126](https://datatracker.ietf.org/doc/html/rfc2126)

## Examples

Examples may be found in the [examples](https://github.com/gazzasaur/rusty-iccp/blob/main/rusty-tpkt/examples) directory. Basic useage is shown below.

```
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
    let connection = server.accept().await?;

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
```
