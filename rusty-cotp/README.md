# Rusty COTP
A pure rust implementation of COTP over TPKT.

COTP is a glue protocol between the ISO standard protocols and byte streams (TCP/Serial links). This implementation is Class 0 which limits its use to lossless connections like TCP.

This standard is known by:
* COTP
* X.224
* RFC 905
* ISO 8073

This package is intended to be used in conjunction with a higher level protocol. For example:
* [rusty-mms-service](https://crates.io/crates/rusty-mms-service)

## Using this Library

#### Static Dispatch

This library uses static dispatch. This protocol is a very small slice in a large protocol stack. It is called very often. Static dispatch removes vtable lookups reducing call overhead. Static dispatch also allows the types to be resolved at compile time, giving the compiler greater scope to perform optimisations. This also makes it ideal for use in embedded devices.

The trade of is that static dispatch may be more difficult to work with in complex applications. The rusty-mms-service provides one example of going from a static dispatch to a dynamic dispatch environment without degrading performance.

#### Async and STD

This library uses async rust and std components. If using this in embedded systems, FreeRTOS may be required to provide and adaption layer between embedded hardware and this library.

#### Cancel Safety

Send and Recv operations are cancel safe as long as the caller does not drop their buffer after cancel if it still contains data. It is safe to call Send and Recv anytime after cancellation.

## Conformance
This packet implements Class 0 functionality.

This allows most ISO protcols to be operated over this implementation, normally using the 'kernel only' or 'core features' of higher layer protocols. Please refer to the conformance statement of the standard you are using to ensure all the features you require are offered given the comformance of this implementation.

## References
* [RFC 905](https://datatracker.ietf.org/doc/html/rfc905)
* [X.224](https://www.itu.int/rec/T-REC-X.224/)

## Examples

Examples may be found in the [examples](https://github.com/gazzasaur/rusty-iccp/blob/main/rusty-cotp/examples) directory. Basic useage is shown below.

```
use std::{collections::VecDeque, net::SocketAddr};

use anyhow::anyhow;
use rusty_cotp::{CotpConnection, CotpConnectionParameters, CotpProtocolInformation, CotpReader, CotpResponder, CotpWriter, RustyCotpResponder, RustyCotpConnection};
use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};

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
    let tpkt_connection = server.accept().await?;

    // Upgrade the TPKT connection to a COTP connection.
    let (cotp_acceptor, incoming_propertites) = RustyCotpResponder::<TcpTpktReader, TcpTpktWriter>::new(tpkt_connection, Default::default()).await?;

    // If we are okay with the incoming connection attributes, like TSAP id, we will accept the connection.
    let cotp_connection = cotp_acceptor.accept(incoming_propertites.responder()).await?;

    // Split the connection into read and write halves. This is often done for easy multi-tasking.
    let (mut reader, mut writer) = cotp_connection.split().await?;

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
    let tpkt_connection = TcpTpktConnection::connect(address).await?;

    let cotp_connection = RustyCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_connection, CotpProtocolInformation::initiator(Some(vec![1]), Some(vec![2])), CotpConnectionParameters { ..Default::default() }).await?;

    // Split the connection into read and write halves. This is often done for easy multi-tasking.
    let (mut reader, mut writer) = cotp_connection.split().await?;

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
