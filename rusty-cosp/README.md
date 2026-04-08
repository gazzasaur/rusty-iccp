# Rusty COSP
A pure rust implementation of COSP over COTP.

COSP is a glue protocol between the ISO standard protocols and byte streams (TCP/Serial links). This implementation covers kernel functionality of COSP which limits its use to lossless connections like TCP.

This standard is known by:
* COSP
* X.225
* ISO/IEC 8327-1

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
This packet implements kernel functionality.

This allows most ISO protcols to be operated over this implementation, normally using the 'kernel only' or 'core features' of higher layer protocols. Please refer to the conformance statement of the standard you are using to ensure all the features you require are offered given the comformance of this implementation.

## References
* [X.225](https://www.itu.int/rec/T-REC-X.225/)

## Examples

Examples may be found in the [examples](https://github.com/gazzasaur/rusty-iccp/blob/main/rusty-cosp/examples) directory. Basic useage is shown below.

```
use std::{collections::VecDeque, net::SocketAddr};

use anyhow::anyhow;
use rusty_cosp::CospReader;
use rusty_cosp::{CospAcceptor, CospConnection, CospInitiator, CospProtocolInformation, CospRecvResult, CospResponder, CospWriter, RustyCospAcceptorIsoStack, RustyCospInitiatorIsoStack};
use rusty_cotp::{CotpProtocolInformation, CotpResponder, RustyCotpConnection, RustyCotpResponder};
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

    // Upgrade the connection to a COSP connection. This will allow us to inspect the COSP protocol information.
    let (cosp_acceptor, cosp_protocol_information) = RustyCospAcceptorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cotp_connection, Default::default()).await?;

    // We will assert we know who the caller is and ensure it called us.
    assert_eq!(cosp_protocol_information.called_session_selector(), Some(&vec![2]));
    assert_eq!(cosp_protocol_information.calling_session_selector(), Some(&vec![1]));

    // We accept the COSP connection and receive any higher level protocol connection data.
    // COSP has many PDUs that allow for higher level protocols to inject data.
    let (cosp_responder, connect_data) = cosp_acceptor.accept().await?;

    // For example purposes, we will ensure this matches.
    assert_eq!(connect_data, Some(b"Initiator Higher Level Protocol Data".to_vec()));

    // We will completed the connection, which also allows us to send higher level protocol data back.
    let cosp_connection = cosp_responder.complete_connection(Some(b"Responder Higher Level Protocol Data".to_vec())).await?;

    // Split the connection into read and write halves. This is often done for easy multi-tasking.
    let (mut reader, mut writer) = cosp_connection.split().await?;

    // Get data from the client.
    let data = match reader.recv().await? {
        CospRecvResult::Data(data) => data,
        x => return Err(anyhow!("Expected data but got {}", <CospRecvResult as Into<&'static str>>::into(x))),
    };
    assert_eq!(data, "Hello from the client!".as_bytes().to_vec());

    // Send data to the client. This uses a buffer to ensure the operation is cancel safe. Store this buffer on your object an reuse it.
    let mut data = VecDeque::new();
    data.push_back("Hello from the server!".as_bytes().to_vec());
    while data.len() > 0 {
        writer.send(&mut data).await?;
    }

    // In this case, the client will call finish, so we will call disconnect as per the standard.
    match reader.recv().await? {
        CospRecvResult::Finish(_) => (),
        x => return Err(anyhow!("Expected finish but got {}", <CospRecvResult as Into<&'static str>>::into(x))),
    };
    writer.disconnect(None).await?;

    // The connection will be closed when it is dropped.

    Ok(())
}

async fn example_client(address: SocketAddr) -> Result<(), anyhow::Error> {
    // Create the client connection. This will start a connection.
    let tpkt_connection = TcpTpktConnection::connect(address).await?;

    // Initiate the COTP connection. This will be established before the COSP connection uses it.
    let cotp_connection = RustyCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_connection, CotpProtocolInformation::initiator(Some(vec![1]), Some(vec![2])), Default::default()).await?;

    // Upgrade the connection to a COSP connection. Here will will signal our identity and the expected identity of the remote side.
    let cosp_initiator = RustyCospInitiatorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cotp_connection, CospProtocolInformation::new(Some(vec![1]), Some(vec![2])), Default::default()).await?;

    // Initial the COSP connection. This performs the actual singalling. In this case we will get higher layer protcol data back.
    let (cosp_connection, accept_data) = cosp_initiator.initiate(Some(b"Initiator Higher Level Protocol Data".to_vec())).await?;

    // For example purposes, we will ensure this matches.
    assert_eq!(accept_data, Some(b"Responder Higher Level Protocol Data".to_vec()));

    // Split the connection into read and write halves. This is often done for easy multi-tasking.
    let (mut reader, mut writer) = cosp_connection.split().await?;

    // Send data to the server. This uses a buffer to ensure the operation is cancel safe. Store this buffer on your object an reuse it.
    let mut data = VecDeque::new();
    data.push_back("Hello from the client!".as_bytes().to_vec());
    while data.len() > 0 {
        writer.send(&mut data).await?;
    }

    // Get data from the server.
    let data = match reader.recv().await? {
        CospRecvResult::Data(data) => data,
        x => return Err(anyhow!("Expected data but got {}", <CospRecvResult as Into<&'static str>>::into(x))),
    };
    assert_eq!(data, "Hello from the server!".as_bytes().to_vec());

    // We will close the connection from this side in an orderly manner.
    writer.finish(None).await?;

    // The connection will be closed when it is dropped.

    Ok(())
}
```
