use std::{collections::VecDeque, net::SocketAddr};

use anyhow::anyhow;
use der_parser::oid;
use rusty_copp::{
    CoppConnection, CoppConnectionInformation, CoppInitResult, CoppInitiator, CoppReader, CoppResponder, CoppWriter, PresentationContextType, PresentationDataValueList, PresentationDataValues, RustyCoppInitiatorIsoStack,
    RustyCoppResponder, UserData,
};
use rusty_cosp::{CospAcceptor, CospProtocolInformation, RustyCospAcceptorIsoStack, RustyCospInitiatorIsoStack};
use rusty_cosp::{RustyCospReaderIsoStack, RustyCospWriterIsoStack};
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

    // Using the cosp responder, create a copp connection.
    let copp_responder = RustyCoppResponder::<_, RustyCospReaderIsoStack<TcpTpktReader>, RustyCospWriterIsoStack<TcpTpktWriter>>::new(cosp_responder, CoppConnectionInformation::default());
    let copp_connection = copp_responder.complete_connection(Some(UserData::FullyEncoded(vec![]))).await?;

    // Split the connection into read and write halves. This is often done for easy multi-tasking.
    let (mut copp_reader, copp_writer) = copp_connection.split().await?;

    // Get data from the client.
    let data = match copp_reader.recv().await? {
        rusty_copp::CoppRecvResult::Data(user_data) => assert_eq!(
            user_data,
            UserData::FullyEncoded(vec![PresentationDataValueList {
                transfer_syntax_name: Some(oid!(1.2.3.4)),
                presentation_context_identifier: vec![0x01],
                presentation_data_values: PresentationDataValues::SingleAsn1Type(vec![0x06, 0x07]),
            }])
        ),
        _ => assert!(false, "Unexpected value"),
    };

    // assert_eq!(data, "Hello from the client!".as_bytes().to_vec());

    // // Send data to the client. This uses a buffer to ensure the operation is cancel safe. Store this buffer on your object an reuse it.
    // let mut data = VecDeque::new();
    // data.push_back("Hello from the server!".as_bytes().to_vec());
    // while data.len() > 0 {
    //     writer.send(&mut data).await?;
    // }

    // // In this case, the client will call finish, so we will call disconnect as per the standard.
    // match reader.recv().await? {
    //     CospRecvResult::Finish(_) => (),
    //     x => return Err(anyhow!("Expected finish but got {}", <CospRecvResult as Into<&'static str>>::into(x))),
    // };
    // writer.disconnect(None).await?;

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

    let copp_initiator = RustyCoppInitiatorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cosp_initiator, CoppConnectionInformation::default());
    let copp_connection = copp_initiator.initiate(PresentationContextType::ContextDefinitionList(vec![]), Some(UserData::FullyEncoded(vec![]))).await?;

    let (copp_connection, user_data) = match copp_connection {
        CoppInitResult::Success(copp_connection, user_data) => (copp_connection, user_data),
        x => {
            let x = <CoppInitResult<_> as Into<&'static str>>::into(x);
            return Err(anyhow!("Unexpected payload: {x}"));
        }
    };

    let (mut copp_reader, mut copp_writer) = copp_connection.split().await?;
    copp_writer
        .send(&mut VecDeque::from(vec![UserData::FullyEncoded(vec![PresentationDataValueList {
            transfer_syntax_name: Some(oid!(1.2.3.4)),
            presentation_context_identifier: vec![0x01],
            presentation_data_values: PresentationDataValues::SingleAsn1Type(vec![0x06, 0x07]),
        }])]))
        .await?;

    copp_reader.recv().await?;

    // // For example purposes, we will ensure this matches.
    // assert_eq!(accept_data, Some(b"Responder Higher Level Protocol Data".to_vec()));

    // // Split the connection into read and write halves. This is often done for easy multi-tasking.
    // let (mut reader, mut writer) = cosp_connection.split().await?;

    // // Send data to the server. This uses a buffer to ensure the operation is cancel safe. Store this buffer on your object an reuse it.
    // let mut data = VecDeque::new();
    // data.push_back("Hello from the client!".as_bytes().to_vec());
    // while data.len() > 0 {
    //     writer.send(&mut data).await?;
    // }

    // // Get data from the server.
    // let data = match reader.recv().await? {
    //     CospRecvResult::Data(data) => data,
    //     x => return Err(anyhow!("Expected data but got {}", <CospRecvResult as Into<&'static str>>::into(x))),
    // };
    // assert_eq!(data, "Hello from the server!".as_bytes().to_vec());

    // // We will close the connection from this side in an orderly manner.
    // writer.finish(None).await?;

    // The connection will be closed when it is dropped.

    Ok(())
}
