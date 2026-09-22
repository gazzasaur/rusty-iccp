use std::{collections::VecDeque, net::SocketAddr};

use anyhow::anyhow;
use der_parser::oid;
use rusty_copp::{
    CoppConnection, CoppConnectionInformation, CoppInitResult, CoppInitiator, CoppListener, CoppReader, CoppRecvResult, CoppResponder, CoppWriter, PresentationContext, PresentationContextIdentifier, PresentationContextType, PresentationDataValueList, PresentationDataValues, RustyCoppInitiatorIsoStack, RustyCoppListenerIsoStack, UserData,
};
use rusty_cosp::{CospProtocolInformation, RustyCospAcceptorIsoStack, RustyCospInitiatorIsoStack};
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

    // Pass the COSP acceptor to the COPP layer.
    let (copp_listener, copp_connection_information) = RustyCoppListenerIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cosp_acceptor).await?;

    // For the presentation layer, we will assert we know who the caller is and ensure it called us.
    assert_eq!(copp_connection_information.called_presentation_selector, Some(vec![2]));
    assert_eq!(copp_connection_information.calling_presentation_selector, Some(vec![1]));

    // Using the cosp responder, create a copp connection.
    let (copp_responder, presentation_context, user_data) = copp_listener.accept().await?;

    // Verify the context. This only supports a subset of OSI encapsulated contexts that require a context list.
    match presentation_context {
        PresentationContextType::ContextDefinitionList(presentation_contexts) => {
            assert_eq!(presentation_contexts.len(), 2);
            assert_eq!(presentation_contexts.get(0), Some(&PresentationContext { identifier: vec![1], abstract_syntax_name: oid!(1.2.3.4), transfer_syntax_name_list: vec![oid!(0.3.2.1)] }));
            assert_eq!(presentation_contexts.get(1), Some(&PresentationContext { identifier: vec![2], abstract_syntax_name: oid!(2.2.3.4), transfer_syntax_name_list: vec![oid!(1.3.2.1), oid!(2.3.2.1)] }));
        }
    }
    match user_data {
        Some(UserData::FullyEncoded(x)) => {
            assert_eq!(x, vec![PresentationDataValueList { transfer_syntax_name: None, presentation_context_identifier: vec![4, 3, 2, 1], presentation_data_values: PresentationDataValues::SingleAsn1Type(vec![0, 2, 4, 6]) }])
        }
        _ => assert!(false, "Unexpected value"),
    }

    let copp_connection = copp_responder
        .complete_connection(Some(UserData::FullyEncoded(vec![PresentationDataValueList {
            transfer_syntax_name: Some(oid!(0.4.3.2.1)),
            presentation_context_identifier: vec![0x07],
            presentation_data_values: PresentationDataValues::SingleAsn1Type(vec![0x04, 0x05]),
        }])))
        .await?;

    // Split the connection into read and write halves. This is often done for easy multi-tasking.
    let (mut copp_reader, mut copp_writer) = copp_connection.split().await?;

    // Get data from the client.
    match copp_reader.recv().await? {
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

    copp_writer
        .send(&mut VecDeque::from(vec![UserData::FullyEncoded(vec![PresentationDataValueList {
            transfer_syntax_name: Some(oid!(1.2.3.5)),
            presentation_context_identifier: vec![0x02],
            presentation_data_values: PresentationDataValues::SingleAsn1Type(vec![0x07, 0x09]),
        }])]))
        .await?;

    // In this case, the client will call finish, so we will call disconnect as per the standard.
    match copp_reader.recv().await? {
        CoppRecvResult::Finish(_) => (),

        // Normally we would just log and drop the connection instead of fail.
        x => return Err(anyhow!("Expected finish but got {}", <CoppRecvResult as Into<&'static str>>::into(x))),
    };
    // copp_writer.disconnect().await?;
    copp_writer.user_abort(Some(vec![PresentationContextIdentifier { identifier: vec![1], transfer_syntax_name: oid!(1.2.3.4) }]), None).await?;

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

    let copp_initiator = RustyCoppInitiatorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cosp_initiator, CoppConnectionInformation { calling_presentation_selector: Some(vec![1]), called_presentation_selector: Some(vec![2]) });
    let copp_connection = copp_initiator
        .initiate(
            PresentationContextType::ContextDefinitionList(vec![
                PresentationContext { identifier: vec![1], abstract_syntax_name: oid!(1.2.3.4), transfer_syntax_name_list: vec![oid!(0.3.2.1)] },
                PresentationContext { identifier: vec![2], abstract_syntax_name: oid!(2.2.3.4), transfer_syntax_name_list: vec![oid!(1.3.2.1), oid!(2.3.2.1)] },
            ]),
            Some(UserData::FullyEncoded(vec![PresentationDataValueList { transfer_syntax_name: None, presentation_context_identifier: vec![4, 3, 2, 1], presentation_data_values: PresentationDataValues::SingleAsn1Type(vec![0, 2, 4, 6]) }])),
        )
        .await?;

    let (copp_connection, user_data) = match copp_connection {
        CoppInitResult::Success(copp_connection, user_data) => (copp_connection, user_data),
        x => {
            let x = <CoppInitResult<_> as Into<&'static str>>::into(x);
            return Err(anyhow!("Unexpected payload: {x}"));
        }
    };
    assert_eq!(
        user_data,
        Some(UserData::FullyEncoded(vec![PresentationDataValueList { transfer_syntax_name: Some(oid!(0.4.3.2.1)), presentation_context_identifier: vec![7], presentation_data_values: PresentationDataValues::SingleAsn1Type(vec![4, 5]) }]))
    );

    let (mut copp_reader, mut copp_writer) = copp_connection.split().await?;

    copp_writer
        .send(&mut VecDeque::from(vec![UserData::FullyEncoded(vec![PresentationDataValueList {
            transfer_syntax_name: Some(oid!(1.2.3.4)),
            presentation_context_identifier: vec![0x01],
            presentation_data_values: PresentationDataValues::SingleAsn1Type(vec![0x06, 0x07]),
        }])]))
        .await?;

    match copp_reader.recv().await? {
        rusty_copp::CoppRecvResult::Data(user_data) => assert_eq!(
            user_data,
            UserData::FullyEncoded(vec![PresentationDataValueList {
                transfer_syntax_name: Some(oid!(1.2.3.5)),
                presentation_context_identifier: vec![0x02],
                presentation_data_values: PresentationDataValues::SingleAsn1Type(vec![0x07, 0x09]),
            }])
        ),
        _ => assert!(false, "Unexpected value"),
    };

    // We will close the connection from this side in an orderly manner.
    copp_writer.finish().await?;

    // Wait for the final disconnect
    match copp_reader.recv().await? {
        CoppRecvResult::Disconnect(_) => (),

        // Normally we would just log and drop the connection instead of fail.
        x => return Err(anyhow!("Expected disconnect but got {}", <CoppRecvResult as Into<&'static str>>::into(x))),
    }

    // The connection will be closed when it is dropped.

    Ok(())
}
