use std::{
    sync::Arc,
    time::Duration,
};

use der_parser::oid;
use rusty_mms::{MmsListener, MmsReader, MmsWriter};

use rusty_acse::RustyOsiSingleValueAcseAcceptorIsoStack;
use rusty_copp::RustyCoppAcceptorIsoStack;
use rusty_cosp::RustyCospAcceptorIsoStack;
use rusty_cotp::{CotpResponder, RustyCotpResponder};
use rusty_mms::{RustyMmsAcceptorIsoStack, RustyMmsReaderIsoStack, RustyMmsWriterIsoStack};
use rusty_mms_service::{MmsServiceConnectionIdentityParameters, MmsServiceConnectionParameters, RustyTcpMmsServiceAssociation, create_mms_service_client};
use rusty_tpkt::{TcpTpktReader, TcpTpktServer, TcpTpktWriter, TpktConnection};
use tokio::{
    join, sync::{
        Mutex, watch::{Receiver, Sender},
    },
};
use tracing::error;

pub fn control_centre_a_identity() -> MmsServiceConnectionIdentityParameters {
    MmsServiceConnectionIdentityParameters { tsap_id: Some(vec![1]), session_selector: Some(vec![1]), presentation_selector: Some(vec![1]), ap_title: Some(oid!(1.2.3.1)), ae_qualifier: Some(vec![1]), ..Default::default() }
}

pub fn control_centre_b_identity() -> MmsServiceConnectionIdentityParameters {
    MmsServiceConnectionIdentityParameters { tsap_id: Some(vec![1]), session_selector: Some(vec![1]), presentation_selector: Some(vec![1]), ap_title: Some(oid!(1.2.3.1)), ae_qualifier: Some(vec![1]), ..Default::default() }
}

/**
 * This scenario demonstrates how two control centres may share datapoints between each other.
 *
 * But first some terms.
 *
 * An ICCP Client is a control centre that will request data points from the server control centre.
 * The ICCP client essentially subscribes to data points.
 * The ICCP client may also control server devices or write values on the server.
 * This does not correspond one-to-one with a TCP client (see Initiator/Caller below).
 *
 * An ICCP Server is a control centre that will serve points requested by the client.
 * This does not correlate one-to-one with the TCP server (see Responder/Called below).
 *
 * The Caller (or Initiator) is the side that initiates the underlying MMS Connection including TCP socket.
 * This side will always act as an ICCP Client but may also act as an ICCP Server by negotiation.
 * This stack only currently supports the Initiator acting as an ICCP Client.
 *
 * The Called side is the side acting as an MMS Responder including listeneing on the TCP Server socket.
 * The term Called is preferred as, in the context of MMS, the responder refers to the side responding to a request, which can be the client or server.
 *
 * For completeness, the standards that MMS is built map initiator and responder one-to-one to TCP Client and Server respectively. Yeah, some of this stuff is just like that.
 *
 * Sometimes I have used the terms interchangeably. This is wrong and I will tighten it up where I see it.
 *
 * To the fun stuff.
 *
 * 1. Each control centre acts as a client and a server. As this stack does not support dual use associations (client and server on the same TCP/MMS connection), we need to create a connection in either direction.
 * 2. Then we create some transfer sets, which is essentially just subscribing to changes in data.
 * 3. Profit.
 *
 * Many stacks need to be restarted to make changes. This example will be as dynamic as possible.
 * ICCP links are usually critical and stopping and entire server to make configuration changes is a bit silly IMHO.
 */

struct IccpAssocation {
    pub id: String,
    pub terminator: Sender<()>,

    pub calling: Arc<MmsServiceConnectionIdentityParameters>,
    pub called: Arc<MmsServiceConnectionIdentityParameters>,

    // Easy way to allow anyone using an association to clean-up when it is dropped.
    _terminate: Receiver<()>,
}

#[tokio::main]
async fn main() {
    join!(data_centre_a(), data_centre_b());
}

async fn data_centre_a() {
    try_data_centre_a().await.err().iter().for_each(|e| println!("{e:?}"));
}

async fn try_data_centre_a() -> Result<(), anyhow::Error> {
    // let associations = Arc::new(Mutex::new(Vec::new()));

    // Normally 102, but to run wihtout perms, using 8102.
    // let server_handle = tokio::task::spawn(mms_server_worker("0.0.0.0".into(), 8102, associations));

    // Give the server time to start
    tokio::time::sleep(Duration::from_secs(1)).await;

    let target_address = "127.0.0.1:8103".parse()?;
    let mms_clinet = create_mms_service_client(
        target_address,
        MmsServiceConnectionParameters {
            local_detail_calling: Some(1 * 1024 * 1024), // Used as Max MMS Payload Size. This is required by most stacks.
            calling: control_centre_a_identity(),
            called: control_centre_b_identity(),
            ..Default::default()
        },
    )
    .await?;

    // mms_clinet.

    Ok(())
}

async fn data_centre_b() -> Result<(), anyhow::Error> {
    let associations = Arc::new(Mutex::new(Vec::new()));

    mms_server_worker("0.0.0.0".into(), 8103, associations).await?;

    Ok(())
}

/**
 * This is the more interesting part of what we are doing here. An MMS connection has a few distinct layers of handshaking.
 *
 * 1. TCP Connection - We accept a socket, this creates a TCP connection.
 * 2. COTP Connection - This is a request response handshake.
 * 3. MMS Connection - This packages the negotiation for COSP, COPP, ACSE and MMS in a single request.
 * 4. ICCP Negotiation - To check the ICCP version, supported features and bilateral agreement.
 *
 * Each protocol has their own form of addressing (except TPKT, this is just for framing/packetising the TCP stream whichh the ISO protocols rely on).
 * 1. TCP Port - We usually do not care about the source port. This can be ephermaral.
 * 2. COTP - This has a source and destination TSAP. These are optional, but we will make both of these mandatory in this implementation. This is a safe bet.
 * 3. COSP - This has a source and destination SSAP. These are also optional, but we will make both of these mandatory in this implementation. This is a safe bet.
 * 4. COPP - This has a source and destination PSAP. These are also optional, but we will make both of these mandatory in this implementation. This is a safe bet.
 * 5. ACSE - This has a bunch of stuff. Most of the time we will only care about AE Title which is a combination of AP Title and AE Qualifier. If you do not know what these are, all good, just magic numbers.
 * 6. MMS - This relies on the lower layers for selection (identifying the caller). THIS IS NOT SECURITY. This is selection and the standards only refer to this as selection, NOT AUTHENTICATION. This stack will support TLS for Authentication.
 * 7. ICCP - Again, relies on lower layers.
 */
async fn mms_server_worker(listener_address: String, listener_port: u16, associations: Arc<Mutex<Vec<IccpAssocation>>>) -> Result<(), anyhow::Error> {
    let listener_address = format!("{listener_address}:{listener_port}").parse()?;

    // Start by listening on the TCP port. This is bundled with TPKT.
    let tpkt_listener = TcpTpktServer::listen(listener_address).await?;

    loop {
        // Process connections as they arrive.
        let tpkt_connection = tpkt_listener.accept().await?;
        tokio::task::spawn(async move { mms_server_worker_acceptor(tpkt_connection).await.err().iter().for_each(|e| println!("{e:?}")) });
    }
}

// To avoid tying up the accept loop for the multi-stage handshake, we will use a separate task.
async fn mms_server_worker_acceptor(tpkt_connection: impl TpktConnection) -> Result<RustyTcpMmsServiceAssociation<impl MmsReader, impl MmsWriter>, anyhow::Error> {
    // This is one possible implementation.
    //
    // COTP is negotiated before anything else. This requires a request and response payload to be sent between hosts.
    // COSP, COPP, ACSE and MMS are then processed together in the same payload.
    //
    // So to get the COTP part out of the way first.
    // It mirrors the TSAP address provided by the caller (if any). This allows the first part of the handshake to complete.
    // Then we can inspect everything up to the MMS layer before replying.

    let (cotp_responder, cotp_initiator_info) = RustyCotpResponder::<TcpTpktReader, TcpTpktWriter>::new(tpkt_connection, Default::default()).await?;
    let cotp_connection = cotp_responder.accept(cotp_initiator_info.responder()).await?;

    // We have now responded to the COTP request. The next COTP payload should not contain the COSP to MMS connection information.

    // We accept the next COTP payload an assume it is a COSP reqeust. If not, this will throw an error.
    let (cosp_acceptor, _) = RustyCospAcceptorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cotp_connection, Default::default()).await?;

    // COPP is next
    let (copp_acceptor, _) = RustyCoppAcceptorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(cosp_acceptor).await?;

    // Then ACSE
    let (acse_acceptor, _) = RustyOsiSingleValueAcseAcceptorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(copp_acceptor).await?;
    acse_acceptor.set_response(response);

    // Then MMS. This is a low level MMS Api. We will wrap this in a higher level one.
    let rusty_mms_listener = RustyMmsAcceptorIsoStack::<TcpTpktReader, TcpTpktWriter>::new(acse_acceptor).await?;

    // You can check the proposed MMS parameters here. This is currently not restricted, but will be in a later version.

    let mms_responder = rusty_mms_listener.responder().await?;
    Ok(RustyTcpMmsServiceAssociation::<RustyMmsReaderIsoStack<TcpTpktReader>, RustyMmsWriterIsoStack<TcpTpktWriter>>::accept(mms_responder).await?)
}
