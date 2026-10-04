use tokio::select;

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
 */

#[tokio::main]
async fn main() {
    select! {
        _ = data_centre_a() => (),
        _ = data_centre_b() => (),
    }
}

async fn data_centre_a() {}

async fn data_centre_b() {}
