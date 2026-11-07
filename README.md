# Rusty ICCP
An ICCP stack built in rust.

## API Choices.

All send and receive operations are asynchronous. This makes it feel more natural to manage several connections and states at a time.
This is no longer a limitation in microprocessor implementations.

The lower layers use impl traits which can be difficult to work with but avoids dyn lookups. This call staack is deep, static dispatch (via impl Traits) saves a lot of lookups.
The upper layers use dynamic dispatch as it is generally easier to work with and, given the concurrency offered in the protocols, makes it very easy to manage multiple clients for the same association.

COSP, COPP, ACSE and MMS require data transmission and active decision making during the handshaking process. For this reason, the process is split into several areas.

Initiator (Calling/Caller):
* Initiator
  * The initiator is used to send the initial handshake and receive the response.
  * Key parameters are passed during construction, like the caller and called addressed.
  * This is then passed to the higher layer protocol to complete the handshake.

Responder (Called):
* Acceptor
  * The acceptor will receive the initial handshake during construction and return key connection information to the API caller. The host may reject the handshake which will consume the acceptor.
  * If the connection details are okay, the host will pass the acceptor to the higher layer protocol.
  * The higher layer protocol will convert the acceptor to a responder. This will consume the acceptor and also return the connect data received during the handshake.
* Responder
  * If the connect data from the consumed acceptor was successfully parsed and processed, the higher level protocol will complete the connection from the responder converting it into a connection. Otherwise it will reject the connection consuming the responder.

## Implementation Decisions
Using async rust as it is much easier for IO bound operations.

This implementation binds the networking stack to TCP Sockets. If a session is disconnected at the ICCP/MMS/Presentation/Session layer, all the lower layers will be disconnected.

### Protocol Handling

Protocol errors are bubbled up to the higher layers and eventually to the application layer.
This is slightly against the state machine for some protocols but allows the reader and writers to be cleanly split, offering better performance at the cost of a User Abort vs a Provider Abort on failure cases. Not a meaningful change.
If a protocol error is received that requires the connection to be closed, the consumer of the library should do so.

Due to the multi-stage multi-layer disconnect proceedure, several methods are bubbled up from COSP to MMS.
The API documentation has notes on how to use these.

Once the writer is dropped, the TCP socket will be closed.

### Cancel Safety

All read/write operations are cancel safe.
For protocols below MMS, the write operation will resume once write is called again.
Calling write with no data will flush the stack.
The read operation will not drop data if cancelled. Calling read again will return the data.
MMS and ICCP are more complicated. A cancelled read and write will not abort the operation, only drop the response.
It is then up to the caller to call read again to get data or verifiy if the write was successful.

### ISO Session Protocol Conformance

* Currently being implemented *

# Roadmap
This is a rough roadmap based on what I know so far. I am using the open version of the standards where possible (X. and RFC) instead of the ISO standards which are generally locked behind a paywall.

* [COMPLETE] ITOT / TPKT / RFC2126 - ISO Transport Service on top of TCP
* [COMPLETE] COTP / RFC905 / ISO 8073 - Connection Orientated Transport Protocol (Class 0 only)
* [COMPLETE] ISO Session Protocol (ISO SP) / X.225 / ISO 8327 -  Version 2 implementing the Kernel and Duplex functional units
* [PRE RELEASE] ISO Presentation Protocol (ISO PP) / X.226 / ISO 8823 - Kernel only
* [PRE RELEASE] ACSE / X.227 / ISO 8650 - Association Control Service Element
* [PRE RELEASE] MMS / ISO 9506 - Manufacturing Message Specification
* [IN PROGRESS] ICCP / TASE.2 - Inter-Control Center Communication Protocol
* [NOT STARTED] ICCP Simulator Web Application
* [NOT STARTED] TLS TPKT Layer

# Development

### Coverage

1. Install the coverage toolset.

```
cargo install cargo-nextest --locked
cargo +stable install cargo-llvm-cov --locked
```

2. Run tests with coverage

```
cargo llvm-cov nextest --lcov --output-path ./target/lcov.info
```

3. Use VS Code Gutters https://github.com/ryanluker/vscode-coverage-gutters to visulaise the coverage.
