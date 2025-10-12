# Rusty ICCP
This repository was created for the purpose of learning the ICCP stack. If others find it useful, awesome.

## API Choices.

Application level decisions have to be made at most layers of the stack. There are convenience builders to assist in this creation.

* TODO List the stack builders.

TPKT and COTP are relatively straight forward. The onlt state TPKT keeps is for fragmented packets. It does not handshake. COTP Does the handshake then transmits data.

COSP, COPP, ACSE and MMS require data transmission and active decision making suring the handshaking process. For this reason, the process is split into several areas.

Initiator:
* Initiator
  * The initiator is used to send the initial handshake and receive the response.
  * Key parameters are passed during construction, like the caller and called addressed.
  * This is then passed to the higher layer protocol that will invoke `initiate` to complete the handshake.

Responder:
* Listener
  * The listener will receive the initial handshake during construction and return key connection information to the API caller. The called may reject the handshake which will consume the listener.
  * If the connection details are okay, caller will pass the listener to the higher layer protocol.
  * The higher layer protocol will convert the listener to a responder. This will consume the listener and also return the connect data received during the handshake.
* Responder
  * If the connect data from the consumed listener was successfully parsed and processed, the higher level protocol will accept the connection from the responder converting it into a connection. Otherwise it will reject the connection consuming the responder.

## Implementation Decisions
Using async rust as it is much easier for IO bound operations like the vast majority of this. I will write wrapper libraries with C bindings that create an async runtime at a later point.

This implementation binds the networking stack to TCP Sockets. If a session is disconnected at the ICCP/MMS/Presentation/Session layer, all the lower layers will be disconnected.

### Not actively closing sockets

Connections are not actively closed on errors for all protocols below ICCP.
Errors in processing are bubbled up to the layer above, and eventually to the ICCP layer.

If you are using this stack for any other protocols, it is left to the higher layer to push the reader and writer out of scope and close the connection or use the reject api calls.
Alternatively, the user may attempt to reuse the connection. Doing this is allowed, but the behaviour is undefined.

### Cancel Safety

All read/write operations are cancel safe.
Use the continue read and continue write operations to ensure the operation was complete.
These are very similar to what one would expect a flush operation to do on a socket.
In the case od continue write, it only ensures the data was sent to the IO buffer before returning.

The continue operations are also cancel safe.

### ISO Session Protocol Conformance

* Currently being implemented *

# Roadmap
This is a rough roadmap based on what I know so far. I am using the open version of the standards where possible (X. and RFC) instead of the ISO standards which are generally locked behind a paywall.

* [COMPLETE] ITOT / TPKT / RFC2126 - ISO Transport Service on top of TCP
* [COMPLETE] COTP / RFC905 / ISO 8073 - Connection Orientated Transport Protocol (Class 0 only)
* [TESTING] ISO Session Protocol (ISO SP) / X.225 / ISO 8327 -  Version 2 implementing the Kernel and Duplex functional units
* [IN PROGRESS] ISO Presentation Protocol (ISO PP) / X.226 / ISO 8823 - Kernel only
* [NOT STARTED] ACSE / X.227 / ISO 8650 - Association Control Service Element
* [NOT STARTED] MMS / ISO 9506 - Manufacturing Message Specification
* [NOT STARTED] ICCP / TASE.2 - Inter-Control Center Communication Protocol
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
