# Rusty ICCP
This repository was created for the purpose of learning the ICCP stack. If others find it useful, awesome.

## Implementation Decisions
~~I am going to stick with sync rust. This is so I can add C bindings later. If I feel the need later, I will add async behind a feature.~~

Using async rust as it is much easier for IO bound operations like the vast majority of this. I will write wrapper libraries with C bindings that create an async runtime at a later point.

This implementation binds the networking stack to TCP Sockets. If a session is disconnected at the ICCP/MMS/Presentation/Session layer, all the lower layers will be disconnected. 

### Size limits

This stack imposes a size limit of 2G on all data.
This is an attempt to prvent bad actors from overloading a system.
However, this limit is likely to be far too large for embedded systems to handle.
Embedded systems should still be constrainted to a secure environment and be connected by secure means.
Most of this is out of scope of this package.

TLS is not currently supported but will be.

### Not actively closing sockets

COTP does not actively close the socket on disconnect.
It is left to the higher layer to push the reader and writer out of scope.
The reader and writer could be re-used which might have undersired results.
This might change at a later point.

### Cancel Safety

All read/write operations are cancel safe.
Use the continue read and continue write operations to ensure the operation was complete.
These are very similar to what one would expect a flush operation to do on a socket.
In the case od continue write, it only ensures the data was sent to the IO buffer before returning.

The continue operations are also cancel safe.

### ISO Session Protocol Conformance

* Currently being implemented *

## Roadmap
This is a rough roadmap based on what I know so far. I am using the open version of the standards where possible (X. and RFC) instead of the ISO standards which are generally locked behind a paywall.

* [COMPLETE] ITOT / TPKT / RFC2126 - ISO Transport Service on top of TCP
* [COMPLETE] COTP / RFC905 / ISO 8073 - Connection Orientated Transport Protocol (Class 0 only)
* [TESTING] ISO Session Protocol (ISO SP) / X.225 / ISO 8327 -  Version 2 implementing the Kernel and Duplex functional units
* [IN PROGRESS] ISO Presentation Protocol (ISO PP) / X.226 / ISO 8823 - Kernel only
* [NOT STARTED] ACSE / X.227 / ISO 8650 - Association Control Service Element
* [NOT STARTED] MMS / ISO 9506 - Manufacturing Message Specification
* [NOT STARTED] ICCP / TASE.2 - Inter-Control Center Communication Protocol
* [NOT STARTED] ICCP Simulator Web Application

Future
For maximum compatability this implementation will include verssion 1 and the half-duplex functional unit for X.225.
This implementation is more restrictive than annex D of x.225 in the following ways.
* X.226 connect will not request connect user data to ensure it is compatible with version 1 negotiations.

# Work Arounds

## Using lower layer services as traits

The intention was to use impl<T: TpktXXXXX<...>> CotpXXXXX<...> for TcpCotpXXXXX so the implementation could be easily swapped out.
However, due to a rust bug https://github.com/rust-lang/rust/issues/100013 it wasn't possible.

This means that, for the implementation, you have to use the lower level services from this library.
The intention was tp be able to swap out parts. For example, provide a TLS service to Tpkt.
Instead I will build a TcpSocketFactory at a later point.

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
