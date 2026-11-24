# Rusty ACSE
A pure rust implementation of Association Control Service Element (ACSE).

This protocol is used to identify calling and called parties during an ISO connection negotiation.
This implementation covers kernel functionality of ACSE:
* Connections can be established and released but not re-negotiated.

This standard is known by:
* ACSE
* X.227
* ISO 8650

This package is intended to be used in conjunction with a higher level protocol. For example:
* [rusty-mms-service](https://crates.io/crates/rusty-mms-service)

## Using this Library

#### Static Dispatch

This library uses static dispatch. This protocol is a very small slice in a large protocol stack. It is called very often. Static dispatch removes vtable lookups reducing call overhead. Static dispatch also allows the types to be resolved at compile time, giving the compiler greater scope to perform optimisations. This also makes it ideal for use in embedded devices.

The trade off is that static dispatch may be more difficult to work with in complex applications. The rusty-mms-service provides one example of going from a static dispatch to a dynamic dispatch environment without degrading performance.

#### Async and STD

This library uses async rust and std components. This has some implications for embedded systems that do not have an OS. Yjis will be explored at a later point.

#### Cancel Safety

Send and Recv operations are cancel safe as long as the caller does not drop their buffer after cancel if it still contains data. It is safe to call Send and Recv anytime after cancellation.

## Conformance
This create implements static conformance kernel functionality, with some restriction.

This allows most ISO protcols to be operated over this implementation, normally using the 'kernel only' or 'core features' of higher layer protocols. Please refer to the conformance statement of the standard you are using to ensure all the features you require are offered given the comformance of this implementation.

## References
* [X.227](https://www.itu.int/rec/T-REC-X.227/)

## Examples

Examples may be found in the [examples](https://github.com/gazzasaur/rusty-iccp/blob/main/rusty-ACSE/examples) directory. Basic useage is shown below.

```
```
