# Rusty ICCP
This repository was created for the purpose of learning the ICCP stack. If others find it useful, awesome.

## Implementation Decisions
I am going to stick with sync rust. This is so I can add C bindings later. If I feel the need later, I will add async behind a feature.

## Roadmap
This is a rough roadmap based on what I know so far. I am using the open version of the standards where possible (X. and RFC) instead of the ISO standards which are generally locked behind a paywall.

I am going to implement the mandatory minimum of the transport, session and presentation standards as we are running this over TCP.

* COTP / RFC905 / ISO 8073 - Connection Orientated Transport Protocol (Class 0 only)
* COSP / X.225 / ISO 8327 - Connection Orientated Session Protocol
* COPP / X.226 / ISO 8823 - Connection Orientated Presentation Protocol
* MMS / ISO 9506 - Manufacturing Message Specification
* ICCP / TASE.2 - Inter-Control Center Communication Protocol
