 /**

Version 1 Only

----- Kernel -----
Connect
OverflowAccept          <- Only required if the s-connect is segmented (Maybe not required for our purposes)
ConnectDataOverflow     <- Only required if the s-connect is segmented (Maybe not required for our purposes)
Accept
Refuse
Finish
Disconnect
Abort
AbortAccept             <- Only need to process these, don't need to send them.
DataTransfer

Options for connect sequence
a) Send Connect -> Accept/Refuse        OR
b) Receive Connect -> Accept/Refuse     OR
c) Do both <--- We are going to do both


----- HalfDuplex -----
GiveTokens
PleaseTokens

----- Duplex -----
Nothing Extra Required
  */
  
pub mod connect;
pub mod parameters;
