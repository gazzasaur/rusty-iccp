/**
 * MIT License
 *
 * Copyright (c) 2025 gazzasaur
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
