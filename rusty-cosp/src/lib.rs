use std::collections::VecDeque;

use rusty_cotp::{CotpConnection, CotpReader, CotpRecvResult, CotpWriter};

use crate::{
    api::{CospAcceptor, CospConnection, CospError, CospReader, CospRecvResult, CospWriter},
    common::TsduMaximumSize,
    message::CospMessage,
    packet::{parameters::SessionPduParameter, pdu::SessionPduList},
    service::{receive_accept_with_all_user_data, receive_connect_data_overflow, receive_message, receive_overflow_accept, send_accept, send_connect_data_overflow, send_connect_reqeust, send_overflow_accept},
};

pub mod api;
pub(crate) mod common;
pub(crate) mod message;
pub(crate) mod packet;
pub(crate) mod service;

// impl TcpCospServer {
//     async fn accept<'a>(&self) -> Result<(impl 'a + CospAcceptor<SocketAddr>, Option<Vec<u8>>), CospError> {
//         let (mut cotp_reader, mut cotp_writer) = self.cotp_server.accept().await?.split().await?;

//         let connect_request = match receive_message(&mut cotp_reader).await? {
//             CospMessage::CN(connect_message) => connect_message,
//             message => return Err(CospError::ProtocolError(format!("Expecting a connect message, but got {}", <CospMessage as Into<&'static str>>::into(message)))),
//         };

//         let maximum_size_to_initiator = connect_request.maximum_size_to_initiator();
//         let has_more_data = match &connect_request.data_overflow() {
//             Some(overflow) => overflow.more_data(),
//             None => false,
//         };

//         let mut user_data = VecDeque::new();
//         let has_user_data = connect_request.user_data().is_some() || connect_request.data_overflow().is_some();
//         if let Some(request_user_data) = connect_request.user_data() {
//             user_data.extend(request_user_data);
//         }

//         if has_more_data {
//             send_overflow_accept(&mut cotp_writer, &maximum_size_to_initiator).await?;
//             user_data.extend(receive_connect_data_overflow(&mut cotp_reader).await?);
//         }

//         let user_data = match has_user_data {
//             true => Some(user_data.drain(..).collect()),
//             false => None,
//         };
//         Ok((TcpCospAcceptor::new(cotp_reader, cotp_writer, *maximum_size_to_initiator), user_data))
//     }
// }

pub struct TcpCospAcceptor<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    maximum_size_to_initiator: TsduMaximumSize,
}

impl<R: CotpReader, W: CotpWriter> TcpCospAcceptor<R, W> {
    // TODO Return Connection Information alongside user data.
    pub async fn receive(cotp_connection: impl CotpConnection) -> Result<(TcpCospAcceptor<impl CotpReader, impl CotpWriter>, Option<Vec<u8>>), CospError> {
        let (mut cotp_reader, mut cotp_writer) = cotp_connection.split().await?;

        let connect_request = match receive_message(&mut cotp_reader).await? {
            CospMessage::CN(connect_message) => connect_message,
            message => return Err(CospError::ProtocolError(format!("Expecting a connect message, but got {}", <CospMessage as Into<&'static str>>::into(message)))),
        };

        let maximum_size_to_initiator = connect_request.maximum_size_to_initiator();
        let has_more_data = match &connect_request.data_overflow() {
            Some(overflow) => overflow.more_data(),
            None => false,
        };

        let mut user_data = VecDeque::new();
        let has_user_data = connect_request.user_data().is_some() || connect_request.data_overflow().is_some();
        if let Some(request_user_data) = connect_request.user_data() {
            user_data.extend(request_user_data);
        }

        if has_more_data {
            send_overflow_accept(&mut cotp_writer, &maximum_size_to_initiator).await?;
            user_data.extend(receive_connect_data_overflow(&mut cotp_reader).await?);
        }

        let user_data = match has_user_data {
            true => Some(user_data.drain(..).collect()),
            false => None,
        };
        Ok((TcpCospAcceptor::<R, W>::new(cotp_reader, cotp_writer, *maximum_size_to_initiator), user_data))
    }

    fn new(cotp_reader: impl CotpReader, cotp_writer: impl CotpWriter, maximum_size_to_initiator: TsduMaximumSize) -> TcpCospAcceptor<impl CotpReader, impl CotpWriter> {
        TcpCospAcceptor {
            cotp_reader,
            cotp_writer,
            maximum_size_to_initiator,
        }
    }
}

impl<R: CotpReader + Send, W: CotpWriter + Send> CospAcceptor for TcpCospAcceptor<R, W> {
    async fn accept(mut self, accept_data: Option<&[u8]>) -> Result<impl CospConnection, CospError> {
        send_accept(&mut self.cotp_writer, &self.maximum_size_to_initiator, accept_data).await?;
        Ok(TcpCospConnection::<R, W>::new(self.cotp_reader, self.cotp_writer, self.maximum_size_to_initiator))
    }
}

pub struct TcpCospConnection<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    _remote_max_size: TsduMaximumSize,
}

impl<R: CotpReader, W: CotpWriter> TcpCospConnection<R, W> {
    // TODO Also need to handle refuse which will just generically error at the moment.
    pub async fn connect(cotp_connection: impl CotpConnection, connect_data: Option<&[u8]>) -> Result<(TcpCospConnection<impl CotpReader, impl CotpWriter>, Option<Vec<u8>>), CospError> {
        let (mut cotp_reader, mut cotp_writer) = cotp_connection.split().await?;

        let send_connect_result = send_connect_reqeust(&mut cotp_writer, connect_data).await?;

        let accept_message = match (send_connect_result, connect_data) {
            (service::SendConnectionRequestResult::Complete, _) => receive_accept_with_all_user_data(&mut cotp_reader).await?,
            (service::SendConnectionRequestResult::Overflow(sent_data), Some(user_data)) => {
                receive_overflow_accept(&mut cotp_reader).await?;
                send_connect_data_overflow(&mut cotp_writer, &user_data[sent_data..]).await?;
                receive_accept_with_all_user_data(&mut cotp_reader).await?
            }
            (service::SendConnectionRequestResult::Overflow(_), None) => return Err(CospError::InternalError("User data was sent even though user data was not provided.".into())),
        };

        Ok((
            TcpCospConnection::<R, W>::new(cotp_reader, cotp_writer, *accept_message.maximum_size_to_responder()),
            accept_message.user_data().map(|data| data.clone()),
        ))
    }

    fn new(cotp_reader: impl CotpReader, cotp_writer: impl CotpWriter, remote_max_size: TsduMaximumSize) -> TcpCospConnection<impl CotpReader, impl CotpWriter> {
        TcpCospConnection {
            cotp_reader,
            cotp_writer,
            _remote_max_size: remote_max_size,
        }
    }
}

impl<R: CotpReader + Send, W: CotpWriter + Send> CospConnection for TcpCospConnection<R, W> {
    async fn split(self) -> Result<(impl CospReader, impl CospWriter), CospError> {
        Ok((
            TcpCospReader {
                cotp_reader: self.cotp_reader,
                _buffer: VecDeque::new(),
            },
            TcpCospWriter { cotp_writer: self.cotp_writer },
        ))
    }
}

pub struct TcpCospReader<R: CotpReader> {
    cotp_reader: R,
    _buffer: VecDeque<u8>,
}

impl<R: CotpReader + Send> CospReader for TcpCospReader<R> {
    async fn recv(&mut self) -> Result<CospRecvResult, CospError> {
        let receive_result = self.cotp_reader.recv().await?;
        let data = match receive_result {
            CotpRecvResult::Closed => return Ok(CospRecvResult::Closed),
            CotpRecvResult::Data(data) => data,
        };

        let received_message = CospMessage::from_spdu_list(SessionPduList::deserialise(&data)?)?;
        let data_transfer_message = match received_message {
            CospMessage::DT(message) => message,
            _ => todo!(),
        };

        // TODO Need to cater for fragmentation

        Ok(CospRecvResult::Data(data_transfer_message.take_user_information()))
    }
}

pub struct TcpCospWriter<W: CotpWriter> {
    cotp_writer: W,
}

impl<W: CotpWriter + Send> CospWriter for TcpCospWriter<W> {
    async fn send(&mut self, data: &[u8]) -> Result<(), CospError> {
        // TODO Segmentation
        //        let payload = SessionPduList::new(vec![], data.to_vec()).serialise()?;
        let payload = SessionPduList::new(vec![SessionPduParameter::GiveTokens(), SessionPduParameter::DataTransfer(vec![])], data.to_vec()).serialise()?;
        self.cotp_writer.send(&payload).await?;
        Ok(())
    }

    async fn continue_send(&mut self) -> Result<(), CospError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // use std::ops::Range;

    // use rusty_cotp::{CotpAcceptor, CotpConnectOptions, CotpConnectionInformation, TcpCotpAcceptor};
    // use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter, TpktReader, TpktWriter};
    // use tokio::join;
    // use tracing_test::traced_test;

    // use super::*;

    // #[tokio::test]
    // #[traced_test]
    // async fn it_should_negotiate_a_version_2_unlimited_size_connection() -> Result<(), anyhow::Error> {
    //     let (client_connection, server_connection) = create_cotp_connection_pair().await?;

    //     let (mut client_reader, mut client_writer) = client_connection.split().await?;
    //     let (mut server_reader, mut server_writer) = server_connection.split().await?;

    //     client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
    //     match server_reader.recv().await? {
    //         CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
    //         CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
    //     }
    //     server_writer.send(&[1, 2, 3, 4]).await?;
    //     match client_reader.recv().await? {
    //         CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
    //         CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
    //     }

    //     Ok(())
    // }

    // #[tokio::test]
    // #[traced_test]
    // async fn it_should_pass_small_connect_and_accept_data() -> Result<(), anyhow::Error> {
    //     let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
    //     let server = TcpCospService::create_server(test_address).await?;

    //     let accept_data = vec![5, 4, 3];
    //     let (client_result, acceptor_result) = join!(TcpCospService::connect(test_address, Some(&[5, 6, 7]), CotpConnectOptions::default()), async {
    //         let (acceptor, acceptor_user_data) = server.accept().await?;
    //         assert_eq!(acceptor_user_data, Some(vec![5, 6, 7]));
    //         acceptor.complete_accept(Some(&accept_data)).await
    //     });
    //     let (client_connection, received_accept_data) = client_result?;
    //     let server_connection = acceptor_result?;
    //     assert_eq!(received_accept_data, Some(accept_data));

    //     let (mut client_reader, mut client_writer) = client_connection.split().await?;
    //     let (mut server_reader, mut server_writer) = server_connection.split().await?;

    //     client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
    //     match server_reader.recv().await? {
    //         CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
    //         CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
    //     }
    //     server_writer.send(&[1, 2, 3, 4]).await?;
    //     match client_reader.recv().await? {
    //         CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
    //         CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
    //     }

    //     Ok(())
    // }

    // #[tokio::test]
    // #[traced_test]
    // async fn it_should_pass_medium_connect_and_accept_data() -> Result<(), anyhow::Error> {
    //     let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
    //     let server = TcpCospService::create_server(test_address).await?;

    //     let mut initial_connect_data = vec![0xabu8; 10240];
    //     rand::fill(initial_connect_data.as_mut_slice());

    //     let mut init_accept_data = vec![0x8; 65510];
    //     rand::fill(init_accept_data.as_mut_slice());

    //     let (client_result, acceptor_result) = join!(TcpCospService::connect(test_address, Some(initial_connect_data.as_slice()), CotpConnectOptions::default()), async {
    //         let (acceptor, acceptor_user_data) = server.accept().await?;
    //         assert_eq!(acceptor_user_data, Some(initial_connect_data.clone()));
    //         acceptor.complete_accept(Some(&init_accept_data)).await
    //     });
    //     let (client_connection, received_accept_data) = client_result?;
    //     let server_connection = acceptor_result?;
    //     assert_eq!(received_accept_data, Some(init_accept_data));

    //     let (mut client_reader, mut client_writer) = client_connection.split().await?;
    //     let (mut server_reader, mut server_writer) = server_connection.split().await?;

    //     client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
    //     match server_reader.recv().await? {
    //         CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
    //         CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
    //     }
    //     server_writer.send(&[1, 2, 3, 4]).await?;
    //     match client_reader.recv().await? {
    //         CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
    //         CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
    //     }

    //     Ok(())
    // }

    // // Need to fix Accept
    // // Need to take into account the mtu of the peer
    // #[tokio::test]
    // #[traced_test]
    // async fn it_should_pass_jumbo_connect_and_accept_data() -> Result<(), anyhow::Error> {
    //     let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
    //     let server = TcpCospService::create_server(test_address).await?;

    //     let mut initial_connect_data = vec![0x00u8; 10240 + 65520 + 65520 + 100];
    //     rand::fill(initial_connect_data.as_mut_slice());

    //     let mut init_accept_data = vec![0x00u8; 65510 + 65510 + 100];
    //     rand::fill(init_accept_data.as_mut_slice());

    //     let (client_result, acceptor_result) = join!(TcpCospService::connect(test_address, Some(initial_connect_data.as_slice()), CotpConnectOptions::default()), async {
    //         let (acceptor, acceptor_user_data) = server.accept().await?;
    //         assert_eq!(acceptor_user_data, Some(initial_connect_data.clone()));
    //         acceptor.complete_accept(Some(&init_accept_data)).await
    //     });
    //     let (client_connection, received_accept_data) = client_result?;
    //     let server_connection = acceptor_result?;
    //     assert_eq!(received_accept_data, Some(init_accept_data));

    //     let (mut client_reader, mut client_writer) = client_connection.split().await?;
    //     let (mut server_reader, mut server_writer) = server_connection.split().await?;

    //     client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
    //     match server_reader.recv().await? {
    //         CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
    //         CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
    //     }
    //     server_writer.send(&[1, 2, 3, 4]).await?;
    //     match client_reader.recv().await? {
    //         CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
    //         CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
    //     }

    //     Ok(())
    // }

    // async fn create_cotp_connection_pair() -> Result<(impl CospConnection, impl CospConnection), anyhow::Error> {
    //     let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;

    //     let tpkt_listener = TcpTpktServer::listen(test_address).await?;
    //     let (tpkt_client, tpkt_server) = join!(TcpTpktConnection::connect(test_address), tpkt_listener.accept());

    //     let (cotp_initiator, cotp_acceptor) = join!(async { TcpCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_client?, CotpConnectOptions {}).await }, async {
    //         let (acceptor, remote) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::receive(tpkt_server?.0).await?;
    //         assert_eq!(remote, CotpConnectionInformation::default());
    //         acceptor.accept().await
    //     });

    //     let cotp_client = cotp_initiator?;
    //     let cotp_server = cotp_acceptor?;

    //     let (cosp_client, cosp_server) = join!(async { TcpCospConnection::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::connect(cotp_client, None).await }, async {
    //         let (acceptor, _) = TcpCospAcceptor::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::receive(cotp_server).await?;
    //         acceptor.accept(None).await
    //     });

    //     Ok((cosp_client?.0, cosp_server?))
    // }
}
