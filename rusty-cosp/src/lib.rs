use std::{collections::VecDeque, marker::PhantomData};

use rusty_cotp::{CotpConnection, CotpReader, CotpRecvResult, CotpWriter};

use crate::{
    api::{CospConnection, CospConnectionInformation, CospConnector, CospError, CospReader, CospRecvResult, CospResponder, CospWriter},
    message::{CospMessage, parameters::TsduMaximumSize},
    packet::{
        parameters::{EnclosureField, SessionPduParameter},
        pdu::SessionPduList,
    },
    service::{
        MAX_PAYLOAD_SIZE, MIN_PAYLOAD_SIZE,
        connect::{SendConnectionRequestResult, send_connect_reqeust},
        overflow::{receive_connect_data_overflow, receive_overflow_accept, send_connect_data_overflow, send_overflow_accept},
        receive_accept_with_all_user_data, receive_message, send_accept,
    },
};

pub mod api;
pub(crate) mod message;
pub(crate) mod packet;
pub(crate) mod service;

pub struct TcpCospConnector<T: CotpConnection, R: CotpReader, W: CotpWriter> {
    cotp_connection: T,
    _phantom_reader: PhantomData<R>,
    _phantom_writer: PhantomData<W>,
}

impl<T: CotpConnection, R: CotpReader, W: CotpWriter> TcpCospConnector<T, R, W> {
    fn new(cotp_connection: T) -> TcpCospConnector<T, R, W> {
        TcpCospConnector::<T, R, W> {
            cotp_connection,
            _phantom_reader: PhantomData::default(),
            _phantom_writer: PhantomData::default(),
        }
    }
}

impl<T: CotpConnection, R: CotpReader, W: CotpWriter> CospConnector for TcpCospConnector<T, R, W> {
    // TODO Return Connection Information alongside user data.
    async fn receive(self) -> Result<(impl CospResponder, CospConnectionInformation, Option<Vec<u8>>), CospError> {
        let (mut cotp_reader, mut cotp_writer) = self.cotp_connection.split().await?;

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
        Ok((
            TcpCospAcceptor::<R, W>::new(cotp_reader, cotp_writer, *maximum_size_to_initiator),
            CospConnectionInformation {
                tsdu_maximum_size: if let TsduMaximumSize::Size(x) = maximum_size_to_initiator { Some(*x) } else { None },
                called_session_selector: None,
                calling_session_selector: None,
            },
            user_data,
        ))
    }
}

pub struct TcpCospAcceptor<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    maximum_size_to_initiator: TsduMaximumSize,
}

impl<R: CotpReader, W: CotpWriter> TcpCospAcceptor<R, W> {
    fn new(cotp_reader: impl CotpReader, cotp_writer: impl CotpWriter, maximum_size_to_initiator: TsduMaximumSize) -> TcpCospAcceptor<impl CotpReader, impl CotpWriter> {
        TcpCospAcceptor {
            cotp_reader,
            cotp_writer,
            maximum_size_to_initiator,
        }
    }
}

impl<R: CotpReader, W: CotpWriter> CospResponder for TcpCospAcceptor<R, W> {
    async fn accept(self, accept_data: Option<&[u8]>) -> Result<impl CospConnection, CospError> {
        let cotp_reader = self.cotp_reader;
        let mut cotp_writer = self.cotp_writer;

        send_accept(&mut cotp_writer, &self.maximum_size_to_initiator, accept_data).await?;
        Ok(TcpCospConnection::<R, W>::new(cotp_reader, cotp_writer, self.maximum_size_to_initiator))
    }
}

pub struct TcpCospConnection<R: CotpReader, W: CotpWriter> {
    cotp_reader: R,
    cotp_writer: W,
    remote_max_size: TsduMaximumSize,
}

impl<R: CotpReader, W: CotpWriter> TcpCospConnection<R, W> {
    // TODO Also need to handle refuse which will just generically error at the moment.
    pub async fn connect(cotp_connection: impl CotpConnection, options: CospConnectionInformation, connect_data: Option<&[u8]>) -> Result<(TcpCospConnection<impl CotpReader, impl CotpWriter>, Option<Vec<u8>>), CospError> {
        let (mut cotp_reader, mut cotp_writer) = cotp_connection.split().await?;

        let send_connect_result = send_connect_reqeust(&mut cotp_writer, options, connect_data).await?;

        let accept_message = match (send_connect_result, connect_data) {
            (SendConnectionRequestResult::Complete, _) => receive_accept_with_all_user_data(&mut cotp_reader).await?,
            (SendConnectionRequestResult::Overflow(sent_data), Some(user_data)) => {
                let overflow_accept = receive_overflow_accept(&mut cotp_reader).await?;
                send_connect_data_overflow(&mut cotp_writer, *overflow_accept.maximum_size_to_responder(), &user_data[sent_data..]).await?;
                receive_accept_with_all_user_data(&mut cotp_reader).await?
            }
            (SendConnectionRequestResult::Overflow(_), None) => return Err(CospError::InternalError("User data was sent even though user data was not provided.".into())),
        };

        Ok((
            TcpCospConnection::<R, W>::new(cotp_reader, cotp_writer, *accept_message.maximum_size_to_responder()),
            accept_message.user_data().map(|data| data.clone()),
        ))
    }

    fn new(cotp_reader: impl CotpReader, cotp_writer: impl CotpWriter, remote_max_size: TsduMaximumSize) -> TcpCospConnection<impl CotpReader, impl CotpWriter> {
        TcpCospConnection { cotp_reader, cotp_writer, remote_max_size }
    }
}

impl<R: CotpReader, W: CotpWriter> CospConnection for TcpCospConnection<R, W> {
    async fn split(self) -> Result<(impl CospReader, impl CospWriter), CospError> {
        Ok((
            TcpCospReader {
                cotp_reader: self.cotp_reader,
                _buffer: VecDeque::new(),
            },
            TcpCospWriter {
                cotp_writer: self.cotp_writer,
                remote_max_size: self.remote_max_size,
            },
        ))
    }
}

pub struct TcpCospReader<R: CotpReader> {
    cotp_reader: R,
    _buffer: VecDeque<u8>,
}

impl<R: CotpReader> CospReader for TcpCospReader<R> {
    async fn recv(&mut self) -> Result<CospRecvResult, CospError> {
        let mut buffer = VecDeque::new();
        loop {
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

            let enclosure = data_transfer_message.enclosure();
            buffer.extend(data_transfer_message.take_user_information());
            match enclosure {
                Some(x) if x.end() => return Ok(CospRecvResult::Data(buffer.drain(..).collect())),
                None => return Ok(CospRecvResult::Data(buffer.drain(..).collect())),
                Some(_) => (),
            }
        }
    }
}

pub struct TcpCospWriter<W: CotpWriter> {
    cotp_writer: W,
    remote_max_size: TsduMaximumSize,
}

impl<W: CotpWriter> CospWriter for TcpCospWriter<W> {
    async fn send(&mut self, data: &[u8]) -> Result<(), CospError> {
        const HEADER_LENGTH_WITHOUT_ENCLOSURE: usize = 4; // GT + DT

        match self.remote_max_size {
            TsduMaximumSize::Size(x) if data.len() < MAX_PAYLOAD_SIZE && data.len() + HEADER_LENGTH_WITHOUT_ENCLOSURE < x as usize => {
                let payload = SessionPduList::new(vec![SessionPduParameter::GiveTokens(), SessionPduParameter::DataTransfer(vec![])], data.to_vec()).serialise()?;
                self.cotp_writer.send(&payload).await?;
            }
            TsduMaximumSize::Unlimited => {
                let payload = SessionPduList::new(vec![SessionPduParameter::GiveTokens(), SessionPduParameter::DataTransfer(vec![])], data.to_vec()).serialise()?;
                self.cotp_writer.send(&payload).await?;
            }
            TsduMaximumSize::Size(x) => {
                let mut cursor: usize = 0;
                let payload_length = usize::max(MIN_PAYLOAD_SIZE, usize::min(MAX_PAYLOAD_SIZE, x as usize));

                while cursor < data.len() {
                    let start = cursor;
                    cursor = match cursor + payload_length as usize {
                        cursor if cursor > data.len() => data.len(),
                        cursor => cursor,
                    };
                    let enclosure = EnclosureField(if start == 0 { 1 } else { 0 } + if cursor == data.len() { 2 } else { 0 });
                    let payload = SessionPduList::new(
                        vec![SessionPduParameter::GiveTokens(), SessionPduParameter::DataTransfer(vec![SessionPduParameter::EnclosureParameter(enclosure)])],
                        data[start..cursor].to_vec(),
                    )
                    .serialise()?;
                    self.cotp_writer.send(&payload).await?;
                }
            }
        }
        Ok(())
    }

    async fn continue_send(&mut self) -> Result<(), CospError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use rusty_cotp::{CotpAcceptInformation, CotpConnectInformation, CotpResponder, TcpCotpAcceptor, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    use tokio::join;
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_negotiate_a_version_2_unlimited_size_connection() -> Result<(), anyhow::Error> {
        let (client_connection, server_connection) = create_cosp_connection_pair(None, None).await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
        match server_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
        }
        server_writer.send(&[1, 2, 3, 4]).await?;
        match client_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_should_pass_small_connect_and_accept_data() -> Result<(), anyhow::Error> {
        let (client_connection, server_connection) = create_cosp_connection_pair(Some(&[5, 6, 7]), Some(&[5, 4, 3])).await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
        match server_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
        }
        server_writer.send(&[1, 2, 3, 4]).await?;
        match client_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_should_pass_medium_connect_and_accept_data() -> Result<(), anyhow::Error> {
        let mut initial_connect_data = vec![0xabu8; 10240];
        rand::fill(initial_connect_data.as_mut_slice());

        let mut init_accept_data = vec![0x8; 65510];
        rand::fill(init_accept_data.as_mut_slice());

        let (client_connection, server_connection) = create_cosp_connection_pair(Some(initial_connect_data.as_slice()), Some(init_accept_data.as_slice())).await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
        match server_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
        }
        server_writer.send(&[1, 2, 3, 4]).await?;
        match client_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
        }

        Ok(())
    }

    // TODO Need to fix Accept
    // TODO Need to take into account the mtu of the peer
    // TODO Need to DT a lot bigger data
    #[tokio::test]
    #[traced_test]
    async fn it_should_pass_jumbo_connect_and_accept_data() -> Result<(), anyhow::Error> {
        let mut initial_connect_data = vec![0x00u8; 10240 + 65520 + 65520 + 100];
        rand::fill(initial_connect_data.as_mut_slice());

        let mut init_accept_data = vec![0x00u8; 65510 + 65510 + 100];
        rand::fill(init_accept_data.as_mut_slice());

        let (client_connection, server_connection) = create_cosp_connection_pair(Some(initial_connect_data.as_slice()), Some(init_accept_data.as_slice())).await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
        match server_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
        }
        server_writer.send(&[1, 2, 3, 4]).await?;
        match client_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_should_pass_and_honour_options() -> Result<(), anyhow::Error> {
        let mut initial_connect_data = vec![0x00u8; 10240 + 65520 + 65520 + 100];
        rand::fill(initial_connect_data.as_mut_slice());

        let mut init_accept_data = vec![0x00u8; 65510 + 65510 + 100];
        rand::fill(init_accept_data.as_mut_slice());

        let (client_connection, server_connection) = create_cosp_connection_pair_with_options(
            Some(initial_connect_data.as_slice()),
            CospConnectionInformation {
                tsdu_maximum_size: Some(512),
                calling_session_selector: Some(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
                called_session_selector: Some(vec![0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21]),
            },
            Some(init_accept_data.as_slice()),
        )
        .await?;

        let (mut client_reader, mut client_writer) = client_connection.split().await?;
        let (mut server_reader, mut server_writer) = server_connection.split().await?;

        client_writer.send(&[0x61, 0x02, 0x05, 0x00]).await?;
        match server_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "61020500"),
        }
        server_writer.send(&[1, 2, 3, 4]).await?;
        match client_reader.recv().await? {
            CospRecvResult::Closed => assert!(false, "Expected the connection to be open."),
            CospRecvResult::Data(data) => assert_eq!(hex::encode(data), "01020304"),
        }

        Ok(())
    }

    async fn create_cosp_connection_pair(connect_data: Option<&[u8]>, accept_data: Option<&[u8]>) -> Result<(impl CospConnection, impl CospConnection), anyhow::Error> {
        // let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let test_address = "127.0.0.1:10002".parse()?;

        let connect_information = CotpConnectInformation::default();

        let tpkt_listener = TcpTpktServer::listen(test_address).await?;
        let (tpkt_client, tpkt_server) = join!(TcpTpktConnection::connect(test_address), tpkt_listener.accept());

        let (cotp_initiator, cotp_acceptor) = join!(async { TcpCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_client?, connect_information.clone()).await }, async {
            let (acceptor, remote) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::respond(tpkt_server?.0).await?;
            assert_eq!(remote, connect_information);
            acceptor.accept(CotpAcceptInformation::default()).await
        });

        let cotp_client = cotp_initiator?;
        let cotp_server = cotp_acceptor?;

        let (cosp_client, cosp_server) = join!(
            async { TcpCospConnection::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::connect(cotp_client, CospConnectionInformation::default(), connect_data).await },
            async {
                let (acceptor, user_data) = TcpCospConnector::<TcpCotpConnection<TcpTpktReader>, TcpTpktWriter>, TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_server).await?;
                assert_eq!(connect_data.map(|x| x.to_vec()), user_data);
                acceptor.accept(accept_data).await
            }
        );

        Ok((cosp_client?.0, cosp_server?))
    }

    async fn create_cosp_connection_pair_with_options(connect_data: Option<&[u8]>, options: CospConnectionInformation, accept_data: Option<&[u8]>) -> Result<(impl CospConnection, impl CospConnection), anyhow::Error> {
        // let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let test_address = "127.0.0.1:10002".parse()?;

        let connect_information = CotpConnectInformation::default();

        let tpkt_listener = TcpTpktServer::listen(test_address).await?;
        let (tpkt_client, tpkt_server) = join!(TcpTpktConnection::connect(test_address), tpkt_listener.accept());

        let (cotp_initiator, cotp_acceptor) = join!(async { TcpCotpConnection::<TcpTpktReader, TcpTpktWriter>::initiate(tpkt_client?, connect_information.clone()).await }, async {
            let (acceptor, remote) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::respond(tpkt_server?.0).await?;
            assert_eq!(remote, connect_information);
            acceptor.accept(CotpAcceptInformation::default()).await
        });

        let cotp_client = cotp_initiator?;
        let cotp_server = cotp_acceptor?;

        let (cosp_client, cosp_server) = join!(
            async { TcpCospConnection::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::connect(cotp_client, options, connect_data).await },
            async {
                let (acceptor, user_data) = TcpCospAcceptor::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::receive(cotp_server).await?;
                assert_eq!(connect_data.map(|x| x.to_vec()), user_data);
                acceptor.accept(accept_data).await
            }
        );

        Ok((cosp_client?.0, cosp_server?))
    }
}
