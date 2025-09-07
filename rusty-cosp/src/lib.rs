use std::{
    collections::VecDeque,
    net::SocketAddr,
};

use rusty_cotp::{
    api::{CotpConnectOptions, CotpConnection, CotpReader, CotpServer, CotpService, CotpWriter},
    service::{TcpCotpConnection, TcpCotpReader, TcpCotpServer, TcpCotpService, TcpCotpWriter},
};

use crate::{
    api::{CospAcceptor, CospConnection, CospError, CospReader, CospRecvResult, CospServer, CospService, CospWriter},
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

pub struct TcpCospService {}

impl CospService<SocketAddr> for TcpCospService {
    async fn create_server<'a>(address: SocketAddr) -> Result<impl 'a + CospServer<SocketAddr>, CospError> {
        Ok(TcpCospServer::new(address).await?)
    }

    // TODO Also need to handle refuse which will just generically error at the moment.
    async fn connect<'a>(address: SocketAddr, connect_data: Option<&[u8]>, options: CotpConnectOptions<'a>) -> Result<(impl 'a + CospConnection<SocketAddr>, Option<Vec<u8>>), CospError> {
        let cotp_connection = TcpCotpService::connect(address, options).await?;
        let (mut cotp_reader, mut cotp_writer) = TcpCotpConnection::split(cotp_connection).await?;

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

        Ok((TcpCospConnection::new(cotp_reader, cotp_writer, *accept_message.maximum_size_to_responder()), accept_message.user_data().map(|data| data.clone())))
    }
}

pub struct TcpCospServer {
    cotp_server: TcpCotpServer,
}

impl TcpCospServer {
    pub async fn new(address: SocketAddr) -> Result<Self, CospError> {
        Ok(Self {
            cotp_server: TcpCotpServer::new(address).await?,
        })
    }
}

impl CospServer<SocketAddr> for TcpCospServer {
    async fn accept<'a>(&self) -> Result<(impl 'a + CospAcceptor<SocketAddr>, Option<Vec<u8>>), CospError> {
        let (mut cotp_reader, mut cotp_writer) = self.cotp_server.accept().await?.split().await?;

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
        Ok((TcpCospAcceptor::new(cotp_reader, cotp_writer, *maximum_size_to_initiator), user_data))
    }
}

pub struct TcpCospAcceptor {
    cotp_reader: TcpCotpReader,
    cotp_writer: TcpCotpWriter,
    maximum_size_to_initiator: TsduMaximumSize,
}

impl TcpCospAcceptor {
    pub fn new(cotp_reader: TcpCotpReader, cotp_writer: TcpCotpWriter, maximum_size_to_initiator: TsduMaximumSize) -> Self {
        Self { cotp_reader, cotp_writer, maximum_size_to_initiator }
    }
}

impl CospAcceptor<SocketAddr> for TcpCospAcceptor {
    async fn complete_accept<'a>(mut self, accept_data: Option<&[u8]>) -> Result<impl 'a + CospConnection<SocketAddr>, CospError> {
        send_accept(&mut self.cotp_writer, &self.maximum_size_to_initiator, accept_data).await?;
        Ok(TcpCospConnection::new(self.cotp_reader, self.cotp_writer, self.maximum_size_to_initiator))
    }
}

pub struct TcpCospConnection {
    cotp_reader: TcpCotpReader,
    cotp_writer: TcpCotpWriter,
    _remote_max_size: TsduMaximumSize,
}

impl TcpCospConnection {
    pub fn new(cotp_reader: TcpCotpReader, cotp_writer: TcpCotpWriter, remote_max_size: TsduMaximumSize) -> Self {
        Self {
            cotp_reader,
            cotp_writer,
            _remote_max_size: remote_max_size,
        }
    }
}

impl CospConnection<SocketAddr> for TcpCospConnection {
    async fn split<'a>(self) -> Result<(impl 'a + CospReader<SocketAddr> + Send, impl 'a + CospWriter<SocketAddr> + Send), CospError> {
        Ok((
            TcpCospReader {
                cotp_reader: self.cotp_reader,
                _buffer: VecDeque::new(),
            },
            TcpCospWriter { cotp_writer: self.cotp_writer },
        ))
    }
}

pub struct TcpCospReader {
    cotp_reader: TcpCotpReader,
    _buffer: VecDeque<u8>,
}

impl CospReader<SocketAddr> for TcpCospReader {
    async fn recv(&mut self) -> Result<CospRecvResult, CospError> {
        let receive_result = self.cotp_reader.recv().await?;
        let data = match receive_result {
            rusty_cotp::api::CotpRecvResult::Closed => return Ok(CospRecvResult::Closed),
            rusty_cotp::api::CotpRecvResult::Data(data) => data,
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

pub struct TcpCospWriter {
    cotp_writer: TcpCotpWriter,
}

impl CospWriter<SocketAddr> for TcpCospWriter {
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
    use std::ops::Range;

    use tokio::join;
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_negotiate_a_version_2_unlimited_size_connection() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpCospService::create_server(test_address).await?;

        let (client_result, acceptor_result) = join!(TcpCospService::connect(test_address, None, CotpConnectOptions::default()), async {
            let (acceptor, acceptor_user_data) = server.accept().await?;
            assert_eq!(acceptor_user_data, None);
            acceptor.complete_accept(None).await
        });
        let (client_connection, received_accept_data) = client_result?;
        let server_connection = acceptor_result?;
        assert_eq!(received_accept_data, None);

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
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpCospService::create_server(test_address).await?;

        let accept_data = vec![5, 4, 3];
        let (client_result, acceptor_result) = join!(TcpCospService::connect(test_address, Some(&[5, 6, 7]), CotpConnectOptions::default()), async {
            let (acceptor, acceptor_user_data) = server.accept().await?;
            assert_eq!(acceptor_user_data, Some(vec![5, 6, 7]));
            acceptor.complete_accept(Some(&accept_data)).await
        });
        let (client_connection, received_accept_data) = client_result?;
        let server_connection = acceptor_result?;
        assert_eq!(received_accept_data, Some(accept_data));

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
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpCospService::create_server(test_address).await?;

        let mut initial_connect_data = vec![0xabu8; 10240];
        rand::fill(initial_connect_data.as_mut_slice());

        let mut init_accept_data = vec![0x8; 65510];
        rand::fill(init_accept_data.as_mut_slice());

        let (client_result, acceptor_result) = join!(TcpCospService::connect(test_address, Some(initial_connect_data.as_slice()), CotpConnectOptions::default()), async {
            let (acceptor, acceptor_user_data) = server.accept().await?;
            assert_eq!(acceptor_user_data, Some(initial_connect_data.clone()));
            acceptor.complete_accept(Some(&init_accept_data)).await
        });
        let (client_connection, received_accept_data) = client_result?;
        let server_connection = acceptor_result?;
        assert_eq!(received_accept_data, Some(init_accept_data));

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

    // Need to fix Accept
    // Need to take into account the mtu of the peer
    #[tokio::test]
    #[traced_test]
    async fn it_should_pass_jumbo_connect_and_accept_data() -> Result<(), anyhow::Error> {
        let test_address = format!("127.0.0.1:{}", rand::random_range::<u16, Range<u16>>(20000..30000)).parse()?;
        let server = TcpCospService::create_server(test_address).await?;

        let mut initial_connect_data = vec![0x00u8; 10240 + 65520 + 65520 + 100];
        rand::fill(initial_connect_data.as_mut_slice());

        let mut init_accept_data = vec![0x00u8; 65510 + 65510 + 100];
        rand::fill(init_accept_data.as_mut_slice());

        let (client_result, acceptor_result) = join!(TcpCospService::connect(test_address, Some(initial_connect_data.as_slice()), CotpConnectOptions::default()), async {
            let (acceptor, acceptor_user_data) = server.accept().await?;
            assert_eq!(acceptor_user_data, Some(initial_connect_data.clone()));
            acceptor.complete_accept(Some(&init_accept_data)).await
        });
        let (client_connection, received_accept_data) = client_result?;
        let server_connection = acceptor_result?;
        assert_eq!(received_accept_data, Some(init_accept_data));

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
}
