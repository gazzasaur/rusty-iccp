use std::net::SocketAddr;


use rusty_tpkt::{TcpTpktServer, TcpTpktService, TpktConnection, TpktServer, TpktService};

use crate::api::{CotpConnection, CotpError, CotpServer, CotpService};

pub struct TcpCotpService {}

impl CotpService<SocketAddr> for TcpCotpService {
    // async fn create_server<'a, R: TcpCotpServer<SocketAddr>(address: SocketAddr) -> Result<impl 'a + R, CotpError> {
    async fn create_server<'a>(address: SocketAddr) -> Result<impl 'a + CotpServer<SocketAddr>, CotpError> {
        // news(TcpTpktService::create_server(address).await?);
        // Err::<TcpCotpServer<TcpTpktServer>, CotpError>(CotpError::InternalError("".into()))
        Ok(TcpCotpServer::new(TcpTpktService::create_server(address).await?))
    }
    //     Ok(TcpCotpServer::new(TcpTpktService::create_server(address).await?))
    // }

    // async fn connect<'a>(address: SocketAddr) -> Result<impl 'a + CotpConnection<SocketAddr>, CotpError> {
    //     Ok(TcpCotpConnection::new(TcpTpktService::connect(address).await?))
    // }
}

struct TcpCotpServer<T: TpktServer<SocketAddr>> {
    listener: T,
}

impl<T: TpktServer<SocketAddr>> TcpCotpServer<T> {
    pub fn new(listener: T) -> Self {
        TcpCotpServer { listener }
    }
}

impl<T: TpktServer<SocketAddr>> CotpServer<SocketAddr> for TcpCotpServer<T> {
    // async fn accept<'a>(&self) -> Result<impl 'a + CotpConnection<SocketAddr>, CotpError> {
        
    // }
}

// impl<T: TpktServer<std::net::SocketAddr>> CotpServer<T> for TcpCotpServer<T> {
//     async fn accept<'a>(&self) -> Result<impl 'a + CotpConnection<T>, CotpError> {
//         let tpkt = self.listener.accept().await?;
//         let copt = TcpCotpConnection::new(tpkt);
//         Ok(copt)
//     }
// }

// struct TcpCotpConnection<T: TpktConnection<SocketAddr>> {
    // connection: T,
// }

// impl<T: TpktConnection<SocketAddr>> TcpCotpConnection<T> {
//     pub fn new(tpkt_connection: T) -> Self {
//         TcpCotpConnection { tpkt_connection }
//     }
// }

// impl<T: TpktConnection<SocketAddr>> CotpConnection<T> for TcpCotpConnection<T> {
//     async fn recv(&mut self) -> Result<CotpRecvResult, CotpError> {
//         loop {
//             let buffer = &mut self.receive_buffer;
//             match self.parser.parse(buffer) {
//                 Ok(CotpParserResult::Data(x)) => return Ok(CotpRecvResult::Data(x)),
//                 Ok(CotpParserResult::InProgress) => (),
//                 Err(x) => return Err(x),
//             };
//             if self.stream.read_buf(buffer).await? == 0 {
//                 return Ok(CotpRecvResult::Closed);
//             };
//             match self.parser.parse(buffer) {
//                 Ok(CotpParserResult::Data(x)) => return Ok(CotpRecvResult::Data(x)),
//                 Ok(CotpParserResult::InProgress) => (),
//                 Err(x) => return Err(x),
//             }
//         }
//     }

//     async fn send(&mut self, data: &[u8]) -> Result<(), CotpError> {
//         if data.len() > MAX_PAYLOAD_LENGTH {
//             return Err(CotpError::ProtocolError(format!("Cotp user data must be less than or equal to {} but was {}", MAX_PAYLOAD_LENGTH, data.len())));
//         }
//         let packet_length = ((data.len() + HEADER_LENGTH) as u16).to_be_bytes();
//         self.stream.write_all(&[0x03u8, 0x00u8]).await?;
//         self.stream.write_all(&packet_length).await?;
//         Ok(self.stream.write_all(data).await?)
//     }
// }
