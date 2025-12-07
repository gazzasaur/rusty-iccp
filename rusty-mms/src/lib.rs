pub mod api;
pub(crate) mod error;
pub(crate) mod parameters;
pub(crate) mod pdu;
pub mod service;

use std::marker::PhantomData;

pub use api::*;
use rusty_acse::{AcseRequestInformation, RustyOsiSingleValueAcseInitiatorIsoStack, RustyOsiSingleValueAcseReaderIsoStack, RustyOsiSingleValueAcseWriterIsoStack};
use rusty_copp::{CoppConnectionInformation, RustyCoppInitiatorIsoStack};
use rusty_cosp::{CospConnectionInformation, TcpCospInitiator};
use rusty_cotp::{CotpConnectInformation, TcpCotpConnection, TcpCotpReader, TcpCotpWriter};
use rusty_tpkt::{TpktConnection, TpktReader, TpktWriter};
pub use service::*;

use crate::error::to_mms_error;

pub type RustyMmsReaderIsoStack<R> = RustyMmsReader<RustyOsiSingleValueAcseReaderIsoStack<R>>;
pub type RustyMmsWriterIsoStack<W> = RustyMmsWriter<RustyOsiSingleValueAcseWriterIsoStack<W>>;
pub type RustyMmsInitiatorIsoStack<R, W> = RustyMmsInitiator<RustyOsiSingleValueAcseInitiatorIsoStack<R, W>, RustyOsiSingleValueAcseReaderIsoStack<R>, RustyOsiSingleValueAcseWriterIsoStack<W>>;
// pub type RustyMmsListenerIsoStack<R, W> = RustyMmsListener<RustyAcseResponderIsoStack<R, W>, RustyAcseReaderIsoStack<R>, RustyAcseWriterIsoStack<W>>;
// pub type RustyMmsResponderIsoStack<R, W> = RustyMmsResponder<RustyAcseResponderIsoStack<R, W>, RustyAcseReaderIsoStack<R>, RustyAcseWriterIsoStack<W>>;

pub struct OsiMmsConnectionFactory<T: TpktConnection, R: TpktReader, W: TpktWriter> {
    _tpkt_connection: PhantomData<T>,
    _tpkt_reader: PhantomData<R>,
    _tpkt_writer: PhantomData<W>,
}

impl<T: TpktConnection, R: TpktReader, W: TpktWriter> OsiMmsConnectionFactory<T, R, W> {
    pub async fn connect(
        tpkt_connection: T,
        cotp_information: CotpConnectInformation,
        cosp_information: CospConnectionInformation,
        copp_information: CoppConnectionInformation,
        acse_information: AcseRequestInformation,
        mms_information: MmsRequestInformation,
    ) -> Result<(), MmsError> {
        let cotp_client = TcpCotpConnection::<R, W>::initiate(tpkt_connection, cotp_information)
            .await
            .map_err(to_mms_error("Failed to establish a COTP connection when creating an MMS association"))?;
        let cosp_client = TcpCospInitiator::<TcpCotpReader<R>, TcpCotpWriter<W>>::new(cotp_client, cosp_information)
            .await
            .map_err(to_mms_error("Failed to establish a COSP connection when creating an MMS association"))?;
        let copp_client = RustyCoppInitiatorIsoStack::<R, W>::new(cosp_client, copp_information);
        let acse_client = RustyOsiSingleValueAcseInitiatorIsoStack::<R, W>::new(copp_client, acse_information);

        let mms_client = RustyMmsInitiatorIsoStack::<R, W>::new(acse_client, mms_information);
        mms_client.initiate().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use der_parser::Oid;
    use rusty_acse::{AcseResponseInformation, RustyOsiSingleValueAcseListenerIsoStack};
    use rusty_copp::RustyCoppListener;
    use rusty_cosp::{TcpCospListener, TcpCospReader, TcpCospResponder, TcpCospWriter};
    use rusty_cotp::{CotpAcceptInformation, TcpCotpAcceptor, CotpResponder};
    use rusty_tpkt::{TcpTpktConnection, TcpTpktReader, TcpTpktServer, TcpTpktWriter};
    use tokio::join;
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_works() -> Result<(), anyhow::Error> {
        let test_address = "127.0.0.1:10002".parse()?;
        let client_path = async {
            tokio::time::sleep(Duration::from_millis(1)).await; // Give the server time to start
            let tpkt_client = TcpTpktConnection::connect(test_address).await?;
            let a = OsiMmsConnectionFactory::<TcpTpktConnection, TcpTpktReader, TcpTpktWriter>::connect(
                tpkt_client,
                CotpConnectInformation::default(),
                CospConnectionInformation::default(),
                CoppConnectionInformation::default(),
                AcseRequestInformation {
                    application_context_name: Oid::from(&[1, 2, 3])?,
                    called_ap_title: None,
                    called_ae_qualifier: None,
                    called_ap_invocation_identifier: None,
                    called_ae_invocation_identifier: None,
                    calling_ap_title: None,
                    calling_ae_qualifier: None,
                    calling_ap_invocation_identifier: None,
                    calling_ae_invocation_identifier: None,
                    implementation_information: None,
                },
                MmsRequestInformation::default(),
            )
            .await?;
            Ok(())
        };
        let server_path = async {
            let tpkt_server = TcpTpktServer::listen(test_address).await?;
            let (tpkt_connection, _) = tpkt_server.accept().await?;
            let (cotp_server, _) = TcpCotpAcceptor::<TcpTpktReader, TcpTpktWriter>::new(tpkt_connection).await?;
            let cotp_connection = cotp_server.accept(CotpAcceptInformation::default()).await?;
            let (cosp_listener, _) = TcpCospListener::<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>::new(cotp_connection).await?;
            let (copp_listener, _) =
                RustyCoppListener::<TcpCospResponder<TcpCotpReader<TcpTpktReader>, TcpCotpWriter<TcpTpktWriter>>, TcpCospReader<TcpCotpReader<TcpTpktReader>>, TcpCospWriter<TcpCotpWriter<TcpTpktWriter>>>::new(cosp_listener).await?;
            let acse_listener = RustyOsiSingleValueAcseListenerIsoStack::<TcpTpktReader, TcpTpktWriter>::new(copp_listener).await?;
            Ok(())
        };

        let (copp_client, copp_server): (Result<_, anyhow::Error>, Result<_, anyhow::Error>) = join!(client_path, server_path);

        Ok(())
    }
}
