use std::collections::VecDeque;

use bytes::BytesMut;
use rusty_tpkt::{ProtocolInformation, TpktConnection, TpktReader, TpktWriter};

use crate::{
    api::{CotpConnection, CotpError, CotpProtocolInformation, CotpReader, CotpResponder, CotpWriter},
    packet::{
        connection_confirm::ConnectionConfirm,
        connection_request::ConnectionRequest,
        data_transfer::DataTransfer,
        parameters::{ConnectionClass, CotpParameter, TpduSize},
        payload::TransportProtocolDataUnit,
    },
    parser::packet::TransportProtocolDataUnitParser,
    serialiser::packet::serialise,
};

pub struct TcpCotpConnection<R: TpktReader, W: TpktWriter> {
    reader: R,
    writer: W,

    max_payload_size: usize,
    parser: TransportProtocolDataUnitParser,
    protocol_infomation_list: Vec<Box<dyn ProtocolInformation>>,
}

impl<R: TpktReader, W: TpktWriter> TcpCotpConnection<R, W> {
    pub async fn initiate(connection: impl TpktConnection, options: CotpProtocolInformation) -> Result<TcpCotpConnection<impl TpktReader, impl TpktWriter>, CotpError> {
        // FIXME WARN Log the differences between remote and local parameters.
        let mut protocol_infomation_list = connection.get_protocol_infomation_list().clone();
        let local_calling_tsap = options.calling_tsap_id().cloned();

        let source_reference: u16 = options.initiator_reference();
        let parser = TransportProtocolDataUnitParser::new();
        let (mut reader, mut writer) = connection.split().await?;

        send_connection_request(&mut writer, source_reference, options).await?;
        let connection_confirm = receive_connection_confirm(&mut reader, &parser).await?;
        let (_, max_payload_size) = calculate_remote_size_payload(connection_confirm.parameters()).await?;

        let remote_called_tsap = connection_confirm.parameters().iter().filter_map(|x| if let CotpParameter::CalledTsap(tsap) = x { Some(tsap.clone()) } else { None }).last();
        protocol_infomation_list.push(Box::new(CotpProtocolInformation::new(source_reference, connection_confirm.destination_reference(), local_calling_tsap, remote_called_tsap)));

        Ok(TcpCotpConnection::new(reader, writer, max_payload_size, protocol_infomation_list).await)
    }

    async fn new(reader: R, writer: W, max_payload_size: usize, protocol_infomation_list: Vec<Box<dyn ProtocolInformation>>) -> TcpCotpConnection<R, W> {
        TcpCotpConnection { reader, writer, max_payload_size, parser: TransportProtocolDataUnitParser::new(), protocol_infomation_list }
    }
}

impl<R: TpktReader, W: TpktWriter> CotpConnection for TcpCotpConnection<R, W> {
    fn get_protocol_infomation_list(&self) -> &Vec<Box<dyn rusty_tpkt::ProtocolInformation>> {
        &self.protocol_infomation_list
    }

    async fn split(self) -> Result<(impl CotpReader, impl CotpWriter), CotpError> {
        let reader = self.reader;
        let writer = self.writer;
        Ok((TcpCotpReader::new(reader, self.parser), TcpCotpWriter::new(writer, self.max_payload_size)))
    }
}

pub struct TcpCotpAcceptor<R: TpktReader, W: TpktWriter> {
    reader: R,
    writer: W,
    initiator_reference: u16,
    max_payload_size: usize,
    max_payload_indicator: TpduSize,
    called_tsap_id: Option<Vec<u8>>,
    calling_tsap_id: Option<Vec<u8>>,
    lower_layer_protocol_options_list: Vec<Box<dyn ProtocolInformation>>,
}

impl<R: TpktReader, W: TpktWriter> TcpCotpAcceptor<R, W> {
    pub async fn new(tpkt_connection: impl TpktConnection) -> Result<(TcpCotpAcceptor<impl TpktReader, impl TpktWriter>, CotpProtocolInformation), CotpError> {
        let parser = TransportProtocolDataUnitParser::new();
        let lower_layer_protocol_options_list = tpkt_connection.get_protocol_infomation_list().clone();
        let (mut reader, writer) = tpkt_connection.split().await?;

        let connection_request = receive_connection_request(&mut reader, &parser).await?;
        let (max_payload_indicator, max_payload_size) = calculate_remote_size_payload(connection_request.parameters()).await?;
        verify_class_compatibility(&connection_request).await?;

        let mut calling_tsap_id = None;
        let mut called_tsap_id = None;
        for parameter in connection_request.parameters() {
            match parameter {
                CotpParameter::CallingTsap(tsap_id) => calling_tsap_id = Some(tsap_id.clone()),
                CotpParameter::CalledTsap(tsap_id) => called_tsap_id = Some(tsap_id.clone()),
                _ => (),
            }
        }

        Ok((
            TcpCotpAcceptor {
                reader,
                writer,
                max_payload_size,
                max_payload_indicator,
                called_tsap_id: called_tsap_id.clone(),
                calling_tsap_id: calling_tsap_id.clone(),
                initiator_reference: connection_request.source_reference(),
                lower_layer_protocol_options_list,
            },
            CotpProtocolInformation::new(connection_request.source_reference(), 0, calling_tsap_id, called_tsap_id),
        ))
    }
}

impl<R: TpktReader, W: TpktWriter> CotpResponder for TcpCotpAcceptor<R, W> {
    async fn accept(mut self, options: CotpProtocolInformation) -> Result<impl CotpConnection, CotpError> {
        send_connection_confirm(&mut self.writer, options.responder_reference(), self.initiator_reference, self.max_payload_indicator, self.calling_tsap_id, self.called_tsap_id).await?;
        Ok(TcpCotpConnection::new(self.reader, self.writer, self.max_payload_size, self.lower_layer_protocol_options_list).await)
    }
}

pub struct TcpCotpReader<R: TpktReader> {
    reader: R,
    parser: TransportProtocolDataUnitParser,

    data_buffer: BytesMut,
}

impl<R: TpktReader> TcpCotpReader<R> {
    pub fn new(reader: R, parser: TransportProtocolDataUnitParser) -> Self {
        Self { reader, parser, data_buffer: BytesMut::new() }
    }
}

impl<R: TpktReader> CotpReader for TcpCotpReader<R> {
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, CotpError> {
        loop {
            // FIXME SECURITY Check inbound size per packet and add a limit on the max constructed payload size.

            let raw_data = match self.reader.recv().await? {
                None => return Ok(None),
                Some(raw_data) => raw_data,
            };
            let data_transfer = match self.parser.parse(raw_data.as_slice())? {
                // Choosing the standards based option of reporting the TPDU error locally but not sending an error.
                TransportProtocolDataUnit::ER(tpdu_error) => return Err(CotpError::ProtocolError(format!("Received an error from the remote host: {:?}", tpdu_error.reason()).into())),
                TransportProtocolDataUnit::CR(_) => return Err(CotpError::ProtocolError("Received a Connection Request when expecting data.".into())),
                TransportProtocolDataUnit::CC(_) => return Err(CotpError::ProtocolError("Received a Connection Config when expecting data.".into())),
                TransportProtocolDataUnit::DR(_) => return Ok(None),
                TransportProtocolDataUnit::DT(data_transfer) => data_transfer,
            };

            // Not performing strict checking of source and destination reference:
            // - This is running over a TCP stream.
            // - It can be checked from the protocol info.
            // - Going too strict can lead to more interop problems than it is worth.

            self.data_buffer.extend_from_slice(data_transfer.user_data());
            if data_transfer.end_of_transmission() {
                let data = self.data_buffer.to_vec();
                self.data_buffer.clear();
                return Ok(Some(data));
            }
        }
    }
}

pub struct TcpCotpWriter<W: TpktWriter> {
    writer: W,
    max_payload_size: usize,
    chunks: VecDeque<Vec<u8>>,
}

impl<W: TpktWriter> TcpCotpWriter<W> {
    pub fn new(writer: W, max_payload_size: usize) -> Self {
        Self { writer, max_payload_size, chunks: VecDeque::new() }
    }
}

impl<W: TpktWriter> CotpWriter for TcpCotpWriter<W> {
    async fn send(&mut self, input: &mut VecDeque<Vec<u8>>) -> Result<(), CotpError> {
        const HEADER_LENGTH: usize = 3;

        while let Some(data_item) = input.pop_front() {
            let chunks = data_item.as_slice().chunks(self.max_payload_size - HEADER_LENGTH);
            let chunk_count = chunks.len();
            for (chunk_index, chunk_data) in chunks.enumerate() {
                let end_of_transmission = chunk_index + 1 >= chunk_count;
                let tpdu = DataTransfer::new(end_of_transmission, chunk_data);
                let tpdu_data = serialise(&TransportProtocolDataUnit::DT(tpdu))?;
                self.chunks.push_back(tpdu_data);
            }
        }

        while !self.chunks.is_empty() {
            self.writer.send(&mut self.chunks).await?;
        }

        // Perform one more to ensure lower levels are also flushed even if this layer is complete.
        self.writer.send(&mut self.chunks).await?;
        Ok(())
    }
}

async fn verify_class_compatibility(connection_request: &ConnectionRequest) -> Result<(), CotpError> {
    let empty_set = Vec::new();
    let class_parameters = connection_request
        .parameters()
        .iter()
        .filter_map(|p| match p {
            CotpParameter::AlternativeClassParameter(x) => Some(x),
            _ => None,
        })
        .last()
        .unwrap_or(&empty_set);

    // Verify we can downgrade to Class 0
    match connection_request.preferred_class() {
        ConnectionClass::Class0 => (),
        ConnectionClass::Class1 => (),
        ConnectionClass::Class2 if class_parameters.contains(&&ConnectionClass::Class0) => (),
        ConnectionClass::Class3 if class_parameters.contains(&&ConnectionClass::Class0) => (),
        ConnectionClass::Class3 if class_parameters.contains(&&ConnectionClass::Class1) => (),
        ConnectionClass::Class4 if class_parameters.contains(&&ConnectionClass::Class0) => (),
        ConnectionClass::Class4 if class_parameters.contains(&&ConnectionClass::Class1) => (),
        _ => {
            return Err(CotpError::ProtocolError(format!("Cannot downgrade connection request to Class 0 {:?} - {:?}", connection_request.preferred_class(), class_parameters)));
        }
    };
    Ok(())
}

async fn receive_connection_request(reader: &mut impl TpktReader, parser: &TransportProtocolDataUnitParser) -> Result<ConnectionRequest, CotpError> {
    let data = match reader.recv().await {
        Ok(Some(x)) => x,
        Ok(None) => return Err(CotpError::ProtocolError("The connection was closed before the COTP handshake was complete.".into())),
        Err(e) => return Err(e.into()),
    };
    return Ok(match parser.parse(data.as_slice())? {
        TransportProtocolDataUnit::CR(x) => x,
        TransportProtocolDataUnit::CC(_) => return Err(CotpError::ProtocolError("Expected connection request on handshake but got a connextion confirm".into())),
        TransportProtocolDataUnit::DR(_) => return Err(CotpError::ProtocolError("Expected connection request on handshake but got a disconnect reqeust".into())),
        TransportProtocolDataUnit::DT(_) => return Err(CotpError::ProtocolError("Expected connection request on handshake but got a data transfer".into())),
        TransportProtocolDataUnit::ER(_) => return Err(CotpError::ProtocolError("Expected connection request on handshake but got a error response".into())),
    });
}

async fn calculate_remote_size_payload(parameters: &[CotpParameter]) -> Result<(TpduSize, usize), CotpError> {
    let parameter: &TpduSize = parameters
        .iter()
        .filter_map(|p| match p {
            CotpParameter::TpduLengthParameter(x) => Some(x),
            _ => None,
        })
        .last()
        .unwrap_or(&TpduSize::Size128);

    Ok(match parameter {
        TpduSize::Size8192 => return Err(CotpError::ProtocolError("The remote side selected an 8192 bytes COTP payload but Class 0 support a maximum for 2048 bytes.".into())),
        TpduSize::Size4096 => return Err(CotpError::ProtocolError("The remote side selected an 4096 bytes COTP payload but Class 0 support a maximum for 2048 bytes.".into())),
        TpduSize::Unknown(x) => return Err(CotpError::ProtocolError(format!("The requested TPDU size is unknown {:?}.", x).into())),
        TpduSize::Size128 => (TpduSize::Size128, 128),
        TpduSize::Size256 => (TpduSize::Size256, 256),
        TpduSize::Size512 => (TpduSize::Size512, 512),
        TpduSize::Size1024 => (TpduSize::Size1024, 1024),
        TpduSize::Size2048 => (TpduSize::Size2048, 2048),
    })
}

async fn send_connection_confirm<W: TpktWriter>(writer: &mut W, source_reference: u16, destination_reference: u16, size: TpduSize, calling_tsap_id: Option<Vec<u8>>, called_tsap_id: Option<Vec<u8>>) -> Result<(), CotpError> {
    let mut parameters = vec![CotpParameter::TpduLengthParameter(size)];
    if let Some(tsap_id) = calling_tsap_id {
        parameters.push(CotpParameter::CallingTsap(tsap_id));
    }
    if let Some(tsap_id) = called_tsap_id {
        parameters.push(CotpParameter::CalledTsap(tsap_id));
    }

    let payload = serialise(&TransportProtocolDataUnit::CC(ConnectionConfirm::new(0, source_reference, destination_reference, ConnectionClass::Class0, vec![], parameters, &[])))?;
    Ok(writer.send(&mut VecDeque::from_iter(vec![payload].into_iter())).await?)
}

async fn send_connection_request(writer: &mut impl TpktWriter, source_reference: u16, options: CotpProtocolInformation) -> Result<(), CotpError> {
    let mut parameters = vec![CotpParameter::TpduLengthParameter(TpduSize::Size2048)];
    if let Some(calling_tsap) = options.calling_tsap_id() {
        parameters.push(CotpParameter::CallingTsap(calling_tsap.clone()));
    }
    if let Some(called_tsap) = options.called_tsap_id() {
        parameters.push(CotpParameter::CalledTsap(called_tsap.clone()));
    }

    let payload = serialise(&TransportProtocolDataUnit::CR(ConnectionRequest::new(source_reference, 0, ConnectionClass::Class0, vec![], parameters, &[])))?;
    Ok(writer.send(&mut VecDeque::from_iter(vec![payload].into_iter())).await?)
}

async fn receive_connection_confirm(reader: &mut impl TpktReader, parser: &TransportProtocolDataUnitParser) -> Result<ConnectionConfirm, CotpError> {
    let data = match reader.recv().await {
        Ok(Some(x)) => x,
        Ok(None) => return Err(CotpError::ProtocolError("The connection was closed before the COTP handshake was complete.".into())),
        Err(e) => return Err(e.into()),
    };
    return Ok(match parser.parse(data.as_slice())? {
        TransportProtocolDataUnit::CC(x) if x.preferred_class() != &ConnectionClass::Class0 => return Err(CotpError::ProtocolError("Remote failed to select COTP Class 0.".into())),
        TransportProtocolDataUnit::CC(x) => x,
        TransportProtocolDataUnit::CR(_) => return Err(CotpError::ProtocolError("Expected connection confirmed on handshake but got a connection request".into())),
        TransportProtocolDataUnit::DR(_) => return Err(CotpError::ProtocolError("Expected connection confirmed on handshake but got a disconnect reqeust".into())),
        TransportProtocolDataUnit::DT(_) => return Err(CotpError::ProtocolError("Expected connection confirmed on handshake but got a data transfer".into())),
        TransportProtocolDataUnit::ER(_) => return Err(CotpError::ProtocolError("Expected connection confirmed on handshake but got a error response".into())),
    });
}
