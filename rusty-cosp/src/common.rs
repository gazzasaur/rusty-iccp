use crate::api::IsoSpError;

#[derive(Clone, Copy)]
pub enum TsduMaximumSize {
    Unlimited,
    Size(u16),
}

pub fn slice_tlv_data(data: &[u8]) -> Result<(u8, &[u8], usize), IsoSpError> {
    let (tag, data_offset, data_length) = if data.len() < 2 {
        return Err(IsoSpError::ProtocolError(format!("Not enough data to form an SPDU. Needed at least 2 bytes but {} found", data.len())));
    } else if data[1] == 0xFF && data.len() < 4 {
        return Err(IsoSpError::ProtocolError(format!("Not enough data to form an SPDU. Needed at least 4 bytes but {} found", data.len())));
    } else if data[1] == 0xFF {
        (
            data[0],
            4,
            u16::from_be_bytes(data[2..4].try_into().map_err(|e: std::array::TryFromSliceError| IsoSpError::InternalError(e.to_string()))?) as usize,
        )
    } else {
        (data[0], 2, data[1] as usize)
    };

    if data.len() < data_offset + data_length {
        return Err(IsoSpError::ProtocolError(format!(
            "Not enough data to form an SPDU. Needed at least {} bytes but {} found",
            data_offset + data_length,
            data.len()
        )));
    }

    return Ok((tag, &data[data_offset..(data_offset + data_length)], data_offset + data_length));
}


#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn it_should_split_data() -> Result<(), anyhow::Error> {
        let mut payload_data = vec![0u8; 50];
        rand::fill(payload_data.as_mut_slice());

        let mut payload: Vec<u8> = vec![0x12, 0x32];
        payload.extend_from_slice(payload_data.as_slice());
        let (subject_tag, subject_data, subject_consumed_data) = slice_tlv_data(&payload)?;
        assert_eq!(0x12, subject_tag);
        assert_eq!(payload_data, subject_data);
        assert_eq!(52, subject_consumed_data);

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_should_split_long_data() -> Result<(), anyhow::Error> {
        let mut payload_data = vec![0u8; 61234];
        rand::fill(payload_data.as_mut_slice());

        let mut payload: Vec<u8> = vec![0xab, 0xff, 0xef, 0x32];
        payload.extend_from_slice(payload_data.as_slice());
        let (subject_tag, subject_data, subject_consumed_data) = slice_tlv_data(&payload)?;
        assert_eq!(0xab, subject_tag);
        assert_eq!(payload_data, subject_data);
        assert_eq!(61238, subject_consumed_data);

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn it_should_split_composite_data() -> Result<(), anyhow::Error> {
        let mut payload: Vec<u8> = vec![0xab, 0x03, 0xfe, 0xdc, 0xba];
        payload.extend_from_slice(&[0x98, 0x00]);
        payload.extend_from_slice(&[0x76, 0x01, 0x54]);

        let mut consumed_data = 0;

        let (subject_tag, subject_data, subject_consumed_data) = slice_tlv_data(&payload)?;
        assert_eq!(0xab, subject_tag);
        assert_eq!(&[0xfe, 0xdc, 0xba], subject_data);
        assert_eq!(5, subject_consumed_data);
        consumed_data += subject_consumed_data;

        let (subject_tag, subject_data, subject_consumed_data) = slice_tlv_data(&payload[consumed_data..])?;
        assert_eq!(0x98, subject_tag);
        assert_eq!(0, subject_data.len());
        assert_eq!(2, subject_consumed_data);
        consumed_data += subject_consumed_data;

        let (subject_tag, subject_data, subject_consumed_data) = slice_tlv_data(&payload[consumed_data..])?;
        assert_eq!(0x76, subject_tag);
        assert_eq!(&[0x54], subject_data);
        assert_eq!(3, subject_consumed_data);

        Ok(())
    }
}
