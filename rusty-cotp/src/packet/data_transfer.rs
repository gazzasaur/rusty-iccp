pub const DATA_TRANSFER_CODE: u8 = 0xF0u8;

#[derive(Debug, PartialEq)]
pub struct DataTransfer {
    end_of_transmission: bool,
    user_data: Vec<u8>,
}

impl DataTransfer {
    pub fn new(end_of_transmission: bool, user_data: &[u8]) -> Self {
        Self {
            end_of_transmission,
            user_data: user_data.into(),
        }
    }

    pub fn end_of_transmission(&self) -> bool {
        self.end_of_transmission
    }

    pub fn user_data(&self) -> &[u8] {
        &self.user_data
    }
}
