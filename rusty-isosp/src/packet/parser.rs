use std::collections::VecDeque;

pub struct SpduParser {
    user_data: VecDeque<u8>
}

impl SpduParser {
    pub fn new() -> Self {
        Self { user_data: VecDeque::new() }
    }

    pub fn parse(data: Vec<u8>) {
        
    }   
}

