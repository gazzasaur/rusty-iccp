pub mod error;
pub mod model;
pub mod parser;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use std::io;

    use crate::error::CotpError;

    use super::*;

    #[test]
    fn it_works() {
        let e = { Err::<(), io::Error>(io::Error::from_raw_os_error(1)) }.map_err(|e| CotpError::IoError(e));
        match e {
            Err(e) => print!("{:?}", e),
            _ => ()
        };

        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
