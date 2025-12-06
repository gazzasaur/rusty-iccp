pub mod api;
pub mod service;
pub(crate) mod parameters;
pub(crate) mod pdu;
pub(crate) mod error;

pub use api::*;
use rusty_acse::{RustyOsiSingleValueAcseInitiatorIsoStack, RustyOsiSingleValueAcseReaderIsoStack, RustyOsiSingleValueAcseWriterIsoStack};
pub use service::*;

pub type RustyMmsReaderIsoStack<R> = RustyMmsReader<RustyOsiSingleValueAcseReaderIsoStack<R>>;
pub type RustyMmsWriterIsoStack<W> = RustyMmsWriter<RustyOsiSingleValueAcseWriterIsoStack<W>>;
pub type RustyMmsInitiatorIsoStack<R, W> = RustyMmsInitiator<RustyOsiSingleValueAcseInitiatorIsoStack<R, W>, RustyOsiSingleValueAcseReaderIsoStack<R>, RustyOsiSingleValueAcseWriterIsoStack<W>>;
// pub type RustyMmsListenerIsoStack<R, W> = RustyMmsListener<RustyAcseResponderIsoStack<R, W>, RustyAcseReaderIsoStack<R>, RustyAcseWriterIsoStack<W>>;
// pub type RustyMmsResponderIsoStack<R, W> = RustyMmsResponder<RustyAcseResponderIsoStack<R, W>, RustyAcseReaderIsoStack<R>, RustyAcseWriterIsoStack<W>>;


pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
