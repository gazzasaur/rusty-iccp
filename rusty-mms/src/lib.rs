pub mod api;
pub mod service;

pub use api::*;
pub use service::*;

// pub type RustyMmsReaderIsoStack<R> = RustyMmsReader<RustyCoppReaderIsoStack<R>>;
// pub type RustyMmsWriterIsoStack<W> = RustyMmsWriter<RustyCoppWriterIsoStack<W>>;
// pub type RustyMmsInitiatorIsoStack<R, W> = RustyMmsInitiator<RustyCoppInitiatorIsoStack<R, W>, RustyCoppReaderIsoStack<R>, RustyCoppWriterIsoStack<W>>;
// pub type RustyMmsListenerIsoStack<R, W> = RustyMmsListener<RustyCoppResponderIsoStack<R, W>, RustyCoppReaderIsoStack<R>, RustyCoppWriterIsoStack<W>>;
// pub type RustyMmsResponderIsoStack<R, W> = RustyMmsResponder<RustyCoppResponderIsoStack<R, W>, RustyCoppReaderIsoStack<R>, RustyCoppWriterIsoStack<W>>;


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
