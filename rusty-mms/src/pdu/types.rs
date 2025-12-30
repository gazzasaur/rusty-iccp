#[repr(u8)]
pub(crate) enum ConfirmedMmsPduType {
    ReadRequestPduType(ReadRequestPdu) = 1,
}
