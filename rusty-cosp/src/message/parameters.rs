#[derive(Clone, Copy)]
pub(crate) enum TsduMaximumSize {
    Unlimited,
    Size(u16),
}
