use thiserror::Error;

#[derive(Error, Debug)]
pub enum CotpError {
    #[error("Failed to perform IO operation")]
    IoError(#[from] std::io::Error),

    #[error("Protocol Error: {}", .0)]
    ProtocolError(String),

    #[error("Unknown Error")]
    UnknownError(#[from] anyhow::Error),
}
