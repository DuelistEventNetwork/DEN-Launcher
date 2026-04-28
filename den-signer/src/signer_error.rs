use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("manifest decode failed: {0}")]
    Decode(String),

    #[error("manifest validation failed: {0}")]
    Validation(String),

    #[error("signature error: {0}")]
    Signature(String),

    #[error("bitcode error: {0}")]
    Bitcode(String),

    #[error("{0}")]
    Other(String),
}
