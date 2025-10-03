//! Error types for libdelve

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Invalid DNS record format: {0}")]
    InvalidDnsRecord(String),

    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Challenge expired")]
    ChallengeExpired,

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[cfg(feature = "delegate")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Authorization pending")]
    AuthorizationPending,

    #[error("Authorization rejected")]
    AuthorizationRejected,

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(String),

    #[error("Invalid mode: {0}")]
    InvalidMode(String),

    #[error("Missing required field: {0}")]
    MissingField(String),
}
