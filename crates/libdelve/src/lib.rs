#![doc = include_str!("../README.md")]

pub mod discovery;
pub mod challenge;
pub mod crypto;
pub mod types;

#[cfg(feature = "delegate")]
pub mod delegate_client;

pub mod verifier;
pub mod error;

pub use error::{Error, Result};
pub use types::*;
