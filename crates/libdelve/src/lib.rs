//! # libdelve
//!
//! Core library for the Delegatable Verification Protocol (DelVe).
//!
//! This library provides functionality for both delegates and verifiers to implement
//! the DelVe protocol as specified in SPEC.md.

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
