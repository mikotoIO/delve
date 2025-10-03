//! Core types for the DelVe protocol

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Protocol version
pub const PROTOCOL_VERSION: &str = "delve0.1";

/// Verification mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationMode {
    Delegate,
    Direct,
}

/// DNS record configuration
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub version: String,
    pub mode: VerificationMode,
    pub endpoint: Option<String>,
    pub public_key: String,
}

/// Challenge request to delegate service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub domain: String,
    pub verifier: String,
    #[serde(rename = "verifierId")]
    pub verifier_id: String,
    pub challenge: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

/// Challenge response from delegate service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: RequestStatus,
    #[serde(rename = "authorizationUrl")]
    pub authorization_url: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}

/// Token response from delegate service
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum TokenResponse {
    Authorized {
        #[serde(rename = "requestId")]
        request_id: String,
        token: VerificationToken,
    },
    Pending {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "authorizationUrl")]
        authorization_url: String,
    },
    Rejected {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "rejectedAt")]
        rejected_at: DateTime<Utc>,
    },
}

/// Status of a verification request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestStatus {
    Pending,
    Authorized,
    Rejected,
}

/// Verification token with signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationToken {
    pub domain: String,
    pub verifier: String,
    #[serde(rename = "verifierId")]
    pub verifier_id: String,
    pub challenge: String,
    pub signature: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "signedAt")]
    pub signed_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}

/// Canonical signing payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningPayload {
    pub challenge: String,
    pub domain: String,
    #[serde(rename = "signedAt")]
    pub signed_at: String,
    pub verifier: String,
    #[serde(rename = "verifierId")]
    pub verifier_id: String,
}

impl SigningPayload {
    /// Create canonical JSON representation for signing
    pub fn to_canonical_json(&self) -> crate::Result<String> {
        // Serialize with keys in alphabetical order (serde_json maintains field order)
        serde_json::to_string(self).map_err(Into::into)
    }
}

/// Error response from delegate service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}
