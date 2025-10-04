//! Core types for the DelVe protocol

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{challenge::generate_challenge, Result};

/// Protocol version
pub const PROTOCOL_VERSION: &str = "delve0.1";

/// Verification mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

impl DnsConfig {
    /// Format as a DNS TXT record value
    ///
    /// Returns a string in the format: `v=delve0.1; mode=delegate; endpoint=https://...; key=<base64>`
    pub fn to_dns_record(&self) -> String {
        let mut parts = vec![
            format!("v={}", self.version),
            format!(
                "mode={}",
                match self.mode {
                    VerificationMode::Delegate => "delegate",
                    VerificationMode::Direct => "direct",
                }
            ),
        ];

        if let Some(ref endpoint) = self.endpoint {
            parts.push(format!("endpoint={}", endpoint));
        }

        parts.push(format!("key={}", self.public_key));

        parts.join("; ")
    }
}

/// Challenge request to delegate service
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    pub domain: String,
    pub verifier_id: String,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl ChallengeRequest {
    pub fn new(domain: &str, verifier_id: &str, expires_in: Duration) -> Result<Self> {
        let (ch, exp) = generate_challenge(expires_in)?;
        Ok(ChallengeRequest {
            domain: domain.to_string(),
            verifier_id: verifier_id.to_string(),
            challenge: ch,
            expires_at: exp,
            metadata: None,
        })
    }

    pub fn with_meta(self, metadata: HashMap<String, serde_json::Value>) -> Self {
        Self {
            metadata: Some(metadata),
            ..self
        }
    }

    /// Create a signing payload for this challenge request
    pub fn create_signing_payload(&self, signed_at: DateTime<Utc>) -> SigningPayload {
        SigningPayload {
            challenge: self.challenge.clone(),
            domain: self.domain.clone(),
            signed_at: signed_at.to_rfc3339(),
            verifier_id: self.verifier_id.clone(),
        }
    }
}

/// Challenge response from delegate service
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub request_id: String,
    pub status: RequestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// Token response from delegate service
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum TokenResponse {
    Authorized {
        request_id: String,
        token: VerificationToken,
    },
    Pending {
        request_id: String,
        authorization_url: String,
    },
    Rejected {
        request_id: String,
        rejected_at: DateTime<Utc>,
    },
}

/// Status of a verification request
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RequestStatus {
    Pending,
    Authorized,
    Rejected,
}

/// Verification token with signature
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationToken {
    pub domain: String,
    pub verifier_id: String,
    pub challenge: String,
    pub signature: String,
    pub public_key: String,
    pub key_id: String,
    pub signed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl VerificationToken {
    /// Create a new verification token from a challenge request
    pub fn new(
        request: &ChallengeRequest,
        signature: String,
        public_key: String,
        key_id: String,
        signed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            domain: request.domain.clone(),
            verifier_id: request.verifier_id.clone(),
            challenge: request.challenge.clone(),
            signature,
            public_key,
            key_id,
            signed_at,
            expires_at: request.expires_at,
        }
    }
}

/// Canonical signing payload
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningPayload {
    pub challenge: String,
    pub domain: String,
    pub signed_at: String,
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
