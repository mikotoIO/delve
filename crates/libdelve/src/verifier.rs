//! Verifier implementation for validating domain ownership

use crate::{
    challenge::{generate_challenge, validate_challenge_expiry, validate_challenge_format},
    crypto::verify_signature,
    discovery::discover_dns_config,
    Error, Result, SigningPayload, VerificationToken,
};
use chrono::{DateTime, Duration, Utc};

#[cfg(feature = "delegate")]
use crate::{delegate_client::DelegateClient, ChallengeRequest};

/// Verifier for validating domain ownership through DelVe protocol
pub struct Verifier {
    verifier_name: String,
    verifier_id: String,
    challenge_duration: Duration,
}

impl Verifier {
    /// Create a new verifier
    ///
    /// # Arguments
    ///
    /// * `verifier_name` - Human-readable name of the verifier service
    /// * `verifier_id` - Unique identifier for this verifier instance
    /// * `challenge_duration` - How long challenges remain valid (recommended: 15-60 minutes)
    pub fn new(
        verifier_name: impl Into<String>,
        verifier_id: impl Into<String>,
        challenge_duration: Duration,
    ) -> Self {
        Self {
            verifier_name: verifier_name.into(),
            verifier_id: verifier_id.into(),
            challenge_duration,
        }
    }

    /// Discover how a domain performs verification
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to verify
    ///
    /// # Returns
    ///
    /// DNS configuration including mode (delegate/direct) and public key
    pub async fn discover(&self, domain: &str) -> Result<crate::DnsConfig> {
        discover_dns_config(domain).await
    }

    /// Generate a challenge for a domain
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to verify
    ///
    /// # Returns
    ///
    /// A tuple of (challenge_string, expiration_time)
    pub fn create_challenge(&self, _domain: &str) -> Result<(String, DateTime<Utc>)> {
        generate_challenge(self.challenge_duration)
    }

    /// Submit a challenge to a delegate service
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain being verified
    /// * `delegate_endpoint` - The delegate service endpoint URL
    /// * `challenge` - The challenge string
    /// * `expires_at` - When the challenge expires
    /// * `user_identifier` - Optional user identifier for display (e.g., "[email protected]")
    ///
    /// # Returns
    ///
    /// The request ID for polling
    #[cfg(feature = "delegate")]
    pub async fn submit_challenge_to_delegate(
        &self,
        domain: &str,
        delegate_endpoint: &str,
        challenge: &str,
        expires_at: DateTime<Utc>,
        user_identifier: Option<String>,
    ) -> Result<String> {
        let client = DelegateClient::new(delegate_endpoint);

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("serviceName".to_string(), self.verifier_name.clone());
        if let Some(user_id) = user_identifier {
            metadata.insert("userIdentifier".to_string(), user_id);
        }

        let request = ChallengeRequest {
            domain: domain.to_string(),
            verifier: self.verifier_name.clone(),
            verifier_id: self.verifier_id.clone(),
            challenge: challenge.to_string(),
            expires_at,
            metadata: Some(metadata),
        };

        let response = client.submit_challenge(&request).await?;

        Ok(response.request_id)
    }

    /// Poll for a verification token from a delegate service
    ///
    /// # Arguments
    ///
    /// * `delegate_endpoint` - The delegate service endpoint URL
    /// * `request_id` - The request ID from challenge submission
    /// * `max_attempts` - Maximum number of polling attempts (default: 60)
    /// * `poll_interval_secs` - Seconds to wait between polls (default: 5)
    ///
    /// # Returns
    ///
    /// The verification token if authorized
    #[cfg(feature = "delegate")]
    pub async fn poll_for_token(
        &self,
        delegate_endpoint: &str,
        request_id: &str,
        max_attempts: Option<u32>,
        poll_interval_secs: Option<u64>,
    ) -> Result<VerificationToken> {
        let client = DelegateClient::new(delegate_endpoint);

        let attempts = max_attempts.unwrap_or(60);
        let interval = std::time::Duration::from_secs(poll_interval_secs.unwrap_or(5));

        client.poll_for_token(request_id, attempts, interval).await
    }

    /// Verify a verification token
    ///
    /// This validates:
    /// - Challenge format
    /// - Challenge hasn't expired
    /// - Signature is valid
    /// - Domain and verifier ID match
    ///
    /// # Arguments
    ///
    /// * `token` - The verification token to validate
    /// * `expected_domain` - The domain we expect to be verified
    /// * `expected_challenge` - The challenge we originally issued
    /// * `dns_public_key` - The public key from DNS discovery
    ///
    /// # Returns
    ///
    /// Ok(()) if verification succeeds
    pub fn verify_token(
        &self,
        token: &VerificationToken,
        expected_domain: &str,
        expected_challenge: &str,
        dns_public_key: &str,
    ) -> Result<()> {
        // Validate challenge format
        validate_challenge_format(&token.challenge)?;

        // Check expiration
        validate_challenge_expiry(token.expires_at)?;

        // Verify domain matches
        if token.domain != expected_domain {
            return Err(Error::InvalidResponse(format!(
                "Domain mismatch: expected {}, got {}",
                expected_domain, token.domain
            )));
        }

        // Verify challenge matches
        if token.challenge != expected_challenge {
            return Err(Error::InvalidResponse(
                "Challenge mismatch".to_string(),
            ));
        }

        // Verify verifier ID matches
        if token.verifier_id != self.verifier_id {
            return Err(Error::InvalidResponse(format!(
                "Verifier ID mismatch: expected {}, got {}",
                self.verifier_id, token.verifier_id
            )));
        }

        // Verify public key matches DNS record
        if token.public_key != dns_public_key {
            return Err(Error::InvalidResponse(
                "Public key mismatch with DNS record".to_string(),
            ));
        }

        // Construct signing payload
        let payload = SigningPayload {
            challenge: token.challenge.clone(),
            domain: token.domain.clone(),
            signed_at: token.signed_at.to_rfc3339(),
            verifier: token.verifier.clone(),
            verifier_id: token.verifier_id.clone(),
        };

        // Verify signature
        verify_signature(&token.public_key, &token.signature, &payload)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let verifier = Verifier::new(
            "Test Service",
            "test-instance-123",
            Duration::minutes(30),
        );

        assert_eq!(verifier.verifier_name, "Test Service");
        assert_eq!(verifier.verifier_id, "test-instance-123");
    }

    #[test]
    fn test_create_challenge() {
        let verifier = Verifier::new(
            "Test Service",
            "test-instance-123",
            Duration::minutes(30),
        );

        let (challenge, expires_at) = verifier.create_challenge("example.com").unwrap();

        // Challenge should be non-empty
        assert!(!challenge.is_empty());

        // Expiration should be in the future
        assert!(expires_at > Utc::now());
    }

    // More comprehensive tests would require mocking DNS and HTTP calls
}
