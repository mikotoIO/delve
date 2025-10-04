//! HTTP client for interacting with delegate services

use crate::{ChallengeRequest, ChallengeResponse, Error, Result, TokenResponse, VerificationToken};
use reqwest::Client;

/// Client for interacting with a DelVe delegate service
pub struct DelegateClient {
    client: Client,
    base_url: String,
}

impl DelegateClient {
    /// Create a new delegate client
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Base URL of the delegate service (e.g., "https://verify.example.org")
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: endpoint.into(),
        }
    }

    /// Submit a challenge to the delegate service
    ///
    /// # Arguments
    ///
    /// * `request` - The challenge request
    ///
    /// # Returns
    ///
    /// The challenge response with request ID and authorization URL
    pub async fn submit_challenge(&self, request: &ChallengeRequest) -> Result<ChallengeResponse> {
        let url = format!("{}/v1/challenge", self.base_url);

        let response = self.client.post(&url).json(request).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(Error::InvalidResponse(format!(
                "HTTP {}: {}",
                status, error_text
            )));
        }

        let challenge_response: ChallengeResponse = response.json().await?;

        Ok(challenge_response)
    }

    /// Retrieve a verification token
    ///
    /// # Arguments
    ///
    /// * `request_id` - The request ID from the challenge response
    ///
    /// # Returns
    ///
    /// The token response, which may be pending, authorized, or rejected
    pub async fn get_token(&self, request_id: &str) -> Result<TokenResponse> {
        let url = format!("{}/v1/token/{}", self.base_url, request_id);

        let response = self.client.get(&url).send().await?;

        let status = response.status();

        if status.is_success() || status.as_u16() == 202 {
            let token_response: TokenResponse = response.json().await?;
            Ok(token_response)
        } else if status.as_u16() == 403 {
            let token_response: TokenResponse = response.json().await?;
            Ok(token_response)
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(Error::InvalidResponse(format!(
                "HTTP {}: {}",
                status, error_text
            )))
        }
    }

    /// Poll for token until authorized or rejected (convenience method)
    ///
    /// # Arguments
    ///
    /// * `request_id` - The request ID from the challenge response
    /// * `max_attempts` - Maximum number of polling attempts
    /// * `poll_interval` - Duration to wait between polls
    ///
    /// # Returns
    ///
    /// The verification token if authorized
    pub async fn poll_for_token(
        &self,
        request_id: &str,
        max_attempts: u32,
        poll_interval: std::time::Duration,
    ) -> Result<VerificationToken> {
        for _ in 0..max_attempts {
            match self.get_token(request_id).await? {
                TokenResponse::Authorized { token, .. } => return Ok(token),
                TokenResponse::Rejected { .. } => return Err(Error::AuthorizationRejected),
                TokenResponse::Pending { .. } => {
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }

        Err(Error::AuthorizationPending)
    }

    /// Revoke authorization for a verifier
    ///
    /// # Arguments
    ///
    /// * `verifier_id` - The verifier ID to revoke
    pub async fn revoke_authorization(&self, verifier_id: &str) -> Result<()> {
        let url = format!("{}/v1/authorization/{}", self.base_url, verifier_id);

        let response = self.client.delete(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(Error::InvalidResponse(format!(
                "HTTP {}: {}",
                status, error_text
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = DelegateClient::new("https://verify.example.org");
        assert_eq!(client.base_url, "https://verify.example.org");
    }

    // Integration tests would require a running delegate service
    // For now, we just test client creation
}
