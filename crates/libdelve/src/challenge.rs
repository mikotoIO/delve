//! Challenge generation and validation

use crate::{Error, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;

/// Minimum challenge size in bytes (spec requires at least 32 bytes)
const MIN_CHALLENGE_BYTES: usize = 32;

/// Generate a cryptographically secure challenge
///
/// The challenge includes a timestamp and random bytes to prevent replay attacks.
///
/// Format: `base64(timestamp || random_bytes(32))`
///
/// # Arguments
///
/// * `expires_in` - Duration until the challenge expires (recommended: 15-60 minutes)
///
/// # Returns
///
/// A tuple of (challenge_string, expiration_time)
pub fn generate_challenge(expires_in: Duration) -> Result<(String, DateTime<Utc>)> {
    let now = Utc::now();
    let expires_at = now + expires_in;

    // Create challenge: timestamp (RFC3339) + random bytes
    let timestamp = now.to_rfc3339();
    let mut random_bytes = vec![0u8; MIN_CHALLENGE_BYTES];
    rand::thread_rng().fill_bytes(&mut random_bytes);

    // Combine timestamp and random data
    let mut challenge_data = timestamp.as_bytes().to_vec();
    challenge_data.push(b'|');
    challenge_data.extend_from_slice(&random_bytes);

    // Base64 encode
    let challenge = BASE64.encode(&challenge_data);

    Ok((challenge, expires_at))
}

/// Validate a challenge format
///
/// Ensures the challenge is properly formatted and contains enough entropy.
pub fn validate_challenge_format(challenge: &str) -> Result<()> {
    // Decode from base64
    let decoded = BASE64
        .decode(challenge)
        .map_err(|e| Error::InvalidChallenge(format!("Invalid base64: {}", e)))?;

    // Check minimum size (timestamp + separator + 32 random bytes)
    if decoded.len() < MIN_CHALLENGE_BYTES {
        return Err(Error::InvalidChallenge(format!(
            "Challenge too short: {} bytes (minimum {})",
            decoded.len(),
            MIN_CHALLENGE_BYTES
        )));
    }

    Ok(())
}

/// Check if a challenge has expired
pub fn is_challenge_expired(expires_at: DateTime<Utc>) -> bool {
    Utc::now() > expires_at
}

/// Validate that a challenge hasn't expired
pub fn validate_challenge_expiry(expires_at: DateTime<Utc>) -> Result<()> {
    if is_challenge_expired(expires_at) {
        Err(Error::ChallengeExpired)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let (challenge, expires_at) = generate_challenge(Duration::minutes(30)).unwrap();

        // Check that challenge is base64
        assert!(BASE64.decode(&challenge).is_ok());

        // Check that expiration is in the future
        assert!(expires_at > Utc::now());

        // Validate format
        assert!(validate_challenge_format(&challenge).is_ok());
    }

    #[test]
    fn test_validate_challenge_format_valid() {
        let (challenge, _) = generate_challenge(Duration::minutes(30)).unwrap();
        assert!(validate_challenge_format(&challenge).is_ok());
    }

    #[test]
    fn test_validate_challenge_format_invalid_base64() {
        let result = validate_challenge_format("not-valid-base64!!!");
        assert!(matches!(result, Err(Error::InvalidChallenge(_))));
    }

    #[test]
    fn test_validate_challenge_format_too_short() {
        let short_challenge = BASE64.encode(b"short");
        let result = validate_challenge_format(&short_challenge);
        assert!(matches!(result, Err(Error::InvalidChallenge(_))));
    }

    #[test]
    fn test_challenge_expiry() {
        let now = Utc::now();
        let future = now + Duration::hours(1);
        let past = now - Duration::hours(1);

        assert!(!is_challenge_expired(future));
        assert!(is_challenge_expired(past));

        assert!(validate_challenge_expiry(future).is_ok());
        assert!(matches!(
            validate_challenge_expiry(past),
            Err(Error::ChallengeExpired)
        ));
    }

    #[test]
    fn test_challenges_are_unique() {
        let (challenge1, _) = generate_challenge(Duration::minutes(30)).unwrap();
        let (challenge2, _) = generate_challenge(Duration::minutes(30)).unwrap();

        // Each challenge should be unique due to random component
        assert_ne!(challenge1, challenge2);
    }
}
