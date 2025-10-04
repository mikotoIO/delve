//! Challenge generation and validation

use crate::Result;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;

/// Minimum challenge size in bytes (spec requires at least 32 bytes)
pub const MIN_CHALLENGE_BYTES: usize = 32;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenges_are_unique() {
        let (challenge1, _) = generate_challenge(Duration::minutes(30)).unwrap();
        let (challenge2, _) = generate_challenge(Duration::minutes(30)).unwrap();

        // Each challenge should be unique due to random component
        assert_ne!(challenge1, challenge2);
    }
}
