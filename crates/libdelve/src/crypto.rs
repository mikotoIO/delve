//! Cryptographic operations for DelVe protocol

use crate::{Error, Result, SigningPayload};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// Generate a new Ed25519 keypair
///
/// Returns (private_key_base64, public_key_base64)
pub fn generate_keypair() -> (String, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_key = BASE64.encode(signing_key.to_bytes());
    let public_key = BASE64.encode(verifying_key.to_bytes());

    (private_key, public_key)
}

/// Sign a payload with a private key
///
/// # Arguments
///
/// * `private_key_base64` - Base64-encoded Ed25519 private key (32 bytes)
/// * `payload` - The signing payload to sign
///
/// # Returns
///
/// Base64-encoded signature
pub fn sign_payload(private_key_base64: &str, payload: &SigningPayload) -> Result<String> {
    // Decode private key
    let private_key_bytes = BASE64
        .decode(private_key_base64)
        .map_err(|e| Error::InvalidPublicKey(format!("Invalid base64: {}", e)))?;

    let signing_key = SigningKey::from_bytes(
        &private_key_bytes
            .try_into()
            .map_err(|_| Error::InvalidPublicKey("Invalid key length".to_string()))?,
    );

    // Create canonical JSON
    let canonical_json = payload.to_canonical_json()?;

    // Sign
    let signature = signing_key.sign(canonical_json.as_bytes());

    Ok(BASE64.encode(signature.to_bytes()))
}

/// Verify a signature
///
/// # Arguments
///
/// * `public_key_base64` - Base64-encoded Ed25519 public key (32 bytes)
/// * `signature_base64` - Base64-encoded signature (64 bytes)
/// * `payload` - The signing payload that was signed
///
/// # Returns
///
/// Ok(()) if signature is valid, Err otherwise
pub fn verify_signature(
    public_key_base64: &str,
    signature_base64: &str,
    payload: &SigningPayload,
) -> Result<()> {
    // Decode public key
    let public_key_bytes = BASE64
        .decode(public_key_base64)
        .map_err(|e| Error::InvalidPublicKey(format!("Invalid base64: {}", e)))?;

    let verifying_key = VerifyingKey::from_bytes(
        &public_key_bytes
            .try_into()
            .map_err(|_| Error::InvalidPublicKey("Invalid key length".to_string()))?,
    )
    .map_err(|e| Error::InvalidPublicKey(format!("Invalid public key: {}", e)))?;

    // Decode signature
    let signature_bytes = BASE64
        .decode(signature_base64)
        .map_err(|e| Error::Crypto(format!("Invalid signature base64: {}", e)))?;

    let signature = Signature::from_bytes(
        &signature_bytes
            .try_into()
            .map_err(|_| Error::Crypto("Invalid signature length".to_string()))?,
    );

    // Create canonical JSON
    let canonical_json = payload.to_canonical_json()?;

    // Verify
    verifying_key
        .verify(canonical_json.as_bytes(), &signature)
        .map_err(|_| Error::InvalidSignature)?;

    Ok(())
}

/// Decode a public key from base64 and validate its format
pub fn validate_public_key(public_key_base64: &str) -> Result<()> {
    let public_key_bytes = BASE64
        .decode(public_key_base64)
        .map_err(|e| Error::InvalidPublicKey(format!("Invalid base64: {}", e)))?;

    VerifyingKey::from_bytes(
        &public_key_bytes
            .try_into()
            .map_err(|_| Error::InvalidPublicKey("Invalid key length".to_string()))?,
    )
    .map_err(|e| Error::InvalidPublicKey(format!("Invalid public key: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (private_key, public_key) = generate_keypair();

        // Keys should be base64 encoded
        assert!(BASE64.decode(&private_key).is_ok());
        assert!(BASE64.decode(&public_key).is_ok());

        // Ed25519 keys are 32 bytes
        assert_eq!(BASE64.decode(&private_key).unwrap().len(), 32);
        assert_eq!(BASE64.decode(&public_key).unwrap().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let (private_key, public_key) = generate_keypair();

        let payload = SigningPayload {
            challenge: "test-challenge".to_string(),
            domain: "example.com".to_string(),
            signed_at: "2025-10-02T10:30:00Z".to_string(),
            verifier_id: "service.example.net".to_string(),
        };

        // Sign
        let signature = sign_payload(&private_key, &payload).unwrap();

        // Verify with correct key should succeed
        assert!(verify_signature(&public_key, &signature, &payload).is_ok());
    }

    #[test]
    fn test_verify_with_wrong_key_fails() {
        let (private_key, _) = generate_keypair();
        let (_, wrong_public_key) = generate_keypair();

        let payload = SigningPayload {
            challenge: "test-challenge".to_string(),
            domain: "example.com".to_string(),
            signed_at: "2025-10-02T10:30:00Z".to_string(),
            verifier_id: "service.example.net".to_string(),
        };

        let signature = sign_payload(&private_key, &payload).unwrap();

        // Verify with wrong key should fail
        assert!(matches!(
            verify_signature(&wrong_public_key, &signature, &payload),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_verify_tampered_payload_fails() {
        let (private_key, public_key) = generate_keypair();

        let payload = SigningPayload {
            challenge: "test-challenge".to_string(),
            domain: "example.com".to_string(),
            signed_at: "2025-10-02T10:30:00Z".to_string(),
            verifier_id: "service.example.net".to_string(),
        };

        let signature = sign_payload(&private_key, &payload).unwrap();

        // Tamper with payload
        let tampered_payload = SigningPayload {
            domain: "evil.com".to_string(),
            ..payload
        };

        // Verification should fail
        assert!(matches!(
            verify_signature(&public_key, &signature, &tampered_payload),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_validate_public_key() {
        let (_, public_key) = generate_keypair();
        assert!(validate_public_key(&public_key).is_ok());

        assert!(matches!(
            validate_public_key("invalid-key"),
            Err(Error::InvalidPublicKey(_))
        ));

        assert!(matches!(
            validate_public_key("dG9vLXNob3J0"),
            Err(Error::InvalidPublicKey(_))
        ));
    }
}
