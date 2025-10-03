# libdelve

Core library for the Delegatable Verification Protocol (DelVe).

DelVe is a protocol for verifying domain ownership across multiple decentralized services through an optional delegate service. It enables domain owners to manage verification across numerous instances while maintaining full control over authorization decisions.

## Features

- DNS-based configuration discovery
- Support for both delegated and direct verification modes
- Ed25519 signature verification
- Challenge generation and validation
- HTTP client for delegate service integration (with `delegate` feature)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libdelve = "0.1"
```

For direct verification mode only (without delegate client):

```toml
[dependencies]
libdelve = { version = "0.1", default-features = false }
```

## Usage Example

### Verifier (Service validating domain ownership)

```rust
use libdelve::{Verifier, VerificationMode};
use chrono::Duration;

#[tokio::main]
async fn main() -> libdelve::Result<()> {
    // Create a verifier instance
    let verifier = Verifier::new(
        "My Service",                    // Service name
        "instance-123",                  // Unique instance ID
        Duration::minutes(30),           // Challenge validity duration
    );

    let domain = "example.com";

    // 1. Discover how the domain performs verification
    let config = verifier.discover(domain).await?;
    println!("Domain uses {:?} mode", config.mode);

    // 2. Generate a challenge
    let (challenge, expires_at) = verifier.create_challenge(domain)?;
    println!("Challenge: {}", challenge);

    // 3. Submit challenge (if using delegate mode)
    if config.mode == VerificationMode::Delegate {
        let endpoint = config.endpoint.as_ref().unwrap();

        let request_id = verifier.submit_challenge_to_delegate(
            domain,
            endpoint,
            &challenge,
            expires_at,
            Some("[email protected]".to_string()),
        ).await?;

        println!("Request ID: {}", request_id);
        println!("Waiting for domain owner authorization...");

        // 4. Poll for verification token
        let token = verifier.poll_for_token(
            endpoint,
            &request_id,
            Some(60),  // max attempts
            Some(5),   // poll interval in seconds
        ).await?;

        // 5. Verify the token
        verifier.verify_token(
            &token,
            domain,
            &challenge,
            &config.public_key,
        )?;

        println!("✓ Domain verified successfully!");
    }

    Ok(())
}
```

### Delegate Service (Managing verification for domain owners)

```rust
use libdelve::{
    crypto::{generate_keypair, sign_payload},
    challenge::validate_challenge_format,
    SigningPayload, ChallengeRequest, ChallengeResponse,
    TokenResponse, VerificationToken, RequestStatus,
};
use chrono::Utc;
use std::collections::HashMap;

// In-memory storage for demo (use a database in production)
struct DelegateService {
    private_key: String,
    public_key: String,
    requests: HashMap<String, StoredRequest>,
}

struct StoredRequest {
    challenge_request: ChallengeRequest,
    status: RequestStatus,
    authorized_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl DelegateService {
    fn new() -> Self {
        let (private_key, public_key) = generate_keypair();
        Self {
            private_key,
            public_key,
            requests: HashMap::new(),
        }
    }

    // POST /api/v1/challenge - Submit a challenge
    fn submit_challenge(&mut self, request: ChallengeRequest) -> libdelve::Result<ChallengeResponse> {
        // Validate challenge format
        validate_challenge_format(&request.challenge)?;

        // Generate request ID
        let request_id = uuid::Uuid::new_v4().to_string();

        // Store request
        self.requests.insert(request_id.clone(), StoredRequest {
            challenge_request: request.clone(),
            status: RequestStatus::Pending,
            authorized_at: None,
        });

        // Generate authorization URL for domain owner
        let auth_url = format!(
            "https://verify.example.org/authorize/{}",
            request_id
        );

        Ok(ChallengeResponse {
            request_id,
            status: RequestStatus::Pending,
            authorization_url: auth_url,
            expires_at: request.expires_at,
        })
    }

    // GET /api/v1/token/{request_id} - Poll for token
    fn get_token(&self, request_id: &str) -> libdelve::Result<TokenResponse> {
        let stored = self.requests.get(request_id)
            .ok_or_else(|| libdelve::Error::InvalidResponse("Request not found".to_string()))?;

        match stored.status {
            RequestStatus::Pending => Ok(TokenResponse::Pending {
                request_id: request_id.to_string(),
                authorization_url: format!("https://verify.example.org/authorize/{}", request_id),
            }),
            RequestStatus::Authorized => {
                let req = &stored.challenge_request;

                // Create signing payload
                let signed_at = stored.authorized_at.unwrap_or_else(Utc::now);
                let payload = SigningPayload {
                    challenge: req.challenge.clone(),
                    domain: req.domain.clone(),
                    signed_at: signed_at.to_rfc3339(),
                    verifier: req.verifier.clone(),
                    verifier_id: req.verifier_id.clone(),
                };

                // Sign the payload
                let signature = sign_payload(&self.private_key, &payload)?;

                let token = VerificationToken {
                    domain: req.domain.clone(),
                    verifier: req.verifier.clone(),
                    verifier_id: req.verifier_id.clone(),
                    challenge: req.challenge.clone(),
                    signature,
                    public_key: self.public_key.clone(),
                    key_id: "primary".to_string(),
                    signed_at,
                    expires_at: req.expires_at,
                };

                Ok(TokenResponse::Authorized {
                    request_id: request_id.to_string(),
                    token,
                })
            }
            RequestStatus::Rejected => Ok(TokenResponse::Rejected {
                request_id: request_id.to_string(),
                rejected_at: stored.authorized_at.unwrap_or_else(Utc::now),
            }),
        }
    }

    // Domain owner authorizes the request
    fn authorize_request(&mut self, request_id: &str) -> libdelve::Result<()> {
        let stored = self.requests.get_mut(request_id)
            .ok_or_else(|| libdelve::Error::InvalidResponse("Request not found".to_string()))?;

        stored.status = RequestStatus::Authorized;
        stored.authorized_at = Some(Utc::now());
        Ok(())
    }
}
```

### DNS Configuration Discovery

```rust
use libdelve::discovery::discover_dns_config;

#[tokio::main]
async fn main() -> libdelve::Result<()> {
    let config = discover_dns_config("example.com").await?;

    println!("Version: {}", config.version);
    println!("Mode: {:?}", config.mode);
    println!("Public Key: {}", config.public_key);

    if let Some(endpoint) = config.endpoint {
        println!("Delegate Endpoint: {}", endpoint);
    }

    Ok(())
}
```

## DNS Record Format

Domains must publish a TXT record at `_delve.<domain>` with the following format:

**Delegate Mode:**
```
v=delve0.1; mode=delegate; endpoint=https://verify.example.org; key=<base64-encoded-public-key>
```

**Direct Mode:**
```
v=delve0.1; mode=direct; key=<base64-encoded-public-key>
```

## Documentation

For the full protocol specification, see [SPEC.md](../../SPEC.md) in the repository root.

## License

See the repository root for license information.
