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

For a complete example of implementing a delegate service, see [examples/delegate_service.rs](examples/delegate_service.rs).

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
