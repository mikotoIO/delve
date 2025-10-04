# DelVe Reference Delegate

A reference implementation of a DelVe delegate service for domain verification.

## Overview

The reference delegate is a server that implements the DelVe (Delegatable Verification Protocol) delegate service specification. It allows domain owners to verify their ownership across multiple decentralized services through a centralized interface while maintaining full control over authorization decisions.

## Quick Start

### Configuration

The delegate service is configured via environment variables:

- `DELVE_DATA_DIR`: Directory for storing keypairs and requests (default: `./data`)
- `DELVE_BASE_URL`: Public URL of this delegate service (default: `http://localhost:3000`)
- `DELVE_BIND_ADDR`: Address to bind the server (default: `0.0.0.0:3000`)

### Running the Service

```bash
# With default configuration
cargo run

# With custom configuration
DELVE_DATA_DIR=/var/lib/delve \
DELVE_BASE_URL=https://verify.example.org \
DELVE_BIND_ADDR=0.0.0.0:8080 \
cargo run
```

## Example: Verifying a Domain

This example demonstrates how to use the reference delegate to verify ownership of `example.com` on a service.

### Step 1: DNS Configuration

Configure your domain's DNS with a `_delve` TXT record pointing to your delegate service:

```dns
_delve.example.com. 3600 IN TXT "v=delve0.1; mode=delegate; endpoint=https://verify.example.org; key=<YOUR_PUBLIC_KEY>"
```

The public key will be automatically generated when the delegate receives its first challenge for your domain. You can retrieve it from the delegate's data directory at `<DELVE_DATA_DIR>/keypairs/<domain>.json`.

### Step 2: Verifier Issues Challenge

A service that wants to verify your domain will send a challenge to your delegate:

```bash
curl -X POST https://verify.example.org/v1/challenge \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "verifier": "social.example.net",
    "verifierId": "instance-abc123",
    "challenge": "MjAyNS0xMC0wMlQxMDowMDowMFp8cmFuZG9tZGF0YWhlcmU=",
    "expiresAt": "2025-10-02T11:00:00Z",
    "metadata": {
      "serviceName": "Example Social Network",
      "userIdentifier": "[email protected]"
    }
  }'
```

Response:
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "authorizationUrl": "https://verify.example.org/authorize/550e8400-e29b-41d4-a716-446655440000",
  "expiresAt": "2025-10-02T11:00:00Z"
}
```

### Step 3: Authorize the Request

As the domain owner, visit the authorization URL in your browser:

```
https://verify.example.org/authorize/550e8400-e29b-41d4-a716-446655440000
```

You'll see a page showing:
- Which service is requesting verification (`social.example.net`)
- The user identifier (`[email protected]`)
- The domain being verified (`example.com`)
- Buttons to approve or reject the request

Click "Approve" to authorize the delegate to sign this challenge.

### Step 4: Verifier Retrieves Token

The verifier polls for the signed token:

```bash
curl https://verify.example.org/v1/token/550e8400-e29b-41d4-a716-446655440000
```

Response (after authorization):
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "authorized",
  "token": {
    "domain": "example.com",
    "verifier": "social.example.net",
    "verifierId": "instance-abc123",
    "challenge": "MjAyNS0xMC0wMlQxMDowMDowMFp8cmFuZG9tZGF0YWhlcmU=",
    "signature": "base64-encoded-signature-here",
    "publicKey": "base64-encoded-public-key",
    "keyId": "example.com-2025-01",
    "signedAt": "2025-10-02T10:30:00Z",
    "expiresAt": "2025-10-02T11:00:00Z"
  }
}
```

### Step 5: Verifier Validates

The verifier:
1. Retrieves the public key from your domain's `_delve` DNS record
2. Verifies the signature matches the challenge
3. Confirms the domain is now verified

## API Endpoints

### POST /v1/challenge

Create a new verification challenge request.

**Request Body:**
```json
{
  "domain": "example.com",
  "verifier": "service.example.net",
  "verifierId": "unique-service-id",
  "challenge": "base64-encoded-challenge",
  "expiresAt": "2025-10-02T12:00:00Z",
  "metadata": {
    "serviceName": "Service Name",
    "userIdentifier": "[email protected]"
  }
}
```

**Response:** `202 Accepted`

### GET /v1/token/{requestId}

Retrieve the status and token for a verification request.

**Responses:**
- `200 OK`: Token available (authorized)
- `202 Accepted`: Still pending authorization
- `403 Forbidden`: Request was rejected
- `410 Gone`: Challenge expired

### GET /authorize/{requestId}

Display the authorization UI for domain owners (HTML page).

### POST /v1/authorize/{requestId}

Process an authorization decision (used by the UI).

**Request Body:**
```json
{
  "approve": true
}
```

### GET /health

Health check endpoint.

## Storage

The delegate stores:

- **Keypairs**: One Ed25519 keypair per domain in `<DELVE_DATA_DIR>/keypairs/`
- **Requests**: Pending and completed verification requests in `<DELVE_DATA_DIR>/requests/`

All data is stored as JSON files for easy inspection and debugging.

## Security Considerations

- The delegate requires explicit authorization for each verification request
- Keypairs are stored locally and never transmitted
- Challenges expire after the time specified by the verifier
- All API communication should use HTTPS in production
- Consider implementing authentication for the authorization UI in production deployments

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run

# Run tests
cargo test

# Build release version
cargo build --release
```

## License

See the main DelVe project LICENSE file.
