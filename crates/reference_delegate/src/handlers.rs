//! HTTP request handlers for delegate service

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use chrono::Utc;
use libdelve::{ChallengeRequest, ChallengeResponse, RequestStatus, SigningPayload, TokenResponse, VerificationToken};
use std::sync::Arc;
use uuid::Uuid;

use crate::storage::{Storage, StoredRequest};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<Storage>,
    pub base_url: String,
}

/// Handle POST /v1/challenge
pub async fn create_challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    // Validate challenge format
    libdelve::challenge::validate_challenge_format(&req.challenge)?;

    // Check expiration
    libdelve::challenge::validate_challenge_expiry(req.expires_at)?;

    // Ensure we have a keypair for this domain
    state.storage.get_or_create_keypair(&req.domain)?;

    // Create request ID
    let request_id = Uuid::new_v4().to_string();

    // Store the request
    let stored_request = StoredRequest {
        request_id: request_id.clone(),
        domain: req.domain.clone(),
        verifier: req.verifier.clone(),
        verifier_id: req.verifier_id.clone(),
        challenge: req.challenge.clone(),
        expires_at: req.expires_at,
        status: RequestStatus::Pending,
        metadata: req.metadata.clone(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        token: None,
        rejected_at: None,
    };

    state.storage.store_request(stored_request)?;

    // Return response
    let response = ChallengeResponse {
        request_id: request_id.clone(),
        status: RequestStatus::Pending,
        authorization_url: format!("{}/authorize/{}", state.base_url, request_id),
        expires_at: req.expires_at,
    };

    Ok(Json(response))
}

/// Handle GET /v1/token/{request_id}
pub async fn get_token(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> Result<Json<TokenResponse>, AppError> {
    let request = state
        .storage
        .get_request(&request_id)?
        .ok_or_else(|| AppError::NotFound("Request not found".to_string()))?;

    // Check if expired
    if libdelve::challenge::is_challenge_expired(request.expires_at) {
        return Err(AppError::ChallengeExpired);
    }

    match request.status {
        RequestStatus::Authorized => {
            let token = request
                .token
                .ok_or_else(|| AppError::Internal("Token missing for authorized request".to_string()))?;

            Ok(Json(TokenResponse::Authorized {
                request_id: request.request_id,
                token,
            }))
        }
        RequestStatus::Pending => {
            Ok(Json(TokenResponse::Pending {
                request_id: request.request_id,
                authorization_url: format!("{}/authorize/{}", state.base_url, request_id),
            }))
        }
        RequestStatus::Rejected => {
            let rejected_at = request
                .rejected_at
                .ok_or_else(|| AppError::Internal("Rejected time missing".to_string()))?;

            Ok(Json(TokenResponse::Rejected {
                request_id: request.request_id,
                rejected_at,
            }))
        }
    }
}

/// Handle GET /authorize/{request_id} - Display authorization UI
pub async fn show_authorization(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> Result<Html<String>, AppError> {
    let request = state
        .storage
        .get_request(&request_id)?
        .ok_or_else(|| AppError::NotFound("Request not found".to_string()))?;

    // Check if expired
    if libdelve::challenge::is_challenge_expired(request.expires_at) {
        return Err(AppError::ChallengeExpired);
    }

    // Build metadata display
    let metadata_html = if let Some(metadata) = &request.metadata {
        metadata
            .iter()
            .map(|(k, v)| format!("<li><strong>{}:</strong> {}</li>", escape_html(k), escape_html(v)))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        String::new()
    };

    let status_badge = match request.status {
        RequestStatus::Pending => "<span style='color: orange;'>⏳ Pending</span>",
        RequestStatus::Authorized => "<span style='color: green;'>✓ Authorized</span>",
        RequestStatus::Rejected => "<span style='color: red;'>✗ Rejected</span>",
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>DelVe Authorization Request</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            margin-top: 0;
        }}
        .info {{
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .info dt {{
            font-weight: bold;
            color: #555;
            margin-top: 10px;
        }}
        .info dd {{
            margin-left: 0;
            color: #333;
        }}
        .buttons {{
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }}
        button {{
            flex: 1;
            padding: 12px 24px;
            font-size: 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
        }}
        .approve {{
            background: #28a745;
            color: white;
        }}
        .approve:hover {{
            background: #218838;
        }}
        .reject {{
            background: #dc3545;
            color: white;
        }}
        .reject:hover {{
            background: #c82333;
        }}
        .approve:disabled, .reject:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}
        .status {{
            font-size: 18px;
            margin-bottom: 15px;
        }}
        ul {{
            margin: 0;
            padding-left: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 DelVe Authorization Request</h1>

        <div class="status">Status: {}</div>

        <div class="info">
            <dl>
                <dt>Domain</dt>
                <dd>{}</dd>

                <dt>Verifier</dt>
                <dd>{}</dd>

                <dt>Verifier ID</dt>
                <dd><code>{}</code></dd>

                <dt>Challenge</dt>
                <dd><code style="word-break: break-all;">{}</code></dd>

                <dt>Expires At</dt>
                <dd>{}</dd>

                {}
            </dl>
        </div>

        <div class="buttons">
            <button class="approve" onclick="authorize(true)" {}>
                ✓ Approve
            </button>
            <button class="reject" onclick="authorize(false)" {}>
                ✗ Reject
            </button>
        </div>
    </div>

    <script>
        async function authorize(approve) {{
            const buttons = document.querySelectorAll('button');
            buttons.forEach(b => b.disabled = true);

            try {{
                const response = await fetch('/v1/authorize/{}', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ approve }})
                }});

                if (response.ok) {{
                    alert(approve ? 'Request approved!' : 'Request rejected!');
                    location.reload();
                }} else {{
                    const error = await response.text();
                    alert('Error: ' + error);
                    buttons.forEach(b => b.disabled = false);
                }}
            }} catch (e) {{
                alert('Error: ' + e.message);
                buttons.forEach(b => b.disabled = false);
            }}
        }}
    </script>
</body>
</html>"#,
        status_badge,
        escape_html(&request.domain),
        escape_html(&request.verifier),
        escape_html(&request.verifier_id),
        escape_html(&request.challenge),
        request.expires_at.to_rfc3339(),
        if !metadata_html.is_empty() {
            format!("<dt>Metadata</dt><dd><ul>{}</ul></dd>", metadata_html)
        } else {
            String::new()
        },
        if request.status != RequestStatus::Pending { "disabled" } else { "" },
        if request.status != RequestStatus::Pending { "disabled" } else { "" },
        request_id,
    );

    Ok(Html(html))
}

/// Handle POST /v1/authorize/{request_id} - Process authorization decision
#[derive(serde::Deserialize)]
pub struct AuthorizeRequest {
    approve: bool,
}

pub async fn process_authorization(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    Json(auth): Json<AuthorizeRequest>,
) -> Result<StatusCode, AppError> {
    let mut request = state
        .storage
        .get_request(&request_id)?
        .ok_or_else(|| AppError::NotFound("Request not found".to_string()))?;

    // Check if already processed
    if request.status != RequestStatus::Pending {
        return Err(AppError::BadRequest("Request already processed".to_string()));
    }

    // Check if expired
    if libdelve::challenge::is_challenge_expired(request.expires_at) {
        return Err(AppError::ChallengeExpired);
    }

    if auth.approve {
        // Get keypair for domain
        let keypair = state.storage.get_or_create_keypair(&request.domain)?;

        // Create signing payload
        let signed_at = Utc::now();
        let payload = SigningPayload {
            challenge: request.challenge.clone(),
            domain: request.domain.clone(),
            signed_at: signed_at.to_rfc3339(),
            verifier: request.verifier.clone(),
            verifier_id: request.verifier_id.clone(),
        };

        // Sign the payload
        let signature = libdelve::crypto::sign_payload(&keypair.private_key, &payload)?;

        // Create verification token
        let token = VerificationToken {
            domain: request.domain.clone(),
            verifier: request.verifier.clone(),
            verifier_id: request.verifier_id.clone(),
            challenge: request.challenge.clone(),
            signature,
            public_key: keypair.public_key.clone(),
            key_id: keypair.key_id.clone(),
            signed_at,
            expires_at: request.expires_at,
        };

        // Update request
        request.status = RequestStatus::Authorized;
        request.token = Some(token);
        request.updated_at = Utc::now();
    } else {
        // Reject
        request.status = RequestStatus::Rejected;
        request.rejected_at = Some(Utc::now());
        request.updated_at = Utc::now();
    }

    state.storage.update_request(request)?;

    Ok(StatusCode::OK)
}

/// Escape HTML special characters
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Application error type
#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    BadRequest(String),
    ChallengeExpired,
    Internal(String),
    Storage(anyhow::Error),
    Libdelve(libdelve::Error),
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Storage(err)
    }
}

impl From<libdelve::Error> for AppError {
    fn from(err: libdelve::Error) -> Self {
        AppError::Libdelve(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::ChallengeExpired => (StatusCode::GONE, "Challenge expired".to_string()),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::Storage(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Storage error: {}", err)),
            AppError::Libdelve(err) => match err {
                libdelve::Error::InvalidChallenge(msg) => (StatusCode::BAD_REQUEST, format!("Invalid challenge: {}", msg)),
                libdelve::Error::ChallengeExpired => (StatusCode::GONE, "Challenge expired".to_string()),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {}", err)),
            },
        };

        let body = Json(serde_json::json!({
            "error": status.canonical_reason().unwrap_or("error"),
            "message": message
        }));

        (status, body).into_response()
    }
}
