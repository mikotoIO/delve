//! HTTP request handlers for delegate service

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use chrono::Utc;
use libdelve::{
    ChallengeRequest, ChallengeResponse, RequestStatus, TokenResponse, VerificationToken,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::storage::{Storage, StoredRequest};
use crate::template::{render_authorization_page, AuthorizationPageData};

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

    // Check if this domain-service combination was previously approved
    let is_approved =
        state
            .storage
            .is_domain_service_approved(&req.domain, &req.verifier, &req.verifier_id)?;

    let (status, token) = if is_approved {
        // Auto-approve: create token immediately
        let keypair = state.storage.get_or_create_keypair(&req.domain)?;
        let signed_at = Utc::now();
        let payload = req.create_signing_payload(signed_at);
        let signature = libdelve::crypto::sign_payload(&keypair.private_key, &payload)?;
        let token = VerificationToken::new(
            &req,
            signature,
            keypair.public_key.clone(),
            keypair.key_id.clone(),
            signed_at,
        );

        // Update the approval timestamp
        state.storage.record_domain_service_approval(
            &req.domain,
            &req.verifier,
            &req.verifier_id,
        )?;

        (RequestStatus::Authorized, Some(token))
    } else {
        // Require manual approval
        (RequestStatus::Pending, None)
    };

    // Store the request
    let stored_request = StoredRequest {
        request_id: request_id.clone(),
        request: req.clone(),
        status: status.clone(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        token: token.clone(),
        rejected_at: None,
    };

    if status == RequestStatus::Pending {
        state.storage.store_request(stored_request)?;
    }

    // Return response
    let response = ChallengeResponse {
        request_id: request_id.clone(),
        status,
        authorization_url: if status == RequestStatus::Pending {
            Some(format!("{}/authorize/{}", state.base_url, request_id))
        } else {
            None
        },
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
    if libdelve::challenge::is_challenge_expired(request.request.expires_at) {
        return Err(AppError::ChallengeExpired);
    }

    match request.status {
        RequestStatus::Authorized => {
            let token = request.token.ok_or_else(|| {
                AppError::Internal("Token missing for authorized request".to_string())
            })?;

            Ok(Json(TokenResponse::Authorized {
                request_id: request.request_id,
                token,
            }))
        }
        RequestStatus::Pending => Ok(Json(TokenResponse::Pending {
            request_id: request.request_id,
            authorization_url: format!("{}/authorize/{}", state.base_url, request_id),
        })),
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
    if libdelve::challenge::is_challenge_expired(request.request.expires_at) {
        return Err(AppError::ChallengeExpired);
    }

    let data = AuthorizationPageData::new(request.status, request.request, request_id);

    let html = render_authorization_page(data)
        .map_err(|e| AppError::Internal(format!("Template error: {}", e)))?;

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
        return Err(AppError::BadRequest(
            "Request already processed".to_string(),
        ));
    }

    // Check if expired
    if libdelve::challenge::is_challenge_expired(request.request.expires_at) {
        return Err(AppError::ChallengeExpired);
    }

    if auth.approve {
        // Get keypair for domain
        let keypair = state
            .storage
            .get_or_create_keypair(&request.request.domain)?;

        // Create signing payload
        let signed_at = Utc::now();
        let payload = request.request.create_signing_payload(signed_at);

        // Sign the payload
        let signature = libdelve::crypto::sign_payload(&keypair.private_key, &payload)?;

        // Create verification token
        let token = VerificationToken::new(
            &request.request,
            signature,
            keypair.public_key.clone(),
            keypair.key_id.clone(),
            signed_at,
        );

        // Update request
        request.status = RequestStatus::Authorized;
        request.token = Some(token);
        request.updated_at = Utc::now();

        // Record this approval for future auto-approval
        state.storage.record_domain_service_approval(
            &request.request.domain,
            &request.request.verifier,
            &request.request.verifier_id,
        )?;
    } else {
        // Reject
        request.status = RequestStatus::Rejected;
        request.rejected_at = Some(Utc::now());
        request.updated_at = Utc::now();
    }

    state.storage.update_request(request)?;

    Ok(StatusCode::OK)
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
            AppError::Storage(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", err),
            ),
            AppError::Libdelve(err) => match err {
                libdelve::Error::InvalidChallenge(msg) => (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid challenge: {}", msg),
                ),
                libdelve::Error::ChallengeExpired => {
                    (StatusCode::GONE, "Challenge expired".to_string())
                }
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
