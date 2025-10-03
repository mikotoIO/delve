//! HTML templates for the authorization UI

use handlebars::{handlebars_helper, Handlebars};
use libdelve::RequestStatus;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::OnceLock;

handlebars_helper!(eq: |x: String, y: String| x == y);

static HANDLEBARS: OnceLock<Handlebars<'static>> = OnceLock::new();

fn get_handlebars() -> &'static Handlebars<'static> {
    HANDLEBARS.get_or_init(|| {
        let mut hb = Handlebars::new();
        hb.register_helper("eq", Box::new(eq));
        hb.register_template_string(
            "authorization",
            include_str!("../templates/authorization.html"),
        )
        .expect("Failed to register authorization template");
        hb
    })
}

#[derive(Serialize)]
pub struct AuthorizationPageData {
    pub status: String,
    pub domain: String,
    pub verifier: String,
    pub verifier_id: String,
    pub challenge: String,
    pub expires_at: String,
    pub metadata: Option<HashMap<String, String>>,
    pub is_pending: bool,
    pub request_id: String,
}

impl AuthorizationPageData {
    pub fn new(
        status: RequestStatus,
        domain: String,
        verifier: String,
        verifier_id: String,
        challenge: String,
        expires_at: String,
        metadata: Option<HashMap<String, String>>,
        request_id: String,
    ) -> Self {
        let status_str = match status {
            RequestStatus::Pending => "pending",
            RequestStatus::Authorized => "authorized",
            RequestStatus::Rejected => "rejected",
        };

        Self {
            status: status_str.to_string(),
            domain,
            verifier,
            verifier_id,
            challenge,
            expires_at,
            metadata,
            is_pending: status == RequestStatus::Pending,
            request_id,
        }
    }
}

/// Renders the authorization page HTML
pub fn render_authorization_page(
    data: AuthorizationPageData,
) -> Result<String, handlebars::RenderError> {
    get_handlebars().render("authorization", &data)
}
