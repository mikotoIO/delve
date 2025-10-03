mod handlers;
mod storage;
mod template;

use axum::{
    routing::{get, post},
    Router,
};
use handlers::AppState;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use storage::Storage;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "reference_delegate=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Get configuration from environment
    let data_dir = env::var("DELVE_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let base_url =
        env::var("DELVE_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let bind_addr = env::var("DELVE_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    // Initialize storage
    tracing::info!("Initializing storage at: {}", data_dir);
    let storage = Arc::new(Storage::new(data_dir)?);

    // Create application state
    let state = AppState { storage, base_url };

    // Build router
    let app = Router::new()
        // API endpoints
        .route("/v1/challenge", post(handlers::create_challenge))
        .route("/v1/token/:request_id", get(handlers::get_token))
        .route(
            "/v1/authorize/:request_id",
            post(handlers::process_authorization),
        )
        // UI endpoints
        .route("/authorize/:request_id", get(handlers::show_authorization))
        // Health check
        .route("/health", get(|| async { "OK" }))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    // Parse bind address
    let addr: SocketAddr = bind_addr.parse()?;

    tracing::info!("Starting DelVe reference delegate server");
    tracing::info!("Listening on: {}", addr);
    tracing::info!(
        "Base URL: {}",
        env::var("DELVE_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
    );

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
