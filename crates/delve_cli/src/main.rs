use anyhow::Result;
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use colored::Colorize;
use libdelve::{delegate_client::DelegateClient, ChallengeRequest};
use rand::Rng;
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "delve")]
#[command(about = "CLI for interacting with DelVe delegate services", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Submit a verification challenge to a delegate
    Challenge {
        /// Delegate endpoint URL (e.g., https://verify.example.org)
        #[arg(short, long)]
        endpoint: String,

        /// Domain to verify
        #[arg(short, long)]
        domain: String,

        /// Verifier identifier (your service)
        #[arg(short, long)]
        verifier: String,

        /// Verifier instance ID
        #[arg(long)]
        verifier_id: String,

        /// Base64-encoded challenge string (auto-generated if not provided)
        #[arg(short, long)]
        challenge: Option<String>,

        /// Expiration time in minutes from now
        #[arg(long, default_value = "60")]
        expires_in: i64,

        /// Service name (metadata)
        #[arg(long)]
        service_name: Option<String>,

        /// User identifier (metadata)
        #[arg(long)]
        user_identifier: Option<String>,
    },

    /// Retrieve a verification token
    Token {
        /// Delegate endpoint URL
        #[arg(short, long)]
        endpoint: String,

        /// Request ID from challenge response
        #[arg(short, long)]
        request_id: String,
    },

    /// Poll for a verification token until authorized
    Poll {
        /// Delegate endpoint URL
        #[arg(short, long)]
        endpoint: String,

        /// Request ID from challenge response
        #[arg(short, long)]
        request_id: String,

        /// Maximum number of polling attempts
        #[arg(long, default_value = "30")]
        max_attempts: u32,

        /// Polling interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,
    },

    /// Revoke authorization for a verifier
    Revoke {
        /// Delegate endpoint URL
        #[arg(short, long)]
        endpoint: String,

        /// Verifier ID to revoke
        #[arg(short, long)]
        verifier_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Challenge {
            endpoint,
            domain,
            verifier,
            verifier_id,
            challenge,
            expires_in,
            service_name,
            user_identifier,
        } => {
            let client = DelegateClient::new(&endpoint);

            let mut metadata = HashMap::new();
            if let Some(name) = service_name {
                metadata.insert("serviceName".to_string(), name);
            }
            if let Some(uid) = user_identifier {
                metadata.insert("userIdentifier".to_string(), uid);
            }

            // Generate challenge if not provided
            let challenge = challenge.unwrap_or_else(|| {
                let mut rng = rand::rng();
                let random_bytes: Vec<u8> = (0..32).map(|_| rng.random()).collect();
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &random_bytes)
            });

            let request = ChallengeRequest {
                domain: domain.clone(),
                verifier,
                verifier_id,
                challenge,
                expires_at: Utc::now() + Duration::minutes(expires_in),
                metadata: if metadata.is_empty() {
                    None
                } else {
                    Some(metadata)
                },
            };

            println!("{}", "Submitting challenge...".cyan());
            let response = client.submit_challenge(&request).await?;

            println!("\n{}", "Challenge submitted successfully!".green().bold());
            println!("\n{}", "Response:".bold());
            println!("  {}: {}", "Request ID".bold(), response.request_id);
            println!(
                "  {}: {}",
                "Status".bold(),
                format!("{:?}", response.status).yellow()
            );
            println!(
                "  {}: {}",
                "Authorization URL".bold(),
                response.authorization_url.underline()
            );
            println!("  {}: {}", "Expires At".bold(), response.expires_at);

            println!("\n{}", "Next steps:".cyan().bold());
            println!("  1. Visit the authorization URL to approve the request");
            println!(
                "  2. Run: {} to retrieve the token",
                format!("delve token -e {} -r {}", endpoint, response.request_id).yellow()
            );
            println!(
                "     Or: {} to wait for authorization",
                format!("delve poll -e {} -r {}", endpoint, response.request_id).yellow()
            );
        }

        Commands::Token {
            endpoint,
            request_id,
        } => {
            let client = DelegateClient::new(&endpoint);

            println!("{}", "Retrieving token...".cyan());
            let response = client.get_token(&request_id).await?;

            match response {
                libdelve::TokenResponse::Authorized { request_id, token } => {
                    println!("\n{}", "Token authorized!".green().bold());
                    println!("\n{}", "Token Details:".bold());
                    println!("  {}: {}", "Request ID".bold(), request_id);
                    println!("  {}: {}", "Domain".bold(), token.domain);
                    println!("  {}: {}", "Verifier".bold(), token.verifier);
                    println!("  {}: {}", "Verifier ID".bold(), token.verifier_id);
                    println!("  {}: {}", "Key ID".bold(), token.key_id);
                    println!("  {}: {}", "Signed At".bold(), token.signed_at);
                    println!("  {}: {}", "Expires At".bold(), token.expires_at);
                    println!("\n{}", "Full Token (JSON):".bold());
                    println!("{}", serde_json::to_string_pretty(&token)?);
                }
                libdelve::TokenResponse::Pending {
                    request_id,
                    authorization_url,
                } => {
                    println!("\n{}", "Request still pending".yellow().bold());
                    println!("\n{}", "Details:".bold());
                    println!("  {}: {}", "Request ID".bold(), request_id);
                    println!(
                        "  {}: {}",
                        "Authorization URL".bold(),
                        authorization_url.underline()
                    );
                    println!("\n{}", "Action required:".cyan().bold());
                    println!("  Visit the authorization URL to approve the request");
                }
                libdelve::TokenResponse::Rejected {
                    request_id,
                    rejected_at,
                } => {
                    println!("\n{}", "Request was rejected".red().bold());
                    println!("\n{}", "Details:".bold());
                    println!("  {}: {}", "Request ID".bold(), request_id);
                    println!("  {}: {}", "Rejected At".bold(), rejected_at);
                }
            }
        }

        Commands::Poll {
            endpoint,
            request_id,
            max_attempts,
            interval,
        } => {
            let client = DelegateClient::new(&endpoint);

            println!(
                "{}",
                format!(
                    "Polling for token (max {} attempts, {} second interval)...",
                    max_attempts, interval
                )
                .cyan()
            );

            let poll_interval = std::time::Duration::from_secs(interval);
            match client
                .poll_for_token(&request_id, max_attempts, poll_interval)
                .await
            {
                Ok(token) => {
                    println!("\n{}", "Token authorized!".green().bold());
                    println!("\n{}", "Token Details:".bold());
                    println!("  {}: {}", "Domain".bold(), token.domain);
                    println!("  {}: {}", "Verifier".bold(), token.verifier);
                    println!("  {}: {}", "Verifier ID".bold(), token.verifier_id);
                    println!("  {}: {}", "Key ID".bold(), token.key_id);
                    println!("  {}: {}", "Signed At".bold(), token.signed_at);
                    println!("  {}: {}", "Expires At".bold(), token.expires_at);
                    println!("\n{}", "Full Token (JSON):".bold());
                    println!("{}", serde_json::to_string_pretty(&token)?);
                }
                Err(libdelve::Error::AuthorizationRejected) => {
                    println!("\n{}", "Request was rejected".red().bold());
                }
                Err(libdelve::Error::AuthorizationPending) => {
                    println!(
                        "\n{}",
                        "Request still pending after maximum attempts"
                            .yellow()
                            .bold()
                    );
                    println!("\n{}", "Suggestions:".cyan().bold());
                    println!("  - Check if the authorization URL was visited");
                    println!("  - Try polling again with more attempts");
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        Commands::Revoke {
            endpoint,
            verifier_id,
        } => {
            let client = DelegateClient::new(&endpoint);

            println!("{}", "Revoking authorization...".cyan());
            client.revoke_authorization(&verifier_id).await?;

            println!("\n{}", "Authorization revoked successfully!".green().bold());
            println!("\n{}", "Details:".bold());
            println!("  {}: {}", "Verifier ID".bold(), verifier_id);
        }
    }

    Ok(())
}
