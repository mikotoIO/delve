use anyhow::Result;
use chrono::Duration;
use clap::{Parser, Subcommand};
use colored::Colorize;
use libdelve::{
    delegate_client::DelegateClient, discovery::discover_dns_config, verifier::Verifier,
};

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
        /// If not provided, will use DNS discovery from the domain
        #[arg(short, long)]
        endpoint: Option<String>,

        /// Domain to verify
        #[arg(short, long)]
        domain: String,

        /// Verifier instance ID
        #[arg(long)]
        verifier: String,

        /// Expiration time in minutes from now
        #[arg(long, default_value = "60")]
        expires_in: i64,
    },

    /// Retrieve and verify a verification token
    Token {
        /// Delegate endpoint URL
        #[arg(short, long)]
        endpoint: String,

        /// Request ID from challenge response
        #[arg(short, long)]
        request_id: String,

        /// Domain being verified
        #[arg(short, long)]
        domain: String,

        /// Verifier instance ID
        #[arg(long)]
        verifier: String,

        /// Original challenge string
        #[arg(short, long)]
        challenge: String,
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
            expires_in,
        } => {
            // Discover DNS configuration
            println!(
                "{}",
                format!("Discovering configuration for {}...", domain).cyan()
            );
            let dns_config = discover_dns_config(&domain).await?;

            // Resolve endpoint from DNS if not provided
            let endpoint = if let Some(ep) = endpoint {
                ep
            } else {
                dns_config.endpoint.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Domain {} uses direct mode, no delegate endpoint available",
                        domain
                    )
                })?
            };

            // Create verifier instance
            let verifier_instance = Verifier::new(&verifier, Duration::minutes(expires_in));

            // Generate challenge
            let (challenge, expires_at) = verifier_instance.create_challenge(&domain)?;

            println!("Submitting challenge to delegate {}", endpoint.cyan());
            let (request_id, immediate_token) = verifier_instance
                .submit_challenge_to_delegate(&domain, &endpoint, &challenge, expires_at)
                .await?;

            println!("\n{}", "Challenge submitted!".green().bold());
            println!("  {}: {}", "Request ID".bold(), request_id);

            // Use immediate token if available, otherwise poll
            let token = if let Some(token) = immediate_token {
                println!("\n{}", "✓ Immediately authorized!".green().bold());
                token
            } else {
                println!("\n{}", "Waiting for authorization...".cyan());
                verifier_instance
                    .poll_for_token(&endpoint, &request_id, Some(60), Some(5))
                    .await?
            };

            println!("\n{}", "Token received!".green().bold());
            println!("  {}: {}", "Domain".bold(), token.domain);
            println!("  {}: {}", "Signed At".bold(), token.signed_at);

            // Verify signature
            println!("\n{}", "Verifying signature...".cyan());
            verifier_instance.verify_token(&token, &domain, &challenge, &dns_config.public_key)?;

            println!("\n{}", "✓ Verification successful!".green().bold());
            println!("\n{}", "Token Details:".bold());
            println!("  {}: {}", "Domain".bold(), token.domain);
            println!("  {}: {}", "Verifier ID".bold(), token.verifier_id);
            println!("  {}: {}", "Key ID".bold(), token.key_id);
            println!("  {}: {}", "Signed At".bold(), token.signed_at);
            println!("  {}: {}", "Expires At".bold(), token.expires_at);
            println!("\n{}", "Full Token (JSON):".bold());
            println!("{}", serde_json::to_string_pretty(&token)?);
        }

        Commands::Token {
            endpoint,
            request_id,
            domain,
            verifier,
            challenge,
        } => {
            // Discover DNS configuration
            println!(
                "{}",
                format!("Discovering configuration for {}...", domain).cyan()
            );
            let dns_config = discover_dns_config(&domain).await?;

            let client = DelegateClient::new(&endpoint);

            println!("{}", "Retrieving token...".cyan());
            let response = client.get_token(&request_id).await?;

            match response {
                libdelve::TokenResponse::Authorized {
                    request_id: _,
                    token,
                } => {
                    println!("\n{}", "Token received!".green().bold());
                    println!("  {}: {}", "Domain".bold(), token.domain);
                    println!("  {}: {}", "Signed At".bold(), token.signed_at);

                    // Verify signature
                    println!("\n{}", "Verifying signature...".cyan());
                    let verifier_instance = Verifier::new(&verifier, Duration::minutes(60));
                    verifier_instance.verify_token(
                        &token,
                        &domain,
                        &challenge,
                        &dns_config.public_key,
                    )?;

                    println!("\n{}", "✓ Verification successful!".green().bold());
                    println!("\n{}", "Token Details:".bold());
                    println!("  {}: {}", "Domain".bold(), token.domain);
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
