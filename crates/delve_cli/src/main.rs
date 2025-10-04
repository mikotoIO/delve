use anyhow::Result;
use chrono::Duration;
use clap::{Parser, Subcommand};
use colored::Colorize;
use libdelve::{
    delegate_client::DelegateClient, discovery::discover_dns_config, ChallengeRequest,
    RequestStatus,
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
        verifier_id: String,

        /// Expiration time in minutes from now
        #[arg(long, default_value = "60")]
        expires_in: i64,
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
            verifier_id,
            expires_in,
        } => {
            // Resolve endpoint from DNS if not provided
            let endpoint = if let Some(ep) = endpoint {
                ep
            } else {
                println!(
                    "{}",
                    format!("Discovering endpoint for {}...", domain).cyan()
                );
                let config = discover_dns_config(&domain).await?;
                config.endpoint.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Domain {} uses direct mode, no delegate endpoint available",
                        domain
                    )
                })?
            };

            let client = DelegateClient::new(&endpoint);

            let request =
                ChallengeRequest::new(&domain, &verifier_id, Duration::minutes(expires_in))?;

            println!("Submitting challenge to delegate {}", endpoint.cyan());
            let response = client.submit_challenge(&request).await?;

            println!("\n{}", "Challenge submitted successfully!".green().bold());
            println!("\n{}", "Response:".bold());
            println!("  {}: {}", "Request ID".bold(), response.request_id);
            println!(
                "  {}: {}",
                "Status".bold(),
                match response.status {
                    RequestStatus::Authorized => format!("{:?}", response.status).green(),
                    RequestStatus::Rejected => format!("{:?}", response.status).red(),
                    RequestStatus::Pending => format!("{:?}", response.status).yellow(),
                }
            );
            if let Some(auth_url) = &response.authorization_url {
                println!("  {}: {}", "Authorization URL".bold(), auth_url.underline());
            }

            if response.status == RequestStatus::Pending {
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
