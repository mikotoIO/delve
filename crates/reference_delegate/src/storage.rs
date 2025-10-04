//! JSON file-based storage for delegate service

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use libdelve::{ChallengeRequest, RequestStatus, VerificationToken};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Storage for verification requests
#[derive(Debug, Clone)]
pub struct Storage {
    data_dir: PathBuf,
}

/// A stored verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRequest {
    pub request_id: String,
    pub request: ChallengeRequest,
    pub status: RequestStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub token: Option<VerificationToken>,
    pub rejected_at: Option<DateTime<Utc>>,
}

/// Keypair storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeypair {
    pub domain: String,
    pub public_key: String,
    pub private_key: String,
    pub key_id: String,
    pub created_at: DateTime<Utc>,
}

/// Domain-service approval record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainServiceApproval {
    pub domain: String,
    pub verifier: String,
    pub verifier_id: String,
    pub first_approved_at: DateTime<Utc>,
    pub last_approved_at: DateTime<Utc>,
}

impl Storage {
    /// Create a new storage instance
    pub fn new(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let data_dir = data_dir.into();

        // Create directories if they don't exist
        let requests_dir = data_dir.join("requests");
        let keys_dir = data_dir.join("keys");
        let approvals_dir = data_dir.join("approvals");

        fs::create_dir_all(&requests_dir)
            .with_context(|| format!("Failed to create requests directory: {:?}", requests_dir))?;
        fs::create_dir_all(&keys_dir)
            .with_context(|| format!("Failed to create keys directory: {:?}", keys_dir))?;
        fs::create_dir_all(&approvals_dir)
            .with_context(|| format!("Failed to create approvals directory: {:?}", approvals_dir))?;

        Ok(Self { data_dir })
    }

    /// Get path to requests directory
    fn requests_dir(&self) -> PathBuf {
        self.data_dir.join("requests")
    }

    /// Get path to keys directory
    fn keys_dir(&self) -> PathBuf {
        self.data_dir.join("keys")
    }

    /// Get path to approvals directory
    fn approvals_dir(&self) -> PathBuf {
        self.data_dir.join("approvals")
    }

    /// Get path to a specific request file
    fn request_path(&self, request_id: &str) -> PathBuf {
        self.requests_dir().join(format!("{}.json", request_id))
    }

    /// Get path to a domain's keypair file
    fn keypair_path(&self, domain: &str) -> PathBuf {
        // Sanitize domain name for filename
        let safe_domain = domain.replace(['/', '\\', ':'], "_");
        self.keys_dir().join(format!("{}.json", safe_domain))
    }

    /// Get path to a domain-service approval file
    fn approval_path(&self, domain: &str, verifier: &str, verifier_id: &str) -> PathBuf {
        // Create a unique filename from domain, verifier, and verifier_id
        let safe_domain = domain.replace(['/', '\\', ':', '.'], "_");
        let safe_verifier = verifier.replace(['/', '\\', ':', '.'], "_");
        let safe_verifier_id = verifier_id.replace(['/', '\\', ':', '.'], "_");
        let filename = format!("{}__{}__{}.json", safe_domain, safe_verifier, safe_verifier_id);
        self.approvals_dir().join(filename)
    }

    /// Store a new verification request
    pub fn store_request(&self, request: StoredRequest) -> Result<()> {
        let path = self.request_path(&request.request_id);
        let json = serde_json::to_string_pretty(&request).context("Failed to serialize request")?;

        fs::write(&path, json).with_context(|| format!("Failed to write request to {:?}", path))?;

        Ok(())
    }

    /// Get a verification request by ID
    pub fn get_request(&self, request_id: &str) -> Result<Option<StoredRequest>> {
        let path = self.request_path(request_id);

        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read request from {:?}", path))?;

        let request: StoredRequest =
            serde_json::from_str(&json).context("Failed to deserialize request")?;

        Ok(Some(request))
    }

    /// Update a verification request
    pub fn update_request(&self, request: StoredRequest) -> Result<()> {
        self.store_request(request)
    }

    /// Delete a verification request
    #[allow(dead_code)]
    pub fn delete_request(&self, request_id: &str) -> Result<()> {
        let path = self.request_path(request_id);

        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to delete request from {:?}", path))?;
        }

        Ok(())
    }

    /// List all requests for a domain
    #[allow(dead_code)]
    pub fn list_requests_for_domain(&self, domain: &str) -> Result<Vec<StoredRequest>> {
        let mut requests = Vec::new();

        let requests_dir = self.requests_dir();
        if !requests_dir.exists() {
            return Ok(requests);
        }

        for entry in fs::read_dir(&requests_dir)
            .with_context(|| format!("Failed to read requests directory: {:?}", requests_dir))?
        {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let json = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read request from {:?}", path))?;

            let request: StoredRequest =
                serde_json::from_str(&json).context("Failed to deserialize request")?;

            if request.request.domain == domain {
                requests.push(request);
            }
        }

        Ok(requests)
    }

    /// Store a keypair for a domain
    pub fn store_keypair(&self, keypair: StoredKeypair) -> Result<()> {
        let path = self.keypair_path(&keypair.domain);
        let json = serde_json::to_string_pretty(&keypair).context("Failed to serialize keypair")?;

        fs::write(&path, json).with_context(|| format!("Failed to write keypair to {:?}", path))?;

        Ok(())
    }

    /// Get a keypair for a domain
    pub fn get_keypair(&self, domain: &str) -> Result<Option<StoredKeypair>> {
        let path = self.keypair_path(domain);

        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read keypair from {:?}", path))?;

        let keypair: StoredKeypair =
            serde_json::from_str(&json).context("Failed to deserialize keypair")?;

        Ok(Some(keypair))
    }

    /// Generate and store a new keypair for a domain
    pub fn generate_keypair_for_domain(&self, domain: &str) -> Result<StoredKeypair> {
        let (private_key, public_key) = libdelve::crypto::generate_keypair();

        let keypair = StoredKeypair {
            domain: domain.to_string(),
            public_key,
            private_key,
            key_id: format!("{}-{}", domain, Utc::now().format("%Y-%m")),
            created_at: Utc::now(),
        };

        self.store_keypair(keypair.clone())?;

        Ok(keypair)
    }

    /// Get or create a keypair for a domain
    pub fn get_or_create_keypair(&self, domain: &str) -> Result<StoredKeypair> {
        if let Some(keypair) = self.get_keypair(domain)? {
            Ok(keypair)
        } else {
            self.generate_keypair_for_domain(domain)
        }
    }

    /// Check if a domain-service combination has been previously approved
    pub fn is_domain_service_approved(&self, domain: &str, verifier: &str, verifier_id: &str) -> Result<bool> {
        let path = self.approval_path(domain, verifier, verifier_id);
        Ok(path.exists())
    }

    /// Get a domain-service approval record
    pub fn get_domain_service_approval(&self, domain: &str, verifier: &str, verifier_id: &str) -> Result<Option<DomainServiceApproval>> {
        let path = self.approval_path(domain, verifier, verifier_id);

        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read approval from {:?}", path))?;

        let approval: DomainServiceApproval =
            serde_json::from_str(&json).context("Failed to deserialize approval")?;

        Ok(Some(approval))
    }

    /// Record a domain-service approval
    pub fn record_domain_service_approval(&self, domain: &str, verifier: &str, verifier_id: &str) -> Result<()> {
        let now = Utc::now();

        // Check if approval already exists
        let approval = if let Some(mut existing) = self.get_domain_service_approval(domain, verifier, verifier_id)? {
            // Update last_approved_at
            existing.last_approved_at = now;
            existing
        } else {
            // Create new approval
            DomainServiceApproval {
                domain: domain.to_string(),
                verifier: verifier.to_string(),
                verifier_id: verifier_id.to_string(),
                first_approved_at: now,
                last_approved_at: now,
            }
        };

        let path = self.approval_path(domain, verifier, verifier_id);
        let json = serde_json::to_string_pretty(&approval).context("Failed to serialize approval")?;

        fs::write(&path, json).with_context(|| format!("Failed to write approval to {:?}", path))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn test_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();

        assert!(storage.requests_dir().exists());
        assert!(storage.keys_dir().exists());
    }

    #[test]
    fn test_store_and_get_request() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();

        let request = StoredRequest {
            request_id: Uuid::new_v4().to_string(),
            request: ChallengeRequest {
                domain: "example.com".to_string(),
                verifier: "service.example.net".to_string(),
                verifier_id: "instance-123".to_string(),
                challenge: "test-challenge".to_string(),
                expires_at: Utc::now() + Duration::hours(1),
                metadata: None,
            },
            status: RequestStatus::Pending,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            token: None,
            rejected_at: None,
        };

        storage.store_request(request.clone()).unwrap();

        let retrieved = storage.get_request(&request.request_id).unwrap().unwrap();
        assert_eq!(retrieved.request_id, request.request_id);
        assert_eq!(retrieved.request.domain, request.request.domain);
    }

    #[test]
    fn test_keypair_generation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();

        let keypair = storage.generate_keypair_for_domain("example.com").unwrap();

        assert_eq!(keypair.domain, "example.com");
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.private_key.is_empty());

        let retrieved = storage.get_keypair("example.com").unwrap().unwrap();
        assert_eq!(retrieved.public_key, keypair.public_key);
    }

    #[test]
    fn test_get_or_create_keypair() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();

        let keypair1 = storage.get_or_create_keypair("example.com").unwrap();
        let keypair2 = storage.get_or_create_keypair("example.com").unwrap();

        // Should return the same keypair
        assert_eq!(keypair1.public_key, keypair2.public_key);
    }
}
