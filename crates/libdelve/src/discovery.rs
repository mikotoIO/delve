//! DNS-based discovery for DelVe configuration

use crate::{DnsConfig, Error, Result, VerificationMode};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// Discover DelVe configuration for a domain via DNS
///
/// Looks up the `_delve.<domain>` TXT record and parses the configuration.
///
/// # Example
///
/// ```no_run
/// # use libdelve::discovery::discover_dns_config;
/// # async fn example() -> libdelve::Result<()> {
/// let config = discover_dns_config("example.com").await?;
/// println!("Mode: {:?}", config.mode);
/// # Ok(())
/// # }
/// ```
pub async fn discover_dns_config(domain: &str) -> Result<DnsConfig> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let lookup_domain = format!("_delve.{}", domain);

    let txt_records = resolver
        .txt_lookup(&lookup_domain)
        .await
        .map_err(|e| Error::Dns(format!("Failed to lookup {}: {}", lookup_domain, e)))?;

    // Find and parse the delve record
    for record in txt_records.iter() {
        let txt_data = record
            .iter()
            .map(|data| String::from_utf8_lossy(data.as_ref()))
            .collect::<String>();

        if txt_data.starts_with("v=delve") {
            return parse_dns_record(&txt_data);
        }
    }

    Err(Error::InvalidDnsRecord(format!(
        "No valid DelVe TXT record found for {}",
        lookup_domain
    )))
}

/// Parse a DelVe DNS TXT record
///
/// Expected format: `v=delve0.1; mode=delegate; endpoint=https://...; key=<base64>`
fn parse_dns_record(record: &str) -> Result<DnsConfig> {
    let mut version = None;
    let mut mode = None;
    let mut endpoint = None;
    let mut public_key = None;

    // Split by semicolon and parse key=value pairs
    for part in record.split(';') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            match key.trim() {
                "v" => version = Some(value.trim().to_string()),
                "mode" => mode = Some(value.trim().to_string()),
                "endpoint" => endpoint = Some(value.trim().to_string()),
                "key" => public_key = Some(value.trim().to_string()),
                _ => {} // Ignore unknown fields for forward compatibility
            }
        }
    }

    // Validate version
    let version = version.ok_or_else(|| Error::MissingField("v".to_string()))?;
    if !version.starts_with("delve0.") {
        return Err(Error::UnsupportedVersion(version));
    }

    // Parse mode
    let mode_str = mode.ok_or_else(|| Error::MissingField("mode".to_string()))?;
    let mode = match mode_str.as_str() {
        "delegate" => VerificationMode::Delegate,
        "direct" => VerificationMode::Direct,
        _ => return Err(Error::InvalidMode(mode_str)),
    };

    // Validate required fields based on mode
    let public_key = public_key.ok_or_else(|| Error::MissingField("key".to_string()))?;

    if mode == VerificationMode::Delegate && endpoint.is_none() {
        return Err(Error::MissingField("endpoint".to_string()));
    }

    Ok(DnsConfig {
        version,
        mode,
        endpoint,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_delegate_mode() {
        let record = "v=delve0.1; mode=delegate; endpoint=https://verify.example.org; key=MCowBQYDK2VwAyEAXXXX";
        let config = parse_dns_record(record).unwrap();

        assert_eq!(config.version, "delve0.1");
        assert_eq!(config.mode, VerificationMode::Delegate);
        assert_eq!(
            config.endpoint,
            Some("https://verify.example.org".to_string())
        );
        assert_eq!(config.public_key, "MCowBQYDK2VwAyEAXXXX");
    }

    #[test]
    fn test_parse_direct_mode() {
        let record = "v=delve0.1; mode=direct; key=MCowBQYDK2VwAyEAYYYY";
        let config = parse_dns_record(record).unwrap();

        assert_eq!(config.version, "delve0.1");
        assert_eq!(config.mode, VerificationMode::Direct);
        assert_eq!(config.endpoint, None);
        assert_eq!(config.public_key, "MCowBQYDK2VwAyEAYYYY");
    }

    #[test]
    fn test_parse_missing_version() {
        let record = "mode=delegate; endpoint=https://verify.example.org; key=XXXX";
        assert!(matches!(
            parse_dns_record(record),
            Err(Error::MissingField(_))
        ));
    }

    #[test]
    fn test_parse_invalid_version() {
        let record = "v=delve1.0; mode=delegate; endpoint=https://verify.example.org; key=XXXX";
        assert!(matches!(
            parse_dns_record(record),
            Err(Error::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn test_parse_delegate_missing_endpoint() {
        let record = "v=delve0.1; mode=delegate; key=XXXX";
        assert!(matches!(
            parse_dns_record(record),
            Err(Error::MissingField(_))
        ));
    }

    #[test]
    fn test_parse_invalid_mode() {
        let record = "v=delve0.1; mode=invalid; key=XXXX";
        assert!(matches!(
            parse_dns_record(record),
            Err(Error::InvalidMode(_))
        ));
    }
}
