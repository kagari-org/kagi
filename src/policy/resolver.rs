use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use hickory_resolver::Resolver as HickoryResolver;
use hickory_resolver::TokioResolver;

pub struct SystemResolver {
    inner: TokioResolver,
}

impl SystemResolver {
    pub fn new() -> Result<Self> {
        let inner = HickoryResolver::builder_tokio()
            .context("failed to create DNS resolver builder")?
            .build()
            .context("failed to build DNS resolver")?;
        Ok(Self { inner })
    }

    #[cfg(test)]
    pub fn for_test() -> Self {
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::net::runtime::TokioRuntimeProvider;

        let inner = TokioResolver::builder_with_config(
            ResolverConfig::from_name_servers(Vec::new()),
            TokioRuntimeProvider::default(),
        )
        .build()
        .expect("test resolver");
        Self { inner }
    }

    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let lookup = self
            .inner
            .lookup_ip(host)
            .await
            .with_context(|| format!("DNS lookup failed for {host}"))?;
        let mut ips = Vec::new();
        for ip in lookup.iter() {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        Ok(ips)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizedHost {
    Ip(IpAddr),
    Name(String),
}

pub fn normalize_host(raw: &str) -> Result<NormalizedHost> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("target host is empty");
    }
    let without_brackets = raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw);
    if let Ok(ip) = without_brackets.parse::<IpAddr>() {
        return Ok(NormalizedHost::Ip(ip));
    }
    if raw.len() > 253 {
        bail!("target host is too long");
    }
    let normalized = raw.trim_end_matches('.').to_lowercase();
    if normalized.is_empty() {
        bail!("target host is empty");
    }
    if !normalized.is_ascii() {
        bail!("non-ASCII host names are not supported");
    }
    if normalized.chars().any(|c| {
        c.is_ascii_whitespace()
            || c.is_ascii_control()
            || matches!(c, '/' | '\\' | '@' | '#' | '?' | '%')
    }) {
        bail!("target host contains unsupported characters");
    }
    if normalized
        .split('.')
        .any(|label| label.is_empty() || label.len() > 63)
    {
        bail!("target host has an invalid label");
    }
    Ok(NormalizedHost::Name(normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ipv4_and_ipv6() {
        assert_eq!(
            normalize_host("127.0.0.1").unwrap(),
            NormalizedHost::Ip("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            normalize_host("[::1]").unwrap(),
            NormalizedHost::Ip("::1".parse().unwrap())
        );
    }

    #[test]
    fn normalizes_names() {
        assert_eq!(
            normalize_host("API.Example.COM.").unwrap(),
            NormalizedHost::Name("api.example.com".into())
        );
    }

    #[test]
    fn rejects_bad_names() {
        assert!(normalize_host("").is_err());
        assert!(normalize_host("a b").is_err());
        assert!(normalize_host("a/b").is_err());
        assert!(normalize_host("münchen.example").is_err());
    }
}
