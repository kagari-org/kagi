use std::fmt;
use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use globset::{GlobBuilder, GlobMatcher};
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ForwardKind {
    #[default]
    Connect,
    Listen,
    Any,
}

impl ForwardKind {
    pub fn applies(self, direction: Direction) -> bool {
        match self {
            ForwardKind::Any => true,
            ForwardKind::Connect => direction == Direction::Connect,
            ForwardKind::Listen => direction == Direction::Listen,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    #[default]
    Glob,
    Regex,
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Connect,
    Listen,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    One(u16),
    Text(String),
    Many(Vec<PortItem>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortItem {
    One(u16),
    Text(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub action: Action,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub forward: ForwardKind,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default, rename = "match")]
    pub match_kind: MatchKind,
    #[serde(default)]
    pub port: Option<PortSpec>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
pub enum HostMatcher {
    Exact(String),
    Glob {
        matcher: GlobMatcher,
        pattern: String,
    },
    Regex {
        regex: Regex,
        pattern: String,
    },
}

impl HostMatcher {
    pub fn matches(&self, host: &str) -> bool {
        match self {
            HostMatcher::Exact(value) => value.eq_ignore_ascii_case(host),
            HostMatcher::Glob { matcher, .. } => matcher.is_match(host),
            HostMatcher::Regex { regex, .. } => regex.is_match(host),
        }
    }
}

impl fmt::Display for HostMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostMatcher::Exact(value) => f.write_str(value),
            HostMatcher::Glob { pattern, .. } => f.write_str(pattern),
            HostMatcher::Regex { pattern, .. } => f.write_str(pattern),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PortSet {
    Any,
    Ranges(Vec<(u16, u16)>),
}

impl PortSet {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortSet::Any => true,
            PortSet::Ranges(ranges) => {
                if port == 0 {
                    return false;
                }
                ranges
                    .iter()
                    .any(|(start, end)| (*start..=*end).contains(&port))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub source: String,
    pub action: Action,
    pub forward: ForwardKind,
    pub host: Option<HostMatcher>,
    pub cidr: Option<IpNet>,
    pub ports: PortSet,
}

impl Rule {
    pub fn summary(&self) -> String {
        let action = match self.action {
            Action::Allow => "allow",
            Action::Deny => "deny",
        };
        let target = match (&self.host, &self.cidr) {
            (Some(host), None) => format!("host={host}"),
            (None, Some(cidr)) => format!("cidr={cidr}"),
            _ => "any".to_string(),
        };
        let ports = match &self.ports {
            PortSet::Any => "*".to_string(),
            PortSet::Ranges(ranges) => ranges
                .iter()
                .map(|(a, b)| {
                    if a == b {
                        a.to_string()
                    } else {
                        format!("{a}-{b}")
                    }
                })
                .collect::<Vec<_>>()
                .join(","),
        };
        format!("{action} {target} port={ports}")
    }
}

pub fn compile_rule(source: String, cfg: &RuleConfig) -> Result<Option<Rule>> {
    if !cfg.enabled {
        return Ok(None);
    }
    if cfg.host.is_none() && cfg.cidr.is_none() {
        bail!("{source}: rule must specify host or cidr");
    }
    if cfg.host.is_some() && cfg.cidr.is_some() {
        bail!("{source}: host and cidr are mutually exclusive");
    }

    let host = match &cfg.host {
        Some(raw) => {
            let raw = raw.trim();
            if raw.is_empty() {
                bail!("{source}: host pattern is empty");
            }
            let matcher = match cfg.match_kind {
                MatchKind::Exact => HostMatcher::Exact(raw.to_lowercase()),
                MatchKind::Glob => HostMatcher::Glob {
                    matcher: GlobBuilder::new(&raw.to_lowercase())
                        .case_insensitive(true)
                        .literal_separator(false)
                        .backslash_escape(false)
                        .build()
                        .with_context(|| format!("{source}: invalid glob"))?
                        .compile_matcher(),
                    pattern: raw.to_string(),
                },
                MatchKind::Regex => HostMatcher::Regex {
                    regex: RegexBuilder::new(&format!("^(?:{raw})$"))
                        .case_insensitive(true)
                        .size_limit(1 << 20)
                        .build()
                        .with_context(|| format!("{source}: invalid regex"))?,
                    pattern: raw.to_string(),
                },
            };
            Some(matcher)
        }
        None => None,
    };

    let cidr = match &cfg.cidr {
        Some(raw) => Some(parse_cidr(raw).with_context(|| format!("{source}: invalid cidr"))?),
        None => None,
    };

    let ports = match &cfg.port {
        Some(spec) => compile_ports(source.as_str(), spec)?,
        None => PortSet::Any,
    };

    Ok(Some(Rule {
        source,
        action: cfg.action,
        forward: cfg.forward,
        host,
        cidr,
        ports,
    }))
}

fn parse_cidr(raw: &str) -> Result<IpNet> {
    let raw = raw.trim();
    if let Ok(net) = raw.parse::<IpNet>() {
        return Ok(net);
    }
    let ip = raw.parse::<IpAddr>()?;
    Ok(match ip {
        IpAddr::V4(ip) => IpNet::new(IpAddr::V4(ip), 32)?,
        IpAddr::V6(ip) => IpNet::new(IpAddr::V6(ip), 128)?,
    })
}

fn compile_ports(source: &str, spec: &PortSpec) -> Result<PortSet> {
    let mut ranges = Vec::new();
    match spec {
        PortSpec::One(port) => add_port(source, *port, &mut ranges)?,
        PortSpec::Text(text) => {
            if text.trim() == "*" {
                return Ok(PortSet::Any);
            }
            for part in text.split(',') {
                add_port_text(source, part.trim(), &mut ranges)?;
            }
        }
        PortSpec::Many(items) => {
            for item in items {
                match item {
                    PortItem::One(port) => add_port(source, *port, &mut ranges)?,
                    PortItem::Text(text) => add_port_text(source, text.trim(), &mut ranges)?,
                }
            }
        }
    }
    if ranges.is_empty() {
        bail!("{source}: port set is empty");
    }
    Ok(PortSet::Ranges(ranges))
}

fn add_port(source: &str, port: u16, ranges: &mut Vec<(u16, u16)>) -> Result<()> {
    if port == 0 {
        bail!("{source}: port 0 must be expressed as \"*\"");
    }
    ranges.push((port, port));
    Ok(())
}

fn add_port_text(source: &str, text: &str, ranges: &mut Vec<(u16, u16)>) -> Result<()> {
    if text.is_empty() {
        bail!("{source}: empty port entry");
    }
    if let Some((a, b)) = text.split_once('-') {
        let start: u16 = a
            .trim()
            .parse()
            .with_context(|| format!("{source}: bad port range"))?;
        let end: u16 = b
            .trim()
            .parse()
            .with_context(|| format!("{source}: bad port range"))?;
        if start == 0 || end == 0 || start > end {
            bail!("{source}: invalid port range {start}-{end}");
        }
        ranges.push((start, end));
    } else {
        add_port(
            source,
            text.parse()
                .with_context(|| format!("{source}: bad port"))?,
            ranges,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_rule(pattern: &str, action: Action, ports: PortSet) -> Rule {
        compile_rule(
            "test".into(),
            &RuleConfig {
                action,
                enabled: true,
                forward: ForwardKind::Connect,
                host: Some(pattern.into()),
                cidr: None,
                match_kind: MatchKind::Glob,
                port: None,
            },
        )
        .unwrap()
        .unwrap()
        .with_ports(ports)
    }

    impl Rule {
        fn with_ports(mut self, ports: PortSet) -> Self {
            self.ports = ports;
            self
        }
    }

    #[test]
    fn glob_host_matches_case_insensitively() {
        let rule = host_rule("*.Example.com", Action::Allow, PortSet::Any);
        let host = rule.host.as_ref().unwrap();
        assert!(host.matches("api.example.com"));
        assert!(!host.matches("example.com"));
    }

    #[test]
    fn port_ranges_and_any() {
        assert!(PortSet::Any.matches(0));
        let set = compile_ports("t", &PortSpec::Text("80,443,8000-8100".into())).unwrap();
        assert!(set.matches(80));
        assert!(set.matches(8099));
        assert!(!set.matches(9000));
        assert!(!set.matches(0));
    }

    #[test]
    fn cidr_and_single_ip() {
        let rule = compile_rule(
            "test".into(),
            &RuleConfig {
                action: Action::Deny,
                enabled: true,
                forward: ForwardKind::Connect,
                host: None,
                cidr: Some("10.0.0.0/8".into()),
                match_kind: MatchKind::Glob,
                port: None,
            },
        )
        .unwrap()
        .unwrap();
        let cidr = rule.cidr.as_ref().unwrap();
        assert!(cidr.contains(&"10.1.2.3".parse::<std::net::IpAddr>().unwrap()));
        assert!(!cidr.contains(&"192.168.1.1".parse::<std::net::IpAddr>().unwrap()));
    }

    #[test]
    fn rule_requires_host_or_cidr() {
        let err = compile_rule(
            "test".into(),
            &RuleConfig {
                action: Action::Allow,
                enabled: true,
                forward: ForwardKind::Any,
                host: None,
                cidr: None,
                match_kind: MatchKind::Glob,
                port: None,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("must specify host or cidr"));
    }
}
