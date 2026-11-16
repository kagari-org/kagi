use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use globset::{GlobBuilder, GlobMatcher};
use regex::{Regex, RegexBuilder};
use russh::keys::{HashAlg, PublicKey, parse_public_key_base64};
use tracing::warn;

use crate::config::{Action, Config, DefaultPolicy, Direction, MatchKind, Rule, compile_rule};

pub mod resolver;

pub use resolver::{NormalizedHost, SystemResolver, normalize_host};

const MAX_DNS_CANDIDATES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Subject(String);

impl Subject {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn label(&self) -> String {
        self.0.clone()
    }
}

#[derive(Clone)]
pub enum UserMatcher {
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

impl UserMatcher {
    pub fn matches(&self, login: &str) -> bool {
        match self {
            Self::Exact(value) => value == login,
            Self::Glob { matcher, .. } => matcher.is_match(login),
            Self::Regex { regex, .. } => regex.is_match(login),
        }
    }
}

impl std::fmt::Debug for UserMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact(value) => f.debug_tuple("Exact").field(value).finish(),
            Self::Glob { pattern, .. } => f.debug_tuple("Glob").field(pattern).finish(),
            Self::Regex { pattern, .. } => f.debug_tuple("Regex").field(pattern).finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserPolicy {
    pub name: String,
    pub matcher: UserMatcher,
    pub admin: bool,
    pub enabled: bool,
    pub skip_key_check: bool,
    pub stream_buffer_bytes: usize,
    pub groups: Vec<String>,
    pub fingerprints: Vec<String>,
    pub rules: Vec<Arc<Rule>>,
}

#[derive(Debug, Clone)]
pub struct GroupPolicy {
    pub name: String,
    pub rules: Vec<Arc<Rule>>,
}

pub struct Policy {
    pub config: Config,
    pub generation: u64,
    pub users: BTreeMap<String, UserPolicy>,
    pub exact_users: HashMap<String, String>,
    pub groups: BTreeMap<String, GroupPolicy>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub requested_host: String,
    pub candidates: Vec<IpAddr>,
    pub port: u16,
    pub direction: Direction,
}

#[derive(Debug, Clone)]
pub struct RuleHit {
    pub source: String,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub allowed: bool,
    pub allowed_ips: Vec<IpAddr>,
    pub matched: Vec<RuleHit>,
}

impl Policy {
    pub fn build(config: Config, generation: u64) -> Result<Self> {
        let mut warnings = Vec::new();

        if !config.users.values().any(|u| u.admin) {
            warnings.push("no user with admin = true; the admin TUI is unavailable".to_string());
        }
        if config.server.default_policy == DefaultPolicy::Allow {
            warnings.push(
                "default_policy=allow permits every target that is not explicitly denied"
                    .to_string(),
            );
        }
        if config.server.allow_remote_forward {
            warnings.push(
                "global -R is enabled; remote forwarding is available to every configured user"
                    .to_string(),
            );
        }
        if let Some(user) = config.users.get("admin")
            && !user.admin
        {
            warnings.push(
                "a user named `admin` exists but admin = false; the `admin` command will be rejected"
                    .to_string(),
            );
        }

        let mut groups = BTreeMap::new();
        for (name, group) in &config.groups {
            let mut rules = Vec::new();
            for (idx, rule) in group.rules.iter().enumerate() {
                let source = format!("group:{name}#{idx}");
                if let Some(rule) = compile_rule(source, rule)? {
                    rules.push(Arc::new(rule));
                }
            }
            groups.insert(
                name.clone(),
                GroupPolicy {
                    name: name.clone(),
                    rules,
                },
            );
        }

        let mut users = BTreeMap::new();
        let mut exact_users = HashMap::new();
        let mut key_index = HashMap::new();
        for (name, user) in &config.users {
            let matcher = compile_user_matcher(name, user.match_kind)
                .with_context(|| format!("user {name}: invalid match pattern"))?;
            if let UserMatcher::Exact(value) = &matcher {
                exact_users.insert(value.clone(), name.clone());
            }
            if user.keys.is_empty() && !user.skip_key_check {
                bail!(
                    "user {name}: keys must not be empty (set skip_key_check = true for anonymous access)"
                );
            }
            for group in &user.groups {
                if !groups.contains_key(group) {
                    bail!("user {name}: unknown group {group}");
                }
            }
            if user.enabled && user.skip_key_check && name != "anonymous" {
                warnings.push(format!(
                    "user {name}: skip_key_check=true; any login matching this entry can authenticate without a key"
                ));
            }
            if user.enabled && user.admin && user.skip_key_check {
                warnings.push(format!(
                    "user {name}: admin=true with skip_key_check=true; any matching login can open the admin TUI"
                ));
            }

            let mut fingerprints = Vec::new();
            for (idx, line) in user.keys.iter().enumerate() {
                let key = parse_public_key(line)
                    .with_context(|| format!("user {name}: invalid key #{idx}"))?;
                let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
                if fingerprints.contains(&fingerprint) {
                    continue;
                }
                if let Some(existing) = key_index.insert(fingerprint.clone(), name.clone()) {
                    bail!("key {fingerprint} is assigned to both {existing} and {name}");
                }
                fingerprints.push(fingerprint);
            }

            let mut rules = Vec::new();
            for (idx, rule) in user.rules.iter().enumerate() {
                let source = format!("user:{name}#{idx}");
                if let Some(rule) = compile_rule(source, rule)? {
                    rules.push(Arc::new(rule));
                }
            }
            for group in &user.groups {
                if let Some(group) = groups.get(group) {
                    rules.extend(group.rules.iter().cloned());
                }
            }

            users.insert(
                name.clone(),
                UserPolicy {
                    name: name.clone(),
                    matcher,
                    admin: user.admin,
                    enabled: user.enabled,
                    skip_key_check: user.skip_key_check,
                    stream_buffer_bytes: user.stream_buffer_bytes,
                    groups: user.groups.clone(),
                    fingerprints,
                    rules,
                },
            );
        }

        Ok(Self {
            config,
            generation,
            users,
            exact_users,
            groups,
            warnings,
        })
    }

    pub fn user_for_login(&self, login: &str) -> Option<&UserPolicy> {
        if let Some(name) = self.exact_users.get(login) {
            return self.users.get(name);
        }
        let mut matched = None;
        for user in self.users.values() {
            if !user.enabled || matches!(&user.matcher, UserMatcher::Exact(_)) {
                continue;
            }
            if user.matcher.matches(login) {
                if matched.is_some() {
                    warn!("login {login} matches multiple user patterns; rejecting");
                    return None;
                }
                matched = Some(user);
            }
        }
        matched
    }

    fn subject_rules(&self, subject: &Subject) -> Option<&[Arc<Rule>]> {
        let user = self.users.get(subject.as_str())?;
        if !user.enabled {
            return None;
        }
        Some(&user.rules)
    }

    pub fn evaluate(&self, subject: &Subject, target: &Target) -> Option<Decision> {
        let rules = self.subject_rules(subject)?;
        Some(evaluate_rules(
            rules,
            target,
            self.config.server.default_policy,
        ))
    }

    pub fn warning_list(&self) -> &[String] {
        &self.warnings
    }
}

fn compile_user_matcher(pattern: &str, kind: MatchKind) -> Result<UserMatcher> {
    if pattern.is_empty() {
        bail!("user name pattern is empty");
    }
    match kind {
        MatchKind::Exact => Ok(UserMatcher::Exact(pattern.to_string())),
        MatchKind::Glob => Ok(UserMatcher::Glob {
            matcher: GlobBuilder::new(pattern)
                .case_insensitive(false)
                .literal_separator(false)
                .backslash_escape(false)
                .build()
                .context("invalid glob")?
                .compile_matcher(),
            pattern: pattern.to_string(),
        }),
        MatchKind::Regex => Ok(UserMatcher::Regex {
            regex: RegexBuilder::new(&format!("^(?:{pattern})$"))
                .case_insensitive(false)
                .size_limit(1 << 20)
                .build()
                .context("invalid regex")?,
            pattern: pattern.to_string(),
        }),
    }
}

fn parse_public_key(line: &str) -> Result<PublicKey> {
    let line = line.trim();
    if line.is_empty() {
        bail!("empty public key");
    }
    if let Ok(key) = PublicKey::from_openssh(line) {
        return Ok(key);
    }
    let base64 = line.split_whitespace().nth(1).unwrap_or(line);
    parse_public_key_base64(base64).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn evaluate_rules(
    rules: &[Arc<Rule>],
    target: &Target,
    default_policy: DefaultPolicy,
) -> Decision {
    let mut host_denied = false;
    let mut host_allowed = false;
    let mut hits: BTreeMap<String, RuleHit> = BTreeMap::new();

    for rule in rules {
        if !rule.forward.applies(target.direction) || !rule.ports.matches(target.port) {
            continue;
        }
        let Some(matcher) = &rule.host else {
            continue;
        };
        if matcher.matches(&target.requested_host) {
            record_hit(&mut hits, rule);
            match rule.action {
                Action::Deny => host_denied = true,
                Action::Allow => host_allowed = true,
            }
        }
    }

    if host_denied {
        return Decision {
            allowed: false,
            allowed_ips: Vec::new(),
            matched: hits.into_values().collect(),
        };
    }

    let mut allowed_ips = Vec::new();
    for ip in &target.candidates {
        let mut denied = false;
        let mut allowed = host_allowed;
        for rule in rules {
            if !rule.forward.applies(target.direction) || !rule.ports.matches(target.port) {
                continue;
            }
            let Some(cidr) = &rule.cidr else {
                continue;
            };
            if cidr.contains(ip) {
                record_hit(&mut hits, rule);
                match rule.action {
                    Action::Deny => denied = true,
                    Action::Allow => allowed = true,
                }
            }
        }
        if denied {
            continue;
        }
        if !allowed && default_policy == DefaultPolicy::Allow {
            allowed = true;
        }
        if allowed {
            allowed_ips.push(*ip);
        }
    }

    Decision {
        allowed: !allowed_ips.is_empty(),
        allowed_ips,
        matched: hits.into_values().collect(),
    }
}

fn record_hit(hits: &mut BTreeMap<String, RuleHit>, rule: &Rule) {
    hits.entry(rule.source.clone()).or_insert_with(|| RuleHit {
        source: rule.source.clone(),
        summary: rule.summary(),
    });
}

pub async fn resolve_target(
    host: &str,
    port: u16,
    direction: Direction,
    resolver: &SystemResolver,
    timeout: Duration,
) -> Result<Target> {
    let normalized = normalize_host(host)?;
    let (requested_host, candidates) = match normalized {
        NormalizedHost::Ip(ip) => (ip.to_string(), vec![ip]),
        NormalizedHost::Name(name) => {
            let ips = tokio::time::timeout(timeout, resolver.resolve(&name))
                .await
                .context("DNS lookup timed out")??;
            let mut candidates = Vec::new();
            for ip in ips {
                if !candidates.contains(&ip) {
                    candidates.push(ip);
                }
                if candidates.len() >= MAX_DNS_CANDIDATES {
                    break;
                }
            }
            if candidates.is_empty() {
                bail!("DNS lookup returned no addresses for {name}");
            }
            (name, candidates)
        }
    };
    Ok(Target {
        requested_host,
        candidates,
        port,
        direction,
    })
}

pub fn normalize_bind_address(raw: &str) -> Result<IpAddr> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "*" {
        return Ok("0.0.0.0".parse().unwrap());
    }
    if raw.eq_ignore_ascii_case("localhost") {
        return Ok("127.0.0.1".parse().unwrap());
    }
    raw.parse::<IpAddr>()
        .with_context(|| format!("unsupported remote-forward bind address {raw}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, parse};

    fn target(host: &str, ip: &str, port: u16) -> Target {
        Target {
            requested_host: host.into(),
            candidates: vec![ip.parse().unwrap()],
            port,
            direction: Direction::Connect,
        }
    }

    fn policy(text: &str) -> Policy {
        let config: Config = parse(text).unwrap();
        Policy::build(config, 1).unwrap()
    }

    #[test]
    fn deny_wins_across_groups() {
        let policy = policy(
            r#"
            [server]
            default_policy = "deny"

            [groups.dev]
            [[groups.dev.rules]]
            action = "allow"
            host = "*.example.com"
            port = 443
            [[groups.dev.rules]]
            action = "deny"
            host = "secret.example.com"
            port = 443

            [users.alice]
            keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL8h9/fYiA4XTq+SVumFEeWB6vmsGkbBXVH6rRXRavmd alice"]
            groups = ["dev"]
            "#,
        );
        // The key above is only used to satisfy parsing; this test targets rules.
        let decision = policy
            .evaluate(
                &Subject::new("alice"),
                &target("secret.example.com", "10.0.0.1", 443),
            )
            .unwrap();
        assert!(!decision.allowed);
    }

    #[test]
    fn ip_candidate_filtering() {
        let policy = policy(
            r#"
            [server]
            default_policy = "deny"

            [users.alice]
            keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL8h9/fYiA4XTq+SVumFEeWB6vmsGkbBXVH6rRXRavmd alice"]
            [[users.alice.rules]]
            action = "allow"
            host = "api.example.com"
            port = 443
            [[users.alice.rules]]
            action = "deny"
            cidr = "10.0.0.2/32"
            port = 443
            "#,
        );
        let mut target = target("api.example.com", "10.0.0.1", 443);
        target.candidates.push("10.0.0.2".parse().unwrap());
        let decision = policy.evaluate(&Subject::new("alice"), &target).unwrap();
        assert!(decision.allowed);
        assert_eq!(
            decision.allowed_ips,
            vec!["10.0.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn port_zero_only_matches_any() {
        let policy = policy(
            r#"
            [server]
            default_policy = "deny"

            [users.alice]
            keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL8h9/fYiA4XTq+SVumFEeWB6vmsGkbBXVH6rRXRavmd alice"]
            [[users.alice.rules]]
            action = "allow"
            forward = "listen"
            host = "127.0.0.1"
            port = "*"
            "#,
        );
        let mut target = target("127.0.0.1", "127.0.0.1", 0);
        target.direction = Direction::Listen;
        assert!(
            policy
                .evaluate(&Subject::new("alice"), &target)
                .unwrap()
                .allowed
        );
    }

    #[test]
    fn user_glob_and_regex_map_many_logins_to_one_entry() {
        let policy = policy(
            r#"
            [users.alice]
            skip_key_check = true

            [users."team-*"]
            match = "glob"
            skip_key_check = true

            [users."svc-[0-9]+"]
            match = "regex"
            skip_key_check = true
            "#,
        );

        assert_eq!(policy.user_for_login("alice").unwrap().name, "alice");
        assert_eq!(policy.user_for_login("team-ops").unwrap().name, "team-*");
        assert_eq!(policy.user_for_login("team-dev").unwrap().name, "team-*");
        assert_eq!(policy.user_for_login("svc-42").unwrap().name, "svc-[0-9]+");
        assert!(policy.user_for_login("svc-x").is_none());
    }

    #[test]
    fn exact_user_wins_over_pattern() {
        let policy = policy(
            r#"
            [users.alice]
            skip_key_check = true

            [users."*"]
            match = "glob"
            skip_key_check = true
            "#,
        );

        assert_eq!(policy.user_for_login("alice").unwrap().name, "alice");
        assert_eq!(policy.user_for_login("bob").unwrap().name, "*");
    }

    #[test]
    fn overlapping_user_patterns_are_ambiguous() {
        let policy = policy(
            r#"
            [users."team-*"]
            match = "glob"
            skip_key_check = true

            [users."*-ops"]
            match = "glob"
            skip_key_check = true
            "#,
        );

        assert!(policy.user_for_login("team-ops").is_none());
        assert_eq!(policy.user_for_login("team-dev").unwrap().name, "team-*");
    }
}
