use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use russh::keys::HashAlg;
use russh::keys::PrivateKey;
use russh::keys::ssh_key::LineEnding;
use serde::Deserialize;
use tracing::{info, warn};

pub mod rule;

pub use rule::{
    Action, Direction, ForwardKind, MatchKind, PortSet, PortSpec, Rule, RuleConfig, compile_rule,
};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub animation: AnimationConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub groups: BTreeMap<String, GroupConfig>,
    #[serde(default)]
    pub users: BTreeMap<String, UserConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Optional path. If absent, `<config dir>/host_ed25519` is generated on
    /// first start and reused afterwards.
    #[serde(default)]
    pub host_key: Option<PathBuf>,
    #[serde(default)]
    pub default_policy: DefaultPolicy,
    #[serde(default)]
    pub allow_remote_forward: bool,
    #[serde(default = "default_max_auth_attempts")]
    pub max_auth_attempts: usize,
    #[serde(default = "default_max_sessions_per_user")]
    pub max_sessions_per_user: usize,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    #[serde(default = "default_connection_rate_per_min")]
    pub connection_rate_per_min: u32,
    #[serde(default = "default_auth_failures_per_min")]
    pub auth_failures_per_min: u32,
    #[serde(default = "default_auth_cooldown_secs")]
    pub auth_cooldown_secs: u64,
    #[serde(default = "default_inactivity_timeout")]
    pub inactivity_timeout_secs: u64,
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval_secs: u64,
    #[serde(default = "default_keepalive_max")]
    pub keepalive_max: usize,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_resolve_timeout")]
    pub resolve_timeout_secs: u64,
    #[serde(default = "default_max_direct_channels_per_conn")]
    pub max_direct_channels_per_conn: usize,
    #[serde(default = "default_max_direct_channels_global")]
    pub max_direct_channels_global: usize,
    #[serde(default = "default_max_direct_channels_per_user")]
    pub max_direct_channels_per_user: usize,
    #[serde(default = "default_max_remote_forwards_per_conn")]
    pub max_remote_forwards_per_conn: usize,
    #[serde(default = "default_max_remote_forwards_per_user")]
    pub max_remote_forwards_per_user: usize,
    #[serde(default = "default_max_remote_forwards_global")]
    pub max_remote_forwards_global: usize,
    #[serde(default = "default_max_streams_per_user")]
    pub max_streams_per_user: usize,
    #[serde(default = "default_stream_broadcast_capacity")]
    pub stream_broadcast_capacity: usize,
    #[serde(default = "default_stream_retained_timeout")]
    pub stream_retained_timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnimationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_animation_interval")]
    pub interval_ms: u64,
    #[serde(default)]
    pub ascii: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GroupConfig {
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    #[serde(default = "default_user_match", rename = "match")]
    pub match_kind: MatchKind,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub admin: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub skip_key_check: bool,
    #[serde(default = "default_stream_buffer_bytes")]
    pub stream_buffer_bytes: usize,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            host_key: None,
            default_policy: DefaultPolicy::Deny,
            allow_remote_forward: false,
            max_auth_attempts: default_max_auth_attempts(),
            max_sessions_per_user: default_max_sessions_per_user(),
            max_sessions: default_max_sessions(),
            max_connections_per_ip: default_max_connections_per_ip(),
            connection_rate_per_min: default_connection_rate_per_min(),
            auth_failures_per_min: default_auth_failures_per_min(),
            auth_cooldown_secs: default_auth_cooldown_secs(),
            inactivity_timeout_secs: default_inactivity_timeout(),
            keepalive_interval_secs: default_keepalive_interval(),
            keepalive_max: default_keepalive_max(),
            connect_timeout_secs: default_connect_timeout(),
            resolve_timeout_secs: default_resolve_timeout(),
            max_direct_channels_per_conn: default_max_direct_channels_per_conn(),
            max_direct_channels_global: default_max_direct_channels_global(),
            max_direct_channels_per_user: default_max_direct_channels_per_user(),
            max_remote_forwards_per_conn: default_max_remote_forwards_per_conn(),
            max_remote_forwards_per_user: default_max_remote_forwards_per_user(),
            max_remote_forwards_global: default_max_remote_forwards_global(),
            max_streams_per_user: default_max_streams_per_user(),
            stream_broadcast_capacity: default_stream_broadcast_capacity(),
            stream_retained_timeout_secs: default_stream_retained_timeout(),
        }
    }
}

impl Default for AnimationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: default_animation_interval(),
            ascii: false,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::Text,
        }
    }
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            match_kind: MatchKind::Exact,
            keys: Vec::new(),
            groups: Vec::new(),
            admin: false,
            enabled: true,
            skip_key_check: false,
            stream_buffer_bytes: default_stream_buffer_bytes(),
            rules: Vec::new(),
        }
    }
}

pub fn load(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    parse(&text).with_context(|| format!("failed to parse config {}", path.display()))
}

pub fn parse(text: &str) -> Result<Config> {
    let config: Config = toml::from_str(text)?;
    if config.server.listen.trim().is_empty() {
        anyhow::bail!("server.listen is empty");
    }
    if config.server.max_auth_attempts == 0 {
        anyhow::bail!("server.max_auth_attempts must be > 0");
    }
    Ok(config)
}

pub fn host_key_path(config_path: &Path, configured: Option<&Path>) -> PathBuf {
    if let Some(path) = configured {
        return path.to_path_buf();
    }
    config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("host_ed25519")
}

pub struct HostKey {
    pub key: PrivateKey,
    pub generated: bool,
}

pub fn load_or_generate_host_key(config_path: &Path, configured: Option<&Path>) -> Result<HostKey> {
    let path = host_key_path(config_path, configured);
    if path.exists() {
        let key = PrivateKey::read_openssh_file(&path)
            .with_context(|| format!("failed to read host key {}", path.display()))?;
        if key.is_encrypted() {
            anyhow::bail!(
                "host key {} is encrypted; kagi cannot prompt for a passphrase",
                path.display()
            );
        }
        warn_private_file_permissions(&path, "host key");
        info!(
            path = %path.display(),
            fingerprint = %key.public_key().fingerprint(HashAlg::Sha256),
            "loaded host key"
        );
        return Ok(HostKey {
            key,
            generated: false,
        });
    }

    let mut rng = rand::rng();
    let key = PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)
        .context("failed to generate host key")?;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    match key.write_openssh_file(&path, LineEnding::LF) {
        Ok(()) => {
            set_private_permissions(&path);
            info!(
                path = %path.display(),
                fingerprint = %key.public_key().fingerprint(HashAlg::Sha256),
                "generated new host key"
            );
            Ok(HostKey {
                key,
                generated: true,
            })
        }
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "failed to persist generated host key; using an ephemeral key for this process"
            );
            info!(
                fingerprint = %key.public_key().fingerprint(HashAlg::Sha256),
                "generated ephemeral host key"
            );
            Ok(HostKey {
                key,
                generated: true,
            })
        }
    }
}

fn set_private_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            warn!(path = %path.display(), error = %err, "failed to restrict private file permissions");
        }
    }
}

fn warn_private_file_permissions(path: &Path, label: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                warn!(path = %path.display(), "{label} is a symlink");
            }
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    path = %path.display(),
                    mode = format!("{mode:03o}"),
                    "{label} is accessible by group or others"
                );
            }
        }
    }
}

pub fn generate_host_key(path: &Path) -> Result<()> {
    if path.exists() {
        anyhow::bail!("refusing to overwrite existing {}", path.display());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let mut rng = rand::rng();
    let key = PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)?;
    key.write_openssh_file(path, LineEnding::LF)?;
    set_private_permissions(path);
    println!(
        "wrote {} ({})",
        path.display(),
        key.public_key().fingerprint(HashAlg::Sha256)
    );
    Ok(())
}

pub fn host_key_summary(config_path: &Path, configured: Option<&Path>) -> String {
    let path = host_key_path(config_path, configured);
    if path.exists() {
        match PrivateKey::read_openssh_file(&path) {
            Ok(key) => format!(
                "{} (exists, {})",
                path.display(),
                key.public_key().fingerprint(HashAlg::Sha256)
            ),
            Err(err) => format!("{} (unreadable: {err})", path.display()),
        }
    } else {
        format!("{} (will be generated)", path.display())
    }
}

fn default_user_match() -> MatchKind {
    MatchKind::Exact
}

fn default_true() -> bool {
    true
}

fn default_listen() -> String {
    "0.0.0.0:2222".to_string()
}

fn default_max_auth_attempts() -> usize {
    3
}

fn default_max_sessions_per_user() -> usize {
    16
}

fn default_max_sessions() -> usize {
    1024
}

fn default_max_connections_per_ip() -> usize {
    20
}

fn default_connection_rate_per_min() -> u32 {
    60
}

fn default_auth_failures_per_min() -> u32 {
    10
}

fn default_auth_cooldown_secs() -> u64 {
    60
}

fn default_max_direct_channels_per_user() -> usize {
    256
}

fn default_max_remote_forwards_per_user() -> usize {
    32
}

fn default_max_remote_forwards_global() -> usize {
    512
}

fn default_inactivity_timeout() -> u64 {
    3600
}

fn default_keepalive_interval() -> u64 {
    30
}

fn default_keepalive_max() -> usize {
    3
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_resolve_timeout() -> u64 {
    5
}

fn default_max_direct_channels_per_conn() -> usize {
    256
}

fn default_max_direct_channels_global() -> usize {
    4096
}

fn default_max_remote_forwards_per_conn() -> usize {
    32
}

fn default_max_streams_per_user() -> usize {
    16
}

fn default_stream_retained_timeout() -> u64 {
    300
}

fn default_stream_buffer_bytes() -> usize {
    8 * 1024 * 1024
}

fn default_stream_broadcast_capacity() -> usize {
    1024
}

fn default_animation_interval() -> u64 {
    3000
}

fn default_log_level() -> String {
    "info".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let config = parse(
            r#"
            [server]
            listen = "127.0.0.1:2222"
            "#,
        )
        .unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:2222");
        assert_eq!(config.server.default_policy, DefaultPolicy::Deny);
        assert!(!config.server.allow_remote_forward);
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = parse(
            r#"
            [server]
            listen = "127.0.0.1:2222"
            nope = true
            "#,
        );
        assert!(err.is_err());
    }
}
