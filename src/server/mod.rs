use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use russh::server::Server as RusshServer;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::audit::AuditLog;
use crate::config::Config;
use crate::policy::{Policy, SystemResolver};
use crate::registry::Registry;

mod animation;
mod commands;
mod forward;
mod handler;
mod proxy;
mod rate_limit;
pub(crate) mod state;

use handler::KagiHandler;
use state::Shared;

struct KagiServer {
    shared: Arc<Shared>,
    next_id: AtomicU64,
}

impl KagiServer {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            next_id: AtomicU64::new(1),
        }
    }
}

impl RusshServer for KagiServer {
    type Handler = KagiHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        let session_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        KagiHandler::new(Arc::clone(&self.shared), session_id, peer_addr)
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        warn!("SSH session error: {error}");
    }
}

pub async fn run(
    config_path: PathBuf,
    config: Config,
    host_key: russh::keys::PrivateKey,
) -> Result<()> {
    let policy = Policy::build(config.clone(), 1)?;
    for warning in policy.warning_list() {
        warn!("{warning}");
    }

    let resolver = Arc::new(SystemResolver::new()?);
    let registry = Arc::new(Registry::new(config.server.stream_broadcast_capacity));
    let audit = Arc::new(AuditLog::new(2048));
    let rate_limiter = Arc::new(rate_limit::RateLimiter::new(
        config.server.max_connections_per_ip,
        config.server.connection_rate_per_min,
        config.server.auth_failures_per_min,
        config.server.auth_cooldown_secs,
    ));
    let shared = Arc::new(Shared {
        policy: ArcSwap::from_pointee(policy),
        registry,
        audit: Arc::clone(&audit),
        resolver,
        rate_limiter,
        active_direct: AtomicUsize::new(0),
        config_path: config_path.clone(),
        reload_lock: std::sync::Mutex::new(()),
    });

    let russh_config = russh::server::Config {
        server_id: russh::SshId::Standard(Cow::Borrowed("SSH-2.0-kagi_0.1")),
        inactivity_timeout: Some(Duration::from_secs(
            config.server.inactivity_timeout_secs.max(1),
        )),
        keepalive_interval: Some(Duration::from_secs(
            config.server.keepalive_interval_secs.max(1),
        )),
        keepalive_max: config.server.keepalive_max.max(1),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        max_auth_attempts: config.server.max_auth_attempts.max(1),
        keys: vec![host_key],
        nodelay: true,
        ..Default::default()
    };

    let listener = TcpListener::bind(&config.server.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.server.listen))?;
    let local = listener.local_addr().ok();
    info!(
        listen = ?local,
        config = %config_path.display(),
        "kagi SSH server listening"
    );

    let mut server = KagiServer::new(Arc::clone(&shared));
    let russh_config = Arc::new(russh_config);
    let mut connections = JoinSet::new();
    let signal_shared = Arc::clone(&shared);
    let shutdown = async move { shutdown_signal(signal_shared).await };
    tokio::pin!(shutdown);
    let mut stream_cleanup = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            reason = &mut shutdown => {
                info!("shutting down: {reason}");
                break;
            }
            _ = stream_cleanup.tick() => {
                let timeout = shared
                    .config()
                    .config
                    .server
                    .stream_retained_timeout_secs
                    .max(1);
                shared
                    .registry
                    .purge_closed_streams(Duration::from_secs(timeout));
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(value) => value,
                    Err(err) => {
                        warn!("accept failed: {err}");
                        continue;
                    }
                };
                let Some(guard) = shared.rate_limiter.allow_connection(peer.ip()) else {
                    warn!(peer = %peer, "connection rate limit exceeded");
                    continue;
                };
                let handler = server.new_client(Some(peer));
                let config = Arc::clone(&russh_config);
                connections.spawn(async move {
                    match russh::server::run_stream(config, stream, handler).await {
                        Ok(running) => {
                            if let Err(err) = running.await {
                                warn!(peer = %peer, "SSH session error: {err}");
                            }
                        }
                        Err(err) => warn!(peer = %peer, "SSH handshake failed: {err}"),
                    }
                    drop(guard);
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(err) = result {
                    warn!("SSH task failed: {err}");
                }
            }
        }
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}

    audit.info("server stopped");
    Ok(())
}

async fn shutdown_signal(shared: Arc<Shared>) -> String {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(value) => value,
            Err(err) => {
                error!("failed to install SIGTERM handler: {err}");
                return "signal handler error".to_string();
            }
        };
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(value) => value,
            Err(err) => {
                error!("failed to install SIGHUP handler: {err}");
                return "signal handler error".to_string();
            }
        };
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return "SIGINT".to_string(),
                _ = sigterm.recv() => return "SIGTERM".to_string(),
                _ = sighup.recv() => {
                    match shared.reload().await {
                        Ok(()) => info!("SIGHUP: config reloaded"),
                        Err(err) => {
                            shared.audit.error(format!("SIGHUP reload failed: {err}"));
                        }
                    }
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = shared;
        let _ = tokio::signal::ctrl_c().await;
        "SIGINT".to_string()
    }
}
