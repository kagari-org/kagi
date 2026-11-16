use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use crate::audit::AuditLog;
use crate::config::Config;
use crate::policy::{Policy, SystemResolver};
use crate::registry::{Registry, Role, SessionSnapshot};

use super::rate_limit::RateLimiter;

pub struct Shared {
    pub policy: ArcSwap<Policy>,
    pub registry: Arc<Registry>,
    pub audit: Arc<AuditLog>,
    pub resolver: Arc<SystemResolver>,
    pub rate_limiter: Arc<RateLimiter>,
    pub active_direct: AtomicUsize,
    pub config_path: PathBuf,
    pub reload_lock: Mutex<()>,
}

impl Shared {
    pub fn config(&self) -> Arc<Policy> {
        self.policy.load_full()
    }

    pub async fn reload(&self) -> anyhow::Result<()> {
        let _guard = self
            .reload_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("reload lock poisoned"))?;
        let old = self.policy.load_full();
        let mut config: Config = crate::config::load(&self.config_path)?;
        config.server.listen = old.config.server.listen.clone();
        config.server.host_key = old.config.server.host_key.clone();
        let generation = old.generation + 1;
        let policy = Policy::build(config, generation)?;
        let new = Arc::new(policy);
        for warning in new.warning_list() {
            tracing::warn!("{warning}");
        }

        self.registry.cancel_remote_forwards();
        self.audit
            .warn("config reload cancelled existing remote forwards");
        let invalid: Vec<SessionSnapshot> = self
            .registry
            .sessions_snapshot()
            .into_iter()
            .filter(|session| !session_still_valid(&new, session))
            .collect();
        self.policy.store(new);
        for session in invalid {
            let Some(info) = self.registry.session(session.id) else {
                continue;
            };
            let handle = info.handle.clone();
            self.registry.remove_session(session.id);
            tokio::spawn(async move {
                let _ = handle
                    .disconnect(
                        russh::Disconnect::ByApplication,
                        "configuration changed".to_string(),
                        String::new(),
                    )
                    .await;
            });
            self.audit.warn(format!(
                "config reload disconnected invalid session {} ({})",
                session.id, session.login_name
            ));
        }
        self.audit
            .info(format!("config reloaded (generation {generation})"));
        Ok(())
    }
}

fn session_still_valid(policy: &Policy, session: &SessionSnapshot) -> bool {
    let Some(user) = policy.user_for_login(&session.login_name) else {
        return false;
    };
    if !user.enabled || user.name != session.subject.label() {
        return false;
    }
    if session.role == Role::Admin && !user.admin {
        return false;
    }
    true
}
