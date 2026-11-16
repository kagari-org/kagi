use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use russh::server::{ChannelOpenHandle, Msg};
use russh::{Channel, ChannelOpenFailure};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::config::Direction;
use crate::policy::resolve_target;
use crate::registry::{ForwardInfo, ForwardType, Role, SessionInfo};

use super::state::Shared;

struct DirectGuard {
    shared: Arc<Shared>,
    session: Arc<SessionInfo>,
    admin: bool,
}

impl DirectGuard {
    fn acquire(
        shared: &Arc<Shared>,
        session: &Arc<SessionInfo>,
        max_session: usize,
        max_global: usize,
        max_user: usize,
    ) -> Option<Self> {
        let admin = session.role == Role::Admin;
        if admin {
            session.direct_active.fetch_add(1, Ordering::Relaxed);
            return Some(Self {
                shared: Arc::clone(shared),
                session: Arc::clone(session),
                admin,
            });
        }
        if shared.active_direct.fetch_add(1, Ordering::Relaxed) >= max_global {
            shared.active_direct.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        if session.direct_active.fetch_add(1, Ordering::Relaxed) >= max_session {
            shared.active_direct.fetch_sub(1, Ordering::Relaxed);
            session.direct_active.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        if !shared
            .registry
            .try_acquire_user_direct(&session.subject, max_user)
        {
            shared.active_direct.fetch_sub(1, Ordering::Relaxed);
            session.direct_active.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Self {
            shared: Arc::clone(shared),
            session: Arc::clone(session),
            admin,
        })
    }
}

impl Drop for DirectGuard {
    fn drop(&mut self) {
        if !self.admin {
            self.shared.active_direct.fetch_sub(1, Ordering::Relaxed);
            self.shared
                .registry
                .release_user_direct(&self.session.subject);
        }
        self.session.direct_active.fetch_sub(1, Ordering::Relaxed);
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn handle_direct_tcpip(
    shared: Arc<Shared>,
    session: Arc<SessionInfo>,
    channel: Channel<Msg>,
    reply: ChannelOpenHandle,
    host: String,
    port: u32,
    originator_address: String,
    originator_port: u32,
    cancel: CancellationToken,
) {
    let Ok(port) = u16::try_from(port) else {
        reject(reply, ChannelOpenFailure::AdministrativelyProhibited).await;
        return;
    };
    if port == 0 {
        reject(reply, ChannelOpenFailure::AdministrativelyProhibited).await;
        return;
    }

    let policy = shared.policy.load_full();
    let Some(_guard) = DirectGuard::acquire(
        &shared,
        &session,
        policy.config.server.max_direct_channels_per_conn,
        policy.config.server.max_direct_channels_global,
        policy.config.server.max_direct_channels_per_user,
    ) else {
        shared.audit.warn(format!(
            "session {}: direct-tcpip limit reached",
            session.id
        ));
        reject(reply, ChannelOpenFailure::ResourceShortage).await;
        return;
    };

    let timeout_secs = policy.config.server.connect_timeout_secs;
    let resolve_secs = policy.config.server.resolve_timeout_secs;
    let target = match resolve_target(
        &host,
        port,
        Direction::Connect,
        &shared.resolver,
        Duration::from_secs(resolve_secs.max(1)),
    )
    .await
    {
        Ok(target) => target,
        Err(err) => {
            shared.audit.warn(format!(
                "session {}: cannot resolve {host}:{port}: {err}",
                session.id
            ));
            reject(reply, ChannelOpenFailure::ConnectFailed).await;
            return;
        }
    };

    let Some(decision) = policy.evaluate(&session.subject, &target) else {
        shared.audit.warn(format!(
            "session {}: subject {} is no longer allowed",
            session.id,
            session.subject.label()
        ));
        reject(reply, ChannelOpenFailure::AdministrativelyProhibited).await;
        return;
    };

    let allowed_ips = &decision.allowed_ips;

    if allowed_ips.is_empty() {
        let rules = if decision.matched.is_empty() {
            "default policy".to_string()
        } else {
            decision
                .matched
                .iter()
                .map(|hit| format!("{} {}", hit.source, hit.summary))
                .collect::<Vec<_>>()
                .join(", ")
        };
        shared.audit.warn(format!(
            "session {} ({}) denied {host}:{port} by {}",
            session.id,
            session.subject.label(),
            rules
        ));
        reject(reply, ChannelOpenFailure::AdministrativelyProhibited).await;
        return;
    }

    let id = shared.registry.next_forward_id();
    let forward_cancel = cancel.child_token();
    let forward = Arc::new(ForwardInfo::new(
        id,
        session.id,
        session.subject.clone(),
        ForwardType::Connect,
        format!("{host}:{port}"),
        session.peer,
        forward_cancel,
    ));
    let _forward_guard = shared.registry.insert_forward(Arc::clone(&forward));

    let mut upstream = None;
    for ip in allowed_ips {
        let addr = SocketAddr::new(*ip, port);
        match timeout(
            Duration::from_secs(timeout_secs.max(1)),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                upstream = Some(stream);
                break;
            }
            Ok(Err(err)) => {
                forward.set_state(format!("connect failed: {err}"));
            }
            Err(_) => {
                forward.set_state("connect timeout");
            }
        }
    }
    let Some(mut upstream) = upstream else {
        shared.audit.warn(format!(
            "session {} ({}) failed to connect {host}:{port}",
            session.id,
            session.subject.label()
        ));
        reject(reply, ChannelOpenFailure::ConnectFailed).await;
        return;
    };
    let _ = upstream.set_nodelay(true);

    shared.audit.info(format!(
        "session {} ({}) connect {host}:{port} via {} origin {}:{}",
        session.id,
        session.subject.label(),
        allowed_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        originator_address,
        originator_port
    ));

    reply.accept().await;
    forward.set_state("active");
    let mut channel_stream = channel.into_stream();
    let copy = tokio::io::copy_bidirectional_with_sizes(
        &mut upstream,
        &mut channel_stream,
        16 * 1024,
        16 * 1024,
    );
    tokio::pin!(copy);
    let result = tokio::select! {
        _ = cancel.cancelled() => {
            forward.set_state("cancelled");
            return;
        }
        result = &mut copy => result,
    };
    match result {
        Ok((to_target, from_target)) => {
            forward.bytes_in.fetch_add(to_target, Ordering::Relaxed);
            forward.bytes_out.fetch_add(from_target, Ordering::Relaxed);
            forward.set_state("closed");
        }
        Err(err) => {
            forward.set_state(format!("closed: {err}"));
            tracing::debug!(
                "session {}: proxy {host}:{port} closed with error: {err}",
                session.id
            );
        }
    }
}

async fn reject(reply: ChannelOpenHandle, reason: ChannelOpenFailure) {
    reply.reject(reason).await;
}
