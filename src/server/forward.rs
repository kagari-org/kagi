use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use russh::server::Handle;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::config::Direction;
use crate::policy::{Target, normalize_bind_address};
use crate::registry::{ForwardInfo, ForwardType, Registry, SessionInfo};

use super::state::Shared;

pub struct RemoteForward {
    pub id: u64,
    pub bind_ip: IpAddr,
    pub port: u32,
    cancel: CancellationToken,
    registry: Arc<Registry>,
}

impl Drop for RemoteForward {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.registry.remove_forward(self.id);
    }
}

pub async fn start(
    shared: Arc<Shared>,
    session: Arc<SessionInfo>,
    raw_address: &str,
    requested_port: u32,
    handle: Handle,
) -> Result<RemoteForward, String> {
    let policy = shared.policy.load_full();
    if !policy.config.server.allow_remote_forward {
        return Err("global remote forwarding is disabled".to_string());
    }
    let bind_ip = normalize_bind_address(raw_address).map_err(|e| e.to_string())?;
    let port = u16::try_from(requested_port).map_err(|_| "invalid remote port".to_string())?;

    let target = Target {
        requested_host: bind_ip.to_string(),
        candidates: vec![bind_ip],
        port,
        direction: Direction::Listen,
    };
    let Some(decision) = policy.evaluate(&session.subject, &target) else {
        return Err("subject is not allowed".to_string());
    };
    if !decision.allowed {
        shared.audit.warn(format!(
            "session {} ({}) denied -R bind {bind_ip}:{port}",
            session.id,
            session.subject.label()
        ));
        return Err("remote forwarding denied by policy".to_string());
    }

    let listener = TcpListener::bind(SocketAddr::new(bind_ip, port))
        .await
        .map_err(|e| format!("bind {bind_ip}:{port} failed: {e}"))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("cannot read bound address: {e}"))?;
    let bound_port = bound.port();

    let cancel = session.cancel.child_token();
    let id = shared.registry.next_forward_id();
    let info = Arc::new(ForwardInfo::new(
        id,
        session.id,
        session.subject.clone(),
        ForwardType::Listen,
        format!("{bind_ip}:{bound_port}"),
        session.peer,
        cancel.clone(),
    ));
    info.set_state("listening");
    shared.registry.insert_forward_raw(Arc::clone(&info));

    shared.audit.info(format!(
        "session {} ({}) -R listening on {bind_ip}:{bound_port}",
        session.id,
        session.subject.label()
    ));

    let forward_address = raw_address.to_string();
    let registry = Arc::clone(&shared.registry);
    let session_id = session.id;
    let loop_info = Arc::clone(&info);
    let loop_cancel = cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = loop_cancel.cancelled() => break,
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(value) => value,
                        Err(err) => {
                            tracing::debug!("session {session_id}: -R accept error: {err}");
                            continue;
                        }
                    };
                    let handle = handle.clone();
                    let forward_address = forward_address.clone();
                    let info = Arc::clone(&loop_info);
                    tokio::spawn(async move {
                        match handle
                            .channel_open_forwarded_tcpip(
                                forward_address,
                                u32::from(bound_port),
                                peer.ip().to_string(),
                                u32::from(peer.port()),
                            )
                            .await
                        {
                            Ok(channel) => {
                                let mut stream = stream;
                                let mut channel = channel.into_stream();
                                match tokio::io::copy_bidirectional_with_sizes(
                                    &mut stream,
                                    &mut channel,
                                    16 * 1024,
                                    16 * 1024,
                                )
                                .await
                                {
                                    Ok((to_client, from_client)) => {
                                        info.bytes_in.fetch_add(to_client, Ordering::Relaxed);
                                        info.bytes_out.fetch_add(from_client, Ordering::Relaxed);
                                    }
                                    Err(err) => {
                                        tracing::debug!("session {session_id}: -R connection error: {err}");
                                    }
                                }
                            }
                            Err(err) => {
                                tracing::debug!("session {session_id}: -R channel open failed: {err}");
                            }
                        }
                    });
                }
            }
        }
        loop_info.set_state("closed");
        registry.remove_forward(loop_info.id);
    });

    Ok(RemoteForward {
        id,
        bind_ip,
        port: u32::from(bound_port),
        cancel,
        registry: Arc::clone(&shared.registry),
    })
}
