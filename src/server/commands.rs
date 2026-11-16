use std::time::Duration;

use crate::config::{DefaultPolicy, Direction};
use crate::policy::resolve_target;
use crate::registry::{Role, SessionInfo};

use super::state::Shared;

pub(crate) async fn explain(
    shared: &Shared,
    info: &SessionInfo,
    target_arg: &str,
) -> Result<String, String> {
    let (host, port) = parse_endpoint(target_arg)?;
    let policy = shared.policy.load_full();
    let target = resolve_target(
        &host,
        port,
        Direction::Connect,
        &shared.resolver,
        Duration::from_secs(policy.config.server.resolve_timeout_secs.max(1)),
    )
    .await
    .map_err(|e| e.to_string())?;
    let Some(decision) = policy.evaluate(&info.subject, &target) else {
        return Ok("subject is no longer allowed\n".to_string());
    };
    let mut out = format!(
        "target: {host}:{port}\nresolved: {}\nsubject: {}\nverdict: {}\n",
        target
            .candidates
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        info.subject.label(),
        if decision.allowed { "allow" } else { "deny" }
    );
    if decision.allowed {
        out.push_str(&format!(
            "allowed ips: {}\n",
            decision
                .allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if decision.matched.is_empty() {
        out.push_str(&format!(
            "matched: none (default policy {})\n",
            match policy.config.server.default_policy {
                DefaultPolicy::Deny => "deny",
                DefaultPolicy::Allow => "allow",
            }
        ));
    } else {
        out.push_str("matched:\n");
        for hit in &decision.matched {
            out.push_str(&format!("  {} {}\n", hit.source, hit.summary));
        }
    }
    Ok(out)
}

pub(crate) fn list(shared: &Shared, info: &SessionInfo, arg: Option<&str>) -> String {
    let want = arg.unwrap_or("all");
    let mut out = String::new();
    if info.role == Role::Admin {
        if matches!(want, "all" | "sessions") {
            out.push_str("sessions:\n");
            for session in shared.registry.sessions_snapshot() {
                out.push_str(&format!(
                    "  #{} {} {} {} {} {}\n",
                    session.id,
                    session.login_name,
                    session.subject.label(),
                    session.role.label(),
                    session.auth_method,
                    session.state.label
                ));
            }
        }
        if matches!(want, "all" | "forwards") {
            out.push_str("forwards:\n");
            for forward in shared.registry.forwards_snapshot() {
                out.push_str(&format!(
                    "  #{} {} {} {} {}\n",
                    forward.id,
                    forward.subject.label(),
                    forward.kind.label(),
                    forward.target,
                    forward.state
                ));
            }
        }
        if matches!(want, "all" | "streams") {
            out.push_str("streams:\n");
            for channel in shared.registry.streams_snapshot() {
                out.push_str(&format!(
                    "  #{} {} session={} bytes={}/{} subs={}\n",
                    channel.id,
                    channel.key,
                    channel.session_id,
                    channel.bytes_in,
                    channel.bytes_out,
                    channel.subscribers
                ));
            }
        }
    } else if matches!(want, "all" | "streams") {
        let owner = crate::stream::owner_for(&info.subject, info.id);
        out.push_str("streams:\n");
        for channel in shared.registry.streams_snapshot() {
            if channel.key.owner == owner {
                out.push_str(&format!(
                    "  #{} {} session={} bytes={}/{}\n",
                    channel.id,
                    channel.key,
                    channel.session_id,
                    channel.bytes_in,
                    channel.bytes_out
                ));
            }
        }
    }
    if out.is_empty() {
        out.push_str("nothing to show\n");
    }
    out
}

pub(crate) fn overview(shared: &Shared, info: Option<&SessionInfo>) -> String {
    let mut out = String::new();
    if let Some(info) = info {
        out.push_str(&format!(
            "kagi: logged in as {} ({}, {})\n",
            info.login_name,
            info.subject.label(),
            info.role.label()
        ));
    }
    out.push_str(&format!(
        "remote forwarding: {}\n",
        shared.policy.load().config.server.allow_remote_forward,
    ));
    out.push_str(
        "This SSH server only provides SOCKS/port forwarding and streams.\n\
         Try:\n\
           ssh -D 1080 user@host\n\
           ssh -L 8080:target:80 user@host\n\
           ssh -T user@host            # auto-register stream\n\
           ssh -T user@host stream job\n\
           ssh -t user@host            # keepalive animation\n\
           ssh -t admin@host admin     # admin TUI (requires -t)\n\
           ssh admin@host attach owner/name\n",
    );
    out
}

fn parse_endpoint(raw: &str) -> Result<(String, u16), String> {
    let raw = raw.trim();
    if let Some((host, port)) = raw.rsplit_once(':') {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port: u16 = port.parse().map_err(|_| format!("invalid port in {raw}"))?;
        if host.is_empty() {
            return Err(format!("invalid endpoint {raw}"));
        }
        return Ok((host.to_string(), port));
    }
    Err("expected <host>:<port>".to_string())
}
