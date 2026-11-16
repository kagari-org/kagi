use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use russh::ChannelId;
use russh::server::Handle;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;

use crate::policy::Subject;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    Normal,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Normal => "normal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub owner: String,
    pub name: String,
}

impl StreamKey {
    pub fn new(owner: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            name: name.into(),
        }
    }
}

impl std::fmt::Display for StreamKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

#[derive(Debug)]
pub struct SessionInfo {
    pub id: u64,
    pub login_name: String,
    pub subject: Subject,
    pub role: Role,
    pub auth_method: &'static str,
    pub peer: Option<SocketAddr>,
    pub connected_at: Instant,
    pub anonymous: bool,
    pub handle: Handle,
    pub cancel: CancellationToken,
    pub direct_active: AtomicUsize,
    state: Mutex<SessionState>,
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub label: String,
    pub forwards: usize,
}

impl SessionInfo {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        login_name: String,
        subject: Subject,
        role: Role,
        auth_method: &'static str,
        peer: Option<SocketAddr>,
        anonymous: bool,
        handle: Handle,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            id,
            login_name,
            subject,
            role,
            auth_method,
            peer,
            connected_at: Instant::now(),
            anonymous,
            handle,
            cancel,
            direct_active: AtomicUsize::new(0),
            state: Mutex::new(SessionState {
                label: "connected".to_string(),
                forwards: 0,
            }),
        }
    }

    pub fn set_label(&self, label: impl Into<String>) {
        if let Ok(mut state) = self.state.lock() {
            state.label = label.into();
        }
    }

    pub fn set_forwards(&self, forwards: usize) {
        if let Ok(mut state) = self.state.lock() {
            state.forwards = forwards;
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| SessionState {
                label: "unknown".to_string(),
                forwards: 0,
            })
    }
}

#[derive(Debug)]
pub struct StreamChannel {
    pub id: u64,
    pub key: StreamKey,
    pub session_id: u64,
    pub handle: Handle,
    pub channel: ChannelId,
    pub created_at: Instant,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    output: broadcast::Sender<Bytes>,
    closed: watch::Sender<bool>,
    last_activity: Mutex<Instant>,
    inner: Mutex<StreamInner>,
    buffer_capacity: usize,
}

#[derive(Debug)]
struct StreamInner {
    pending: VecDeque<u8>,
    pending_bytes: usize,
    attached: usize,
    closed_at: Option<Instant>,
}

pub struct StreamSubscription {
    pub pending: Vec<u8>,
    pub output: broadcast::Receiver<Bytes>,
    pub closed: watch::Receiver<bool>,
    channel: Arc<StreamChannel>,
}

impl Drop for StreamSubscription {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.channel.inner.lock() {
            inner.attached = inner.attached.saturating_sub(1);
        }
    }
}

impl StreamChannel {
    pub fn publish(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return,
        };
        if inner.closed_at.is_some() {
            return;
        }
        if inner.attached > 0 {
            if self.output.send(Bytes::copy_from_slice(data)).is_ok() {
                inner.pending.clear();
                inner.pending_bytes = 0;
            } else {
                push_pending(&mut inner, data, self.buffer_capacity);
            }
        } else {
            push_pending(&mut inner, data, self.buffer_capacity);
        }
        self.bytes_in
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        if let Ok(mut at) = self.last_activity.lock() {
            *at = Instant::now();
        }
    }

    pub fn subscribe(self: &Arc<Self>) -> StreamSubscription {
        let output = self.output.subscribe();
        let closed = self.closed.subscribe();
        let pending = self
            .inner
            .lock()
            .map(|mut inner| {
                let pending = inner.pending.drain(..).collect();
                inner.pending_bytes = 0;
                inner.attached += 1;
                pending
            })
            .unwrap_or_default();
        StreamSubscription {
            pending,
            output,
            closed,
            channel: Arc::clone(self),
        }
    }

    pub fn note_output(&self, n: usize) {
        self.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
        if let Ok(mut at) = self.last_activity.lock() {
            *at = Instant::now();
        }
    }

    pub fn close(&self) {
        if let Ok(mut inner) = self.inner.lock()
            && inner.closed_at.is_none()
        {
            inner.closed_at = Some(Instant::now());
        }
        self.closed.send_replace(true);
    }

    pub fn closed_at(&self) -> Option<Instant> {
        self.inner.lock().ok().and_then(|inner| inner.closed_at)
    }

    pub fn subscriber_count(&self) -> usize {
        self.output.receiver_count()
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
            .lock()
            .map(|at| *at)
            .unwrap_or(self.created_at)
    }

    pub fn pending_bytes(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.pending_bytes)
            .unwrap_or(0)
    }
}

fn push_pending(inner: &mut StreamInner, data: &[u8], capacity: usize) {
    let capacity = capacity.max(1);
    if data.len() >= capacity {
        inner.pending.clear();
        inner
            .pending
            .extend(data[data.len() - capacity..].iter().copied());
        inner.pending_bytes = capacity;
        return;
    }
    if inner.pending_bytes + data.len() > capacity {
        let drop = inner.pending_bytes + data.len() - capacity;
        for _ in 0..drop {
            inner.pending.pop_front();
        }
        inner.pending_bytes -= drop;
    }
    inner.pending.extend(data.iter().copied());
    inner.pending_bytes += data.len();
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardType {
    Connect,
    Listen,
}

impl ForwardType {
    pub fn label(self) -> &'static str {
        match self {
            ForwardType::Connect => "connect",
            ForwardType::Listen => "listen",
        }
    }
}

#[derive(Debug)]
pub struct ForwardInfo {
    pub id: u64,
    pub session_id: u64,
    pub subject: Subject,
    pub kind: ForwardType,
    pub target: String,
    pub peer: Option<SocketAddr>,
    pub cancel: CancellationToken,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    state: Mutex<String>,
}

impl ForwardInfo {
    pub fn new(
        id: u64,
        session_id: u64,
        subject: Subject,
        kind: ForwardType,
        target: String,
        peer: Option<SocketAddr>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            id,
            session_id,
            subject,
            kind,
            target,
            peer,
            cancel,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            state: Mutex::new("connecting".to_string()),
        }
    }

    pub fn set_state(&self, state: impl Into<String>) {
        if let Ok(mut current) = self.state.lock() {
            *current = state.into();
        }
    }

    pub fn state(&self) -> String {
        self.state
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

pub struct ForwardGuard {
    registry: Arc<Registry>,
    id: u64,
}

impl Drop for ForwardGuard {
    fn drop(&mut self) {
        self.registry.remove_forward(self.id);
    }
}

#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub id: u64,
    pub login_name: String,
    pub subject: Subject,
    pub role: Role,
    pub auth_method: &'static str,
    pub peer: Option<SocketAddr>,
    pub connected_at: Instant,
    pub anonymous: bool,
    pub state: SessionState,
    pub direct_active: usize,
}

#[derive(Debug, Clone)]
pub struct StreamSnapshot {
    pub id: u64,
    pub key: StreamKey,
    pub session_id: u64,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub subscribers: usize,
}

#[derive(Debug, Clone)]
pub struct ForwardSnapshot {
    pub id: u64,
    pub session_id: u64,
    pub subject: Subject,
    pub kind: ForwardType,
    pub target: String,
    pub peer: Option<SocketAddr>,
    pub state: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

pub struct Registry {
    sessions: DashMap<u64, Arc<SessionInfo>>,
    streams: DashMap<StreamKey, Arc<StreamChannel>>,
    forwards: DashMap<u64, Arc<ForwardInfo>>,
    direct_by_user: DashMap<Subject, AtomicUsize>,
    streams_lock: Mutex<()>,
    next_stream: AtomicU64,
    next_forward: AtomicU64,
    broadcast_capacity: usize,
}

impl Registry {
    pub fn new(broadcast_capacity: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            streams: DashMap::new(),
            forwards: DashMap::new(),
            direct_by_user: DashMap::new(),
            streams_lock: Mutex::new(()),
            next_stream: AtomicU64::new(1),
            next_forward: AtomicU64::new(1),
            broadcast_capacity: broadcast_capacity.max(1),
        }
    }

    pub fn try_acquire_user_direct(&self, subject: &Subject, max: usize) -> bool {
        let entry = self
            .direct_by_user
            .entry(subject.clone())
            .or_insert_with(|| AtomicUsize::new(0));
        if entry.fetch_add(1, Ordering::Relaxed) >= max {
            entry.fetch_sub(1, Ordering::Relaxed);
            false
        } else {
            true
        }
    }

    pub fn release_user_direct(&self, subject: &Subject) {
        if let Some(entry) = self.direct_by_user.get(subject) {
            entry.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn session_count_for_subject(&self, subject: &Subject) -> usize {
        self.sessions
            .iter()
            .filter(|entry| &entry.subject == subject)
            .count()
    }

    pub fn non_admin_session_count(&self) -> usize {
        self.sessions
            .iter()
            .filter(|entry| entry.role != Role::Admin)
            .count()
    }

    pub fn insert_session(&self, info: Arc<SessionInfo>) {
        self.sessions.insert(info.id, info);
    }

    pub fn session(&self, id: u64) -> Option<Arc<SessionInfo>> {
        self.sessions.get(&id).map(|s| Arc::clone(&s))
    }

    pub fn remove_session(&self, id: u64) {
        if let Some((_, info)) = self.sessions.remove(&id) {
            info.cancel.cancel();
        }
        {
            let _stream_guard = self.streams_lock.lock().ok();
            let stream_keys: Vec<StreamKey> = self
                .streams
                .iter()
                .filter(|entry| entry.session_id == id)
                .map(|entry| entry.key.clone())
                .collect();
            for key in stream_keys {
                self.close_stream(&key);
            }
        }
        let forward_ids: Vec<u64> = self
            .forwards
            .iter()
            .filter(|entry| entry.session_id == id)
            .map(|entry| entry.id)
            .collect();
        for forward_id in forward_ids {
            self.remove_forward(forward_id);
        }
    }

    pub fn sessions_snapshot(&self) -> Vec<SessionSnapshot> {
        self.sessions
            .iter()
            .map(|entry| {
                let info = entry.value();
                SessionSnapshot {
                    id: info.id,
                    login_name: info.login_name.clone(),
                    subject: info.subject.clone(),
                    role: info.role,
                    auth_method: info.auth_method,
                    peer: info.peer,
                    connected_at: info.connected_at,
                    anonymous: info.anonymous,
                    state: info.state(),
                    direct_active: info.direct_active.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    pub fn register_stream(
        &self,
        key: StreamKey,
        session_id: u64,
        handle: Handle,
        channel: ChannelId,
        max_per_owner: usize,
        buffer_capacity: usize,
    ) -> Result<Arc<StreamChannel>, String> {
        let _guard = self
            .streams_lock
            .lock()
            .map_err(|_| "stream registry lock poisoned".to_string())?;
        if self.streams.contains_key(&key) {
            return Err(format!("{key} is already registered"));
        }
        let count = self
            .streams
            .iter()
            .filter(|entry| entry.key.owner == key.owner)
            .count();
        if count >= max_per_owner {
            return Err(format!(
                "user {} already has {count} stream channels (limit {max_per_owner})",
                key.owner
            ));
        }
        let (output, _) = broadcast::channel(self.broadcast_capacity);
        let (closed, _) = watch::channel(false);
        let id = self.next_stream.fetch_add(1, Ordering::Relaxed);
        let channel = Arc::new(StreamChannel {
            id,
            key: key.clone(),
            session_id,
            handle,
            channel,
            created_at: Instant::now(),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            output,
            closed,
            last_activity: Mutex::new(Instant::now()),
            inner: Mutex::new(StreamInner {
                pending: VecDeque::new(),
                pending_bytes: 0,
                attached: 0,
                closed_at: None,
            }),
            buffer_capacity: buffer_capacity.max(1),
        });
        self.streams.insert(key, Arc::clone(&channel));
        Ok(channel)
    }

    fn close_stream(&self, key: &StreamKey) {
        // Drop the DashMap read guard before removing from the same shard.
        let channel = self.streams.get(key).map(|entry| Arc::clone(&entry));
        if let Some(channel) = channel {
            channel.close();
            if channel.pending_bytes() == 0 && channel.subscriber_count() == 0 {
                self.streams.remove(key);
            }
        }
    }

    pub fn purge_closed_streams(&self, timeout: Duration) {
        let _guard = self.streams_lock.lock().ok();
        let now = Instant::now();
        let expired: Vec<StreamKey> = self
            .streams
            .iter()
            .filter_map(|entry| {
                let closed_at = entry.closed_at()?;
                (entry.subscriber_count() == 0
                    && (entry.value().as_ref().pending_bytes() == 0
                        || now.duration_since(closed_at) >= timeout))
                    .then(|| entry.key.clone())
            })
            .collect();
        for key in expired {
            self.streams.remove(&key);
        }
    }

    pub fn stream_by_key(&self, key: &StreamKey) -> Option<Arc<StreamChannel>> {
        self.streams.get(key).map(|entry| Arc::clone(&entry))
    }

    pub fn streams_snapshot(&self) -> Vec<StreamSnapshot> {
        self.streams
            .iter()
            .map(|entry| {
                let channel = entry.value();
                StreamSnapshot {
                    id: channel.id,
                    key: channel.key.clone(),
                    session_id: channel.session_id,
                    created_at: channel.created_at,
                    last_activity: channel.last_activity(),
                    bytes_in: channel.bytes_in.load(Ordering::Relaxed),
                    bytes_out: channel.bytes_out.load(Ordering::Relaxed),
                    subscribers: channel.subscriber_count(),
                }
            })
            .collect()
    }

    pub fn resolve_attach(&self, target: &str) -> Result<Arc<StreamChannel>, String> {
        let target = target.trim();
        if target.is_empty() {
            return Err("attach target is empty".to_string());
        }
        if let Some(rest) = target.strip_prefix('#') {
            let id: u64 = rest
                .parse()
                .map_err(|_| format!("invalid stream id {rest}"))?;
            return self
                .streams
                .iter()
                .find(|entry| entry.id == id)
                .map(|entry| Arc::clone(entry.value()))
                .ok_or_else(|| format!("no stream channel with id {id}"));
        }
        if let Some((owner, name)) = target.split_once('/') {
            let key = StreamKey::new(owner, name);
            return self
                .stream_by_key(&key)
                .ok_or_else(|| format!("no stream channel {key}"));
        }
        let owner_matches: Vec<Arc<StreamChannel>> = self
            .streams
            .iter()
            .filter(|entry| entry.key.owner == target)
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        if owner_matches.len() == 1 {
            return Ok(owner_matches[0].clone());
        }
        if owner_matches.len() > 1 {
            return Err(format!(
                "owner {target} has multiple channels: {}",
                owner_matches
                    .iter()
                    .map(|ch| ch.key.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let name_matches: Vec<Arc<StreamChannel>> = self
            .streams
            .iter()
            .filter(|entry| entry.key.name == target)
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        if name_matches.len() == 1 {
            return Ok(name_matches[0].clone());
        }
        if name_matches.len() > 1 {
            return Err(format!(
                "name {target} is ambiguous: {}",
                name_matches
                    .iter()
                    .map(|ch| ch.key.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        Err(format!("no stream channel matching {target}"))
    }

    pub fn insert_forward_raw(&self, info: Arc<ForwardInfo>) {
        self.forwards.insert(info.id, info);
    }

    pub fn insert_forward(self: &Arc<Self>, info: Arc<ForwardInfo>) -> ForwardGuard {
        let id = info.id;
        self.forwards.insert(id, info);
        ForwardGuard {
            registry: Arc::clone(self),
            id,
        }
    }

    pub fn remove_forward(&self, id: u64) {
        if let Some((_, info)) = self.forwards.remove(&id) {
            info.cancel.cancel();
        }
    }

    pub fn forwards_snapshot(&self) -> Vec<ForwardSnapshot> {
        self.forwards
            .iter()
            .map(|entry| {
                let info = entry.value();
                ForwardSnapshot {
                    id: info.id,
                    session_id: info.session_id,
                    subject: info.subject.clone(),
                    kind: info.kind,
                    target: info.target.clone(),
                    peer: info.peer,
                    state: info.state(),
                    bytes_in: info.bytes_in.load(Ordering::Relaxed),
                    bytes_out: info.bytes_out.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    pub fn next_forward_id(&self) -> u64 {
        self.next_forward.fetch_add(1, Ordering::Relaxed)
    }

    pub fn cancel_remote_forwards(&self) {
        let ids: Vec<u64> = self
            .forwards
            .iter()
            .filter(|entry| entry.kind == ForwardType::Listen)
            .map(|entry| entry.id)
            .collect();
        for id in ids {
            self.remove_forward(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inner() -> StreamInner {
        StreamInner {
            pending: VecDeque::new(),
            pending_bytes: 0,
            attached: 0,
            closed_at: None,
        }
    }

    #[test]
    fn pending_fifo_keeps_newest_bytes() {
        let mut inner = inner();
        push_pending(&mut inner, b"abcdef", 4);
        assert_eq!(inner.pending.into_iter().collect::<Vec<_>>(), b"cdef");
        assert_eq!(inner.pending_bytes, 4);
    }

    #[test]
    fn pending_fifo_drops_oldest_before_append() {
        let mut inner = inner();
        push_pending(&mut inner, b"abcd", 5);
        push_pending(&mut inner, b"ef", 5);
        assert_eq!(inner.pending.into_iter().collect::<Vec<_>>(), b"bcdef");
        assert_eq!(inner.pending_bytes, 5);
    }
}
