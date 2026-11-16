use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PeerKey {
    V4(Ipv4Addr),
    V6([u8; 8]),
}

impl PeerKey {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip),
            IpAddr::V6(ip) => {
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&ip.octets()[..8]);
                Self::V6(prefix)
            }
        }
    }
}

#[derive(Debug)]
struct PeerState {
    active: usize,
    window_started: Instant,
    connections: u32,
    failure_started: Instant,
    failures: u32,
    cooldown_until: Option<Instant>,
    last_seen: Instant,
}

impl PeerState {
    fn new(now: Instant) -> Self {
        Self {
            active: 0,
            window_started: now,
            connections: 0,
            failure_started: now,
            failures: 0,
            cooldown_until: None,
            last_seen: now,
        }
    }

    fn reset_window(&mut self, now: Instant) {
        if now.duration_since(self.window_started) >= WINDOW {
            self.window_started = now;
            self.connections = 0;
        }
        if now.duration_since(self.failure_started) >= WINDOW {
            self.failure_started = now;
            self.failures = 0;
        }
    }
}

pub struct RateLimiter {
    inner: Mutex<HashMap<PeerKey, PeerState>>,
    max_active: usize,
    max_connections_per_min: u32,
    max_failures_per_min: u32,
    cooldown: Duration,
    last_cleanup: Mutex<Instant>,
}

pub struct ConnectionGuard {
    limiter: Arc<RateLimiter>,
    key: PeerKey,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter.close(self.key);
    }
}

impl RateLimiter {
    pub fn new(
        max_active: usize,
        max_connections_per_min: u32,
        max_failures_per_min: u32,
        cooldown_secs: u64,
    ) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_active: max_active.max(1),
            max_connections_per_min: max_connections_per_min.max(1),
            max_failures_per_min: max_failures_per_min.max(1),
            cooldown: Duration::from_secs(cooldown_secs),
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    pub fn allow_connection(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionGuard> {
        let now = Instant::now();
        let mut inner = self.inner.lock().ok()?;
        self.cleanup(&mut inner, now);
        let key = PeerKey::from_ip(ip);
        let state = inner.entry(key).or_insert_with(|| PeerState::new(now));
        state.last_seen = now;
        state.reset_window(now);
        if state.cooldown_until.is_some_and(|until| until > now) {
            return None;
        }
        if state.active >= self.max_active {
            return None;
        }
        state.connections = state.connections.saturating_add(1);
        if state.connections > self.max_connections_per_min {
            return None;
        }
        state.active += 1;
        Some(ConnectionGuard {
            limiter: Arc::clone(self),
            key,
        })
    }

    fn close(&self, key: PeerKey) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(state) = inner.get_mut(&key)
        {
            state.active = state.active.saturating_sub(1);
            state.last_seen = Instant::now();
        }
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let Ok(inner) = self.inner.lock() else {
            return false;
        };
        inner
            .get(&PeerKey::from_ip(ip))
            .and_then(|state| state.cooldown_until)
            .is_some_and(|until| until > now)
    }

    pub fn auth_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let state = inner
            .entry(PeerKey::from_ip(ip))
            .or_insert_with(|| PeerState::new(now));
        state.last_seen = now;
        state.reset_window(now);
        state.failures = state.failures.saturating_add(1);
        if state.failures >= self.max_failures_per_min {
            state.cooldown_until = Some(now + self.cooldown);
        }
    }

    pub fn auth_success(&self, ip: IpAddr) {
        let now = Instant::now();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let state = inner
            .entry(PeerKey::from_ip(ip))
            .or_insert_with(|| PeerState::new(now));
        state.last_seen = now;
        state.failures = 0;
        state.failure_started = now;
        state.cooldown_until = None;
    }

    fn cleanup(&self, inner: &mut HashMap<PeerKey, PeerState>, now: Instant) {
        let Ok(mut last) = self.last_cleanup.lock() else {
            return;
        };
        if now.duration_since(*last) < WINDOW {
            return;
        }
        *last = now;
        inner.retain(|_, state| {
            state.active > 0
                || state.cooldown_until.is_some_and(|until| until > now)
                || now.duration_since(state.last_seen) < WINDOW
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new(2, 10, 2, 60))
    }

    #[test]
    fn limits_active_connections() {
        let limiter = limiter();
        let ip = "192.0.2.1".parse().unwrap();
        let first = limiter.allow_connection(ip).unwrap();
        let second = limiter.allow_connection(ip).unwrap();
        assert!(limiter.allow_connection(ip).is_none());
        drop(first);
        assert!(limiter.allow_connection(ip).is_some());
        drop(second);
    }

    #[test]
    fn failures_trigger_cooldown_and_success_resets() {
        let limiter = limiter();
        let ip = "192.0.2.1".parse().unwrap();
        limiter.auth_failure(ip);
        assert!(!limiter.is_blocked(ip));
        limiter.auth_failure(ip);
        assert!(limiter.is_blocked(ip));
        limiter.auth_success(ip);
        assert!(!limiter.is_blocked(ip));
    }

    #[test]
    fn ipv6_failures_are_grouped_by_64() {
        let limiter = limiter();
        let a = "2001:db8:1:2::1".parse().unwrap();
        let b = "2001:db8:1:2::2".parse().unwrap();
        let other = "2001:db8:1:3::1".parse().unwrap();
        limiter.auth_failure(a);
        assert!(!limiter.is_blocked(b));
        limiter.auth_failure(b);
        assert!(limiter.is_blocked(a));
        assert!(limiter.is_blocked(b));
        assert!(!limiter.is_blocked(other));
    }
}
