use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLevel {
    Info,
    Warn,
    Error,
}

impl AuditLevel {
    pub fn label(self) -> &'static str {
        match self {
            AuditLevel::Info => "INFO",
            AuditLevel::Warn => "WARN",
            AuditLevel::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub at: Instant,
    pub level: AuditLevel,
    pub message: String,
}

pub struct AuditLog {
    inner: Mutex<VecDeque<AuditEvent>>,
    capacity: usize,
}

impl AuditLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(4096))),
            capacity: capacity.max(1),
        }
    }

    pub fn info(&self, message: impl Into<String>) {
        let message = message.into();
        info!("{message}");
        self.push(AuditLevel::Info, message);
    }

    pub fn warn(&self, message: impl Into<String>) {
        let message = message.into();
        warn!("{message}");
        self.push(AuditLevel::Warn, message);
    }

    pub fn error(&self, message: impl Into<String>) {
        let message = message.into();
        error!("{message}");
        self.push(AuditLevel::Error, message);
    }

    fn push(&self, level: AuditLevel, message: String) {
        if let Ok(mut inner) = self.inner.lock() {
            if inner.len() == self.capacity {
                inner.pop_front();
            }
            inner.push_back(AuditEvent {
                at: Instant::now(),
                level,
                message,
            });
        }
    }

    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.inner
            .lock()
            .map(|inner| inner.iter().cloned().collect())
            .unwrap_or_default()
    }
}
