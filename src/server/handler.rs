use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use russh::keys::HashAlg;
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Pty};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::animation;
use crate::input::TerminalEvent;
use crate::policy::Subject;
use crate::registry::{ForwardType, Role, SessionInfo, StreamKey};
use crate::stream::{self, attach};
use crate::tui;

use super::commands;
use super::forward::{self, RemoteForward};
use super::proxy;
use super::state::Shared;

const MAX_PTY_COLS: u32 = 500;
const MAX_PTY_ROWS: u32 = 200;

fn pty_size(cols: u32, rows: u32) -> (u32, u32) {
    (
        if cols == 0 {
            80
        } else {
            cols.clamp(20, MAX_PTY_COLS)
        },
        if rows == 0 {
            24
        } else {
            rows.clamp(6, MAX_PTY_ROWS)
        },
    )
}

#[derive(Debug, Clone)]
struct PtyInfo {
    width: u32,
    height: u32,
}

#[derive(Debug, Clone)]
struct Identity {
    login_name: String,
    subject: Subject,
    role: Role,
    anonymous: bool,
    method: &'static str,
    fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Idle,
    Animation,
    AdminTui,
    Stream,
    Attach,
    Closed,
}

pub struct KagiHandler {
    shared: Arc<Shared>,
    session_id: u64,
    peer: Option<SocketAddr>,
    cancel: CancellationToken,
    pending: Option<Identity>,
    info: Option<Arc<SessionInfo>>,
    session_channel: Option<ChannelId>,
    pty: Option<PtyInfo>,
    mode: Mode,
    remote_forwards: Vec<RemoteForward>,
    tui_input: Option<mpsc::Sender<TerminalEvent>>,
    attach_input: Option<mpsc::Sender<TerminalEvent>>,
    stream_key: Option<StreamKey>,
}

impl KagiHandler {
    pub fn new(shared: Arc<Shared>, session_id: u64, peer: Option<SocketAddr>) -> Self {
        Self {
            shared,
            session_id,
            peer,
            cancel: CancellationToken::new(),
            pending: None,
            info: None,
            session_channel: None,
            pty: None,
            mode: Mode::Idle,
            remote_forwards: Vec::new(),
            tui_input: None,
            attach_input: None,
            stream_key: None,
        }
    }

    fn reject() -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(MethodSet::from([MethodKind::PublicKey].as_slice())),
            partial_success: false,
        }
    }

    fn valid_login_name(login: &str) -> bool {
        !login.is_empty() && login.len() <= 256 && !login.chars().any(char::is_control)
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer.map(|peer| peer.ip())
    }

    fn auth_blocked(&self) -> bool {
        self.peer_ip()
            .is_some_and(|ip| self.shared.rate_limiter.is_blocked(ip))
    }

    fn auth_reject(&self) -> Auth {
        if let Some(ip) = self.peer_ip() {
            self.shared.rate_limiter.auth_failure(ip);
        }
        Self::reject()
    }

    fn session_limit_ok(&self, admin: bool, subject: &Subject) -> bool {
        if admin {
            return true;
        }
        let config = self.shared.policy.load_full();
        let server = &config.config.server;
        self.shared.registry.session_count_for_subject(subject) < server.max_sessions_per_user
            && self.shared.registry.non_admin_session_count() < server.max_sessions
    }

    fn session_channel_ok(&self, channel: ChannelId) -> bool {
        self.session_channel == Some(channel)
    }

    fn finish_session_channel(&mut self, session: &mut Session, channel: ChannelId) {
        if self.mode == Mode::Closed {
            return;
        }
        self.mode = Mode::Closed;
        if let Some(info) = &self.info {
            self.shared.registry.remove_session(info.id);
            info.set_label("closed");
            info!("session {} session channel closed", info.id);
        }
        let _ = session.eof(channel);
        let _ = session.exit_status_request(channel, 0);
        let _ = session.close(channel);
    }

    fn write_stdout(&self, session: &mut Session, channel: ChannelId, text: &str) {
        let _ = session.data(channel, text.as_bytes().to_vec());
    }

    fn write_stderr(&self, session: &mut Session, channel: ChannelId, text: &str) {
        let _ = session.extended_data(channel, 1, text.as_bytes().to_vec());
    }

    fn finish_command(&self, session: &mut Session, channel: ChannelId, status: u32) {
        if let Some(info) = &self.info {
            self.shared.registry.remove_session(info.id);
        }
        let _ = session.eof(channel);
        let _ = session.exit_status_request(channel, status);
        let _ = session.close(channel);
    }

    fn fail_command(&mut self, session: &mut Session, channel: ChannelId, message: &str) {
        self.write_stderr(session, channel, message);
        let _ = session.channel_failure(channel);
        self.finish_command(session, channel, 1);
        self.mode = Mode::Closed;
    }

    fn register_stream(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
        raw_name: Option<&str>,
    ) -> Result<StreamKey, String> {
        if self.pty.is_some() {
            return Err("stream registration requires no PTY (use ssh -T)".to_string());
        }
        let info = self
            .info
            .clone()
            .ok_or_else(|| "not authenticated".to_string())?;
        let name = stream::normalize_name(raw_name, self.session_id).map_err(|e| e.to_string())?;
        let owner = stream::owner_for(&info.subject, self.session_id);
        let key = StreamKey::new(owner, name);
        let policy = self.shared.policy.load_full();
        let account = policy
            .users
            .get(&info.subject.label())
            .ok_or_else(|| "subject is no longer configured".to_string())?;
        let max_stream = if info.role == Role::Admin {
            usize::MAX
        } else {
            policy.config.server.max_streams_per_user
        };
        let buffer_bytes = account.stream_buffer_bytes;
        self.shared.registry.register_stream(
            key.clone(),
            self.session_id,
            session.handle(),
            channel,
            max_stream,
            buffer_bytes,
        )?;
        self.stream_key = Some(key.clone());
        self.mode = Mode::Stream;
        info.set_label("stream");
        self.shared
            .audit
            .info(format!("session {} registered stream {key}", info.id));
        Ok(key)
    }

    fn start_animation(&mut self, session: &mut Session, channel: ChannelId, login_name: String) {
        self.mode = Mode::Animation;
        if let Some(info) = &self.info {
            info.set_label("animation");
        }
        let shared = Arc::clone(&self.shared);
        let handle = session.handle();
        let cancel = self.cancel.clone();
        let session_id = self.session_id;
        let width = self.pty.as_ref().map(|pty| pty.width as u16).unwrap_or(80);
        tokio::spawn(async move {
            animation::run(
                handle, channel, login_name, shared, cancel, session_id, width,
            )
            .await;
        });
    }

    fn start_tui(&mut self, session: &mut Session, channel: ChannelId, login_name: String) {
        let Some(pty) = self.pty.clone() else {
            return;
        };
        let (tx, rx) = mpsc::channel(64);
        self.tui_input = Some(tx);
        self.mode = Mode::AdminTui;
        if let Some(info) = &self.info {
            info.set_label("admin-tui");
        }
        let shared = Arc::clone(&self.shared);
        let handle = session.handle();
        let cancel = self.cancel.clone();
        let session_id = self.session_id;
        tokio::spawn(async move {
            tui::run(
                shared,
                handle,
                channel,
                login_name,
                session_id,
                pty.width as u16,
                pty.height as u16,
                rx,
                cancel,
            )
            .await;
        });
    }

    fn start_direct_attach(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
        target: &str,
    ) -> Result<(), String> {
        let info = self
            .info
            .clone()
            .ok_or_else(|| "not authenticated".to_string())?;
        if info.role != Role::Admin {
            return Err("attach requires admin".to_string());
        }
        let target = self.shared.registry.resolve_attach(target)?;
        let input = if let Some(pty) = self.pty.as_ref() {
            tui::attach::spawn_direct(
                target,
                session.handle(),
                channel,
                self.cancel.clone(),
                pty.width as u16,
                pty.height as u16,
            )
        } else {
            attach::spawn_raw(target, session.handle(), channel, self.cancel.clone())
        };
        self.attach_input = Some(input);
        self.mode = Mode::Attach;
        info.set_label("attach");
        session.channel_success(channel).ok();
        Ok(())
    }
}

impl Handler for KagiHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        if self.auth_blocked() {
            return Ok(Self::reject());
        }
        if !Self::valid_login_name(user) {
            return Ok(Self::reject());
        }
        let policy = self.shared.policy.load_full();
        let Some(account) = policy.user_for_login(user) else {
            return Ok(Self::reject());
        };
        if !account.enabled || !account.skip_key_check {
            return Ok(Self::reject());
        }
        let subject = Subject::new(account.name.clone());
        if !self.session_limit_ok(account.admin, &subject) {
            return Ok(Self::reject());
        }
        self.pending = Some(Identity {
            login_name: user.to_string(),
            subject,
            role: if account.admin {
                Role::Admin
            } else {
                Role::Normal
            },
            anonymous: account.name == "anonymous",
            method: "none",
            fingerprint: None,
        });
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if self.auth_blocked() {
            return Ok(Self::reject());
        }
        if !Self::valid_login_name(user) {
            return Ok(self.auth_reject());
        }
        let fingerprint = key.public_key.fingerprint(HashAlg::Sha256).to_string();
        let policy = self.shared.policy.load_full();
        let Some(account) = policy.user_for_login(user) else {
            return Ok(self.auth_reject());
        };
        if !account.enabled {
            return Ok(self.auth_reject());
        }
        if !account.skip_key_check
            && !account
                .fingerprints
                .iter()
                .any(|known| known == &fingerprint)
        {
            return Ok(self.auth_reject());
        }
        let subject = Subject::new(account.name.clone());
        if !self.session_limit_ok(account.admin, &subject) {
            return Ok(Self::reject());
        }
        self.pending = Some(Identity {
            login_name: user.to_string(),
            subject,
            role: if account.admin {
                Role::Admin
            } else {
                Role::Normal
            },
            anonymous: account.name == "anonymous",
            method: "publickey",
            fingerprint: Some(fingerprint),
        });
        Ok(Auth::Accept)
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _offer: russh::server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        if self.auth_blocked() {
            return Ok(Self::reject());
        }
        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(self.auth_reject())
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        _response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        Ok(self.auth_reject())
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        let Some(identity) = self.pending.take() else {
            return Ok(());
        };
        if let Some(ip) = self.peer_ip() {
            self.shared.rate_limiter.auth_success(ip);
        }
        let info = Arc::new(SessionInfo::new(
            self.session_id,
            identity.login_name.clone(),
            identity.subject.clone(),
            identity.role,
            identity.method,
            self.peer,
            identity.anonymous,
            session.handle(),
            self.cancel.clone(),
        ));
        info.set_label("authenticated");
        self.shared.registry.insert_session(Arc::clone(&info));
        self.info = Some(info);
        self.shared.audit.info(format!(
            "auth session={} login={} subject={} role={} method={} key={} peer={}",
            self.session_id,
            identity.login_name,
            identity.subject.label(),
            identity.role.label(),
            identity.method,
            identity.fingerprint.as_deref().unwrap_or("-"),
            self.peer
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string())
        ));
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.info.is_none() || self.session_channel.is_some() {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        let id = channel.id();
        self.session_channel = Some(id);
        self.mode = Mode::Idle;
        if let Some(info) = &self.info {
            info.set_label("session");
        }
        reply.accept().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(info) = self.info.clone() else {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        let shared = Arc::clone(&self.shared);
        let cancel = self.cancel.clone();
        let host = host_to_connect.to_string();
        let originator_address = originator_address
            .parse::<IpAddr>()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| "invalid".to_string());
        tokio::spawn(async move {
            proxy::handle_direct_tcpip(
                shared,
                info,
                channel,
                reply,
                host,
                port_to_connect,
                originator_address,
                originator_port,
                cancel,
            )
            .await;
        });
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::UnknownChannelType).await;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::UnknownChannelType).await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.session_channel_ok(channel) {
            session.channel_failure(channel).ok();
            return Ok(());
        }
        let (width, height) = pty_size(col_width, row_height);
        self.pty = Some(PtyInfo { width, height });
        session.channel_success(channel).ok();
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.session_channel_ok(channel) {
            session.channel_failure(channel).ok();
            return Ok(());
        }
        let Some(info) = self.info.clone() else {
            session.channel_failure(channel).ok();
            return Ok(());
        };
        if self.pty.is_some() {
            session.channel_success(channel).ok();
            self.start_animation(session, channel, info.login_name.clone());
            return Ok(());
        }

        if info.role == Role::Admin {
            let text = commands::overview(&self.shared, self.info.as_deref());
            session.channel_success(channel).ok();
            self.write_stdout(session, channel, &text);
            self.finish_command(session, channel, 0);
            self.mode = Mode::Closed;
            return Ok(());
        }

        match self.register_stream(session, channel, None) {
            Ok(_) => {
                session.channel_success(channel).ok();
            }
            Err(err) => self.fail_command(session, channel, &format!("{err}\r\n")),
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.session_channel_ok(channel) {
            session.channel_failure(channel).ok();
            return Ok(());
        }
        let Some(info) = self.info.clone() else {
            session.channel_failure(channel).ok();
            return Ok(());
        };
        let command_line = String::from_utf8_lossy(data).to_string();
        let args = match shell_words::split(&command_line) {
            Ok(args) => args,
            Err(err) => {
                self.fail_command(session, channel, &format!("invalid command: {err}\r\n"));
                return Ok(());
            }
        };
        let Some(command) = args.first().map(String::as_str) else {
            self.fail_command(session, channel, "empty command\r\n");
            return Ok(());
        };

        if info.role == Role::Admin {
            match command {
                "admin" => {
                    if self.pty.is_none() {
                        session.channel_success(channel).ok();
                        self.write_stderr(
                            session,
                            channel,
                            "admin TUI requires a PTY; use `ssh -t admin@host admin`\r\n",
                        );
                        self.finish_command(session, channel, 1);
                        self.mode = Mode::Closed;
                        return Ok(());
                    }
                    session.channel_success(channel).ok();
                    self.start_tui(session, channel, info.login_name.clone());
                }
                "attach" => {
                    let Some(target) = args.get(1) else {
                        self.fail_command(session, channel, "usage: attach <owner/name|#id>\r\n");
                        return Ok(());
                    };
                    match self.start_direct_attach(session, channel, target) {
                        Ok(()) => {}
                        Err(err) => {
                            self.fail_command(session, channel, &format!("{err}\r\n"));
                        }
                    }
                }
                "list" => {
                    let text = commands::list(&self.shared, &info, args.get(1).map(String::as_str));
                    session.channel_success(channel).ok();
                    self.write_stdout(session, channel, &text);
                    self.finish_command(session, channel, 0);
                    self.mode = Mode::Closed;
                }
                "explain" => {
                    let Some(target) = args.get(1) else {
                        self.fail_command(session, channel, "usage: explain <host:port>\r\n");
                        return Ok(());
                    };
                    match commands::explain(&self.shared, &info, target).await {
                        Ok(text) => {
                            session.channel_success(channel).ok();
                            self.write_stdout(session, channel, &text);
                            self.finish_command(session, channel, 0);
                            self.mode = Mode::Closed;
                        }
                        Err(err) => self.fail_command(session, channel, &format!("{err}\r\n")),
                    }
                }
                "register" | "stream" => {
                    match self.register_stream(session, channel, args.get(1).map(String::as_str)) {
                        Ok(_) => {
                            session.channel_success(channel).ok();
                        }
                        Err(err) => {
                            self.fail_command(session, channel, &format!("{err}\r\n"));
                        }
                    }
                }
                "help" => {
                    session.channel_success(channel).ok();
                    self.write_stdout(
                        session,
                        channel,
                        &commands::overview(&self.shared, self.info.as_deref()),
                    );
                    self.finish_command(session, channel, 0);
                    self.mode = Mode::Closed;
                }
                other => {
                    self.fail_command(
                        session,
                        channel,
                        &format!("unknown admin command: {other}\r\n"),
                    );
                }
            }
            return Ok(());
        }

        match command {
            "register" | "stream" => {
                match self.register_stream(session, channel, args.get(1).map(String::as_str)) {
                    Ok(_) => {
                        session.channel_success(channel).ok();
                    }
                    Err(err) => {
                        self.fail_command(session, channel, &format!("{err}\r\n"));
                    }
                }
            }
            "list" => {
                let text = commands::list(&self.shared, &info, args.get(1).map(String::as_str));
                session.channel_success(channel).ok();
                self.write_stdout(session, channel, &text);
                self.finish_command(session, channel, 0);
                self.mode = Mode::Closed;
            }
            "help" => {
                session.channel_success(channel).ok();
                self.write_stdout(
                    session,
                    channel,
                    &commands::overview(&self.shared, self.info.as_deref()),
                );
                self.finish_command(session, channel, 0);
                self.mode = Mode::Closed;
            }
            other => {
                self.fail_command(session, channel, &format!("unknown command: {other}\r\n"));
            }
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.session_channel_ok(channel) {
            return Ok(());
        }
        match self.mode {
            Mode::Animation => {
                if data.iter().any(|b| *b == b'q' || *b == 3) {
                    self.cancel.cancel();
                    return Err(russh::Error::Disconnect);
                }
            }
            Mode::AdminTui => {
                if let Some(tx) = &self.tui_input
                    && tx.try_send(TerminalEvent::Input(data.to_vec())).is_err()
                {
                    debug!("session {}: TUI input queue full", self.session_id);
                }
            }
            Mode::Attach => {
                if let Some(tx) = &self.attach_input
                    && tx.try_send(TerminalEvent::Input(data.to_vec())).is_err()
                {
                    debug!("session {}: attach input queue full", self.session_id);
                }
            }
            Mode::Stream => {
                if let Some(key) = &self.stream_key
                    && let Some(channel) = self.shared.registry.stream_by_key(key)
                {
                    channel.publish(data);
                }
            }
            Mode::Idle | Mode::Closed => {}
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.session_channel_ok(channel) {
            self.finish_session_channel(session, channel);
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.session_channel_ok(channel) {
            self.finish_session_channel(session, channel);
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.session_channel_ok(channel) {
            return Ok(());
        }
        if let Some(pty) = &mut self.pty {
            let (width, height) = pty_size(col_width, row_height);
            pty.width = width;
            pty.height = height;
            if let Some(tx) = &self.tui_input {
                let _ = tx.try_send(TerminalEvent::Resize(width as u16, height as u16));
            } else if let Some(tx) = &self.attach_input {
                let _ = tx.try_send(TerminalEvent::Resize(width as u16, height as u16));
            }
        }
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(info) = self.info.clone() else {
            return Ok(false);
        };
        let policy = self.shared.policy.load_full();
        if !policy.config.server.allow_remote_forward {
            warn!(
                "session {}: -R rejected (global switch off)",
                self.session_id
            );
            return Ok(false);
        }
        if info.role != Role::Admin {
            let forwards = self.shared.registry.forwards_snapshot();
            let per_user = forwards
                .iter()
                .filter(|forward| {
                    forward.kind == ForwardType::Listen && forward.subject == info.subject
                })
                .count();
            let global = forwards
                .iter()
                .filter(|forward| {
                    forward.kind == ForwardType::Listen
                        && !policy
                            .users
                            .get(&forward.subject.label())
                            .is_some_and(|user| user.admin)
                })
                .count();
            if self.remote_forwards.len() >= policy.config.server.max_remote_forwards_per_conn
                || per_user >= policy.config.server.max_remote_forwards_per_user
                || global >= policy.config.server.max_remote_forwards_global
            {
                warn!("session {}: -R limit reached", self.session_id);
                return Ok(false);
            }
        }
        match forward::start(
            Arc::clone(&self.shared),
            info.clone(),
            address,
            *port,
            session.handle(),
        )
        .await
        {
            Ok(forward) => {
                *port = forward.port;
                self.remote_forwards.push(forward);
                info.set_forwards(self.remote_forwards.len());
                Ok(true)
            }
            Err(err) => {
                self.shared.audit.warn(format!(
                    "session {}: -R {address}:{} failed: {err}",
                    self.session_id, *port
                ));
                Ok(false)
            }
        }
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let bind_ip = match crate::policy::normalize_bind_address(address) {
            Ok(ip) => ip,
            Err(_) => return Ok(false),
        };
        let before = self.remote_forwards.len();
        self.remote_forwards
            .retain(|forward| !(forward.bind_ip == bind_ip && forward.port == port));
        let removed = before != self.remote_forwards.len();
        if removed && let Some(info) = &self.info {
            info.set_forwards(self.remote_forwards.len());
        }
        Ok(removed)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel).ok();
        Ok(())
    }

    async fn env_request(
        &mut self,
        _channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel).ok();
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

impl Drop for KagiHandler {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.remote_forwards.clear();
        if let Some(info) = &self.info {
            self.shared.registry.remove_session(info.id);
            info!("session {} closed", info.id);
        } else {
            info!("unauthenticated session {} closed", self.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    use arc_swap::ArcSwap;
    use russh::server::{Auth, Handler as _};

    use crate::audit::AuditLog;
    use crate::config::parse;
    use crate::policy::{Policy, SystemResolver};
    use crate::registry::Registry;

    use super::{KagiHandler, Shared};

    fn handler_with_key_only_user() -> KagiHandler {
        let config = parse(
            r#"
            [server]
            listen = "127.0.0.1:0"

            [users.alice]
            keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICZRpEeOxDuYT0I2Pbcuvfq9fBwiBLBZFiV3G5Uh6eL3 test"]
            "#,
        )
        .unwrap();
        let policy = Arc::new(Policy::build(config, 1).unwrap());
        let shared = Arc::new(Shared {
            policy: ArcSwap::from(policy),
            registry: Arc::new(Registry::new(16)),
            audit: Arc::new(AuditLog::new(16)),
            resolver: Arc::new(SystemResolver::for_test()),
            rate_limiter: Arc::new(super::super::rate_limit::RateLimiter::new(2, 100, 2, 60)),
            active_direct: AtomicUsize::new(0),
            config_path: PathBuf::from("unused.toml"),
            reload_lock: Mutex::new(()),
        });
        KagiHandler::new(shared, 1, None)
    }

    #[tokio::test]
    async fn none_probes_do_not_count_as_auth_failures() {
        let mut handler = handler_with_key_only_user();
        for _ in 0..20 {
            assert!(matches!(
                handler.auth_none("alice").await,
                Ok(Auth::Reject { .. })
            ));
        }
        assert!(!handler.auth_blocked());
    }
}
