use std::sync::Arc;
use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Padding, Paragraph, Row, Table, Tabs, Wrap};

use crate::audit::{AuditEvent, AuditLevel};
use crate::policy::Policy;
use crate::registry::{ForwardSnapshot, ForwardType, SessionSnapshot, StreamSnapshot};

use crate::server::state::Shared;

pub struct App {
    pub tab: usize,
    pub selected: usize,
    pub status: String,
    pub show_help: bool,
    pub policy: Arc<Policy>,
    pub sessions: Vec<SessionSnapshot>,
    pub streams: Vec<StreamSnapshot>,
    pub forwards: Vec<ForwardSnapshot>,
    pub logs: Vec<AuditEvent>,
    pub started_at: Instant,
    pub login: String,
}

impl App {
    pub fn new(policy: Arc<Policy>, login: String) -> Self {
        Self {
            tab: 0,
            selected: 0,
            status: "ready".to_string(),
            show_help: false,
            policy,
            sessions: Vec::new(),
            streams: Vec::new(),
            forwards: Vec::new(),
            logs: Vec::new(),
            started_at: Instant::now(),
            login,
        }
    }

    pub fn refresh(&mut self, shared: &Shared) {
        self.policy = shared.policy.load_full();
        self.sessions = shared.registry.sessions_snapshot();
        self.sessions.sort_by_key(|s| s.id);
        self.streams = shared.registry.streams_snapshot();
        self.streams.sort_by_key(|s| s.id);
        self.forwards = shared.registry.forwards_snapshot();
        self.forwards.sort_by_key(|s| s.id);
        self.logs = shared.audit.snapshot();
        let len = self.current_len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    pub fn current_len(&self) -> usize {
        match self.tab {
            1 => self.sessions.len(),
            2 => self.streams.len(),
            3 => self.forwards.len(),
            5 => self.logs.len(),
            _ => 0,
        }
    }

    pub fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        let len = self.current_len();
        if len > 0 && self.selected + 1 < len {
            self.selected += 1;
        }
    }

    pub fn page_up(&mut self) {
        self.selected = self.selected.saturating_sub(10);
    }

    pub fn page_down(&mut self) {
        let len = self.current_len();
        self.selected = (self.selected + 10).min(len.saturating_sub(1));
    }

    pub fn selected_stream(&self) -> Option<&StreamSnapshot> {
        if self.tab == 2 {
            self.streams.get(self.selected)
        } else {
            None
        }
    }

    pub fn selected_session(&self) -> Option<&SessionSnapshot> {
        if self.tab == 1 {
            self.sessions.get(self.selected)
        } else {
            None
        }
    }

    pub fn render(&self, frame: &mut Frame) {
        let area = frame.area();
        if area.width < 40 || area.height < 8 {
            frame.render_widget(
                Paragraph::new("terminal too small (need at least 40x8)")
                    .alignment(Alignment::Center),
                area,
            );
            return;
        }
        let chunks = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

        self.render_header(frame, chunks[0]);
        self.render_tabs(frame, chunks[2]);

        let block = Block::default()
            .borders(Borders::ALL)
            .padding(Padding::new(1, 1, 1, 1))
            .title(self.tab_title());
        match self.tab {
            1 => self.render_sessions(frame, block, chunks[4]),
            2 => self.render_streams(frame, block, chunks[4]),
            3 => self.render_forwards(frame, block, chunks[4]),
            4 => self.render_rules(frame, block, chunks[4]),
            5 => self.render_logs(frame, block, chunks[4]),
            _ => self.render_overview(frame, block, chunks[4]),
        }

        self.render_footer(frame, chunks[5]);
        if self.show_help {
            self.render_help(frame, area);
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let uptime = crate::format_hms(self.started_at.elapsed());
        let remote = if self.policy.config.server.allow_remote_forward {
            "-R:on"
        } else {
            "-R:off"
        };
        let line = Line::from(vec![
            Span::styled(
                " kagi ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                " login:{}  up:{}  config:{}  {remote}  policy:{}",
                self.login,
                uptime,
                self.policy.generation,
                match self.policy.config.server.default_policy {
                    crate::config::DefaultPolicy::Deny => "deny",
                    crate::config::DefaultPolicy::Allow => "allow",
                }
            )),
        ]);
        frame.render_widget(Paragraph::new(line), area);
    }

    fn render_tabs(&self, frame: &mut Frame, area: Rect) {
        let titles: Vec<Line<'static>> = [
            " 1 Overview ",
            " 2 Sessions ",
            " 3 Streams ",
            " 4 Forwards ",
            " 5 Rules ",
            " 6 Logs ",
        ]
        .into_iter()
        .map(Line::from)
        .collect();
        let tabs = Tabs::new(titles)
            .select(self.tab)
            .divider("  ")
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
        frame.render_widget(tabs, area);
    }

    fn tab_title(&self) -> &'static str {
        match self.tab {
            1 => " sessions ",
            2 => " streams ",
            3 => " forwards ",
            4 => " rules ",
            5 => " logs ",
            _ => " overview ",
        }
    }

    fn render_overview(&self, frame: &mut Frame, block: Block<'_>, area: Rect) {
        let anon_sessions = self.sessions.iter().filter(|s| s.anonymous).count();
        let lines = vec![
            Line::from(format!(
                "listen:            {}",
                self.policy.config.server.listen
            )),
            Line::from(format!(
                "host key:          {}",
                self.policy
                    .config
                    .server
                    .host_key
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "auto (<config dir>/host_ed25519)".to_string())
            )),
            Line::from(format!("config:            {}", self.policy.generation)),
            Line::from(format!(
                "uptime:            {}",
                crate::format_hms(self.started_at.elapsed())
            )),
            Line::from(format!(
                "sessions:          {} (anonymous: {anon_sessions})",
                self.sessions.len()
            )),
            Line::from(format!("streams:           {}", self.streams.len())),
            Line::from(format!("forwards:          {}", self.forwards.len())),
            Line::from(format!(
                "remote -R:         {}",
                if self.policy.config.server.allow_remote_forward {
                    "enabled"
                } else {
                    "disabled"
                }
            )),
        ];
        frame.render_widget(
            Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
            area,
        );
    }

    fn render_sessions(&self, frame: &mut Frame, block: Block<'_>, area: Rect) {
        let header = Row::new(vec![
            "ID", "Login", "Subject", "Role", "Auth", "Peer", "Uptime", "State", "Dir",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD));
        let rows: Vec<Row> = self
            .sessions
            .iter()
            .enumerate()
            .map(|(i, session)| {
                let style = if i == self.selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(session.id.to_string()),
                    Cell::from(session.login_name.clone()),
                    Cell::from(session.subject.label()),
                    Cell::from(session.role.label()),
                    Cell::from(session.auth_method),
                    Cell::from(
                        session
                            .peer
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    Cell::from(crate::format_hms(session.connected_at.elapsed())),
                    Cell::from(session.state.label.clone()),
                    Cell::from(session.direct_active.to_string()),
                ])
                .style(style)
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(5),
                Constraint::Length(12),
                Constraint::Length(14),
                Constraint::Length(7),
                Constraint::Length(9),
                Constraint::Length(21),
                Constraint::Length(9),
                Constraint::Length(14),
                Constraint::Length(4),
            ],
        )
        .header(header)
        .block(block)
        .column_spacing(1);
        frame.render_widget(table, area);
    }

    fn render_streams(&self, frame: &mut Frame, block: Block<'_>, area: Rect) {
        let header = Row::new(vec![
            "ID",
            "Owner/Name",
            "Session",
            "Age",
            "Idle",
            "In",
            "Out",
            "Subs",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD));
        let rows: Vec<Row> = self
            .streams
            .iter()
            .enumerate()
            .map(|(i, channel)| {
                let selected = i == self.selected;
                let style = if selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(channel.id.to_string()),
                    Cell::from(channel.key.to_string()),
                    Cell::from(channel.session_id.to_string()),
                    Cell::from(crate::format_hms(channel.created_at.elapsed())),
                    Cell::from(crate::format_hms(channel.last_activity.elapsed())),
                    Cell::from(fmt_bytes(channel.bytes_in)),
                    Cell::from(fmt_bytes(channel.bytes_out)),
                    Cell::from(channel.subscribers.to_string()),
                ])
                .style(style)
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(5),
                Constraint::Length(30),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(5),
            ],
        )
        .header(header)
        .block(block)
        .column_spacing(1);
        frame.render_widget(table, area);
    }

    fn render_forwards(&self, frame: &mut Frame, block: Block<'_>, area: Rect) {
        let header = Row::new(vec![
            "ID", "Subject", "Kind", "Target", "State", "In", "Out", "Peer",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD));
        let rows: Vec<Row> = self
            .forwards
            .iter()
            .enumerate()
            .map(|(i, forward)| {
                let style = if i == self.selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(forward.id.to_string()),
                    Cell::from(forward.subject.label()),
                    Cell::from(match forward.kind {
                        ForwardType::Connect => "connect",
                        ForwardType::Listen => "listen",
                    }),
                    Cell::from(forward.target.clone()),
                    Cell::from(forward.state.clone()),
                    Cell::from(fmt_bytes(forward.bytes_in)),
                    Cell::from(fmt_bytes(forward.bytes_out)),
                    Cell::from(
                        forward
                            .peer
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                ])
                .style(style)
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(5),
                Constraint::Length(16),
                Constraint::Length(8),
                Constraint::Length(26),
                Constraint::Length(14),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(21),
            ],
        )
        .header(header)
        .block(block)
        .column_spacing(1);
        frame.render_widget(table, area);
    }

    fn render_rules(&self, frame: &mut Frame, block: Block<'_>, area: Rect) {
        let mut lines = Vec::new();
        lines.push(Line::from(format!(
            "default policy: {}   remote -R: {}",
            match self.policy.config.server.default_policy {
                crate::config::DefaultPolicy::Deny => "deny",
                crate::config::DefaultPolicy::Allow => "allow",
            },
            self.policy.config.server.allow_remote_forward
        )));
        lines.push(Line::from(""));
        for (name, user) in &self.policy.users {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("user {name}"),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    " admin={} enabled={} groups={} rules={}",
                    user.admin,
                    user.enabled,
                    user.groups.join(","),
                    user.rules.len()
                )),
            ]));
            for rule in &user.rules {
                lines.push(Line::from(format!(
                    "  {:<8} {}",
                    rule.source,
                    rule.summary()
                )));
            }
        }
        if !self.policy.groups.is_empty() {
            lines.push(Line::from(""));
            for (name, group) in &self.policy.groups {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("group {name}"),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(" rules={}", group.rules.len())),
                ]));
                for rule in &group.rules {
                    lines.push(Line::from(format!(
                        "  {:<16} {}",
                        rule.source,
                        rule.summary()
                    )));
                }
            }
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_logs(&self, frame: &mut Frame, block: Block<'_>, area: Rect) {
        let start = self.logs.len().saturating_sub(200);
        let lines: Vec<Line> = self.logs[start..]
            .iter()
            .enumerate()
            .map(|(i, event)| {
                let level_color = match event.level {
                    AuditLevel::Info => Color::Gray,
                    AuditLevel::Warn => Color::Yellow,
                    AuditLevel::Error => Color::Red,
                };
                let selected = i + start == self.selected;
                let span_style = |fg: Color| {
                    if selected {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(fg)
                    }
                };
                Line::from(vec![
                    Span::styled(
                        format!("{:>8} ", crate::format_hms(event.at.elapsed())),
                        span_style(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("{:<5} ", event.level.label()),
                        span_style(level_color),
                    ),
                    Span::styled(event.message.clone(), span_style(level_color)),
                ])
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let hints = "1-6/Tab switch  j/k move  Enter attach  x close  R reload  ? help  q quit";
        let line = if self.status.is_empty() {
            Line::from(hints)
        } else {
            Line::from(vec![
                Span::styled(
                    format!(" {} ", self.status),
                    Style::default().bg(Color::Blue).fg(Color::White),
                ),
                Span::raw(format!("  {hints}")),
            ])
        };
        frame.render_widget(Paragraph::new(line), area);
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let width = area.width.min(72);
        let height = area.height.min(18);
        let popup = Rect {
            x: area.x + (area.width - width) / 2,
            y: area.y + (area.height - height) / 2,
            width,
            height,
        };
        let lines = vec![
            Line::from("kagi admin key bindings"),
            Line::from("  1-6 / Tab / Shift-Tab   switch page"),
            Line::from("  j/k or Up/Down          move selection"),
            Line::from("  PgUp/PgDn, g/G          scroll"),
            Line::from("  Enter                   attach selected stream"),
            Line::from("  Ctrl+]                  detach from attached stream"),
            Line::from("  Ctrl+C                  send interrupt to target (while attached)"),
            Line::from("  x                       close selected session (Sessions page)"),
            Line::from("  r                       refresh now"),
            Line::from("  R                       reload TOML config"),
            Line::from("  ?                       toggle this help"),
            Line::from("  q / Ctrl+C              quit TUI"),
        ];
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" help "))
                .wrap(Wrap { trim: false }),
            popup,
        );
    }
}

fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n}B")
    } else if n < 1024 * 1024 {
        format!("{:.1}K", n as f64 / 1024.0)
    } else {
        format!("{:.1}M", n as f64 / 1024.0 / 1024.0)
    }
}
