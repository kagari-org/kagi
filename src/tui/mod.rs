use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use ratatui::layout::Rect;
use russh::ChannelId;
use russh::server::Handle;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::input::TerminalEvent;
use crate::server::state::Shared;

use self::app::App;
use self::attach_view::AttachView;
use self::input::TuiKey;

mod app;
pub(crate) mod attach;
mod attach_view;
mod backend;
mod input;
mod terminal;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    shared: Arc<Shared>,
    handle: Handle,
    channel: ChannelId,
    login_name: String,
    session_id: u64,
    width: u16,
    height: u16,
    mut input_rx: mpsc::Receiver<TerminalEvent>,
    cancel: CancellationToken,
) {
    ratatui::crossterm::style::Colored::set_ansi_color_disabled(false);
    let _ = handle.data(channel, b"\x1b[?1049h\x1b[?25l".to_vec()).await;
    let (mut cols, mut rows) = terminal::size(width, height);
    let mut terminal = match terminal::make(&handle, channel, cols, rows) {
        Ok(terminal) => terminal,
        Err(err) => {
            tracing::warn!("failed to create TUI terminal: {err}");
            let _ = handle.data(channel, b"\x1b[?1049l\x1b[?25h".to_vec()).await;
            return;
        }
    };

    let mut app = App::new(shared.policy.load_full(), login_name);
    app.refresh(&shared);
    let mut attached: Option<AttachView> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let result: anyhow::Result<()> = async {
        loop {
            if cancel.is_cancelled() {
                break;
            }
            if let Some(mut view) = attached.take() {
                let exit = attach::run(
                    &mut view,
                    &mut terminal,
                    &mut input_rx,
                    &cancel,
                    &mut cols,
                    &mut rows,
                )
                .await;
                app.status = exit.message();
                app.refresh(&shared);
                terminal = terminal::make(&handle, channel, cols, rows)?;
                let _ = handle
                    .data(channel, b"\x1b[0m\x1b[2J\x1b[H\x1b[?25l".to_vec())
                    .await;
                continue;
            }

            terminal.draw(|frame| app.render(frame)).context("terminal.draw")?;

            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tick.tick() => {
                    app.refresh(&shared);
                }
                event = input_rx.recv() => {
                    let Some(event) = event else { break; };
                    match event {
                        TerminalEvent::Resize(new_cols, new_rows) => {
                            (cols, rows) = terminal::size(new_cols, new_rows);
                            let _ = terminal.resize(Rect::new(0, 0, cols, rows));
                            app.refresh(&shared);
                        }
                        TerminalEvent::Input(bytes) => {
                            for key in input::parse(&bytes) {
                                if app.show_help {
                                    match key {
                                        TuiKey::Escape | TuiKey::Char('?') | TuiKey::Char('q') => {
                                            app.show_help = false;
                                        }
                                        _ => {}
                                    }
                                    continue;
                                }
                                match key {
                                    TuiKey::CtrlC | TuiKey::Char('q') => {
                                        return Ok(());
                                    }
                                    TuiKey::Char('1') => { app.tab = 0; app.selected = 0; }
                                    TuiKey::Char('2') => { app.tab = 1; app.selected = 0; }
                                    TuiKey::Char('3') => { app.tab = 2; app.selected = 0; }
                                    TuiKey::Char('4') => { app.tab = 3; app.selected = 0; }
                                    TuiKey::Char('5') => { app.tab = 4; app.selected = 0; }
                                    TuiKey::Char('6') => { app.tab = 5; app.selected = 0; }
                                    TuiKey::Tab => { app.tab = (app.tab + 1) % 6; app.selected = 0; }
                                    TuiKey::BackTab => { app.tab = (app.tab + 5) % 6; app.selected = 0; }
                                    TuiKey::Char('j') | TuiKey::Down => app.move_down(),
                                    TuiKey::Char('k') | TuiKey::Up => app.move_up(),
                                    TuiKey::Char('g') => app.selected = 0,
                                    TuiKey::Char('G') => {
                                        app.selected = app.current_len().saturating_sub(1);
                                    }
                                    TuiKey::PageUp => app.page_up(),
                                    TuiKey::PageDown => app.page_down(),
                                    TuiKey::Char('r') => {
                                        app.refresh(&shared);
                                        app.status = "refreshed".to_string();
                                    }
                                    TuiKey::Char('R') => {
                                        app.status = match shared.reload().await {
                                            Ok(()) => "config reloaded".to_string(),
                                            Err(err) => format!("reload failed: {err}"),
                                        };
                                        app.refresh(&shared);
                                    }
                                    TuiKey::Char('x') => {
                                        if let Some(id) = app.selected_session().map(|s| s.id) {
                                            if id == session_id {
                                                app.status = "cannot close current session".to_string();
                                            } else if let Some(info) = shared.registry.session(id) {
                                                let handle = info.handle.clone();
                                                let login = app.login.clone();
                                                shared.registry.remove_session(id);
                                                tokio::spawn(async move {
                                                    let _ = handle
                                                        .disconnect(
                                                            russh::Disconnect::ByApplication,
                                                            "closed by admin".to_string(),
                                                            String::new(),
                                                        )
                                                        .await;
                                                });
                                                shared.audit.warn(format!(
                                                    "admin {login} closed session {id}"
                                                ));
                                                app.status = format!("closed session {id}");
                                                app.refresh(&shared);
                                            } else {
                                                app.status = format!("session {id} already closed");
                                            }
                                        }
                                    }
                                    TuiKey::Char('?') | TuiKey::F1 => app.show_help = true,
                                    TuiKey::Escape => app.show_help = false,
                                    TuiKey::Enter => {
                                        if let Some(key) =
                                            app.selected_stream().map(|channel| channel.key.to_string())
                                        {
                                            match shared.registry.resolve_attach(&key) {
                                                Ok(target) => {
                                                    attached = Some(AttachView::new(target, cols, rows));
                                                }
                                                Err(err) => app.status = err,
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    .await;

    let _ = handle.data(channel, b"\x1b[?1049l\x1b[?25h".to_vec()).await;
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
    if let Err(err) = result {
        tracing::warn!("admin TUI ended with error: {err}");
    }
}
