use std::sync::Arc;

use ratatui::layout::Rect;
use russh::ChannelId;
use russh::server::Handle;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::input::TerminalEvent;
use crate::registry::StreamChannel;

use super::attach_view::AttachView;
use super::terminal::{self, SshTerminal};

pub(crate) enum AttachExit {
    Detached,
    Closed,
    Lagged,
    InputClosed,
    Error(String),
}

impl AttachExit {
    pub(crate) fn message(self) -> String {
        match self {
            Self::Detached => "detached".to_string(),
            Self::Closed => "channel closed".to_string(),
            Self::Lagged => "output lagged".to_string(),
            Self::InputClosed => "input closed".to_string(),
            Self::Error(message) => message,
        }
    }
}

pub(crate) fn spawn_direct(
    target: Arc<StreamChannel>,
    handle: Handle,
    channel: ChannelId,
    cancel: CancellationToken,
    width: u16,
    height: u16,
) -> mpsc::Sender<TerminalEvent> {
    let (input_tx, input_rx) = mpsc::channel(64);
    tokio::spawn(async move {
        run_direct(
            target,
            handle.clone(),
            channel,
            cancel,
            width,
            height,
            input_rx,
        )
        .await;
        let _ = handle.eof(channel).await;
        let _ = handle.close(channel).await;
    });
    input_tx
}

async fn run_direct(
    target: Arc<StreamChannel>,
    handle: Handle,
    channel: ChannelId,
    cancel: CancellationToken,
    width: u16,
    height: u16,
    mut input_rx: mpsc::Receiver<TerminalEvent>,
) {
    ratatui::crossterm::style::Colored::set_ansi_color_disabled(false);
    let (mut cols, mut rows) = terminal::size(width, height);
    let _ = handle.data(channel, b"\x1b[?1049h\x1b[?25l".to_vec()).await;
    let mut terminal = match terminal::make(&handle, channel, cols, rows) {
        Ok(terminal) => terminal,
        Err(err) => {
            tracing::warn!("failed to create direct attach terminal: {err}");
            let _ = handle.data(channel, b"\x1b[?1049l\x1b[?25h".to_vec()).await;
            return;
        }
    };
    let mut view = AttachView::new(target, cols, rows);
    let _ = run(
        &mut view,
        &mut terminal,
        &mut input_rx,
        &cancel,
        &mut cols,
        &mut rows,
    )
    .await;
    let _ = handle.data(channel, b"\x1b[?1049l\x1b[?25h".to_vec()).await;
}

pub(crate) async fn run(
    view: &mut AttachView,
    terminal: &mut SshTerminal,
    input_rx: &mut mpsc::Receiver<TerminalEvent>,
    cancel: &CancellationToken,
    cols: &mut u16,
    rows: &mut u16,
) -> AttachExit {
    loop {
        if let Err(err) = terminal.draw(|frame| view.render(frame)) {
            return AttachExit::Error(format!("draw failed: {err}"));
        }
        tokio::select! {
            _ = cancel.cancelled() => return AttachExit::Detached,
            output = view.subscription.output.recv() => {
                match output {
                    Ok(data) => view.process_output(&data),
                    Err(broadcast::error::RecvError::Lagged(_)) => return AttachExit::Lagged,
                    Err(broadcast::error::RecvError::Closed) => return AttachExit::Closed,
                }
            }
            changed = view.subscription.closed.changed() => {
                if changed.is_err() || *view.subscription.closed.borrow() {
                    return AttachExit::Closed;
                }
            }
            event = input_rx.recv() => {
                match event {
                    Some(TerminalEvent::Input(bytes)) => {
                        match view.forward(&bytes).await {
                            Ok(true) => {}
                            Ok(false) => return AttachExit::Detached,
                            Err(message) => return AttachExit::Error(message),
                        }
                    }
                    Some(TerminalEvent::Resize(new_cols, new_rows)) => {
                        let (new_cols, new_rows) = terminal::size(new_cols, new_rows);
                        *cols = new_cols;
                        *rows = new_rows;
                        let _ = terminal.resize(Rect::new(0, 0, new_cols, new_rows));
                        view.resize(new_cols, new_rows);
                    }
                    None => return AttachExit::InputClosed,
                }
            }
        }
    }
}
