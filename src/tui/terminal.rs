use anyhow::Result;
use ratatui::Terminal;
use ratatui::TerminalOptions;
use ratatui::Viewport;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use russh::ChannelId;
use russh::server::Handle;

use super::backend::TerminalHandle;

const MAX_COLS: u16 = 500;
const MAX_ROWS: u16 = 200;

pub(crate) type SshTerminal = Terminal<CrosstermBackend<TerminalHandle>>;

pub(crate) fn size(cols: u16, rows: u16) -> (u16, u16) {
    (cols.clamp(20, MAX_COLS), rows.clamp(6, MAX_ROWS))
}

pub(crate) fn make(
    handle: &Handle,
    channel: ChannelId,
    width: u16,
    height: u16,
) -> Result<SshTerminal> {
    let (cols, rows) = size(width, height);
    let backend = CrosstermBackend::new(TerminalHandle::start(handle.clone(), channel));
    Ok(Terminal::with_options(
        backend,
        TerminalOptions {
            viewport: Viewport::Fixed(Rect::new(0, 0, cols, rows)),
        },
    )?)
}
