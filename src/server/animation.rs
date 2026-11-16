use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::ChannelId;
use russh::server::Handle;
use tokio_util::sync::CancellationToken;

use crate::registry::{ForwardSnapshot, ForwardType};
use crate::server::state::Shared;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const ASCII: [&str; 4] = ["|", "/", "-", "\\"];
const MAX_FORWARD_ROWS: usize = 8;

pub async fn run(
    handle: Handle,
    channel: ChannelId,
    login_name: String,
    shared: Arc<Shared>,
    cancel: CancellationToken,
    session_id: u64,
    width: u16,
) {
    let interval = Duration::from_millis(shared.config().config.animation.interval_ms.max(500));
    let ascii = shared.config().config.animation.ascii;
    if !shared.config().config.animation.enabled {
        return;
    }

    let started = Instant::now();
    let mut tick: usize = 0;
    let mut drawn = 0usize;
    let width = usize::from(width.max(20));

    loop {
        let spinner = if ascii {
            ASCII[tick % ASCII.len()]
        } else {
            SPINNER[tick % SPINNER.len()]
        };
        let elapsed = crate::format_hms(started.elapsed());
        let mut forwards: Vec<ForwardSnapshot> = shared
            .registry
            .forwards_snapshot()
            .into_iter()
            .filter(|forward| forward.session_id == session_id)
            .collect();
        forwards.sort_by_key(|forward| forward.id);

        let mut lines = Vec::new();
        lines.push(format!(
            "kagi {spinner} {login_name} | {elapsed} | {} forwards | q quit",
            forwards.len()
        ));
        if forwards.is_empty() {
            lines.push("  (no active forwards)".to_string());
        } else {
            for forward in forwards.iter().take(MAX_FORWARD_ROWS) {
                let kind = match forward.kind {
                    ForwardType::Connect => "connect",
                    ForwardType::Listen => "listen ",
                };
                lines.push(format!("  {kind} {:<28} {}", forward.target, forward.state));
            }
            if forwards.len() > MAX_FORWARD_ROWS {
                lines.push(format!("  ... {} more", forwards.len() - MAX_FORWARD_ROWS));
            }
        }

        let lines: Vec<String> = lines
            .into_iter()
            .map(|line| truncate(&line, width.saturating_sub(1)))
            .map(|line| {
                if ascii {
                    line
                } else if line.starts_with("kagi ") {
                    format!("\x1b[1;36m{line}\x1b[0m")
                } else if line.starts_with("  listen") {
                    format!("\x1b[36m{line}\x1b[0m")
                } else if line.starts_with("  connect") {
                    format!("\x1b[33m{line}\x1b[0m")
                } else if line.starts_with("  (") || line.starts_with("  ...") {
                    format!("\x1b[2m{line}\x1b[0m")
                } else {
                    line
                }
            })
            .collect();
        if !draw(&handle, channel, &lines, &mut drawn).await {
            break;
        }
        tick = tick.wrapping_add(1);

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

async fn draw(handle: &Handle, channel: ChannelId, lines: &[String], drawn: &mut usize) -> bool {
    let mut out = String::new();
    if *drawn > 0 {
        out.push_str(&format!("\x1b[{}A\r", drawn));
    }
    for line in lines {
        out.push_str("\x1b[2K");
        out.push_str(line);
        out.push_str("\r\n");
    }
    if *drawn > lines.len() {
        for _ in lines.len()..*drawn {
            out.push_str("\x1b[2K\r\n");
        }
    }
    *drawn = (*drawn).max(lines.len());
    handle.data(channel, out.into_bytes()).await.is_ok()
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        text.chars()
            .take(width.saturating_sub(1))
            .collect::<String>()
            + "…"
    }
}
