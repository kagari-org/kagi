use std::sync::Arc;

use bytes::Bytes;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::registry::{StreamChannel, StreamSubscription};

const DETACH: u8 = 0x1d;

pub struct AttachView {
    target: Arc<StreamChannel>,
    pub subscription: StreamSubscription,
    parser: vt100::Parser,
    key: String,
    cols: u16,
    rows: u16,
}

impl AttachView {
    pub fn new(target: Arc<StreamChannel>, cols: u16, rows: u16) -> Self {
        let key = target.key.to_string();
        let mut subscription = target.subscribe();
        let grid_rows = rows.saturating_sub(1).max(1);
        let pending = std::mem::take(&mut subscription.pending);
        let mut parser = vt100::Parser::new(grid_rows, cols.max(1), 0);
        if !pending.is_empty() {
            parser.process(&pending);
        }
        Self {
            target,
            subscription,
            parser,
            key,
            cols: cols.max(1),
            rows: rows.max(2),
        }
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.cols = cols.max(1);
        self.rows = rows.max(2);
        self.parser
            .screen_mut()
            .set_size(self.rows.saturating_sub(1).max(1), self.cols);
    }

    pub fn process_output(&mut self, data: &[u8]) {
        self.parser.process(data);
    }

    pub async fn forward(&self, bytes: &[u8]) -> Result<bool, String> {
        let (forward, detach) = split_detach(bytes);
        if !forward.is_empty() {
            self.target.note_output(forward.len());
            if self
                .target
                .handle
                .data(self.target.channel, Bytes::copy_from_slice(forward))
                .await
                .is_err()
            {
                return Err("target closed".to_string());
            }
        }
        Ok(!detach)
    }

    pub fn render(&self, frame: &mut Frame) {
        let area = frame.area();
        if area.height == 0 || area.width == 0 {
            return;
        }
        let top = Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: 1,
        };
        let header = Line::from(vec![
            Span::styled(
                " kagi attach ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" {} | Ctrl+] detach | Ctrl+C SIGINT", self.key)),
        ]);
        frame.render_widget(Paragraph::new(header), top);

        let grid = Rect {
            x: area.x,
            y: area.y + 1,
            width: area.width,
            height: area.height.saturating_sub(1),
        };
        if grid.height == 0 || grid.width == 0 {
            return;
        }
        let lines = screen_lines(self.parser.screen(), grid.width, grid.height);
        frame.render_widget(Paragraph::new(lines), grid);

        let (row, col) = self.parser.screen().cursor_position();
        if row < grid.height && col < grid.width {
            frame.set_cursor_position((grid.x + col, grid.y + row));
        }
    }
}

fn split_detach(input: &[u8]) -> (&[u8], bool) {
    match input.iter().position(|byte| *byte == DETACH) {
        Some(index) => (&input[..index], true),
        None => (input, false),
    }
}

fn screen_lines(screen: &vt100::Screen, width: u16, height: u16) -> Vec<Line<'static>> {
    let (screen_rows, screen_cols) = screen.size();
    let rows = height.min(screen_rows);
    let cols = width.min(screen_cols);
    let mut lines = Vec::with_capacity(usize::from(height));
    for row in 0..rows {
        let mut spans: Vec<Span<'static>> = Vec::new();
        let mut current_style = Style::default();
        let mut text = String::new();
        for col in 0..cols {
            let Some(cell) = screen.cell(row, col) else {
                text.push(' ');
                continue;
            };
            let style = cell_style(cell);
            if style != current_style {
                if !text.is_empty() {
                    spans.push(Span::styled(std::mem::take(&mut text), current_style));
                }
                current_style = style;
            }
            let contents = cell.contents();
            if contents.is_empty() {
                text.push(' ');
            } else {
                text.push_str(contents);
            }
        }
        if !text.is_empty() {
            spans.push(Span::styled(text, current_style));
        }
        lines.push(Line::from(spans));
    }
    while lines.len() < usize::from(height) {
        lines.push(Line::default());
    }
    lines
}

fn cell_style(cell: &vt100::Cell) -> Style {
    let mut style = Style::default()
        .fg(map_color(cell.fgcolor()))
        .bg(map_color(cell.bgcolor()));
    let mut modifier = Modifier::empty();
    if cell.bold() {
        modifier |= Modifier::BOLD;
    }
    if cell.dim() {
        modifier |= Modifier::DIM;
    }
    if cell.italic() {
        modifier |= Modifier::ITALIC;
    }
    if cell.underline() {
        modifier |= Modifier::UNDERLINED;
    }
    if cell.inverse() {
        modifier |= Modifier::REVERSED;
    }
    style = style.add_modifier(modifier);
    style
}

fn map_color(color: vt100::Color) -> Color {
    match color {
        vt100::Color::Default => Color::Reset,
        vt100::Color::Idx(index) => Color::Indexed(index),
        vt100::Color::Rgb(red, green, blue) => Color::Rgb(red, green, blue),
    }
}
