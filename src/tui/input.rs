use termwiz::input::{InputEvent, InputParser, KeyCode, Modifiers};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiKey {
    Char(char),
    Enter,
    Tab,
    BackTab,
    Escape,
    Backspace,
    Delete,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    CtrlC,
    CtrlR,
    CtrlClose,
    F1,
}

pub fn parse(bytes: &[u8]) -> Vec<TuiKey> {
    let mut parser = InputParser::new();
    let events = parser.parse_as_vec(bytes, false);
    let mut keys = Vec::new();
    for event in events {
        match event {
            InputEvent::Key(key) => {
                let ctrl = key.modifiers.contains(Modifiers::CTRL);
                let shift = key.modifiers.contains(Modifiers::SHIFT);
                match key.key {
                    KeyCode::Char('c') if ctrl => keys.push(TuiKey::CtrlC),
                    KeyCode::Char('r') if ctrl => keys.push(TuiKey::CtrlR),
                    KeyCode::Char(']') if ctrl => keys.push(TuiKey::CtrlClose),
                    KeyCode::Char(c) => keys.push(TuiKey::Char(c)),
                    KeyCode::Enter => keys.push(TuiKey::Enter),
                    KeyCode::Tab if shift => keys.push(TuiKey::BackTab),
                    KeyCode::Tab => keys.push(TuiKey::Tab),
                    KeyCode::Escape => keys.push(TuiKey::Escape),
                    KeyCode::Backspace => keys.push(TuiKey::Backspace),
                    KeyCode::Delete => keys.push(TuiKey::Delete),
                    KeyCode::UpArrow => keys.push(TuiKey::Up),
                    KeyCode::DownArrow => keys.push(TuiKey::Down),
                    KeyCode::LeftArrow => keys.push(TuiKey::Left),
                    KeyCode::RightArrow => keys.push(TuiKey::Right),
                    KeyCode::Home => keys.push(TuiKey::Home),
                    KeyCode::End => keys.push(TuiKey::End),
                    KeyCode::PageUp => keys.push(TuiKey::PageUp),
                    KeyCode::PageDown => keys.push(TuiKey::PageDown),
                    KeyCode::Function(1) => keys.push(TuiKey::F1),
                    _ => {}
                }
            }
            InputEvent::Resized { .. } => {}
            _ => {}
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_keys() {
        assert_eq!(parse(b"j"), vec![TuiKey::Char('j')]);
        assert_eq!(parse(b"\r"), vec![TuiKey::Enter]);
        assert_eq!(parse(b"\x1b[A"), vec![TuiKey::Up]);
        assert_eq!(parse(b"\t"), vec![TuiKey::Tab]);
        assert_eq!(parse(b"\x1b[Z"), vec![TuiKey::BackTab]);
        assert_eq!(parse(b"\x03"), vec![TuiKey::CtrlC]);
    }
}
