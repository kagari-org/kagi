#[derive(Debug)]
pub(crate) enum TerminalEvent {
    Input(Vec<u8>),
    Resize(u16, u16),
}
