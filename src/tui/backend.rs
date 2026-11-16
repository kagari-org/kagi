use std::io::{self, Write};

use russh::ChannelId;
use russh::server::Handle;
use tokio::sync::mpsc;

pub struct TerminalHandle {
    sender: mpsc::Sender<Vec<u8>>,
    sink: Vec<u8>,
}

impl TerminalHandle {
    pub fn start(handle: Handle, channel: ChannelId) -> Self {
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(32);
        tokio::spawn(async move {
            while let Some(data) = receiver.recv().await {
                if handle.data(channel, data).await.is_err() {
                    break;
                }
            }
        });
        Self {
            sender,
            sink: Vec::new(),
        }
    }
}

impl Write for TerminalHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sink.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.sink.is_empty() {
            return Ok(());
        }
        let frame = std::mem::take(&mut self.sink);
        match self.sender.try_send(frame) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUI channel closed",
            )),
        }
    }
}
