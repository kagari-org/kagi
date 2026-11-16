use std::sync::Arc;

use bytes::Bytes;
use russh::ChannelId;
use russh::server::Handle;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::input::TerminalEvent;
use crate::registry::{StreamChannel, StreamSubscription};

pub(crate) fn spawn_raw(
    target: Arc<StreamChannel>,
    admin_handle: Handle,
    admin_channel: ChannelId,
    cancel: CancellationToken,
) -> mpsc::Sender<TerminalEvent> {
    let (input_tx, input_rx) = mpsc::channel(64);
    let subscription = target.subscribe();
    tokio::spawn(async move {
        run(
            target,
            admin_handle.clone(),
            admin_channel,
            input_rx,
            subscription,
            cancel,
        )
        .await;
        let _ = admin_handle.eof(admin_channel).await;
        let _ = admin_handle.close(admin_channel).await;
    });
    input_tx
}

async fn run(
    target: Arc<StreamChannel>,
    admin_handle: Handle,
    admin_channel: ChannelId,
    mut input_rx: mpsc::Receiver<TerminalEvent>,
    mut subscription: StreamSubscription,
    cancel: CancellationToken,
) {
    let pending = std::mem::take(&mut subscription.pending);
    if !pending.is_empty()
        && admin_handle
            .data(admin_channel, Bytes::from(pending))
            .await
            .is_err()
    {
        return;
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            input = input_rx.recv() => {
                let Some(event) = input else { return; };
                let TerminalEvent::Input(input) = event else { continue; };
                if input.is_empty() {
                    continue;
                }
                target.note_output(input.len());
                if target
                    .handle
                    .data(target.channel, Bytes::from(input))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            message = subscription.output.recv() => {
                match message {
                    Ok(data) => {
                        if admin_handle.data(admin_channel, data).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_))
                    | Err(broadcast::error::RecvError::Closed) => return,
                }
            }
            changed = subscription.closed.changed() => {
                if changed.is_err() || *subscription.closed.borrow() {
                    return;
                }
            }
        }
    }
}
