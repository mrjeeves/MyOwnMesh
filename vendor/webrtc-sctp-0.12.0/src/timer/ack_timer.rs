use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Weak,
};

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;

pub(crate) const ACK_INTERVAL: Duration = Duration::from_millis(200);

/// ackTimerObserver is the interface to an ack timer observer.
#[async_trait]
pub(crate) trait AckTimerObserver {
    async fn on_ack_timeout(&mut self);
}

/// ackTimer provides the retnransmission timer conforms with RFC 4960 Sec 6.3.1
#[derive(Default, Debug)]
pub(crate) struct AckTimer<T: 'static + AckTimerObserver + Send> {
    pub(crate) timeout_observer: Weak<Mutex<T>>,
    pub(crate) interval: Duration,
    pub(crate) close_tx: Option<mpsc::Sender<()>>,
    // A distinct marker for each start: an expired/cancelled task can never
    // change the state of a later timer instance.
    active: Option<Arc<AtomicBool>>,
}

impl<T: 'static + AckTimerObserver + Send> AckTimer<T> {
    /// newAckTimer creates a new acknowledgement timer used to enable delayed ack.
    pub(crate) fn new(timeout_observer: Weak<Mutex<T>>, interval: Duration) -> Self {
        AckTimer {
            timeout_observer,
            interval,
            close_tx: None,
            active: None,
        }
    }

    /// start starts the timer.
    pub(crate) fn start(&mut self) -> bool {
        if self.is_running() {
            return false;
        }

        let (close_tx, mut close_rx) = mpsc::channel(1);
        let interval = self.interval;
        let timeout_observer = self.timeout_observer.clone();
        let active = Arc::new(AtomicBool::new(true));
        self.active = Some(Arc::clone(&active));

        tokio::spawn(async move {
            let timer = tokio::time::sleep(interval);
            tokio::pin!(timer);

            tokio::select! {
                biased;
                _ = close_rx.recv() => {},
                _ = timer.as_mut() => {
                    if let Some(observer) = timeout_observer.upgrade() {
                        // Cancellation must still win while expiry is waiting
                        // for the association lock, not only during the sleep.
                        tokio::select! {
                            biased;
                            _ = close_rx.recv() => {},
                            mut observer = observer.lock() => {
                                // Publish completion before the callback can
                                // request another delayed ACK. stop() races at
                                // this one-shot claim; a cancelled instance
                                // cannot invoke the observer after a restart.
                                if active.swap(false, Ordering::AcqRel) {
                                    observer.on_ack_timeout().await;
                                }
                            }
                        };
                    }
                }
            }
            active.store(false, Ordering::Release);
        });

        self.close_tx = Some(close_tx);
        true
    }

    /// Cancels the current instance; a subsequent start creates a new instance.
    /// A callback that already claimed expiry under the observer lock may finish.
    pub(crate) fn stop(&mut self) {
        if let Some(active) = self.active.take() {
            active.store(false, Ordering::Release);
        }
        self.close_tx.take();
    }

    /// isRunning tests if the timer is running.
    /// Debug purpose only
    pub(crate) fn is_running(&self) -> bool {
        self.active
            .as_ref()
            .map(|active| active.load(Ordering::Acquire))
            .unwrap_or(false)
    }
}
