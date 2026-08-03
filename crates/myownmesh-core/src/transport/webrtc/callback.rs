#![allow(
    deprecated,
    reason = "the scheduler still classifies frozen legacy media events during migration"
)]

//! Callback classification, lifecycle fencing, and bounded scheduling.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConnectorCallbackClass {
    Control,
    EndpointData,
    Realtime,
}

impl ConnectorCallbackClass {
    pub(super) fn for_event(event: &TransportEvent) -> Self {
        match event {
            TransportEvent::Message(_) => Self::EndpointData,
            TransportEvent::AudioSample(_) | TransportEvent::VideoSample(_) => Self::Realtime,
            _ => Self::Control,
        }
    }

    pub(super) const fn index(self) -> usize {
        match self {
            Self::Control => 0,
            Self::EndpointData => 1,
            Self::Realtime => 2,
        }
    }

    pub(super) const fn from_index(index: usize) -> Self {
        match index % 3 {
            0 => Self::Control,
            1 => Self::EndpointData,
            _ => Self::Realtime,
        }
    }
}

struct ConnectorOperationFenceState {
    closing: bool,
    active_operations: usize,
    accounting_poisoned: bool,
}

/// One total ordering boundary for application-affecting connector work.
///
/// Inbound callbacks, endpoint sends, real-time writes, lane operations, track
/// attachment, and close all enter through this owner. Work admitted before
/// close may finish or be discarded by the receiver, but work presented after
/// close cannot enter. Native close waits for all earlier operations to drop
/// their permits.
pub(super) struct ConnectorOperationFence {
    state: SyncMutex<ConnectorOperationFenceState>,
    closed_signal: watch::Sender<bool>,
    active_signal: watch::Sender<usize>,
}

impl Default for ConnectorOperationFence {
    fn default() -> Self {
        let (closed_signal, _receiver) = watch::channel(false);
        let (active_signal, _receiver) = watch::channel(0);
        Self {
            state: SyncMutex::new(ConnectorOperationFenceState {
                closing: false,
                active_operations: 0,
                accounting_poisoned: false,
            }),
            closed_signal,
            active_signal,
        }
    }
}

impl ConnectorOperationFence {
    pub(super) fn try_enter(self: &Arc<Self>) -> Option<ConnectorOperationPermit> {
        let mut state = self.state.lock();
        if state.closing || state.accounting_poisoned {
            return None;
        }
        let Some(active_operations) = state.active_operations.checked_add(1) else {
            state.accounting_poisoned = true;
            state.closing = true;
            self.closed_signal.send_replace(true);
            return None;
        };
        state.active_operations = active_operations;
        self.active_signal.send_replace(active_operations);
        Some(ConnectorOperationPermit {
            fence: Arc::clone(self),
            active: true,
        })
    }

    pub(super) fn begin_close(&self) -> bool {
        let mut state = self.state.lock();
        if state.closing {
            return false;
        }
        state.closing = true;
        self.closed_signal.send_replace(true);
        true
    }

    pub(super) fn is_closed(&self) -> bool {
        self.state.lock().closing
    }

    pub(super) fn subscribe_close(&self) -> watch::Receiver<bool> {
        self.closed_signal.subscribe()
    }

    pub(super) async fn wait_for_operations(&self) {
        let mut active = self.active_signal.subscribe();
        loop {
            if *active.borrow() == 0 {
                return;
            }
            if active.changed().await.is_err() {
                return;
            }
        }
    }

    #[cfg(test)]
    pub(super) fn active_operations_for_test(&self) -> usize {
        self.state.lock().active_operations
    }
}

pub(super) struct ConnectorOperationPermit {
    fence: Arc<ConnectorOperationFence>,
    active: bool,
}

impl Drop for ConnectorOperationPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.fence.state.lock();
        let Some(active_operations) = state.active_operations.checked_sub(1) else {
            state.accounting_poisoned = true;
            state.closing = true;
            self.fence.closed_signal.send_replace(true);
            return;
        };
        state.active_operations = active_operations;
        self.fence.active_signal.send_replace(active_operations);
        self.active = false;
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ConnectorCallbackScheduler {
    pub(super) weights: [usize; 3],
    pub(super) cursor: usize,
    pub(super) remaining: usize,
}

impl ConnectorCallbackScheduler {
    pub(super) fn new(weights: ConnectorCallbackServiceWeights) -> Self {
        let weights = [
            weights.control().get(),
            weights.endpoint_data().get(),
            weights.realtime().map_or(0, NonZeroUsize::get),
        ];
        Self {
            weights,
            cursor: 0,
            remaining: weights[0],
        }
    }

    pub(super) fn current(&self) -> ConnectorCallbackClass {
        ConnectorCallbackClass::from_index(self.cursor)
    }

    pub(super) fn skip_current(&mut self) {
        loop {
            self.cursor = (self.cursor + 1) % self.weights.len();
            self.remaining = self.weights[self.cursor];
            if self.remaining != 0 {
                break;
            }
        }
    }

    pub(super) fn delivered(&mut self, class: ConnectorCallbackClass) {
        let index = class.index();
        if index != self.cursor {
            self.cursor = index;
            self.remaining = self.weights[index];
        }
        self.remaining = self.remaining.saturating_sub(1);
        if self.remaining == 0 {
            self.skip_current();
        }
    }
}
