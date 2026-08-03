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

/// Source-side ordering boundary for callbacks from one exact data channel.
///
/// The mutex gives enqueue and close one total order without assuming the
/// native dependency invokes callbacks in order. Once close commits, no later
/// callback can enter either connector mailbox.
pub(super) struct DataChannelCallbackFence {
    pub(super) closed: SyncMutex<bool>,
    closed_signal: watch::Sender<bool>,
}

impl Default for DataChannelCallbackFence {
    fn default() -> Self {
        let (closed_signal, _receiver) = watch::channel(false);
        Self {
            closed: SyncMutex::new(false),
            closed_signal,
        }
    }
}

impl DataChannelCallbackFence {
    pub(super) fn begin_close(&self) -> bool {
        let mut closed = self.closed.lock();
        if *closed {
            return false;
        }
        *closed = true;
        self.closed_signal.send_replace(true);
        true
    }

    pub(super) fn is_closed(&self) -> bool {
        *self.closed.lock()
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<bool> {
        self.closed_signal.subscribe()
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
