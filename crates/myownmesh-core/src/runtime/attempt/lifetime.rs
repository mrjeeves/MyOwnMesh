//! Exact attempt liveness, cancellation, and retirement ownership.

use super::*;

pub(super) struct AttemptOwnership {
    pub(super) runtime: RuntimeIncarnation,
    pub(super) active: AtomicBool,
    pub(super) transition: Mutex<()>,
    pub(super) retired: watch::Sender<bool>,
}

/// Unique cancellation and retirement owner for one connection attempt.
///
/// This value is not a resource permit and cannot create connector authority.
/// It only controls whether capabilities already issued by the same admitted
/// attempt remain live. Dropping or retiring it invalidates candidate
/// capabilities that have not already been consumed into a later capability,
/// including candidate values held by delayed callbacks.
pub(crate) struct AttemptLifetime {
    pub(super) attempt: Arc<AttemptOwnership>,
}

impl AttemptLifetime {
    pub(crate) fn retire(&self) {
        {
            let _transition = match self.attempt.transition.lock() {
                Ok(transition) => transition,
                Err(poisoned) => poisoned.into_inner(),
            };
            self.attempt.active.store(false, Ordering::Release);
        }
        // Notify after releasing the attempt transition. Connector cleanup may
        // take its own authority mutex, so this prevents a reverse nested edge.
        self.attempt.retired.send_replace(true);
    }

    #[cfg(test)]
    pub(crate) fn is_active(&self) -> bool {
        self.attempt.active.load(Ordering::Acquire)
    }
}

/// Cloneable, non-retiring witness for work owned by one attempt.
///
/// Only [`AttemptLifetime`] can retire the attempt. Candidate workers retain
/// this witness so they can reject and cancel work after that unique owner has
/// ended the attempt without gaining cancellation authority themselves.
#[derive(Clone)]
pub(crate) struct AttemptLiveness {
    pub(super) attempt: Arc<AttemptOwnership>,
}

impl AttemptLiveness {
    pub(crate) fn is_active(&self) -> bool {
        self.attempt.active.load(Ordering::Acquire)
    }

    #[allow(
        dead_code,
        reason = "production admitted workers will select this signal with connector retirement"
    )]
    pub(crate) fn subscribe_retirement(&self) -> watch::Receiver<bool> {
        self.attempt.retired.subscribe()
    }
}

impl Drop for AttemptLifetime {
    fn drop(&mut self) {
        self.retire();
    }
}
