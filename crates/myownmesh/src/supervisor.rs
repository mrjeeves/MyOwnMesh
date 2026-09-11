//! The one way to ask this daemon's runtime to shut down.
//!
//! Two callers submit the same request through the same object: an embedder
//! calling [`EmbeddedDaemon::shutdown`](crate::embedded::EmbeddedDaemon::shutdown),
//! and the control surface after a reset has removed the state the daemon was
//! running on. Neither ends the host process. What ends the daemon is the
//! ordinary drain the request starts — the control surface returns, hosted
//! services stop, every joined network says goodbye and is torn down — and the
//! process the daemon happens to be hosted in outlives all of it.
//!
//! There is one drain, and it is `EmbeddedDaemon::shutdown`. This object does
//! not perform it; it carries the request to whoever will.
//! [`run_until_shutdown`](crate::embedded::EmbeddedDaemon::run_until_shutdown)
//! is that call for a host with nothing else to wait on, and `myownmesh serve`
//! reaches the same one through a select against the operator's signal. Nothing
//! here stops the control surface alone and leaves services and networks up.
//!
//! No duration participates. The request carries no deadline, starts no timer,
//! and does not become true by elapsing; it is submitted once and the drain
//! runs to completion on its own terms.

use std::sync::Arc;

use tokio::sync::watch;

/// A handle on the daemon runtime's shutdown request.
///
/// The request is a **latched one-way state**, not a notification, and that is
/// the whole of the type. A notification is only seen by whoever was already
/// listening, and the one caller who most needs to see this one — the host
/// application — cannot listen until startup has returned it a handle, while the
/// control socket it started is already accepting the reset that submits it. So
/// the state is what a waiter reads, and a waiter that arrives after the request
/// resolves on the state rather than waiting forever for an event that has been
/// and gone.
///
/// Idempotent: the first submission latches, every later one is a no-op, so a
/// reset that has already asked and an embedder that then calls `shutdown` are
/// two submissions of one request and one drain.
///
/// No duration participates. The state does not become true by elapsing, and
/// nothing here ends the host process.
#[derive(Clone, Debug)]
pub struct RuntimeSupervisor {
    /// Retained rather than only its receiver: a `watch` sender keeps the state
    /// readable for every waiter that subscribes later, including ones that do
    /// not exist yet.
    requested: Arc<watch::Sender<bool>>,
}

impl Default for RuntimeSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeSupervisor {
    /// A runtime whose shutdown has not been requested.
    pub fn new() -> Self {
        Self {
            requested: Arc::new(watch::Sender::new(false)),
        }
    }

    /// Submit the one shutdown request.
    ///
    /// `true` when this call was the submission, `false` when one was already
    /// made. Callers do not need the answer to be correct about lifecycle — the
    /// drain runs exactly once either way — but a control can read it, and it
    /// is what makes "exactly one orderly shutdown request" observable rather
    /// than asserted.
    pub fn request_shutdown(&self) -> bool {
        !self.requested.send_replace(true)
    }

    /// Whether a shutdown request has been submitted.
    pub fn shutdown_requested(&self) -> bool {
        *self.requested.borrow()
    }

    /// Resolve once the runtime has been asked to stop, whenever that was.
    ///
    /// Subscribing and then checking the latched state is the ordering, and it
    /// is inside this method rather than left to each caller because getting it
    /// wrong is invisible: a waiter that checks first and subscribes second
    /// misses a request landing between the two, and a waiter that only
    /// subscribes misses every request that came before it existed. Both are one
    /// missed drain, and both look exactly like a daemon that is still running.
    ///
    /// Request-before-waiter, request-during-construction and
    /// request-after-waiter therefore all resolve, on the same state.
    pub async fn wait_requested(&self) {
        let mut watching = self.requested.subscribe();
        // Subscribed above, so a request landing from here on marks this
        // receiver changed; the borrow answers for every request before it.
        if *watching.borrow_and_update() {
            return;
        }
        // One-way, so the first change is the request. The sender is held by
        // this handle, so `changed` cannot end because the channel closed while
        // a drain is still owed.
        while watching.changed().await.is_ok() {
            if *watching.borrow_and_update() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Long enough that a loaded machine will not trip it, short enough that a
    /// waiter which never resolves is named rather than hanging the suite.
    /// Nothing below asserts *because* of it.
    const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(10);

    async fn resolves(what: &str, waiting: impl std::future::Future<Output = ()>) {
        if tokio::time::timeout(HANG_GUARD, waiting).await.is_err() {
            panic!("hang guard: {what}");
        }
    }

    /// A waiter resolves whether the request came before it, during its
    /// construction, or after it.
    ///
    /// The discriminating control for the whole repair, and the shape the
    /// deleted one could not express. The request used to be a broadcast send,
    /// which only reaches receivers that already exist — while the one party
    /// that most needs it, the host application, cannot obtain this handle until
    /// startup has returned, and the control socket startup spawned is already
    /// accepting the reset that submits it. The submitted flag then stayed true,
    /// suppressing every later request, so the late waiter waited forever for an
    /// event that had been and gone: a daemon whose state was deleted, still
    /// running, with nothing left that could ask it to stop.
    ///
    /// The three orderings are asserted as three, because only the first one
    /// used to fail and a control that took the easy one would have passed
    /// throughout.
    #[tokio::test]
    async fn v4_r7_daemon_b2_a_waiter_resolves_whenever_the_request_was_submitted() {
        // Before: the request is submitted, and only then does anybody wait.
        let before = RuntimeSupervisor::new();
        assert!(
            !before.shutdown_requested(),
            "non-vacuity: nothing has asked yet"
        );
        assert!(
            before.request_shutdown(),
            "the first submission is the submission"
        );
        resolves(
            "a waiter constructed after the request",
            before.wait_requested(),
        )
        .await;

        // During: the future exists but has not been polled, which is where a
        // check-then-subscribe would drop the request on the floor.
        let during = RuntimeSupervisor::new();
        let waiting = during.wait_requested();
        assert!(during.request_shutdown());
        resolves("a waiter constructed before it was polled", waiting).await;

        // After: the ordinary case, which has to keep working.
        let after = RuntimeSupervisor::new();
        let submitter = after.clone();
        let waiting = tokio::spawn(async move { after.wait_requested().await });
        // Through a clone, because the submission is the daemon's rather than
        // any one handle's.
        assert!(submitter.request_shutdown());
        resolves("a waiter that was already parked", async {
            waiting.await.expect("the waiter task does not panic");
        })
        .await;
    }

    /// One request, however many callers submit it, and it stays submitted.
    ///
    /// A reset whose write was refused still submits — the state it removed is
    /// gone either way — so the reset path and an embedder shutting the same
    /// daemon down afterwards are two submissions of one request. That the
    /// second returns `false` is what makes "exactly one orderly shutdown
    /// request" observable rather than asserted, and the latch is what makes a
    /// waiter arriving after all of them still correct.
    #[tokio::test]
    async fn one_runtime_shutdown_request_survives_every_later_caller() {
        let supervisor = RuntimeSupervisor::new();

        assert!(supervisor.request_shutdown(), "the first is the submission");
        assert!(
            !supervisor.request_shutdown(),
            "and a later caller submits nothing second"
        );
        assert!(
            !supervisor.clone().request_shutdown(),
            "including through a clone — the submission is the daemon's, not \
             the handle's"
        );

        assert!(supervisor.shutdown_requested());
        resolves(
            "the state is still the request after every later caller",
            supervisor.wait_requested(),
        )
        .await;
    }
}
