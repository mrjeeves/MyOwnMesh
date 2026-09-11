//! One shared wake, and the lease that owns the block it lives in.
//!
//! Every mechanical closure in this lane is a `Notify` behind an `Arc`: the
//! flow's end-of-life signal and the outbound queue's ready signal are both
//! handed to a pump strongly, on purpose, because a wake that announces "the
//! thing you were waiting on is gone" has to outlive the thing. That is exactly
//! why the funding cannot sit in the flow.
//!
//! **The lease lives inside the shared record.** A lease held beside the `Arc`
//! would be released when the *flow* dropped, while the block it accounts for
//! was still alive in a pump that had not woken yet — an allocation the provider
//! believes is free and the allocator still holds. Here the charge and the bytes
//! are one object, so the release is the last clone's drop and cannot be
//! anything else. This is the same construction a leased label and a leased
//! profile use, for the same reason.

use super::*;

/// A `Notify` that owns its own allocation.
///
/// Field order is the drop order and is chosen: the wake is destroyed first,
/// and only then is the block that held it paid back. A lease released before
/// the thing it accounts for is gone would leave a window in which the provider
/// believes the memory is free while it is still occupied.
pub(in crate::transport::webrtc) struct LeasedWake {
    notify: tokio::sync::Notify,
    /// Never read. Its whole job is to exist for exactly as long as this record
    /// and to release when the last clone of the `Arc` around it drops.
    _root: crate::resource::ResourceLease,
}

impl LeasedWake {
    /// Take the lease that owns one wake's block, then allocate it.
    ///
    /// **Funded before it exists**, which is the whole ordering: a provider
    /// under pressure refuses here and the caller fails closed, rather than
    /// having already allocated a block nothing accounted for and then
    /// discovering it could not pay.
    ///
    /// One `Arc`, one claim: the bytes are `size_of::<Self>()` — the wake and
    /// the lease handle beside it, both inline in the block — plus the
    /// strong/weak counter pair the `Arc` puts there, and one residual for the
    /// one allocation. Nothing is estimated and nothing is calibrated: the size
    /// comes from the concrete type this constructor is about to box.
    pub(super) fn mint(registry: &RealtimeFlowRegistry) -> FlowResult<Arc<Self>> {
        let root = registry
            .acquire_flow_root(std::mem::size_of::<Self>())
            .map_err(realtime_drop_refusal)?;
        Ok(Arc::new(Self {
            notify: tokio::sync::Notify::new(),
            _root: root,
        }))
    }

    /// The wake itself.
    ///
    /// A borrow rather than a clone of anything: a caller that can signal or
    /// await this cannot detach it from the lease that funds it, so there is no
    /// way to end up holding the block without holding its charge.
    pub(in crate::transport::webrtc) fn notify(&self) -> &tokio::sync::Notify {
        &self.notify
    }
}
