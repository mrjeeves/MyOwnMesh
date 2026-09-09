//! Generic request/response RPC over the mesh data channels.
//!
//! Embedders register a handler by `method` name; callers invoke
//! it on a peer via [`Rpc::call`]. Single-shot responses use a
//! `oneshot` round-trip; streaming responses use
//! `tokio::sync::mpsc` plus the
//! [`crate::protocol::rpc::RpcStreamChunkMessage`] /
//! [`crate::protocol::rpc::RpcStreamEndMessage`] frames so a
//! single request can yield many ordered chunks.
//!
//! In-flight requests are fields of the exact promoted peer session that sent
//! them. Each retained record and queued stream item holds its provider lease;
//! replacement, revocation and shutdown drop that session record and resolve
//! its callers.
//!
//! A request id is a routing key, never an authority. Every entry
//! is only looked up after the admitted inbound dispatch has re-entered the
//! captured installation's session record. A replacement connector therefore
//! has no map in which the predecessor's request can exist.
//!
//! Locally the same holds one level finer. Filing an operation also
//! hands its caller a process-local identity for the exact entry it
//! filed, and a caller withdrawing an entry after a failed send
//! matches on that identity rather than on the key and binding,
//! which a recycled id could reproduce exactly. Nothing inbound is
//! ever matched against it.

use std::alloc::Layout;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::engine::state::NetworkState;
use crate::identity::DeviceId;
use crate::protocol::CapabilityAdvert;
use crate::resource::{
    checked_measure_add, mailbox_measure_serialized, strings_measure, FundedArc, LeasedMap,
    LocalApplicationResourceScope, MailboxMeasurement, ResourceClaim, ResourceClaimArithmeticError,
    ResourceClass, ResourceLease, ResourceMailboxItem, ResourceMailboxItemError,
    ResourceMailboxReceiver, ResourceUnavailable,
};

#[derive(thiserror::Error, Debug)]
pub enum RpcError {
    #[error("network down")]
    NetworkDown,
    #[error("peer {0} not in active set")]
    PeerNotFound(String),
    #[error("timeout")]
    Timeout,
    #[error("handler returned error: {0}")]
    Remote(String),
    #[error("no handler registered for method '{0}'")]
    NoHandler(String),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("transport: {0}")]
    Transport(String),
    /// The one request id this call drew was already owned by a
    /// pending operation, so the call was never sent.
    ///
    /// Purely local and, at a 96-bit id, effectively unreachable —
    /// it exists so the collision-safe insertion below has
    /// somewhere to fail *explicitly*. The alternative to naming it
    /// is displacing whichever pending operation already owns the
    /// drawn id, which strands that caller's oneshot forever and
    /// hands its reply to the wrong receiver.
    ///
    /// One draw, no redraw. The bounded retry this replaces existed
    /// only to make "never displace" total, which a single claim
    /// that fails explicitly already is.
    #[error("no unused request id available")]
    RequestIdUnavailable,
    /// The peer had no live promoted session when the call was filed.
    ///
    /// Distinct from [`Self::RequestIdUnavailable`] because the two want
    /// opposite responses: this one is ordinary and worth retrying once a
    /// session establishes, and the other is a local draw colliding and says
    /// nothing about the peer at all.
    #[error("no live session for peer {0}")]
    SessionNotCurrent(String),
    /// The session's resource owner would not fund one more pending operation.
    ///
    /// Also split out of [`Self::RequestIdUnavailable`]. Pointing an operator at
    /// a request-id draw when the actual remedy is a larger grant is worse than
    /// saying nothing, because it is specific and wrong.
    #[error("rpc call refused: {0}")]
    ResourceUnavailable(String),
}

impl RpcRegistrationRefusal {
    /// The caller-facing error for one refusal, naming the peer it was about.
    ///
    /// One place, so the three facts cannot be mapped one way on the unary path
    /// and another on the streaming one — which is how they came to be mapped
    /// to a single wrong answer on both.
    pub(crate) fn into_rpc_error(self, peer: &str) -> RpcError {
        match self {
            Self::SessionNotCurrent => RpcError::SessionNotCurrent(peer.to_string()),
            Self::RequestIdCollision => RpcError::RequestIdUnavailable,
            Self::ResourceUnavailable(e) => {
                RpcError::ResourceUnavailable(format!("no capacity to file the call: {e:?}"))
            }
            Self::Unrepresentable => {
                RpcError::ResourceUnavailable("the call is not representable as a claim".into())
            }
        }
    }
}

/// A single inbound RPC the local handler receives.
#[derive(Debug, Clone)]
pub struct RpcCall {
    pub from: DeviceId,
    pub request_id: String,
    pub method: String,
    pub payload: serde_json::Value,
    pub streaming: bool,
}

/// Response a handler emits for a single-shot RPC. Streaming
/// handlers use [`Rpc::serve_stream`] and emit chunks on the
/// returned sender directly.
#[derive(Debug, Clone)]
pub struct RpcResponse {
    pub body: serde_json::Value,
}

impl RpcResponse {
    pub fn from_value(body: serde_json::Value) -> Self {
        Self { body }
    }

    pub fn from_serialize<T: serde::Serialize>(body: &T) -> Result<Self, serde_json::Error> {
        Ok(Self {
            body: serde_json::to_value(body)?,
        })
    }
}

/// Boxed future returned by an RPC handler.
pub type RpcHandlerFuture =
    Pin<Box<dyn Future<Output = Result<RpcResponse, String>> + Send + 'static>>;

/// One registered single-shot handler, in one allocation funded by the
/// [`FundedArc`] that owns it.
///
/// **The registration charge must outlive every invocation clone, and it must
/// also outlive the allocation itself.** Dispatch clones the handler out of the
/// registry and invokes it after the registry lock is gone, so funding held by
/// the map entry would be released the instant that entry was replaced — while
/// the clone was still running. That is why the charge is not in
/// [`HandlerEntry`]. Nor can it be a field *inside* this struct: that buys the
/// first property at the cost of the second, because a lease among these fields
/// is released by this value's own drop glue, which runs while the allocation is
/// still there.
///
/// [`FundedArc`] gives both. Every strong clone holds the same reservation, so
/// the charge spans every invocation; and the token sits beside the pointer
/// rather than inside the pointee, so it is released only once the allocation
/// is actually gone.
///
/// One allocation, and that is load-bearing rather than tidy: the callable is
/// the trailing **unsized** field, so `Arc<FundedRpcHandler<F>>` coerces to
/// `Arc<FundedRpcHandler>` without boxing the closure separately. A
/// `Box<dyn Fn>` beside the counts would be a second allocation that the
/// registration charge would have to name, and an accounting formula that has
/// to remember a representation detail is one that drifts from it. That
/// coercion is why construction goes through `FundedArc::from_admitted_arc`:
/// unsizing has to happen at the `Arc::new` here, before the funding is
/// attached.
pub struct FundedRpcHandler<C: ?Sized = dyn Fn(RpcCall) -> RpcHandlerFuture + Send + Sync + 'static>
{
    /// Which registration installed this handler. Compared, never displayed:
    /// it exists so a cleanup handle can remove the exact handler it installed
    /// and refuse to remove a successor that legitimately took the name.
    registration: RegistrationIdentity,
    /// Last, because a struct may only be unsized in its final field.
    call: C,
}

impl FundedRpcHandler {
    pub fn invoke(&self, call: RpcCall) -> RpcHandlerFuture {
        (self.call)(call)
    }

    pub(crate) fn registration(&self) -> RegistrationIdentity {
        self.registration
    }
}

/// A registered single-shot handler, funded for the whole life of its
/// allocation.
///
/// `FundedArc` rather than `Arc`: cloning one for an invocation shares the
/// registration's single reservation instead of taking out another, and the
/// charge goes back only after the last clone is gone *and* the allocation with
/// it. Reading through it is unchanged — `Deref` reaches the handler — so
/// `handler.invoke(call)` and `handler.registration()` still work as written.
pub type RpcHandler = FundedArc<FundedRpcHandler>;

/// Streaming-handler item. Every successful handler must explicitly terminate;
/// disappearance without `End` is a failed stream, never clean success.
#[derive(Debug, PartialEq)]
pub enum RpcStreamItem {
    Chunk(serde_json::Value),
    End(Result<(), String>),
}

unsafe impl ResourceMailboxItem for RpcStreamItem {
    fn measured_claim(&self) -> Result<MailboxMeasurement<Self>, ResourceMailboxItemError> {
        let (retained, queued, allocations) = match self {
            Self::Chunk(payload) => mailbox_measure_serialized(payload)?,
            Self::End(Ok(())) => (0, 0, 0),
            Self::End(Err(error)) => strings_measure([error.as_str()])?,
        };
        MailboxMeasurement::from_parts(retained, queued, allocations)
    }
}

pub type RpcStreamHandlerFuture = Pin<
    Box<
        dyn Future<Output = Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
            + Send
            + 'static,
    >,
>;

/// The streaming twin of [`FundedRpcHandler`], on the same rule and for the
/// same reason: one allocation, funded by the [`FundedArc`] that owns it, so an
/// invocation clone cannot outlive the charge that paid for it and the charge
/// cannot outlive being needed.
pub struct FundedRpcStreamHandler<
    C: ?Sized = dyn Fn(RpcCall) -> RpcStreamHandlerFuture + Send + Sync + 'static,
> {
    registration: RegistrationIdentity,
    call: C,
}

impl FundedRpcStreamHandler {
    pub fn invoke(&self, call: RpcCall) -> RpcStreamHandlerFuture {
        (self.call)(call)
    }

    pub(crate) fn registration(&self) -> RegistrationIdentity {
        self.registration
    }
}

/// [`RpcHandler`] for the streaming twin, shared and funded the same way.
pub type RpcStreamHandler = FundedArc<FundedRpcStreamHandler>;

/// Names one installation of one handler, so a cleanup handle can act on
/// exactly the registration it made.
///
/// Removal by method name alone is what this exists to replace: a late cleanup
/// for a handler that has since been legitimately displaced would otherwise
/// tear down its successor. Drawn from a per-dispatcher counter, so two
/// registrations of the same method are never equal and a comparison is a fact
/// rather than a guess.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RegistrationIdentity(u64);

/// RPC dispatcher. One per joined network; cheap to clone.
#[derive(Clone)]
pub struct Rpc {
    pub(crate) inner: crate::resource::FundedArc<RpcInner>,
}

/// Internal RPC state shared between the [`Rpc`] facade and the
/// engine's frame-dispatch path. Public so `NetworkState` can
/// stash it; embedders never construct these directly.
pub struct RpcInner {
    /// Non-owning route back to the runtime. `NetworkState` owns the one RPC
    /// dispatcher; retaining it here would close a permanent strong cycle and
    /// keep handlers and pending effects alive after network retirement.
    pub(crate) network: Weak<NetworkState>,
    pub(crate) handlers: Mutex<LeasedMap<String, HandlerEntry>>,
    handler_resources: LocalApplicationResourceScope,
    /// Seeds [`RegistrationIdentity`]. Monotonic and never reused within one
    /// dispatcher, which is what makes "is this still my registration?" a
    /// comparison rather than an inference from the method name.
    next_registration: std::sync::atomic::AtomicU64,
}

/// Locally-originated operations owned by one exact promoted session.
///
/// This value has no peer key and no installation key: it is a field of
/// `PeerSessionState`, so replacement, revocation and retirement destroy the
/// only map capable of settling the old session's calls.
pub(crate) struct SessionRpcState {
    /// Leased, so every pending operation this session files is funded by that
    /// session and released with it.
    ///
    /// This was a `HashMap`, whose nodes the session paid for through a residual
    /// term inside [`pending_operation_claim`] — a number this module had to
    /// keep in agreement with a representation it does not own. A `LeasedMap`
    /// charges its own node from its own `size_of`, so the two halves are read
    /// where each is knowable and cannot drift apart.
    pending: crate::resource::LeasedMap<String, PendingOp>,
}

impl SessionRpcState {
    pub(crate) fn new() -> Self {
        Self {
            pending: crate::resource::LeasedMap::new(),
        }
    }
}

/// One pending class, the entry it stores, and the half its caller keeps —
/// declared together, in one place, so a filing cannot fund one shape and store
/// another.
///
/// This exists because the obvious form of the prepared filing does not work.
/// Taking a [`PendingClass`] beside a closure returning an arbitrary
/// [`PendingEntry`] leaves the two free to disagree: a caller can fund a `Single`
/// and store a `Stream`, and the only thing standing between that and a
/// mis-classed entry is the caller getting two arguments to match. A
/// `debug_assert` does not close it either — release builds do not run it, and by
/// the time it could run the entry has already been built under the wrong claim,
/// which is the state it was meant to prevent.
///
/// So the class is not a parameter. It is a constant on the same impl that
/// builds the entry, and the filing reads both from there. There is no argument
/// a caller can pass that makes them disagree, and no runtime check to skip.
///
/// **Sealed**, and that is what makes the previous sentence true rather than
/// merely usual. A `pub(crate)` trait anyone in the crate can implement is not a
/// closed mapping: a third impl elsewhere could pair `CLASS = Single` with a
/// `build` returning `PendingEntry::Stream`, and the filing would do exactly
/// what it was told. The supertrait below lives in a private module, so it
/// cannot be named — and therefore cannot be implemented — outside this one.
/// The two impls that follow are the whole mapping, they are next to each other,
/// and adding a third means editing this file.
mod sealed {
    /// Nameable only inside `rpc`, which is the seal.
    pub trait PendingShapeSeal {}
    impl PendingShapeSeal for super::Unary {}
    impl PendingShapeSeal for super::Streaming {}
}

pub(crate) trait PendingShape: sealed::PendingShapeSeal {
    /// The half the caller keeps — the receiver for a unary call, the shared
    /// inbox for a stream.
    type Caller;
    /// The class this shape's operations are funded as.
    const CLASS: PendingClass;
    /// Build both halves. Called only past every refusal.
    fn build() -> (PendingEntry, Self::Caller);
}

/// A single-response call. The caller keeps the receiving half.
pub(crate) struct Unary;

impl PendingShape for Unary {
    type Caller = oneshot::Receiver<FundedRpcResult>;
    const CLASS: PendingClass = PendingClass::Single;

    fn build() -> (PendingEntry, Self::Caller) {
        let (tx, rx) = oneshot::channel();
        (PendingEntry::Single(tx), rx)
    }
}

/// A streaming call. The caller keeps a clone of the shared inbox.
pub(crate) struct Streaming;

impl PendingShape for Streaming {
    type Caller = Arc<RpcStreamInbox>;
    const CLASS: PendingClass = PendingClass::Stream;

    fn build() -> (PendingEntry, Self::Caller) {
        let inbox = Arc::new(RpcStreamInbox::new());
        (PendingEntry::Stream(Arc::clone(&inbox)), inbox)
    }
}

/// A filing that has passed every refusal and holds everything it was funded
/// for, but has not yet built or stored an effect.
///
/// The intermediate state exists so the two filing paths — one that builds its
/// effect from a shape and one, test-only, that was handed a finished entry —
/// share a single refusal sequence without either being able to reach the
/// other's construction rule. Both leases are held here, so an abandoned
/// `FundedFiling` releases exactly what it reserved.
struct FundedFiling<'id> {
    /// Borrowed, not owned. The filing is funded before the routing string
    /// exists; this points at the drawn plan's own stack bytes (or, in a
    /// control, at whatever the control drew) and is turned into a `String`
    /// only by the commit.
    request_id: &'id str,
    op_id: PendingOpId,
    node: ResourceLease,
}

impl Drop for SessionRpcState {
    fn drop(&mut self) {
        // Every value, through the predicate walk, which allocates nothing —
        // this runs while a session is being torn down and a teardown that has
        // to allocate to report a teardown is one that can fail at the worst
        // moment. Answering `false` throughout is what makes it a visit rather
        // than a search.
        self.pending.any_value(|op| {
            if let PendingEntry::Stream(stream) = &op.effect {
                // Borrowed, not allocated: see `RpcStreamInbox::finish`.
                stream.finish_borrowed(Some("RPC session retired"));
            }
            false
        });
    }
}

/// What one pending operation retains, off the map node.
///
/// The map node is **not** here: [`crate::resource::LeasedMap::entry_claim`]
/// adds it, from a `size_of` only the map can take. Everything else a filed
/// operation keeps alive is, and it is more than the entry in the map, because
/// filing one hands the caller a second half that outlives nothing but is
/// funded by nobody else:
///
/// - **The request id, twice.** The map owns one `String` buffer as its key;
///   [`LocalRequest`] owns another, which [`PendingCancellation`] then holds so
///   a dropped caller can withdraw the exact entry it filed. Two buffers, two
///   allocations, both live for the operation's whole life. Charging one was
///   funding half of what is retained.
/// - **The peer name.** [`PendingCancellation`] copies it, because withdrawal
///   has to name the peer after the borrow that filed the entry is gone.
/// - **The identity record.** [`PendingOpId`] names one shared funded record,
///   and that same record holds the operation's lease.
/// - **The cancellation state itself**, inline in the future or [`RpcStream`]
///   the caller holds.
/// - **The effect.** A stream's inbox record is visible here; a unary
///   oneshot's inner allocation remains dependency-private.
///
/// `peer_bytes` and `class` are parameters rather than constants because the
/// first is not knowable here and the second changes what is retained.
fn pending_operation_claim(
    request_id_bytes: usize,
    peer_bytes: usize,
    class: PendingClass,
) -> Result<crate::resource::ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    use crate::resource::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass};
    let overflow = || ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    };
    // Visible record sizes are charged directly. One broad residual below
    // covers shared-allocation metadata and dependency-private layout.
    let identity = std::mem::size_of::<PendingOpMarker>();
    // The stream record is visible here; the oneshot implementation is not.
    let effect = match class {
        PendingClass::Stream => std::mem::size_of::<RpcStreamInbox>(),
        PendingClass::Single => 0,
    };
    let bytes = std::mem::size_of::<PendingOp>()
        .checked_add(std::mem::size_of::<PendingCancellation>())
        .and_then(|bytes| bytes.checked_add(identity))
        .and_then(|bytes| bytes.checked_add(effect))
        .and_then(|bytes| bytes.checked_add(peer_bytes))
        // Twice: the map's key and the cancellation's copy.
        .and_then(|bytes| request_id_bytes.checked_mul(2)?.checked_add(bytes))
        .ok_or_else(overflow)?;
    // Peer-chosen retained bytes stay explicit. Arc control blocks, String
    // allocation counts and dependency-private effect details are covered by
    // one broad per-operation residual instead of allocator microstate.
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(bytes).map_err(|_| overflow())?,
        ),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

/// Why one locally-originated RPC operation was not filed.
///
/// Three facts, kept apart because a caller acts differently on each. An
/// `Option` here would collapse them into
/// [`RpcError::RequestIdUnavailable`], reporting a peer with no live session
/// and a resource owner that would not fund one more pending entry as "no
/// unused request id available". That sentence is false about both, and it
/// points a reader at a 96-bit draw when the actual remedy is to wait for a
/// session or to raise a grant.
#[derive(Debug)]
pub(crate) enum RpcRegistrationRefusal {
    /// No live promoted session for this peer at the moment of filing. Nothing
    /// was written and nothing is pending.
    SessionNotCurrent,
    /// The one drawn id was already owned. The incumbent is untouched — see
    /// [`SessionRpcState::claim_request_id`].
    RequestIdCollision,
    /// The session's resource owner would not fund the entry.
    ResourceUnavailable(crate::resource::ResourceUnavailable),
    /// The entry is not representable as a claim at all.
    Unrepresentable,
}

/// What running one handler task retains, measured from the request's own
/// fields rather than from a copy of them.
///
/// **Borrowed, and counted rather than encoded.** The caller charges *before* it
/// builds the `RpcCall` and the `String`s inside it, so a request too large for
/// the session to fund is refused without this node having allocated the copy —
/// which is the whole point of admitting work: a peer must not be able to make
/// this side allocate in proportion to what it sent and only then discover it
/// cannot pay for it. `mailbox_measure_serialized` serializes into a writer that
/// only adds up lengths, so the measurement itself allocates nothing either;
/// `serde_json::to_vec` would have built the entire encoding first, which is the
/// same defect one layer down.
///
/// **Why the payload's *retained* figure and not its encoded length.** What the
/// task keeps alive is a `serde_json::Value` tree, not a byte string. A
/// two-character `[]` repeated is two bytes of encoding per element and a whole
/// `Value` plus its node overhead per element in memory, and the ratio is chosen
/// by whoever sent the frame. Charging encoded bytes would let an adversary pick
/// the shape that maximises the gap. The retained figure is core's existing
/// conservative structural bound for exactly this — the same one the mailbox
/// charges. One broad residual covers dependency-private allocation details;
/// the peer-chosen retained size still scales with the payload.
///
/// **The request id is charged twice, because two are retained.** A run that is
/// admitted keeps one inside the `RpcCall` the handler is given, and a second
/// for addressing the terminal frame — the call is moved into the handler and
/// is gone by the time the reply is sent, so the reply path cannot borrow from
/// it. Charging one funded half of what success holds, and the id is peer-chosen
/// like every other field here, so the gap was a peer-selected one.
///
/// `WorkerOrTask` stays its own dimension: the spawned task is one task whatever
/// the payload looks like. One broad residual covers its dependency-private
/// allocation details.
///
/// `RpcCall::streaming` is not a parameter, because it retains nothing: it is a
/// `bool` inside the `size_of::<RpcCall>()` already counted, and taking it here
/// only to ignore it would suggest the class changes the price. It does not —
/// the class decides which terminal frame is sent, not what the run holds.
pub(crate) fn handler_task_claim_for(
    from: &str,
    request_id: &str,
    method: &str,
    payload: &serde_json::Value,
) -> Result<crate::resource::ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    use crate::resource::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass};
    let overflow = || ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    };
    // `request_id` twice because two buffers retain those bytes.
    let measure = strings_measure([from, request_id, request_id, method])
        .and_then(|strings| checked_measure_add(strings, mailbox_measure_serialized(payload)?))
        .map_err(|_| overflow())?;
    let bytes = std::mem::size_of::<RpcCall>()
        .checked_add(measure.0)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(overflow)?;
    // One broad residual covers the task record and dependency internals.
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::WorkerOrTask, 1),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

/// [`handler_task_claim_for`] against a call that already exists.
#[cfg(test)]
pub(crate) fn handler_task_claim(
    call: &RpcCall,
) -> Result<crate::resource::ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    handler_task_claim_for(&call.from, &call.request_id, &call.method, &call.payload)
}

/// Which of the two handler shapes a method is registered under.
///
/// Neither variant carries a retention lease of its own: the registration
/// charge is held by the [`FundedArc`] that owns the handler allocation, so it
/// travels with every invocation clone rather than being released the moment
/// this entry is replaced — and it is released only once the last of those
/// clones has gone and the allocation with it. What this entry still owns is
/// its position in the map, funded by the node lease the map holds.
pub enum HandlerEntry {
    Single { handler: RpcHandler },
    Stream { handler: RpcStreamHandler },
}

impl HandlerEntry {
    /// Which registration installed this entry.
    pub(crate) fn registration(&self) -> RegistrationIdentity {
        match self {
            Self::Single { handler } => handler.registration(),
            Self::Stream { handler } => handler.registration(),
        }
    }
}

fn rpc_inner_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let bytes = u64::try_from(std::mem::size_of::<RpcInner>()).map_err(|_| {
        ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

/// Exact provider planning charge for one locally-attached RPC dispatcher.
///
/// This uses the same internal allocation claim that [`Rpc::attach`] acquires,
/// then applies the provider's own reservation bookkeeping charge. It exists so
/// an external finite fixture can fund the dispatcher without duplicating the
/// representation formula used by production admission.
pub fn rpc_dispatcher_planning_claim() -> Result<ResourceClaim, ResourceUnavailable> {
    let claim = rpc_inner_claim().map_err(|_| ResourceUnavailable::ProviderInvariant {
        dimension: ResourceClass::AccountedMemoryBytes,
    })?;
    crate::resource::FiniteResourceProvider::reservation_planning_charge(claim)
}

/// Exact provider planning charge for one [`Rpc::attach`] application child.
///
/// Attachment first creates a child application scope and then retains the
/// dispatcher in that scope. Keep both terms in this planner so a fixture pays
/// for the same provider bookkeeping that the production constructor performs.
pub fn rpc_dispatcher_attachment_planning_claim() -> Result<ResourceClaim, ResourceUnavailable> {
    rpc_dispatcher_planning_claim()?
        .checked_add(
            crate::application_gateway::ApplicationGateway::rpc_resource_scope_planning_charge(),
        )
        .map_err(|_| ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::OpaqueDependencyResidual,
        })
}

/// The layout of what an `Arc<FundedRpcHandler<C>>` holds, with `C` inferred
/// from the closure itself: the type is anonymous and cannot be written down,
/// but it can be pointed at.
fn funded_handler_layout<C>(_probe: &C) -> Layout {
    Layout::new::<FundedRpcHandler<C>>()
}

/// [`funded_handler_layout`] for the streaming twin.
fn funded_stream_handler_layout<C>(_probe: &C) -> Layout {
    Layout::new::<FundedRpcStreamHandler<C>>()
}

/// What is known about what a handler closure reaches past its own inline
/// storage — which is either something the caller stated, or nothing at all.
///
/// These are not two spellings of the same thing, and the distinction is the
/// whole point of the type. `Declared(ZERO)` is a caller *asserting* that the
/// closure allocates nothing behind it. `Opaque` is an admission that nobody
/// asked, and it is funded as one residual standing for the entire unseen set.
/// Collapsing them would let the honest assertion and the unanswered question
/// price identically, which is exactly the conflation this exists to prevent.
enum CaptureFunding {
    Declared(ResourceClaim),
    Opaque,
}

/// What the installed entry retains, stated in the parts that are knowable in
/// different places.
///
/// **What this function can see, and charges:** the map key's bytes and the
/// funded registration record that carries the identity, lease, and closure
/// inline. The closure's visible inline size is charged directly. One broad
/// residual covers shared-allocation and dependency-private layout rather than
/// turning allocator control-block details into an API invariant.
///
/// **What it cannot see, and therefore does not pretend to contain:**
/// `size_of::<F>()` is the closure struct, not its reach. A handler that
/// captured an `Arc<T>` measures one pointer here however large `T` is; one
/// that captured a `String` measures the 24-byte header and none of its buffer.
/// Only the caller who wrote the closure knows what it holds, so `captures` is
/// where that is said — declared and added (not maxed: the inline storage and
/// the heap behind it are both retained), or [`CaptureFunding::Opaque`] and
/// named as its own residual, distinct from the registration allocation's.
///
/// This charges the key buffer only. The cleanup handle's copy of the name is a
/// *separate owner* with a separate lifetime and is funded by
/// [`cleanup_handle_claim`]; see there for why the two must not share a lease.
fn entry_retention_claim(
    method: &str,
    captures: CaptureFunding,
    handler: Layout,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let registration_allocation = handler.size();
    let bytes = method
        .len()
        .checked_add(registration_allocation)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    // One broad residual covers the funded registration record and its method
    // buffer's allocator-private details.
    let known = ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])?;
    match captures {
        CaptureFunding::Declared(claim) => known.checked_add(claim),
        // One residual for the whole capture set, and it is deliberately not
        // folded into `allocations` above: that count is a statement about
        // allocations this function measured, and this one is a statement that
        // there is something here it did not.
        CaptureFunding::Opaque => known.checked_add(ResourceClaim::try_from_entries([(
            ResourceClass::OpaqueDependencyResidual,
            1,
        )])?),
    }
}

/// What the cleanup handle retains, funded on its own lease.
///
/// The handle owns an `Arc<str>` of the method name so it can name what it must
/// remove after the key has been moved into the map. That buffer outlives the
/// entry it refers to: a successor displaces the entry, the old handler's `Arc`
/// drops with its lease, and a still-held [`OwnedMethodRegistration`] keeps
/// naming a method it no longer owns for as long as its holder keeps it. Funding
/// the handle from the entry's lease would leave that retention uncharged from
/// displacement until handle drop — an interval with no bound, since the holder
/// chooses it. So the handle carries its own lease and releases it in its own
/// `Drop`, and no drop-order relationship between the two owners is assumed.
fn cleanup_handle_claim(method: &str) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    // The name bytes are explicit; one residual covers the shared allocation.
    let bytes =
        u64::try_from(method.len()).map_err(|_| ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

/// An isolated, finitely-granted scope for handlers a test never registers.
///
/// Isolated per call: a control that wants to observe a handler's charge wants
/// it alone in the ledger, not summed with every other test in the binary.
#[cfg(test)]
fn test_handler_scope() -> LocalApplicationResourceScope {
    test_handler_scope_with_provider().2
}

/// The isolated handler scope together with the provider a pressure control
/// must observe and the grant that provider owns.
///
/// Most handler fixtures need only the scope, so [`test_handler_scope`] keeps
/// the narrower answer. A ledger control needs all three values: the provider
/// is the authority for exact live use, and the grant is what lets the control
/// seal every unrelated unit without restating any of this scope's charges.
#[cfg(test)]
fn test_handler_scope_with_provider() -> (
    crate::resource::FiniteResourceProvider,
    ResourceClaim,
    LocalApplicationResourceScope,
) {
    let grant =
        ResourceClaim::try_from_entries(ResourceClass::ALL.map(|dimension| (dimension, 1_000_000)))
            .expect("test grant is representable");
    let finite = crate::resource::FiniteResourceProvider::new(grant);
    let provider = crate::resource::ResourceProviderPort::new(finite.clone())
        .expect("test grant funds process bookkeeping");
    let root = crate::resource::ProcessResourceRoot::isolated();
    root.install_local_application_provider(provider)
        .expect("isolated root accepts its provider");
    let scope = root
        .issue_local_application_scope()
        .expect("test local-application scope");
    (finite, grant, scope)
}

/// What a handler that is never registered costs: the one `Arc` allocation and
/// nothing else.
///
/// Deliberately the *production* formula with the registration-only terms
/// dropped out by their own arithmetic rather than a second formula that could
/// drift from it — an empty method contributes no key bytes and no key
/// allocation, and no map node or cleanup handle exists to fund. `Opaque` is
/// the honest reading of an arbitrary test closure: nobody declared its reach.
#[cfg(test)]
fn unregistered_handler_claim(handler: Layout) -> ResourceClaim {
    entry_retention_claim("", CaptureFunding::Opaque, handler)
        .expect("one handler allocation is representable")
}

#[cfg(test)]
impl FundedRpcHandler {
    /// Wrap `call` as a genuinely funded single-shot handler, unregistered.
    ///
    /// The lease is acquired against the layout of the very callable stored
    /// below, so a control using this measures the same allocation a live
    /// registration would — not a synthetic zero that would hide it.
    pub(crate) fn for_test<F, Fut>(call: F) -> RpcHandler
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, String>> + Send + 'static,
    {
        let call = move |request: RpcCall| -> RpcHandlerFuture { Box::pin(call(request)) };
        let retention = test_handler_scope()
            .acquire(unregistered_handler_claim(funded_handler_layout(&call)))
            .expect("the isolated test grant funds one handler allocation");
        // Unsized here, funded after: the coercion has to happen at this
        // `Arc::new`, which is exactly what `from_admitted_arc` is for.
        let handler: Arc<FundedRpcHandler> = Arc::new(FundedRpcHandler {
            registration: RegistrationIdentity(0),
            call,
        });
        FundedArc::from_admitted_arc(handler, retention)
            .expect("an admitted handler lease may be shared")
    }
}

#[cfg(test)]
impl FundedRpcStreamHandler {
    /// [`FundedRpcHandler::for_test`] for the streaming twin, funded the same
    /// way against the streaming callable's own layout.
    pub(crate) fn for_test<F, Fut>(call: F) -> RpcStreamHandler
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
            + Send
            + 'static,
    {
        let call = move |request: RpcCall| -> RpcStreamHandlerFuture { Box::pin(call(request)) };
        let retention = test_handler_scope()
            .acquire(unregistered_handler_claim(funded_stream_handler_layout(
                &call,
            )))
            .expect("the isolated test grant funds one handler allocation");
        let handler: Arc<FundedRpcStreamHandler> = Arc::new(FundedRpcStreamHandler {
            registration: RegistrationIdentity(0),
            call,
        });
        FundedArc::from_admitted_arc(handler, retention)
            .expect("an admitted handler lease may be shared")
    }
}

/// The response class a pending operation will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingClass {
    Single,
    Stream,
}

/// The effect one pending operation will settle with.
///
/// Deliberately left `pub`, as it has always been. Narrowing it
/// would be public API removal that buys nothing: the authority
/// boundary is the `pending` map, which is private, together with
/// the three bound operations that are the only way to reach it.
/// Naming this type gets a caller no closer to an entry — it cannot
/// look one up, insert one, or settle one — so the visibility is
/// orthogonal to the binding rule and is left where downstream
/// found it.
pub(crate) enum PendingEntry {
    Single(oneshot::Sender<FundedRpcResult>),
    Stream(Arc<RpcStreamInbox>),
}

/// A settled stream's reason, with the funding for it when it owns bytes.
///
/// `None` retention is not "unfunded" — it is "nothing variable to fund": every
/// borrowed reason is a `&'static str` this module wrote.
struct StreamTerminal {
    reason: Option<std::borrow::Cow<'static, str>>,
    _retention: Option<ResourceLease>,
}

/// What a stream's owned terminal reason retains: its buffer, and the one
/// allocation holding it.
fn terminal_claim(bytes: usize) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?,
        ),
        (
            ResourceClass::OpaqueDependencyResidual,
            u64::from(bytes > 0),
        ),
    ])
}

pub(crate) struct RpcStreamInbox {
    mailbox: Mutex<crate::application_gateway::GatewayMailbox<serde_json::Value>>,
    terminal: Mutex<Option<StreamTerminal>>,
    ready: tokio::sync::Notify,
    finished: std::sync::atomic::AtomicBool,
}

impl RpcStreamInbox {
    pub(crate) fn new() -> Self {
        Self {
            mailbox: Mutex::new(crate::application_gateway::GatewayMailbox::new()),
            terminal: Mutex::new(None),
            ready: tokio::sync::Notify::new(),
            finished: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Admit one stream item, or say exactly why not.
    ///
    /// The refusal is typed because the two ways this fails are different facts
    /// with different remedies, and the caller settles a waiting application
    /// with one of them. `Pressure` means the provider would not fund this item:
    /// the stream is well formed and the owner is out of capacity, which is a
    /// sizing answer. `Malformed` means the item could not be represented at all
    /// — it did not encode, or its size is not expressible as a claim — which is
    /// a statement about the frame and not about the resource owner.
    ///
    /// An untyped `bool` would collapse the two, leaving a caller to turn every
    /// `false` into "RPC stream refused by resource owner". That sentence is
    /// true of one arm and false of the other, and the arm it is false about is
    /// the one that means a peer sent something this side could not admit. An
    /// untyped refusal does not merely lose detail here; it reports a resource
    /// owner that refused nothing.
    pub(crate) fn push(
        &self,
        session: &crate::runtime::session_broker::SessionCapability,
        payload: serde_json::Value,
    ) -> Result<(), crate::application_gateway::GatewayRefusal> {
        use crate::application_gateway::{GatewayMailbox, GatewayRefusal};

        // Counted, not encoded: `mailbox_measure_serialized` serializes into a
        // length-counting writer, so a chunk this side may be about to refuse
        // costs no allocation to measure. Encoding first, with
        // `serde_json::to_vec`, would take a peer-sized allocation before
        // admission — the defect admission exists to prevent.
        //
        // All three figures, because for a `Value` they are three different
        // things and the sender picks the ratio between them: the tree's
        // retained size, the queued encoding's size, and the number of separate
        // fragments. One residual could not honestly stand for the last of
        // those.
        let (retained, queued, allocations) =
            mailbox_measure_serialized(&payload).map_err(|_| GatewayRefusal::Malformed)?;
        // Measured, then funded, then retained — the order every admission in
        // this crate takes, so nothing is held that the provider never got to
        // refuse.
        let retention = session
            .reserve_retained(
                GatewayMailbox::<serde_json::Value>::retention_claim(retained, queued, allocations)
                    .map_err(|_| GatewayRefusal::Malformed)?,
            )
            .map_err(GatewayRefusal::Pressure)?;
        let node = session
            .reserve_retained(
                GatewayMailbox::<serde_json::Value>::node_claim()
                    .map_err(|_| GatewayRefusal::Malformed)?,
            )
            .map_err(GatewayRefusal::Pressure)?;
        self.mailbox.lock().accept(payload, retention, node);
        self.ready.notify_one();
        Ok(())
    }

    /// Settle the stream with a reason this module wrote, once.
    ///
    /// Borrowed, so it costs nothing to state and cannot fail. That matters most
    /// at teardown: `SessionRpcState::drop` finishes every stream it still
    /// holds, and allocating once per stream at the moment a session is being
    /// torn down is allocation-heavy cleanup at the worst possible time.
    ///
    /// Every reason reachable this way is a fixed sentence chosen here, so there
    /// is nothing variable to fund and no way for this to refuse.
    pub(crate) fn finish_borrowed(&self, error: Option<&'static str>) {
        self.settle(error.map(std::borrow::Cow::Borrowed), None);
    }

    /// Settle the stream with a reason that came from somewhere else, funding
    /// the bytes before retaining them.
    ///
    /// The distinction from [`Self::finish_borrowed`] is ownership, and it is
    /// the point. A peer's stream-end error text and a refusal message assembled
    /// at runtime are both `String`s whose length this side did not choose, and
    /// storing one here retains it until the local caller happens to call
    /// `recv` — an interval the caller controls and may never end. The frame
    /// that carried the peer's text is released as soon as its dispatch
    /// finishes, and the pending operation's claim prices coordinates rather
    /// than terminal text, so neither of them was ever paying for this.
    ///
    /// So the bytes are charged to the session that delivered them, and the
    /// lease is stored beside the reason and released when the terminal is
    /// taken.
    ///
    /// **A refusal still terminates the stream.** If the owner will not fund the
    /// text, the stream settles with a fixed borrowed sentence instead of
    /// staying open: a caller left awaiting a terminal that never comes is a
    /// worse outcome than a caller told less than the peer said, and dropping
    /// the reason is the one part of this that is safe to drop.
    pub(crate) fn finish_owned(
        &self,
        session: &crate::runtime::session_broker::SessionCapability,
        error: String,
    ) {
        let funded = terminal_claim(error.len())
            .ok()
            .and_then(|claim| session.reserve_retained(claim).ok());
        match funded {
            Some(lease) => self.settle(Some(std::borrow::Cow::Owned(error)), Some(lease)),
            None => self.finish_borrowed(Some(
                "RPC stream terminated; its reason could not be funded",
            )),
        }
    }

    fn settle(
        &self,
        error: Option<std::borrow::Cow<'static, str>>,
        retention: Option<ResourceLease>,
    ) {
        let mut terminal = self.terminal.lock();
        if terminal.is_none() {
            *terminal = Some(StreamTerminal {
                reason: error,
                _retention: retention,
            });
            self.finished
                .store(true, std::sync::atomic::Ordering::Release);
            self.ready.notify_waiters();
        }
    }

    /// Whether this stream has been settled.
    ///
    /// Test-only. Controls that prove a retirement finishes the streams it was
    /// carrying need to see the terminal without consuming it — `recv` would
    /// take it and then be indistinguishable from a stream that simply ended.
    #[cfg(test)]
    pub(crate) fn is_finished(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::Acquire)
    }

    async fn recv_funded(&self) -> Option<Result<RpcStreamChunk, RpcStreamTerminal>> {
        self.recv_funded_with_before_wait(|| {}).await
    }

    async fn recv_funded_with_before_wait(
        &self,
        mut before_wait: impl FnMut(),
    ) -> Option<Result<RpcStreamChunk, RpcStreamTerminal>> {
        loop {
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(delivery) = self.mailbox.lock().pop() {
                // The chunk takes the value across verbatim and holds its
                // funding for it; the two never become separate locals here.
                return Some(Ok(RpcStreamChunk { delivery }));
            }
            if let Some(StreamTerminal { reason, _retention }) = self.terminal.lock().take() {
                // The lease leaves *with* the reason rather than being dropped
                // here. Releasing it at this line — `into_owned()` and the
                // lease's destruction in one expression — would leave every
                // caller past it holding peer-sized text that nothing was paying
                // for, including a forwarder that has yet to measure it for a
                // writer mailbox. Whoever receives this decides when the funding
                // ends, and an application that wants an ordinary `String` says
                // so through `RpcStreamTerminal::into_reason`.
                //
                // A clean end carries no reason and no lease, and the `map`
                // below drops both without constructing anything.
                return reason.map(|reason| Err(RpcStreamTerminal { reason, _retention }));
            }
            if self.finished.load(std::sync::atomic::Ordering::Acquire) {
                return None;
            }
            before_wait();
            notified.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&self) -> Option<RpcStreamChunk> {
        self.mailbox
            .lock()
            .pop()
            .map(|delivery| RpcStreamChunk { delivery })
    }
}

impl PendingEntry {
    /// The class this effect *is*.
    ///
    /// Derived from the variant rather than stored beside it. A
    /// second field would be a second source of truth that could
    /// disagree with the effect it describes, and the disagreement
    /// would read as a class mismatch and silently strand the call.
    fn class(&self) -> PendingClass {
        match self {
            Self::Single(_) => PendingClass::Single,
            Self::Stream(_) => PendingClass::Stream,
        }
    }
}

/// One in-flight local request, owned by the exact session that filed it.
///
/// **The rule.** A request id identifies an operation; it does not authorize
/// settling one. Before ownership moved here, `pending` was a network-global
/// map keyed on the id alone, and every inbound response arm looked an entry up
/// by the id the *frame* carried — so any authenticated peer that learned or
/// guessed another peer's in-flight id could complete that call: resolve
/// someone else's oneshot with a body of its choosing, inject chunks into
/// someone else's stream, or end it early.
///
/// **What binds an operation to its owner.** This value lives in a
/// [`SessionRpcState`], which is a field of one `PeerSessionState`. Reaching it
/// at all requires the capability of that exact session, so an operation filed
/// by one session is unreachable from any other — including a later session
/// with the same peer over a freshly authenticated connector.
///
/// That last case is why the record carries no `expect_from` device id. A
/// device-id comparison would *admit* it: the same canonical device returning
/// on a replacement connector would look like a legitimate completion of a
/// still-pending call. Session ownership does not, and must not — the
/// replacement is a different session, its predecessor's pending operations
/// were resolved when that session was retired, and there is nothing left for
/// it to settle.
///
/// **Identity is not ownership.** `id` names *this* entry among every entry
/// this process ever filed, and `effect` says what class of response it takes.
/// Inbound settling matches the class, because a frame cannot know an identity
/// and must not have to; local withdrawal matches the identity, because a
/// caller abandoning its own send failure must reach exactly one entry and not
/// whichever entry currently holds the id.
struct PendingOp {
    /// Also the operation's funding — the identity's handle carries it; see
    /// [`PendingOpMarker`]. There is no separate lease field here,
    /// deliberately: one that dropped with this entry would defund an effect
    /// already extracted for a send.
    id: PendingOpId,
    effect: PendingEntry,
    next_stream_seq: u64,
}

impl PendingOp {
    /// Whether an inbound frame from `from`, of class `class`, is
    /// the one this operation is waiting for.
    ///
    /// Both halves must hold. A wrong source with the right class,
    /// and a right source with the wrong class, are equally not
    /// this operation's response.
    fn accepts(&self, class: PendingClass) -> bool {
        self.effect.class() == class
    }
}

/// The process-local identity of one filed pending operation.
///
/// A private marker allocation, never a number. Identity *is* the
/// allocation: two of these name the same operation exactly when
/// both are clones of the one minted for it, which [`Self::names`]
/// decides with [`Arc::ptr_eq`]. Every comparison holds a strong
/// reference on both sides for its whole duration, so both
/// allocations are live, and a live allocation's address is never
/// also another live allocation's — a stale owner still holding its
/// clone is precisely what makes its identity unreusable.
///
/// **A process-local ownership token — a local capability, and not a
/// generation.** Holding this private value is what authorizes withdrawing
/// *this* filed operation: the capability is exactly what it is for. What it is
/// not is any of the kinds of authority that would matter beyond this process.
/// It is not network
/// authority: it is never serialized, sent, advertised, or derived from
/// anything a remote supplies, and no inbound path reads it. It is not durable
/// authority: it lives and dies with the allocation, and nothing persists or
/// reconstructs it. It is not route, remote, or session authority: it names one
/// entry in one map and speaks for nothing else. And it is not a generation —
/// there is no counter to advance and nothing ordered to compare.
///
/// The pointee is a private type no other module can name or construct, so the
/// capability cannot be forged, only held or cloned by code that was already
/// given one. Its single job is to let the local caller that filed an entry
/// name *that* entry again later, so a withdrawal reaches one operation instead
/// of every operation that happens to look like it.
///
/// Deliberately **not** [`PartialEq`], and now for a starker reason than
/// before. A derived one compares pointees, and the pointee is
/// [`PendingOpMarker`] — which is empty. Every marker would compare equal to
/// every other, so *every* identity would name every operation and a withdrawal
/// would remove whichever entry it reached first. Comparing what an identity
/// contains was already the wrong question when the pointee held the lease; with
/// an empty marker it is not merely wrong but uniformly true.
///
/// [`Self::names`] asks the right question instead — `FundedArc::ptr_eq`, which
/// is about *which allocation this is* and cannot be satisfied by a coincidence
/// of contents.
#[derive(Clone)]
pub(crate) struct PendingOpId(crate::resource::FundedArc<PendingOpMarker>);

/// The allocation [`PendingOpId`] is identity over.
///
/// Empty, and the emptiness is load-bearing. The operation's lease must not
/// live *in here*. A pointee is destroyed on the final *strong* drop, while the
/// allocation it sits in survives for as long as any weak handle does, so a
/// lease inside the pointee would go back to the provider while the storage it
/// was paying for was still there.
///
/// The funding therefore lives in the [`FundedArc`] holding this marker, which
/// releases the claim when the last funded strong handle is gone — and the
/// map's entry, the caller's [`LocalRequest`], and an effect extracted for a
/// send in flight all hold clones, so removing the map entry does not release
/// the funding while an extracted sender is still on its way to being used. The
/// identity still has to be an allocation — that is what makes `ptr_eq` a fact
/// rather than a comparison of contents — and it is still exactly one
/// allocation: a shared lease lives in the handle's own inline fields and adds
/// no second record.
///
/// [`FundedArc`]: crate::resource::FundedArc
#[derive(Debug)]
pub(crate) struct PendingOpMarker;

impl PendingOpId {
    /// Mint a fresh identity around the lease that funds its operation.
    fn funded(lease: crate::resource::ResourceLease) -> Self {
        Self(
            crate::resource::FundedArc::new(PendingOpMarker, lease)
                // Unreachable rather than unlikely: the only refusal is a
                // speculative lease, and this one came from
                // `SessionCapability::reserve_retained`, which reaches
                // `reserve_session` — that names `Admitted` itself and takes no
                // authority from its caller. There is no spelling of a
                // speculative operation lease, so minting stays infallible.
                .expect("an operation lease is admitted, never speculative"),
        )
    }

    /// Whether `other` is this same identity — the same allocation,
    /// not merely a value that compares equal to it.
    fn names(&self, other: &Self) -> bool {
        crate::resource::FundedArc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for PendingOpId {
    /// Names the type and nothing else.
    ///
    /// There is nothing inside worth printing — the pointee is a marker, and
    /// the funding is deliberately unreadable — and an address would invite a
    /// reader to treat one as comparable by what it prints rather than by
    /// [`Self::names`].
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PendingOpId")
    }
}

/// Something taken out of the pending map, with the funding that outlives the
/// entry it came from.
///
/// Extraction and use are two steps: the map's guard is released, and only then
/// does the caller act on what it extracted. Between them the entry no longer
/// exists, so whatever paid for the effect's allocation must be held by the
/// value in flight rather than by the map. That is what the identity clone
/// here is for; it is never read.
///
/// **The two halves do not come apart.** A `(T, PendingOpId)` pair would leave
/// the funding outliving the effect only by convention — a caller that bound
/// the second name rather than discarding it. Here the stream callers read
/// through [`Self::value`], and the one caller that has to consume its effect
/// goes through [`Extracted::answer`], which owns the whole struct across the
/// send. `value` is declared before `_funding` so the drop order is structural
/// too.
pub(crate) struct Extracted<T> {
    value: T,
    _funding: PendingOpId,
}

impl<T> Extracted<T> {
    /// The extracted effect, borrowed. The funding outlives the borrow.
    ///
    /// This is the whole surface for the stream cases: finishing an inbox takes
    /// `&self`, so those callers never need the value moved out and cannot
    /// separate it from what pays for it.
    pub(crate) fn value(&self) -> &T {
        &self.value
    }
}

impl Extracted<oneshot::Sender<FundedRpcResult>> {
    /// Answer the local caller, then release the operation's funding.
    ///
    /// The one extracted effect that genuinely cannot work from a borrow:
    /// `oneshot::Sender::send` consumes the sender. So instead of handing the
    /// pair back and asking the caller to keep the second half alive by
    /// convention, the send happens in here, between the move and the drop.
    ///
    /// Deliberately not a callback and deliberately not generic. There is no
    /// `FnOnce` to smuggle the sender out through, no type parameter to
    /// instantiate as the sender itself, and no return value — the only thing
    /// that crosses this boundary is a `FundedRpcResult` the caller already
    /// owns. Nothing the caller can write makes the sender outlive
    /// `_funding`, which is the property the pair could only ask for in prose.
    ///
    /// The `Err` from `send` is a returned-unsent `FundedRpcResult`, which
    /// happens when the local caller stopped waiting. Dropping it here releases
    /// the body's retention, which is the correct answer to nobody wanting it.
    pub(crate) fn answer(self, result: FundedRpcResult) {
        let Self { value, _funding } = self;
        let _ = value.send(result);
        drop(_funding);
    }
}

/// One filed pending operation, as handed back to the local caller
/// that filed it.
///
/// Carries the two names that job needs and keeps them apart: the
/// `request_id` is the routing key that goes on the wire, the
/// `op_id` is the identity that never does. The caller sends under
/// the first and withdraws under the second.
#[derive(Debug)]
pub(crate) struct LocalRequest {
    pub(crate) request_id: String,
    op_id: PendingOpId,
}

struct PendingCancellation {
    network: Weak<NetworkState>,
    peer: String,
    filed: Option<LocalRequest>,
}

impl PendingCancellation {
    fn new(network: &Arc<NetworkState>, peer: &str, filed: LocalRequest) -> Self {
        Self {
            network: Arc::downgrade(network),
            peer: peer.to_string(),
            filed: Some(filed),
        }
    }

    /// A cancellation with nothing filed to withdraw.
    ///
    /// For [`TransportLabStreamInbox::stream`] and nothing else. A control that
    /// wants a real [`RpcStream`] does not have — and must not fabricate — a
    /// pending entry on some network's gateway: it is testing what the *holder*
    /// of a stream does, and the withdrawal this type performs is the gateway's
    /// own behaviour, covered where the gateway is. Both halves are inert rather
    /// than fake: the `Weak` never upgrades and there is nothing filed, so `drop`
    /// takes its first early return and reaches no gateway at all.
    ///
    /// `request_id` is never called on one. It is read only at the three call
    /// sites, on the cancellation each has just built from its own filed
    /// request.
    #[cfg(feature = "transport-lab")]
    fn unarmed() -> Self {
        Self {
            network: Weak::new(),
            peer: String::new(),
            filed: None,
        }
    }

    fn request_id(&self) -> &str {
        &self.filed.as_ref().expect("armed cancellation").request_id
    }
}

impl Drop for PendingCancellation {
    fn drop(&mut self) {
        let (Some(network), Some(filed)) = (self.network.upgrade(), self.filed.as_ref()) else {
            return;
        };
        network
            .application_gateway
            .abandon_rpc_request(&network, &self.peer, filed);
    }
}

/// A session-owned streaming response. Dropping the receiver cancels the exact
/// pending operation immediately; a recycled request coordinate cannot match
/// its private allocation identity.
pub struct RpcStream {
    inbox: Arc<RpcStreamInbox>,
    _cancellation: PendingCancellation,
}

/// One settled single-shot result, with the funding for whatever it carries.
///
/// **Internal, and deliberately so.** [`RpcResponse`] is public and stays
/// exactly as it is: no new field, no lost `Clone`, no broken struct literal.
/// The lease only has to span the part of the journey core owns — from the
/// inbound frame that produced the body to the moment [`Rpc::call`] hands it
/// out — because at that boundary the value becomes application-owned, which is
/// the same line [`RpcStreamChunk::value`] draws for a chunk.
///
/// What it closes: a response body is a `serde_json::Value` tree and an error is
/// a `String`, both sized by the peer. Sent through the oneshot on their own,
/// they would travel after the decoded frame that funded them had already been
/// released — retained by nobody between the send and the caller's `await`, an
/// interval the caller controls.
pub(crate) struct FundedRpcResult {
    result: Result<RpcResponse, String>,
    _retention: ResourceLease,
}

impl FundedRpcResult {
    pub(crate) fn new(result: Result<RpcResponse, String>, retention: ResourceLease) -> Self {
        Self {
            result,
            _retention: retention,
        }
    }

    /// Hand the result to the application and release its funding.
    ///
    /// The release is the point of the boundary: past here the value is the
    /// embedder's, held for as long as the embedder likes, and core is no longer
    /// the party that should be charged for it.
    pub(crate) fn into_result(self) -> Result<RpcResponse, String> {
        self.result
    }

    /// The response body, borrowed. `None` when the peer answered with an error.
    pub(crate) fn body(&self) -> Option<&serde_json::Value> {
        self.result.as_ref().ok().map(|response| &response.body)
    }

    /// The peer's error text, borrowed. `None` when the peer answered with a
    /// body.
    pub(crate) fn error(&self) -> Option<&str> {
        self.result.as_ref().err().map(String::as_str)
    }
}

/// One settled unary reply, still funded, for a caller that will re-encode it.
///
/// Returned by [`Rpc::call_funded`]. The peer-sized body or error text stays
/// charged to core for as long as this value lives, which is what lets a
/// forwarder serialize and write the reply without a window in which the bytes
/// are live and the claim is not.
///
/// **Borrow-only, and that is the whole design.** There is no `into_inner`, no
/// `into_result`, and no accessor splitting the value from its funding: each of
/// those hands the reply out and drops the retention in the same expression,
/// which is the defect this type exists to remove. A caller that genuinely
/// wants ownership of the reply wants [`Rpc::call`], which draws that boundary
/// deliberately and says so.
#[doc(hidden)]
pub struct FundedRpcCallResult {
    funded: FundedRpcResult,
}

impl FundedRpcCallResult {
    /// Build one the way production does, for a fixture that has no live peer.
    ///
    /// **Funded, not fabricated.** There is deliberately no constructor that
    /// simply wraps a value: one would hand a fixture an owner whose whole
    /// meaning is "these bytes are paid for" without anything having been paid,
    /// and a daemon control binding against it would prove its forwarding path
    /// worked in a world where retention is free. So this measures the reply
    /// with [`single_response_claim`] — the same function the settling frame
    /// uses, not a fixture copy of it — acquires a real lease from a real
    /// scope, and refuses under real pressure. A control that runs out of grant
    /// here is being told something true.
    ///
    /// Feature-gated rather than `#[cfg(test)]` because the caller is another
    /// crate's controls. That does make it a buildable surface, and it is a
    /// safe one: it cannot be used to separate a value from its funding — it is
    /// the constructor *of* the funded owner, and everything it returns is
    /// still borrow-only.
    #[cfg(feature = "transport-lab")]
    pub fn transport_lab_funded(
        scope: &crate::resource::LocalApplicationResourceScope,
        result: Result<RpcResponse, String>,
    ) -> Result<Self, crate::resource::ResourceUnavailable> {
        let claim = single_response_claim(
            result.as_ref().ok().map(|response| &response.body),
            result.as_ref().err().map(String::as_str),
        )
        // The reply is already in memory, so its measurement is representable
        // by construction: an unrepresentable one would have to be larger than
        // the address space it is sitting in.
        .expect("a reply that exists has a representable claim");
        let retention = scope.acquire(claim)?;
        Ok(Self {
            funded: FundedRpcResult::new(result, retention),
        })
    }

    /// The response body, borrowed. `None` when the peer answered with an error.
    pub fn body(&self) -> Option<&serde_json::Value> {
        self.funded.body()
    }

    /// The peer's error text, borrowed. `None` when the peer answered with a
    /// body.
    pub fn error(&self) -> Option<&str> {
        self.funded.error()
    }
}

/// What one settled single-shot result retains: the response body's tree or
/// error text, plus one broad residual for dependency-private allocation
/// details.
///
/// Measured from the inbound frame's own fields, before anything is copied out
/// of them, on the same contract as [`handler_task_claim_for`].
pub(crate) fn single_response_claim(
    body: Option<&serde_json::Value>,
    error: Option<&str>,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let overflow = || ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    };
    let measure = strings_measure(error)
        .and_then(|text| match body {
            Some(body) => checked_measure_add(text, mailbox_measure_serialized(body)?),
            // A response with no body retains no tree. `Value::Null` is not the
            // same thing and is measured like any other value.
            None => Ok(text),
        })
        .map_err(|_| overflow())?;
    // The payload the oneshot carries is the whole `FundedRpcResult` — the
    // `Result` discriminant, the response or the error, and the lease travelling
    // with them — not just the `RpcResponse` inside it.
    let bytes = std::mem::size_of::<FundedRpcResult>()
        .checked_add(measure.0)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(overflow)?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

/// One popped stream value with its off-node retention lease. The queue node
/// is released at pop; the value remains funded until this wrapper is dropped.
pub struct RpcStreamChunk {
    /// The delivery, whole. Not the value with its lease beside it: those are
    /// two things a holder could drop in either order, and the order that
    /// releases the funding first is the one that tells the provider these
    /// bytes are free while a reader still has them.
    delivery: crate::application_gateway::GatewayDelivery<serde_json::Value>,
}

impl std::fmt::Debug for RpcStreamChunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value().fmt(f)
    }
}

impl PartialEq<serde_json::Value> for RpcStreamChunk {
    fn eq(&self, other: &serde_json::Value) -> bool {
        self.value() == other
    }
}

impl RpcStreamChunk {
    /// The chunk's payload, borrowed.
    ///
    /// Borrowed rather than taken. An `into_value(self) -> Value` handed the
    /// payload out and dropped the delivery — and with it the funding — at the
    /// same instant, so every caller of it held live JSON the provider had been
    /// told was released. A reader serializes or inspects through this borrow
    /// while the chunk is alive, and the funding goes back when the chunk does.
    pub fn value(&self) -> &serde_json::Value {
        self.delivery.value()
    }

    /// The claim already funding this chunk's payload.
    ///
    /// For a forwarder that queues this chunk onward. The payload graph is
    /// *moved* into the outer frame, not copied, so an outer mailbox that
    /// measures the whole frame and charges all of it bills the process grant
    /// twice for one live tree — once here, where the claim is still held, and
    /// again for bytes no second allocation exists for. Netting this out with
    /// [`ResourceClaim::checked_sub`] leaves the outer owner paying for what is
    /// genuinely new: its own routing state, its queue node, its scheduled work.
    ///
    /// Recomputed rather than stored, and that is what makes it trustworthy: it
    /// is the same measurement `RpcStreamInbox::push` funded this payload with,
    /// derived from the same value by the same function. A stored copy would be
    /// a second source of truth that could disagree with the reservation it
    /// claims to describe, which is the drift this crate keeps removing.
    ///
    /// **Bare, and deliberately.** This is the payload's own claim, not what the
    /// provider's ledger moved when it took the reservation — that additionally
    /// carries a per-reservation bookkeeping residual which exists because a
    /// reservation exists, not because the payload does. A subtracting caller
    /// wants the bare form: its outer claim contains this payload, so that is
    /// the double charge to remove, and it does not contain a record of a
    /// reservation it never took.
    pub fn funded_claim(&self) -> Result<ResourceClaim, ResourceMailboxItemError> {
        let (retained, queued, allocations) = mailbox_measure_serialized(self.value())?;
        type ChunkMailbox = crate::application_gateway::GatewayMailbox<serde_json::Value>;
        Ok(ChunkMailbox::retention_claim(
            retained,
            queued,
            allocations,
        )?)
    }
}

/// A settled stream's reason, still funded.
///
/// The streaming twin of [`FundedRpcResult`], and it exists for the same reason
/// on a longer path. A stream-end error is text the *peer* chose the length of.
/// [`RpcStreamInbox`] funds it on arrival and holds it. Taking the terminal must
/// not convert it to an owned `String` and drop the lease in the same
/// expression: from that instant the text would be live in a forwarding task
/// with no owner, and the writer mailbox that eventually pays for it does not
/// measure until after the allocation already exists.
///
/// This keeps the two together. The reason is readable by borrow for as long as
/// core or a forwarder owns the value, so it can be measured, admitted and
/// encoded while still funded, and the claim goes back when this wrapper does.
///
/// **Converting out is allowed, and is the public boundary.** An application
/// receiving an error wants a `String`, not a resource wrapper it must hold
/// forever; [`Self::into_reason`] is that conversion and [`RpcStream::recv`]
/// performs it. The conversion belongs where the value becomes the
/// application's, not several owners earlier — a forwarder is not at that
/// boundary until it has forwarded.
pub struct RpcStreamTerminal {
    reason: std::borrow::Cow<'static, str>,
    /// Held, never read. `None` is not "unfunded" — it is "nothing variable to
    /// fund", which is every reason this module wrote as a `&'static str`.
    _retention: Option<ResourceLease>,
}

impl std::fmt::Debug for RpcStreamTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RpcStreamTerminal")
            .field(&self.reason())
            .finish()
    }
}

impl std::fmt::Display for RpcStreamTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl RpcStreamTerminal {
    /// The reason, borrowed. The funding outlives the borrow.
    ///
    /// The whole read surface. A forwarder measures and encodes through here
    /// while this value is alive, which is exactly the interval the claim
    /// covers.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Take the reason as an ordinary application-owned `String`, releasing the
    /// funding.
    ///
    /// The declared end of MyOwnMesh's ownership: past here the text is the
    /// caller's, held for as long as the caller likes, and core is no longer the
    /// party that should be charged for it. Same line [`FundedRpcResult`] draws
    /// for a unary result.
    ///
    /// The order inside is the usual one and is not incidental. The `String`
    /// exists before the lease is dropped, so there is no instant at which the
    /// provider has been told these bytes are free while they are still being
    /// produced. For the owned case that is a move rather than a copy; the
    /// borrowed case allocates, and carries no lease to release because a
    /// `&'static str` this module wrote was never charged.
    pub fn into_reason(self) -> String {
        let Self { reason, _retention } = self;
        let owned = reason.into_owned();
        drop(_retention);
        owned
    }
}

/// A real stream inbox, for another crate's controls.
///
/// **There is deliberately no constructor for [`RpcStreamTerminal`].** One would
/// hand a fixture a value whose entire meaning is "this text is paid for and
/// still is" without it having travelled the path that funds it, and a daemon
/// control forwarding it would prove its forwarding worked on a terminal core
/// never produced. What a control needs is not a terminal but a *stream that
/// ends*, so that is what this is: a genuine [`RpcStreamInbox`], settled by the
/// production `settle` under the production [`terminal_claim`] measurement, and
/// drained by the production `recv_funded`. The value that comes out is the
/// value production makes, funded by a lease a real provider really issued and
/// really refuses when it cannot.
///
/// The one thing that differs from `RpcStreamInbox::finish_owned` is where the
/// lease comes from — a caller-supplied application scope rather than a
/// `SessionCapability`, which another crate cannot hold — and that difference is
/// visible in the signature rather than hidden. The claim, the settle and the
/// take are all production's.
#[cfg(feature = "transport-lab")]
#[doc(hidden)]
pub struct TransportLabStreamInbox {
    inbox: Arc<RpcStreamInbox>,
}

#[cfg(feature = "transport-lab")]
impl TransportLabStreamInbox {
    pub fn new() -> Self {
        Self {
            inbox: Arc::new(RpcStreamInbox::new()),
        }
    }

    /// The receiving half, as production's own [`RpcStream`], over this exact
    /// inbox.
    ///
    /// **Why this exists.** A stream's *holder* is another crate: the daemon
    /// files one, answers its caller, and only then starts forwarding it. What
    /// that crate has to be able to prove is what happens to the stream when the
    /// answer never arrives — and it cannot, because `RpcStream`'s fields are
    /// private and every production constructor needs a network, a peer and a
    /// filed pending entry, none of which a control about the *holder* has any
    /// business arranging.
    ///
    /// What is shared is the real thing: the same `Arc<RpcStreamInbox>` this
    /// fixture pushes into and settles, drained by the production `recv_funded`.
    /// The one part that is not production's is the cancellation, which is
    /// [`PendingCancellation::unarmed`] — inert, because the withdrawal it would
    /// perform belongs to the gateway that filed the entry and is tested there.
    /// Nothing here relaxes a rule: a control still cannot mint a terminal, and
    /// this still cannot reach a network.
    pub fn stream(&self) -> RpcStream {
        RpcStream {
            inbox: Arc::clone(&self.inbox),
            _cancellation: PendingCancellation::unarmed(),
        }
    }

    /// Settle the stream with a clean end and no peer-supplied reason.
    ///
    /// This is the transport-lab counterpart of the production stream's
    /// natural `recv_funded` exhaustion path. It deliberately calls the same
    /// inbox settlement primitive as production; unlike [`Self::finish_owned`]
    /// it has no variable terminal text and therefore acquires no lease.
    pub fn finish_clean(&self) {
        self.inbox.settle(None, None);
    }

    /// Settle the stream with peer-supplied text, funded before it is retained.
    ///
    /// Refuses rather than degrading. Production's `finish_owned` falls back to
    /// a fixed borrowed sentence when the owner will not fund the text, because
    /// a caller left awaiting a terminal that never comes is worse than a caller
    /// told less than the peer said. That fallback is right there and wrong
    /// here: a control that silently received a borrowed reason would observe no
    /// lease at all and pass while proving nothing. So a fixture too small to
    /// fund its own terminal is told so.
    pub fn finish_owned(
        &self,
        scope: &crate::resource::LocalApplicationResourceScope,
        error: String,
    ) -> Result<(), crate::resource::ResourceUnavailable> {
        let claim =
            terminal_claim(error.len()).expect("text that exists has a representable claim");
        let retention = scope.acquire(claim)?;
        self.inbox
            .settle(Some(std::borrow::Cow::Owned(error)), Some(retention));
        Ok(())
    }

    /// Admit one chunk through the production admission path.
    pub fn push(
        &self,
        scope: &crate::resource::LocalApplicationResourceScope,
        payload: serde_json::Value,
    ) -> Result<(), crate::resource::ResourceUnavailable> {
        type ChunkMailbox = crate::application_gateway::GatewayMailbox<serde_json::Value>;
        let (retained, queued, allocations) =
            mailbox_measure_serialized(&payload).expect("a payload that exists is measurable");
        let retention = scope.acquire(
            ChunkMailbox::retention_claim(retained, queued, allocations)
                .expect("a measured payload has a representable claim"),
        )?;
        let node = scope
            .acquire(ChunkMailbox::node_claim().expect("a queue node has a representable claim"))?;
        self.inbox.mailbox.lock().accept(payload, retention, node);
        self.inbox.ready.notify_one();
        Ok(())
    }

    /// Take through the production path, funded.
    pub async fn recv_funded(&self) -> Option<Result<RpcStreamChunk, RpcStreamTerminal>> {
        self.inbox.recv_funded().await
    }
}

#[cfg(feature = "transport-lab")]
impl Default for TransportLabStreamInbox {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcStream {
    /// The ordinary receive. The terminal arrives as an application-owned
    /// `String`, its funding released at the boundary where the value becomes
    /// the application's.
    pub async fn recv(&mut self) -> Option<Result<RpcStreamChunk, String>> {
        self.recv_funded()
            .await
            .map(|item| item.map_err(RpcStreamTerminal::into_reason))
    }

    /// The receive for a caller that is not the final owner.
    ///
    /// A forwarder — the daemon writing `RpcCallStreamEnd` to a client socket —
    /// still has to measure, admit and encode the peer's text after receiving
    /// it. Through [`Self::recv`] that text arrives already converted and
    /// already released, so every one of those steps happens on an allocation
    /// nothing is paying for. Here it arrives funded, and stays funded until the
    /// forwarder drops it, which it does after the write-side owner exists.
    pub async fn recv_funded(&mut self) -> Option<Result<RpcStreamChunk, RpcStreamTerminal>> {
        self.inbox.recv_funded().await
    }
}

/// The pending-operation surface.
///
/// These are the only ways to reach the `pending` map, and they take a request
/// id and a class — nothing more. They take no authenticated device to compare
/// against, and need none.
///
/// **What a device comparison would defend is structural here.** This map is a
/// field of one `PeerSessionState`, reached only through the capability of that
/// exact promoted session, so an operation filed by one session is not merely
/// refused to another — it is unreachable from it. There is no argument a
/// caller could pass that would widen the set of entries these methods can see,
/// which is a stronger statement than any comparison, and one that cannot be
/// got wrong by a caller passing the wrong device. A network-global map would
/// make a request id an authority on its own: any authenticated peer that
/// learned another's in-flight id could settle that peer's call.
///
/// **Guard discipline.** The containing session record gives each operation
/// exclusive access to the leased map. It decides and extracts there, then
/// returns what it extracted to its caller. None of them sends, awaits, or
/// invokes a callback while a guard is live — the engine performs the send after
/// the operation has returned and the guard is gone.
///
/// **Non-destructive refusal.** A wrong class is not a settle attempt that
/// fails; it is not a settle at all. The predicate and the removal are the same
/// exclusive step, so a refused frame performs zero action, zero removal and
/// zero mutation, and the operation under that id is left exactly as it was.
impl SessionRpcState {
    /// Claim `request_id` for one locally-originated operation, constructing its
    /// effect **only after** the session has funded it.
    ///
    /// `Ok((filed, caller))` means the id was unused and is now owned by an
    /// entry under a freshly minted identity, which comes back with the caller's
    /// own half of what was built. Every `Err` means nothing happened: no entry
    /// was displaced, no capacity was taken, and no effect exists — which is why
    /// the refusal carries a reason and not a returned effect.
    ///
    /// The occupancy test and the insert are separated only by this function's
    /// own steps, all of them under one exclusive borrow of `self`, so there is
    /// no window in which the id reads as free and is then taken by a concurrent
    /// call before this one writes. The identity is minted around the lease, so
    /// an entry is never observable without one.
    ///
    /// The order is the whole point. A caller that built its effect first —
    /// `Rpc::call` its `oneshot`, `Rpc::call_stream` its `Arc<RpcStreamInbox>`
    /// — and handed the finished value in would leave the claim naming
    /// allocations that already existed, so a refusal could not refuse them:
    /// the peer-sized work would be done before the owner was asked, and "no
    /// capacity" would arrive after the capacity had been spent. Acquiring
    /// first and building from the shape afterwards makes the refusal real. On
    /// any arm below, nothing was built.
    ///
    /// The class is not a parameter: it is [`PendingShape::CLASS`], read off the
    /// same impl that builds the entry, so the claim this filing is funded under
    /// and the entry it stores cannot name different operations. See
    /// [`PendingShape`] for why the parameter form does not work.
    ///
    /// `S::Caller` is the caller's own half of whatever was built: the
    /// `Receiver` for a unary call, the `Arc<RpcStreamInbox>` for a stream. It
    /// travels out with the filing so no out-parameter is needed and no second
    /// lookup can disagree about which effect was filed.
    fn claim_request_id_prepared<S: PendingShape>(
        &mut self,
        request_id: &str,
        peer: &str,
        session: &crate::runtime::session_broker::SessionCapability,
    ) -> Result<(LocalRequest, S::Caller), RpcRegistrationRefusal> {
        let funded = self.reserve_filing(request_id, peer, session, S::CLASS)?;
        // Past every refusal. The effect is built here and nowhere earlier.
        let (effect, caller) = S::build();
        Ok((self.commit_filing(funded, effect), caller))
    }

    /// [`Self::claim_request_id_prepared`] for a caller that already holds its
    /// effect and only needs it filed.
    ///
    /// Controls only. Production never has an effect before the funding — that
    /// is the whole property the prepared form exists to enforce — so this is
    /// gated to the controls that drive the filing itself and have no caller
    /// half to receive. It takes the class *from the effect it was handed*,
    /// which is the same "one source" rule the shape enforces for production:
    /// here there really is an entry to ask, so asking it is what makes a
    /// mismatch unrepresentable on this path too.
    #[cfg(test)]
    fn claim_request_id(
        &mut self,
        request_id: &str,
        peer: &str,
        session: &crate::runtime::session_broker::SessionCapability,
        effect: PendingEntry,
    ) -> Result<LocalRequest, RpcRegistrationRefusal> {
        let funded = self.reserve_filing(request_id, peer, session, effect.class())?;
        Ok(self.commit_filing(funded, effect))
    }

    /// Everything a filing must have before it may build or store anything:
    /// the id is free, the operation is funded, and the map node is funded.
    ///
    /// Split from the commit so that the two callers above share one refusal
    /// path. Nothing here constructs an effect, which is the property that makes
    /// every early return below an honest refusal — on each of them the caller
    /// has allocated nothing and there is nothing to hand back.
    fn reserve_filing<'id>(
        &mut self,
        request_id: &'id str,
        peer: &str,
        session: &crate::runtime::session_broker::SessionCapability,
        class: PendingClass,
    ) -> Result<FundedFiling<'id>, RpcRegistrationRefusal> {
        // Occupancy first, and nothing is built on this arm. Displacing the
        // owner would strand its caller on a oneshot nothing can resolve. This
        // is a plain read rather than an entry API because `&mut self` is the
        // exclusion: nothing else can touch this map between the question and
        // the insert, so there is no window to close.
        //
        // The refusal no longer hands an effect back, because there is no
        // longer an effect to hand back — a colliding call destroys nothing
        // because it created nothing.
        if self.pending.contains_key(request_id) {
            return Err(RpcRegistrationRefusal::RequestIdCollision);
        }
        // Measured, then funded, then built, then filed. Two reservations
        // because two things are retained and each is released by its own
        // owner: the operation's, held by the identity every half of it clones,
        // and the node's, held by the map entry.
        let Ok(claim) = pending_operation_claim(request_id.len(), peer.len(), class) else {
            return Err(RpcRegistrationRefusal::Unrepresentable);
        };
        let lease = match session.reserve_retained(claim) {
            Ok(lease) => lease,
            Err(e) => return Err(RpcRegistrationRefusal::ResourceUnavailable(e)),
        };
        // The identity is minted around the lease, so no state exists between
        // "funded" and "named" in which one could be dropped without the other.
        let op_id = PendingOpId::funded(lease);
        let Ok(node_claim) = crate::resource::LeasedMap::<String, PendingOp>::entry_claim() else {
            return Err(RpcRegistrationRefusal::Unrepresentable);
        };
        let node = match session.reserve_retained(node_claim) {
            Ok(node) => node,
            Err(e) => return Err(RpcRegistrationRefusal::ResourceUnavailable(e)),
        };
        Ok(FundedFiling {
            request_id,
            op_id,
            node,
        })
    }

    /// Store a funded filing's entry. Infallible by construction.
    fn commit_filing(&mut self, funded: FundedFiling<'_>, effect: PendingEntry) -> LocalRequest {
        let FundedFiling {
            request_id,
            op_id,
            node,
        } = funded;
        // The deferred allocation, and the only place the routing string is
        // built. Everything that could refuse this filing has already run and
        // declined to, so no path reaches here having allocated and then failed.
        let request_id = request_id.to_owned();
        self.pending
            .insert(
                request_id.clone(),
                PendingOp {
                    id: op_id.clone(),
                    effect,
                    next_stream_seq: 1,
                },
                node,
            )
            // The map refuses a key it already holds, and the occupancy test in
            // `reserve_filing` ran under the *caller's* single exclusive borrow
            // of `self`, which spans that call and this one — nothing can have
            // inserted between them, because nothing else can hold this map at
            // all. So this arm is a violation of the map's own contract rather
            // than a state a caller can reach, and it is deliberately not given
            // a refusal variant: by here the effect has been built and the
            // caller's half handed out, so there is no refusal that could
            // truthfully say nothing happened.
            .expect("the id was vacant under the caller's same exclusive borrow");
        LocalRequest { request_id, op_id }
    }

    /// Register one locally-originated pending operation under a
    /// freshly drawn id, bound to the device it was addressed to and
    /// named by a fresh identity.
    ///
    /// **One draw, one claim, no retry.** A claim that collides
    /// answers `None`, which the caller reports as
    /// [`RpcError::RequestIdUnavailable`] rather than displacing
    /// whoever holds the id. That refusal is a real path, not a
    /// decorative one: a 96-bit draw makes a collision negligibly
    /// unlikely, never impossible, so it is handled explicitly here
    /// rather than assumed away. The bounded redraw it replaces
    /// bought nothing the single claim does not already give —
    /// "never displace" is total either way — while reading as a
    /// policy that will eventually secure an id, when the honest
    /// answer is that one collision fails the call.
    /// The refusal is typed, and on every arm of it nothing was built: there is
    /// no effect to drop and no channel to resolve with a bare receive error,
    /// which said nothing. The returned reason is what the caller reports
    /// instead, and it is returned rather than logged because only the caller
    /// knows whether "no session yet" is worth retrying and "out of capacity" is
    /// not.
    pub(crate) fn register_local_request_prepared<S: PendingShape>(
        &mut self,
        peer: &str,
        session: &crate::runtime::session_broker::SessionCapability,
    ) -> Result<(LocalRequest, S::Caller), RpcRegistrationRefusal> {
        // Drawn on the stack, admitted from a borrow. The plan lives for this
        // call and the `String` is built only if the filing is funded, so a
        // refusal here leaves the heap exactly as it found it.
        let plan = RequestIdPlan::draw();
        self.claim_request_id_prepared::<S>(plan.as_str(), peer, session)
    }

    /// [`Self::register_local_request_prepared`] for a control that already
    /// holds its effect.
    ///
    /// Test-only for the same reason [`Self::claim_request_id`] is: production
    /// has no effect to hand in before the funding, and a production caller
    /// that did would be the defect the prepared form removes.
    #[cfg(test)]
    pub(crate) fn register_local_request(
        &mut self,
        peer: &str,
        session: &crate::runtime::session_broker::SessionCapability,
        effect: PendingEntry,
    ) -> Result<LocalRequest, RpcRegistrationRefusal> {
        let plan = RequestIdPlan::draw();
        self.claim_request_id(plan.as_str(), peer, session, effect)
    }

    /// Drop a local operation the caller is abandoning, but only if
    /// the entry under that key is still the *exact* operation this
    /// caller filed.
    ///
    /// Used when the outbound send fails: the call will never be
    /// answered, so its entry must not linger.
    ///
    /// The condition is the identity, not the coordinates. Matching the peer
    /// and class instead was the gap: they describe a *class* of operations
    /// rather than one, so if this caller's own entry had already left the map —
    /// settled by a response that raced the failing send, say — and this same
    /// session had since redrawn the id for a fresh call in the same class,
    /// every coordinate the predicate looked at matched the newcomer
    /// exactly. The stale abandonment then removed a live operation,
    /// and its caller waited on a oneshot no inbound frame could
    /// reach any more. An identity names one registration and this
    /// caller is holding the one it filed, so the match is total: it
    /// finds that entry, or it finds nothing and does nothing.
    pub(crate) fn abandon_local_request(&mut self, filed: &LocalRequest) {
        if self
            .pending
            .get(filed.request_id.as_str())
            .is_some_and(|op| op.id.names(&filed.op_id))
        {
            if let Some(op) = self.pending.remove(filed.request_id.as_str()) {
                if let PendingEntry::Stream(stream) = op.effect {
                    stream.finish_borrowed(Some("RPC caller cancelled"));
                }
            }
        }
    }

    /// Read the exact session's existing pending map under its logical-session
    /// fence. This is only a quiescence observation, never a settling path.
    pub(crate) fn pending_is_empty(&self) -> bool {
        self.pending.len() == 0
    }

    /// Whether an operation of `class` is pending under `request_id`, without
    /// removing or otherwise touching it.
    ///
    /// Asked *before* the inbound path measures or funds a response, so a peer
    /// sending an enormous body under a request id nobody is waiting on cannot
    /// force this side to take a reservation for it — even a transient one that
    /// is released a line later. The frame is refused by having nothing to
    /// settle rather than by being unaffordable, which is both cheaper and the
    /// truthful reason.
    /// How many operations this session currently has pending.
    ///
    /// Test-only, and narrow on purpose. The F5 controls have to distinguish
    /// "the predecessor's callers were resolved" from "the replacement's were
    /// resolved too", and the two are only distinguishable by looking at each
    /// session's own map. A count is the smallest thing that does that; it
    /// exposes no effect, no identity and no way to reach an entry, so it
    /// cannot become a settling path by accident.
    ///
    /// Also reached from another crate's controls through
    /// [`crate::JoinedNetwork::pending_call_count_for_test`], which is why the
    /// gate is the `transport-lab` feature and not `test` alone: `cfg(test)`
    /// holds only while this crate compiles its own tests. One count with two
    /// callers, rather than a second witness that could disagree with it.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Whether this session still holds the exact operation `filed` names.
    ///
    /// Identity, not the id — the same discrimination `abandon_local_request`
    /// makes, for the same reason: a control that asked by id alone would be
    /// satisfied by a successor that had merely reused the coordinate.
    #[cfg(test)]
    pub(crate) fn still_holds(&self, filed: &LocalRequest) -> bool {
        self.pending
            .get(filed.request_id.as_str())
            .is_some_and(|op| op.id.names(&filed.op_id))
    }

    pub(crate) fn accepts(&self, request_id: &str, class: PendingClass) -> bool {
        self.pending
            .get(request_id)
            .is_some_and(|op| op.accepts(class))
    }

    /// Take the single-response sender for `request_id`, but only
    /// if `from` is the bound device and the operation is a
    /// single-response one.
    ///
    /// Removes on success — a single response settles the call. A wrong source
    /// or a streaming operation removes nothing. The operation's funding leaves
    /// with the sender rather than with the entry, so nothing is defunded while
    /// the response is still in flight.
    pub(crate) fn take_single_response(
        &mut self,
        request_id: &str,
    ) -> Option<Extracted<oneshot::Sender<FundedRpcResult>>> {
        if !self.pending.get(request_id)?.accepts(PendingClass::Single) {
            return None;
        }
        let op = self.pending.remove(request_id)?;
        match op.effect {
            // The identity leaves with the sender, so the operation stays
            // funded across the gap between this removal and the send.
            PendingEntry::Single(tx) => Some(Extracted {
                value: tx,
                _funding: op.id,
            }),
            // Unreachable: the predicate above admitted only
            // `Single`, and the class is derived from this very
            // variant. Answering `None` rather than panicking keeps
            // a future change to either side non-destructive.
            PendingEntry::Stream(_) => None,
        }
    }

    /// Clone the chunk sender for `request_id`, but only if `from`
    /// is the bound device and the operation is a streaming one.
    ///
    /// Removes **nothing**: a chunk is one item of a stream that is
    /// still open, and the operation stays pending until its end
    /// frame arrives. The sender is cloned out under the shard
    /// guard and returned, so the caller sends after the guard has
    /// been released.
    pub(crate) fn stream_chunk_sender(
        &mut self,
        request_id: &str,
        seq: u64,
    ) -> Option<Arc<RpcStreamInbox>> {
        // The shard guard is the closure's argument, so it is
        // released when the closure returns — the clone crosses out,
        // the guard does not.
        self.pending.get_mut(request_id).and_then(|op| {
            if !op.accepts(PendingClass::Stream) {
                return None;
            }
            if seq != op.next_stream_seq {
                return None;
            }
            op.next_stream_seq = op.next_stream_seq.checked_add(1)?;
            match &op.effect {
                PendingEntry::Stream(tx) => Some(tx.clone()),
                // Unreachable: `accepts` already matched the class.
                PendingEntry::Single(_) => None,
            }
        })
    }

    /// Take the stream sender for `request_id`, but only if `from`
    /// is the bound device and the operation is a streaming one.
    ///
    /// Removes on success — an end frame closes the stream. A wrong source or a
    /// single-response operation removes nothing, so a foreign peer cannot cut
    /// another peer's stream short. The funding leaves with the inbox, exactly
    /// as in [`Self::take_single_response`].
    pub(crate) fn take_stream_end(
        &mut self,
        request_id: &str,
    ) -> Option<Extracted<Arc<RpcStreamInbox>>> {
        if !self.pending.get(request_id)?.accepts(PendingClass::Stream) {
            return None;
        }
        let op = self.pending.remove(request_id)?;
        match op.effect {
            // Unreachable for the same reason as in
            // `take_single_response`, and refused the same way.
            PendingEntry::Single(_) => None,
            PendingEntry::Stream(tx) => Some(Extracted {
                value: tx,
                _funding: op.id,
            }),
        }
    }
}

impl RpcInner {
    /// Draw the next never-before-used registration identity.
    ///
    /// Checked rather than wrapping, and that is the whole reason this is
    /// fallible. Exact cleanup rests on "no two registrations of one dispatcher
    /// compare equal"; a counter that wrapped would hand out `0` a second time
    /// and a stale handle would then remove a live successor — the precise
    /// defect the identity exists to prevent, reappearing at the far end of the
    /// range. Saturating is no better: every identity past the ceiling would be
    /// equal to every other. So exhaustion refuses instead, which is a state no
    /// process reaches — `u64` registrations at one per nanosecond is roughly
    /// six hundred years — but is refused rather than assumed away.
    ///
    /// `Malformed` is the truthful refusal: the registration cannot be given a
    /// distinct identity, so it cannot be represented. It is the one reason
    /// this path returns it that is not about a resource claim.
    fn mint_registration(
        &self,
    ) -> Result<RegistrationIdentity, crate::application_gateway::GatewayRefusal> {
        self.next_registration
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |current| current.checked_add(1),
            )
            .map(RegistrationIdentity)
            .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)
    }

    /// Acquire everything a registration will need, and publish nothing.
    ///
    /// Every way installing a handler can fail lives here: the network is gone,
    /// the gateway is closed, the entry is not representable, the owner will
    /// not fund it. The handlers map is not touched on any of those paths — not
    /// even read — so a refused registration leaves the incumbent exactly as it
    /// was, including when the refusal is a `Single`↔`Stream` displacement that
    /// got as far as building its replacement.
    ///
    /// That is a stronger guarantee than a rollback, and deliberately so. A
    /// remove-then-restore has to re-acquire a node lease to put the incumbent
    /// back, and that re-acquisition fails under exactly the pressure that made
    /// the displacement fail in the first place — so the one path that must
    /// never fail would be the one most likely to.
    /// Takes the funded handle as an argument rather than as a receiver.
    ///
    /// A free function over the handle rather than a method, because it has to
    /// put a second handle on the dispatcher into the `PreparedRegistration` it
    /// returns and a plain `&self` cannot produce one. The allocation is held
    /// by [`FundedArc`], and a custom smart pointer cannot be a receiver on
    /// stable — so the handle arrives as a parameter and is cloned through
    /// `FundedArc::clone`, which adds a holder to the same reservation. No raw
    /// `Arc` is reachable at any point: reconstructing one here would be an
    /// unfunded alias of an allocation every handle of which carries its share
    /// of the claim.
    fn prepare_entry(
        inner: &crate::resource::FundedArc<Self>,
        method: &str,
        entry: HandlerEntry,
    ) -> Result<PreparedRegistration, crate::application_gateway::GatewayRefusal> {
        let network = inner
            .network
            .upgrade()
            .ok_or(crate::application_gateway::GatewayRefusal::Revoked)?;
        if network.application_gateway.is_closed() {
            return Err(crate::application_gateway::GatewayRefusal::Revoked);
        }
        let node = inner
            .handler_resources
            .acquire(
                LeasedMap::<String, HandlerEntry>::entry_claim()
                    .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?,
            )
            .map_err(crate::application_gateway::GatewayRefusal::Pressure)?;
        // The cleanup handle's own lease, acquired here with everything else
        // fallible, and carried by the handle itself rather than by the entry.
        let handle = inner
            .handler_resources
            .acquire(
                cleanup_handle_claim(method)
                    .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?,
            )
            .map_err(crate::application_gateway::GatewayRefusal::Pressure)?;
        Ok(PreparedRegistration {
            inner: crate::resource::FundedArc::clone(inner),
            key: method.to_string(),
            name: Arc::from(method),
            entry,
            node,
            handle,
        })
    }
}

/// The synchronous outcome of publishing a prepared registration.
///
/// A refusal deliberately remains inline: it owns the complete funded
/// [`PreparedRegistration`] so the caller can retry or release it without an
/// allocation on the refusal path. This dedicated, move-only wrapper states
/// that tradeoff directly instead of inviting `Result`'s usual suggestion to
/// box a large error after admission has already finished.
#[must_use = "a refused commit still owns the prepared registration's funding"]
pub struct CommitOutcome<T, E> {
    disposition: CommitDisposition<T, E>,
}

enum CommitDisposition<T, E> {
    Committed(T),
    Refused(E),
}

impl<T, E> CommitOutcome<T, E> {
    fn committed(value: T) -> Self {
        Self {
            disposition: CommitDisposition::Committed(value),
        }
    }

    fn refused(error: E) -> Self {
        Self {
            disposition: CommitDisposition::Refused(error),
        }
    }

    /// Recover the familiar two-way result once the caller is ready to handle
    /// both ownership paths.
    pub fn into_result(self) -> Result<T, E> {
        match self.disposition {
            CommitDisposition::Committed(value) => Ok(value),
            CommitDisposition::Refused(error) => Err(error),
        }
    }
}

/// A registration that is fully funded and not yet published.
///
/// Move-only and `#[must_use]`: dropping one without committing returns every
/// resource it holds and leaves the registry untouched, which is the correct
/// outcome for a caller whose own half of a transaction refused.
#[must_use = "a prepared registration publishes nothing until it is committed"]
pub struct PreparedRegistration {
    inner: crate::resource::FundedArc<RpcInner>,
    /// The map's key. Consumed by `insert` on the vacant path.
    key: String,
    /// The cleanup handle's copy of the same name, so `commit` needs no
    /// allocation once the key has been handed to the map.
    name: Arc<str>,
    entry: HandlerEntry,
    node: ResourceLease,
    /// The cleanup handle's own funding, separate from the entry's for the
    /// reason [`cleanup_handle_claim`] gives: the two have different lifetimes
    /// and different owners, and one displacing the other must not silently
    /// defund what the survivor still holds.
    handle: ResourceLease,
}

impl PreparedRegistration {
    pub fn method(&self) -> &str {
        &self.name
    }

    /// Publish this registration.
    ///
    /// **Acquires nothing.** Every fallible acquisition already happened in
    /// prepare, so this cannot fail for want of a resource, and a caller's own
    /// half refusing between the two phases leaves the incumbent untouched.
    ///
    /// It is nonetheless fallible, for exactly one reason: the gateway may have
    /// closed while this was held. Nothing bounds how long a caller keeps a
    /// prepared registration, so prepare's closed check cannot speak for the
    /// moment of publication, and publishing a funded handler into a revoked
    /// gateway's registry is precisely the thing the close latch exists to
    /// prevent. The refusal returns this value intact rather than consuming it,
    /// so nothing is lost either way — drop it and every lease is released.
    ///
    /// **Why the latch is airtight here**, rather than merely narrow. Gateway
    /// close stores `closed` with `Release` *before* it takes this same
    /// handlers mutex to clear the map. Two interleavings, no third:
    ///
    /// - Close locks first. Its unlock synchronizes-with the lock below, and
    ///   the `Release` store is sequenced before that unlock, so the `Acquire`
    ///   load below is guaranteed to observe `true`. Refused; nothing published.
    /// - This locks first and publishes. Close then takes the map wholesale, so
    ///   the entry just published is dropped with its funding by the close that
    ///   followed it.
    ///
    /// There is no interleaving in which the load misses a store that a
    /// completed clear implies, because the mutex handoff orders them.
    ///
    /// Occupied and vacant are separated because only one of them needs the
    /// node. Replacing in place consumes no map capacity, so the node acquired
    /// for the absent case is released; inserting does, so it is spent. The
    /// displaced entry leaves with its own funding — releasing, never
    /// acquiring.
    pub fn commit(self) -> CommitOutcome<OwnedMethodRegistration, RegistrationRefused> {
        match self
            .commit_with(|| Ok::<(), std::convert::Infallible>(()))
            .into_result()
        {
            Ok((registration, ())) => CommitOutcome::committed(registration),
            Err(refused) => match refused.into_parts() {
                (prepared, CommitRefusal::Revoked) => CommitOutcome::refused(RegistrationRefused {
                    refusal: crate::application_gateway::GatewayRefusal::Revoked,
                    prepared,
                }),
                // Uninhabited: the callback above is the one that cannot fail,
                // which is exactly what makes this the ordinary commit.
                (_, CommitRefusal::Caller(never)) => match never {},
            },
        }
    }

    /// Publish this registration **and** a caller's own half of the same
    /// transaction, under one lock, all-or-nothing.
    ///
    /// This is [`Self::commit`] with the caller given a turn inside the critical
    /// section. The sequence is fixed and the order is the whole design:
    ///
    /// 1. Take the handlers lock.
    /// 2. Recheck the gateway. Closed → refuse; nothing is published and
    ///    `under_lock` is **never called**.
    /// 3. Call `under_lock`, still holding the lock. If it refuses → refuse;
    ///    nothing is published and this value comes back intact alongside the
    ///    caller's own error.
    /// 4. Only now publish, which cannot fail: every acquisition happened in
    ///    prepare, and step 3 already succeeded.
    ///
    /// **Why a callback rather than two commits.** A caller with tables of its
    /// own — a daemon registry that must agree this method is claimed — cannot
    /// get atomicity by ordering two separate commits. Commit-then-claim
    /// publishes a handler the caller may then refuse; claim-then-commit takes a
    /// claim the gateway may then refuse. Either way the incumbent under this
    /// method name is already gone and the transaction is half applied. Giving
    /// the caller its step *inside* this lock removes the interval in which that
    /// is observable: core's close blocks on the handlers lock, the caller's own
    /// shutdown blocks on the caller's lock, and neither side publishes anything
    /// if either refuses.
    ///
    /// The incumbent survives every refusal here for the same reason it survives
    /// a refused prepare — nothing touches the map until step 4.
    ///
    /// **`under_lock` runs under a lock and must behave like one.** It must not
    /// await, block, or re-enter this dispatcher: [`Rpc::serve`],
    /// [`Rpc::forget`], another commit, or anything else that reaches the
    /// handlers map will deadlock, because the lock is held and is not
    /// reentrant. Take your own lock, decide, return. It is synchronous by type
    /// — no future is accepted — and that is deliberate rather than incidental.
    ///
    /// `T` comes back with the registration, so a caller can carry its own
    /// receipt out of the critical section instead of re-deriving it afterwards.
    pub fn commit_with<T, E>(
        self,
        under_lock: impl FnOnce() -> Result<T, E>,
    ) -> CommitOutcome<(OwnedMethodRegistration, T), CommitRefused<E>> {
        let Self {
            inner,
            key,
            name,
            entry,
            node,
            handle,
        } = self;
        let registration = entry.registration();
        let mut handlers = inner.handlers.lock();
        // Under the lock, so the answer cannot go stale before it is used.
        let live = inner
            .network
            .upgrade()
            .is_some_and(|network| !network.application_gateway.is_closed());
        if !live {
            drop(handlers);
            return CommitOutcome::refused(CommitRefused {
                prepared: PreparedRegistration {
                    inner,
                    key,
                    name,
                    entry,
                    node,
                    handle,
                },
                refusal: CommitRefusal::Revoked,
            });
        }
        // The caller's half: before anything of ours is published, and while the
        // lock a close would have to take is still held here.
        let value = match under_lock() {
            Ok(value) => value,
            Err(error) => {
                drop(handlers);
                return CommitOutcome::refused(CommitRefused {
                    prepared: PreparedRegistration {
                        inner,
                        key,
                        name,
                        entry,
                        node,
                        handle,
                    },
                    refusal: CommitRefusal::Caller(error),
                });
            }
        };
        let displaced = if handlers.contains_key(&key) {
            let slot = handlers
                .get_mut(&key)
                .expect("the entry was present under this same lock a line above");
            Some(std::mem::replace(slot, entry))
        } else {
            handlers
                .insert(key, entry, node)
                .expect("the key was absent under this lock and its node was acquired before it");
            None
        };
        // Outside the registry lock: releasing a displaced handler's funding
        // runs its `Drop`, and nothing in a resource release needs this map.
        drop(handlers);
        drop(displaced);
        CommitOutcome::committed((
            OwnedMethodRegistration {
                inner: inner.downgrade(),
                name,
                registration,
                _retention: handle,
                detached: false,
            },
            value,
        ))
    }
}

/// Why a [`PreparedRegistration::commit_with`] published nothing.
pub enum CommitRefusal<E> {
    /// The gateway closed between prepare and commit. The caller's `under_lock`
    /// was not called at all — so there is no half-applied transaction to undo,
    /// because the caller's half never ran.
    Revoked,
    /// The caller's own half refused, and so this one did too.
    Caller(E),
}

/// A refused two-sided commit, with everything it was given.
///
/// The prepared registration comes back rather than being dropped, so a caller
/// that can retry may, and one that cannot drops this and releases every lease.
/// Either way nothing was published and the incumbent is untouched.
#[must_use = "this still holds the prepared registration's funding"]
pub struct CommitRefused<E> {
    prepared: PreparedRegistration,
    refusal: CommitRefusal<E>,
}

impl<E> CommitRefused<E> {
    pub fn refusal(&self) -> &CommitRefusal<E> {
        &self.refusal
    }

    /// Take the prepared registration back, unpublished and still funded.
    pub fn into_prepared(self) -> PreparedRegistration {
        self.prepared
    }

    pub fn into_parts(self) -> (PreparedRegistration, CommitRefusal<E>) {
        (self.prepared, self.refusal)
    }
}

impl<E: std::fmt::Debug> std::fmt::Debug for CommitRefused<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = f.debug_struct("CommitRefused");
        out.field("method", &self.prepared.method());
        match &self.refusal {
            CommitRefusal::Revoked => out.field("refusal", &"Revoked"),
            CommitRefusal::Caller(error) => out.field("refusal", error),
        };
        out.finish()
    }
}

/// A commit that found the gateway closed, with everything it was given.
///
/// The prepared registration is returned rather than dropped so the refusal
/// loses nothing: a caller may inspect the reason and drop this — releasing
/// every lease — or take the prepared value back out. It is never partially
/// applied; a refused commit published nothing.
#[must_use = "this still holds the prepared registration's funding"]
pub struct RegistrationRefused {
    refusal: crate::application_gateway::GatewayRefusal,
    prepared: PreparedRegistration,
}

impl RegistrationRefused {
    pub fn refusal(&self) -> &crate::application_gateway::GatewayRefusal {
        &self.refusal
    }

    /// Take the refusal and release the registration's funding with it.
    pub fn into_refusal(self) -> crate::application_gateway::GatewayRefusal {
        self.refusal
    }

    /// Take the prepared registration back, unpublished and still funded.
    pub fn into_prepared(self) -> PreparedRegistration {
        self.prepared
    }
}

impl std::fmt::Debug for RegistrationRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationRefused")
            .field("method", &self.prepared.method())
            .field("refusal", &self.refusal)
            .finish()
    }
}

/// The live registration a committed handler answers to.
///
/// Move-only and `#[must_use]`. Dropping it removes **exactly** the handler it
/// installed: the stored identity is compared against whatever currently holds
/// the name, so a cleanup that runs after the method was legitimately taken
/// over removes nothing. Removal by name alone cannot express that, which is
/// why the identity exists.
#[must_use = "dropping this immediately removes the handler it registered"]
pub struct OwnedMethodRegistration {
    /// Weak: a registration outliving its dispatcher must not keep the
    /// dispatcher, its handlers, or their funding alive.
    ///
    /// A [`FundedWeak`] does not retain the dispatcher's claim. It upgrades the
    /// value only together with a live funded strong owner, so an outliving
    /// registration can observe retirement without keeping the dispatcher or
    /// its funding alive.
    ///
    /// [`FundedWeak`]: crate::resource::FundedWeak
    inner: crate::resource::FundedWeak<RpcInner>,
    name: Arc<str>,
    registration: RegistrationIdentity,
    /// This handle's own funding, covering the `Arc<str>` above. Held here
    /// rather than by the entry because this outlives the entry whenever a
    /// successor displaces it, and released by this value's own `Drop` — no
    /// drop-order relationship between two separate owners is relied on.
    _retention: ResourceLease,
    detached: bool,
}

impl OwnedMethodRegistration {
    pub fn method(&self) -> &str {
        &self.name
    }

    /// Give up the cleanup half and leave the handler installed.
    ///
    /// This is what [`Rpc::serve`] has always meant: register and walk away,
    /// with removal left to [`Rpc::forget`] by name or to the gateway's close.
    /// Named rather than implicit, because "nobody owns this handler's
    /// removal" is a decision and not a default.
    pub fn detach(mut self) {
        self.detached = true;
    }
}

impl Drop for OwnedMethodRegistration {
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut handlers = inner.handlers.lock();
        // The identity, not the name, is what authorizes the removal. A
        // successor that legitimately took this method has a different one, and
        // is left alone.
        let ours = handlers
            .get(&*self.name)
            .is_some_and(|entry| entry.registration() == self.registration);
        if ours {
            handlers.remove(&*self.name);
        }
    }
}

impl Rpc {
    /// Attach (or look up) the RPC dispatcher for a network. Use
    /// this when you've spun up the engine directly via the explicit
    /// transport-lab facade `engine::transport_lab::spawn_network`
    /// and want to register
    /// handlers or make calls. The [`crate::JoinedNetwork`] facade
    /// attaches automatically — this is the lower-level
    /// equivalent.
    ///
    /// Idempotent: subsequent calls return a fresh `Rpc` handle
    /// over the same underlying state, so previously-registered
    /// handlers remain in effect.
    pub(crate) fn attach(
        network: &Arc<NetworkState>,
    ) -> Result<Self, crate::application_gateway::GatewayRefusal> {
        Self::attach_inner(network)
    }

    fn attach_inner(
        network: &Arc<NetworkState>,
    ) -> Result<Self, crate::application_gateway::GatewayRefusal> {
        if let Some(inner) = network.application_gateway.rpc() {
            if network.application_gateway.is_closed() {
                return Err(crate::application_gateway::GatewayRefusal::Revoked);
            }
            return Ok(Self { inner });
        }
        let handler_resources = network.application_gateway.rpc_resource_scope()?;
        let allocation = handler_resources
            .acquire(
                rpc_inner_claim()
                    .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?,
            )
            .map_err(crate::application_gateway::GatewayRefusal::Pressure)?;
        // The allocation's claim rides in the funded strong handle rather than
        // in the pointee. Weak registrations can observe retirement but cannot
        // keep the dispatcher or its claim alive.
        let candidate = crate::resource::FundedArc::new(
            RpcInner {
                network: Arc::downgrade(network),
                handlers: Mutex::new(LeasedMap::new()),
                handler_resources,
                next_registration: std::sync::atomic::AtomicU64::new(0),
            },
            allocation,
            // Unreachable: the only refusal is a speculative lease, and this one
            // came from `LocalApplicationResourceScope::acquire`, which names
            // `Admitted` itself.
        )
        .expect("a dispatcher allocation is admitted, never speculative");
        let inner = network.application_gateway.install_rpc(candidate)?;
        Ok(Self { inner })
    }

    /// Register a single-shot handler under `method`. Replaces any
    /// previous handler for the same name.
    ///
    /// **What this funds.** The method name, the closure's *inline* storage,
    /// the allocation that carries them — and one residual naming, but not
    /// containing, whatever the closure captured. `size_of::<F>()` measures the
    /// closure struct: a handler holding an `Arc<T>` is one pointer here
    /// however large `T` is. The residual is the honest statement that
    /// something unmeasured is retained; it is not a bound on it. If yours
    /// retains heap the owner should know about, state it with
    /// [`Rpc::serve_with_retention_claim`] rather than leaving this to imply a
    /// containment it cannot provide.
    ///
    /// Removal is by name, through [`Rpc::forget`] or the gateway's close.
    /// A caller that needs to remove *its own* registration and not whichever
    /// one currently holds the name wants [`Rpc::prepare_serve`] and the
    /// cleanup handle its commit returns.
    pub fn serve<F, Fut>(
        &self,
        method: &str,
        handler: F,
    ) -> Result<(), crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, String>> + Send + 'static,
    {
        self.prepare_serve_funded(method, CaptureFunding::Opaque, handler)?
            .commit()
            .into_result()
            .map_err(RegistrationRefused::into_refusal)?
            .detach();
        Ok(())
    }

    /// [`Rpc::serve`], with the closure's retained captures stated exactly.
    ///
    /// `captures` is everything the handler transitively owns and keeps alive
    /// for as long as it is registered: the buffers behind its `String`s and
    /// `Vec`s, the payloads behind its `Arc`s, and one
    /// `OpaqueDependencyResidual` per distinct allocation among them. Do **not**
    /// include `size_of::<F>()`, the method name, or the registration's own
    /// allocation — those are added here, and counting them twice charges the
    /// owner for capacity nobody holds.
    ///
    /// Passing [`ResourceClaim::ZERO`] is an assertion, not a shortcut: it says
    /// this closure allocates nothing behind its inline storage. That is why it
    /// costs *less* than [`Rpc::serve`], which cannot say that and pays a
    /// residual for the unknown. Assert it only when it is true.
    pub fn serve_with_retention_claim<F, Fut>(
        &self,
        method: &str,
        captures: ResourceClaim,
        handler: F,
    ) -> Result<(), crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, String>> + Send + 'static,
    {
        self.prepare_serve_funded(method, CaptureFunding::Declared(captures), handler)?
            .commit()
            .into_result()
            .map_err(RegistrationRefused::into_refusal)?
            .detach();
        Ok(())
    }

    /// Fund a single-shot registration without publishing it.
    ///
    /// The first half of a two-phase registration, for a caller whose own
    /// bookkeeping can also refuse. Every *acquisition* happens here, so the
    /// returned value's `commit` cannot fail for want of a resource; the one
    /// thing it still checks is whether the gateway closed in the meantime,
    /// which no earlier check can answer for it (see
    /// [`PreparedRegistration::commit`]). So a caller may prepare, run its own
    /// fallible half, and only then commit — and if either half refuses, it
    /// drops this and the incumbent handler was never touched.
    ///
    /// Funds the closure's captures as an opaque residual, on the same terms as
    /// [`Rpc::serve`].
    pub fn prepare_serve<F, Fut>(
        &self,
        method: &str,
        handler: F,
    ) -> Result<PreparedRegistration, crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, String>> + Send + 'static,
    {
        self.prepare_serve_funded(method, CaptureFunding::Opaque, handler)
    }

    /// [`Rpc::prepare_serve`] with the closure's retained captures stated
    /// exactly, on the same contract as [`Rpc::serve_with_retention_claim`].
    pub fn prepare_serve_with_retention_claim<F, Fut>(
        &self,
        method: &str,
        captures: ResourceClaim,
        handler: F,
    ) -> Result<PreparedRegistration, crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, String>> + Send + 'static,
    {
        self.prepare_serve_funded(method, CaptureFunding::Declared(captures), handler)
    }

    fn prepare_serve_funded<F, Fut>(
        &self,
        method: &str,
        captures: CaptureFunding,
        handler: F,
    ) -> Result<PreparedRegistration, crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, String>> + Send + 'static,
    {
        let registration = self.inner.mint_registration()?;
        // Build the callable first: its layout is what the registration
        // allocation will actually be, and it cannot be named any other way.
        let call = move |call: RpcCall| -> RpcHandlerFuture { Box::pin(handler(call)) };
        let retention = self
            .inner
            .handler_resources
            .acquire(
                entry_retention_claim(method, captures, funded_handler_layout(&call))
                    .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?,
            )
            .map_err(crate::application_gateway::GatewayRefusal::Pressure)?;
        let handler: Arc<FundedRpcHandler> = Arc::new(FundedRpcHandler { registration, call });
        let handler = FundedArc::from_admitted_arc(handler, retention)
            .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?;
        RpcInner::prepare_entry(&self.inner, method, HandlerEntry::Single { handler })
    }

    /// Register a streaming handler under `method`. Chunks map to wire chunks;
    /// `End` maps exactly to the terminal frame. Bare receiver closure is error.
    ///
    /// Funds the closure's captures as an opaque residual, on the same terms as
    /// [`Rpc::serve`].
    pub fn serve_stream<F, Fut>(
        &self,
        method: &str,
        handler: F,
    ) -> Result<(), crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
            + Send
            + 'static,
    {
        self.prepare_serve_stream_funded(method, CaptureFunding::Opaque, handler)?
            .commit()
            .into_result()
            .map_err(RegistrationRefused::into_refusal)?
            .detach();
        Ok(())
    }

    /// [`Rpc::serve_stream`], with the closure's retained captures stated
    /// exactly, on the same contract as [`Rpc::serve_with_retention_claim`].
    pub fn serve_stream_with_retention_claim<F, Fut>(
        &self,
        method: &str,
        captures: ResourceClaim,
        handler: F,
    ) -> Result<(), crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
            + Send
            + 'static,
    {
        self.prepare_serve_stream_funded(method, CaptureFunding::Declared(captures), handler)?
            .commit()
            .into_result()
            .map_err(RegistrationRefused::into_refusal)?
            .detach();
        Ok(())
    }

    /// Fund a streaming registration without publishing it. The streaming twin
    /// of [`Rpc::prepare_serve`], on the same two-phase contract.
    pub fn prepare_serve_stream<F, Fut>(
        &self,
        method: &str,
        handler: F,
    ) -> Result<PreparedRegistration, crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
            + Send
            + 'static,
    {
        self.prepare_serve_stream_funded(method, CaptureFunding::Opaque, handler)
    }

    /// [`Rpc::prepare_serve_stream`] with the closure's retained captures
    /// stated exactly.
    pub fn prepare_serve_stream_with_retention_claim<F, Fut>(
        &self,
        method: &str,
        captures: ResourceClaim,
        handler: F,
    ) -> Result<PreparedRegistration, crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
            + Send
            + 'static,
    {
        self.prepare_serve_stream_funded(method, CaptureFunding::Declared(captures), handler)
    }

    fn prepare_serve_stream_funded<F, Fut>(
        &self,
        method: &str,
        captures: CaptureFunding,
        handler: F,
    ) -> Result<PreparedRegistration, crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
            + Send
            + 'static,
    {
        let registration = self.inner.mint_registration()?;
        // Built first for the same reason as the single-shot twin: the layout
        // of the anonymous callable is the allocation being funded.
        let call = move |call: RpcCall| -> RpcStreamHandlerFuture { Box::pin(handler(call)) };
        let retention = self
            .inner
            .handler_resources
            .acquire(
                entry_retention_claim(method, captures, funded_stream_handler_layout(&call))
                    .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?,
            )
            .map_err(crate::application_gateway::GatewayRefusal::Pressure)?;
        let handler: Arc<FundedRpcStreamHandler> =
            Arc::new(FundedRpcStreamHandler { registration, call });
        let handler = FundedArc::from_admitted_arc(handler, retention)
            .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?;
        RpcInner::prepare_entry(&self.inner, method, HandlerEntry::Stream { handler })
    }

    /// Drop the handler registered under `method`. Idempotent —
    /// no-op if nothing was registered.
    pub fn forget(&self, method: &str) {
        self.inner.handlers.lock().remove(method);
    }

    /// Single-shot RPC call.
    pub async fn call(
        &self,
        peer: &str,
        method: &str,
        payload: serde_json::Value,
    ) -> Result<RpcResponse, RpcError> {
        // Bound to `peer` at insertion: only that canonical device
        // may resolve this oneshot, and only with a single
        // response. `send_to_peer` resolves the destination by
        // exact registry key, so a `peer` that is not a canonical
        // device id fails the send below rather than filing an
        // entry no inbound frame could ever match. Registration also
        // hands back the identity of the entry it filed, which is
        // what the failure path withdraws.
        //
        // The channel is created *inside* the filing, past the session's
        // funding of it. Built out here, the pending claim would name an
        // allocation that already existed and a refusal could not refuse it —
        // the caller would have paid for what it was about to be told it could
        // not have. The shape is what says "unary" once: the
        // class the claim is derived from and the entry that gets stored both
        // come from `Unary` and cannot disagree.
        let network = self.inner.network.upgrade().ok_or(RpcError::NetworkDown)?;
        let (filed, rx) = network
            .application_gateway
            .register_rpc_request_prepared::<Unary>(&network, peer)
            .map_err(|refusal| refusal.into_rpc_error(peer))?;
        let cancellation = PendingCancellation::new(&network, peer, filed);
        let frame = crate::protocol::RpcRequestMessage {
            request_id: cancellation.request_id().to_string(),
            method: method.to_string(),
            payload,
            streaming: false,
        };
        network
            .application_gateway
            .send_rpc_request(&network, peer, frame)
            .await
            .map_err(map_engine_err)?;
        // The application boundary. `into_result` releases the retention core
        // held on the peer's body or error text; from here the value is the
        // embedder's and core is no longer the party charged for it.
        match rx.await {
            Ok(funded) => match funded.into_result() {
                Ok(resp) => Ok(resp),
                Err(msg) => Err(RpcError::Remote(msg)),
            },
            Err(_) => Err(RpcError::NetworkDown),
        }
    }

    /// [`Self::call`] for a caller that will re-encode the reply rather than
    /// keep it.
    ///
    /// The difference is the boundary. `call` hands the body to the application
    /// and releases core's retention on it at the same moment, which is right
    /// when the value becomes the embedder's to hold for as long as it likes.
    /// It is wrong for a caller that is *not* keeping the value — a daemon
    /// forwarding a remote reply onto a client socket does not want ownership,
    /// it wants to serialize the bytes and drop them, and taking ownership to do
    /// that means the peer-sized body is unfunded for the whole encode-and-write
    /// while core has already been told it is gone.
    ///
    /// So this returns the funded owner instead, borrow-only. The reply is read
    /// through [`FundedRpcCallResult::body`] or
    /// [`FundedRpcCallResult::error`] and the funding is released when the owner
    /// is dropped, after the write. There is deliberately no accessor taking the
    /// value out: one would be `call` with extra steps, and this exists exactly
    /// because that is the shape that cannot be made truthful here.
    #[doc(hidden)]
    pub async fn call_funded(
        &self,
        peer: &str,
        method: &str,
        payload: serde_json::Value,
    ) -> Result<FundedRpcCallResult, RpcError> {
        let network = self.inner.network.upgrade().ok_or(RpcError::NetworkDown)?;
        let (filed, rx) = network
            .application_gateway
            .register_rpc_request_prepared::<Unary>(&network, peer)
            .map_err(|refusal| refusal.into_rpc_error(peer))?;
        let cancellation = PendingCancellation::new(&network, peer, filed);
        let frame = crate::protocol::RpcRequestMessage {
            request_id: cancellation.request_id().to_string(),
            method: method.to_string(),
            payload,
            streaming: false,
        };
        network
            .application_gateway
            .send_rpc_request(&network, peer, frame)
            .await
            .map_err(map_engine_err)?;
        // No application boundary here: the funded owner travels out whole, so
        // the retention the settling frame took is still held while the caller
        // encodes and writes.
        match rx.await {
            Ok(funded) => Ok(FundedRpcCallResult { funded }),
            Err(_) => Err(RpcError::NetworkDown),
        }
    }

    /// Streaming RPC call. The returned receiver yields each chunk
    /// as it arrives; a `None` signals end-of-stream.
    pub async fn call_stream(
        &self,
        peer: &str,
        method: &str,
        payload: serde_json::Value,
    ) -> Result<RpcStream, RpcError> {
        // Bound exactly as the single-shot path above, with the
        // stream class: only `peer` may feed this receiver, and
        // only through chunk and end frames. Withdrawal on a failed
        // send is by identity, exactly as above — and the inbox, like the
        // channel above, is allocated only once the session has funded it.
        let network = self.inner.network.upgrade().ok_or(RpcError::NetworkDown)?;
        let (filed, inbox) = network
            .application_gateway
            .register_rpc_request_prepared::<Streaming>(&network, peer)
            .map_err(|refusal| refusal.into_rpc_error(peer))?;
        let cancellation = PendingCancellation::new(&network, peer, filed);
        let frame = crate::protocol::RpcRequestMessage {
            request_id: cancellation.request_id().to_string(),
            method: method.to_string(),
            payload,
            streaming: true,
        };
        network
            .application_gateway
            .send_rpc_request(&network, peer, frame)
            .await
            .map_err(map_engine_err)?;
        Ok(RpcStream {
            inbox,
            _cancellation: cancellation,
        })
    }

    /// Advertise what this node offers to the mesh.
    ///
    /// None of it crosses in `hello`. An advertisement is application metadata
    /// and a Hello is admitted before a session exists, so the only path out is
    /// [`crate::protocol::CapabilitiesUpdateMessage`], sent to a peer whose
    /// session is live at the moment of the send.
    ///
    /// This call reaches the peers that have one already. A peer that
    /// establishes a session later is sent the value current *then*, on that
    /// establishment — so advertising before any peer exists is not a lost
    /// advertisement, and the embedder is never expected to call this again to
    /// repair one.
    /// **Answers whether the advertisement was committed.** Both ways this can
    /// fail would otherwise be silent returns: a network already down, and a
    /// resource owner that would not fund retaining the encoded advert. The
    /// second is the one that matters — the embedder would be told nothing,
    /// `capabilities()` would keep answering the *previous* value, and every
    /// session established afterwards would be sent that stale value
    /// indefinitely. An advertisement that did not take is not a slow
    /// advertisement.
    ///
    /// `Ok` means the value is stored and is what a later session will be sent.
    /// The fan-out to peers already holding one is a funded command queued for
    /// the driver, and it is deliberately not part of this answer: how many
    /// peers were reachable at one instant is a fact about the mesh, not about
    /// whether this call did its job. A fan-out the mailbox refuses is warned
    /// about and does not change the answer, because the value is stored either
    /// way and every later session is sent it.
    pub fn advertise(&self, caps: CapabilityAdvert) -> Result<(), RpcError> {
        let Some(net) = self.inner.network.upgrade() else {
            return Err(RpcError::NetworkDown);
        };
        net.application_gateway
            .replace_capabilities(net.session_broker.as_ref(), &caps)
            .map_err(|refusal| match refusal {
                crate::application_gateway::CapabilityReplaceRefusal::Revoked => {
                    RpcError::NetworkDown
                }
                crate::application_gateway::CapabilityReplaceRefusal::Unavailable(reason) => {
                    RpcError::ResourceUnavailable(reason)
                }
            })?;
        // The stored value is what a session established later is sent, and it
        // is in place before this returns — which is this call's whole documented
        // answer. The fan-out to peers already holding a session is a command the
        // driver runs on its next turn.
        //
        // A command rather than a spawned task, and that is the point. A detached
        // task was scheduled work no resource owner had funded and no shutdown
        // could wait for: it outlived this call with a strong `Arc` to the
        // network and its own future's allocation, both invisible to the ledger.
        // The mailbox funds the payload, its node, and the scheduled work, and
        // the driver's lifecycle owns the running of it.
        //
        // A refused admission is warned about and *not* returned, because the
        // local commit above already succeeded and this function's answer is
        // about that commit. Turning a fan-out refusal into an error here would
        // tell the embedder its advertisement was not stored, which is false —
        // and every session established afterwards is sent the stored value
        // regardless, so the refusal costs reachable peers a push, not the
        // advertisement.
        if let Err(error) = net.application_gateway.fanout_capabilities(&net, caps) {
            tracing::warn!(
                %error,
                "capability fan-out was not admitted after local commit"
            );
        }
        Ok(())
    }

    /// Snapshot of the currently-advertised capabilities.
    pub fn capabilities(&self) -> CapabilityAdvert {
        self.inner
            .network
            .upgrade()
            .and_then(|network| network.application_gateway.capability_state().current())
            .unwrap_or_default()
    }

    // Pending settlement is scoped to the exact promoted session capability.
    // Its SessionRpcState checks the operation class before extracting an
    // effect; a request id alone cannot reach another session's pending map.

    /// Snapshot registered methods for lifecycle controls. Production lookup
    /// is borrowed and performs no unfunded allocation.
    #[cfg(test)]
    pub(crate) fn registered_methods(&self) -> Vec<String> {
        let handlers = self.inner.handlers.lock();
        let mut methods = Vec::new();
        handlers.for_each(|method, _entry| methods.push(method.clone()));
        methods
    }
}

/// The drawn width of a request id, before encoding.
const REQUEST_ID_BYTES: usize = 12;

/// The encoded width every drawn request id has.
///
/// Base32 spends one character per 5 bits, so this is `REQUEST_ID_BYTES * 8`
/// bits rounded up to the next whole character. It is a constant rather than a
/// measurement because the claim that funds a filing is derived from it *before
/// any id exists to measure* — which is the whole point of the plan below.
const REQUEST_ID_CHARS: usize = (REQUEST_ID_BYTES * 8).div_ceil(5);

/// One drawn request id, before it is a `String`.
///
/// **The pre-admission form.** The path this replaces drew the bytes, encoded
/// them into a `String`, lowercased that into a second `String`, and only then
/// offered the operation to the session for admission. Pressure could refuse
/// the operation, but never the allocation: by the time the refusal was
/// available, the memory it was refusing had already been taken. The refusal
/// was honest about the operation and silent about the bytes.
///
/// Here the draw and its encoding both land in fixed-width arrays on the stack,
/// and the width the filing's claim is measured from is [`REQUEST_ID_CHARS`], a
/// constant. So everything the admission decision needs — the id's text, to
/// test for a collision, and its width, to price the filing — exists while the
/// heap is still untouched. The owned routing string is built in the infallible
/// commit, past the last refusal, and nowhere else.
#[derive(Clone, Copy)]
struct RequestIdPlan {
    encoded: [u8; REQUEST_ID_CHARS],
}

impl RequestIdPlan {
    /// Draw one id. Allocates nothing.
    fn draw() -> Self {
        use rand::Rng;
        let bytes: [u8; REQUEST_ID_BYTES] = rand::thread_rng().gen();
        let mut encoded = [0_u8; REQUEST_ID_CHARS];
        // Encoding into our own buffer rather than into a returned `String`:
        // the widths are fixed and equal by construction, which is what lets
        // this be an array at all.
        data_encoding::BASE32_NOPAD.encode_mut(&bytes, &mut encoded);
        encoded.make_ascii_lowercase();
        Self { encoded }
    }

    /// The id as text, borrowed from this value's own bytes.
    ///
    /// This is what the collision test and the claim read. Borrowed, so asking
    /// the question costs nothing — the previous shape could only be asked by a
    /// caller that had already paid for the answer.
    fn as_str(&self) -> &str {
        // Base32's alphabet is ASCII and `make_ascii_lowercase` keeps it ASCII,
        // so this cannot fail; the arm exists because the crate holds no unsafe.
        std::str::from_utf8(&self.encoded).expect("base32 emits ASCII, which is valid UTF-8")
    }
}

fn map_engine_err(e: crate::error::Error) -> RpcError {
    use crate::error::Error as E;
    match e {
        E::Network(msg) if msg.contains("not found") => RpcError::PeerNotFound(msg),
        E::ResourceMailboxAdmission(crate::resource::ResourceMailboxAdmissionError::Closed) => {
            RpcError::NetworkDown
        }
        E::ResourceMailboxAdmission(crate::resource::ResourceMailboxAdmissionError::Pressure(
            error,
        )) => RpcError::ResourceUnavailable(format!("command admission refused: {error:?}")),
        E::ResourceMailboxAdmission(error) => {
            RpcError::ResourceUnavailable(format!("command is not representable: {error}"))
        }
        E::Transport(msg) => RpcError::Transport(msg),
        other => RpcError::Transport(other.to_string()),
    }
}

/// Flat snapshot of the method names registered on this node, for an embedder
/// that wants to inspect or publish them.
///
/// No mesh path consults it. Method names are not placed in `hello`, and a peer
/// learns what this node offers only from an advertisement the embedder chooses
/// to publish through [`Rpc::advertise`].
// These pre-session-ownership controls exercised the removed network-global
// pending map. Kept temporarily as historical specifications while the exact
// promoted-session integration controls live with the engine fence.
#[cfg(test)]
mod tests {
    use super::*;

    /// Settle a unary operation the way the inbound path does: the body funded
    /// against the same session, and the funding travelling with it.
    ///
    /// Takes the whole `Extracted` for the same reason production does — there
    /// is no way to hold the sender apart from the operation's funding, so a
    /// control cannot demonstrate a settlement the engine could not perform.
    /// Nothing is returned: whether the caller received it is read off the
    /// caller's own receiver, which every caller of this already awaits.
    pub(super) fn settle_funded(
        extracted: Extracted<oneshot::Sender<FundedRpcResult>>,
        session: &crate::runtime::session_broker::SessionCapability,
        body: serde_json::Value,
    ) {
        let retention = session
            .reserve_retained(
                single_response_claim(Some(&body), None).expect("a small body is representable"),
            )
            .expect("the fixture session funds one small response body");
        extracted.answer(FundedRpcResult::new(
            Ok(RpcResponse::from_value(body)),
            retention,
        ));
    }

    fn accounted_bytes(claim: crate::resource::ResourceClaim) -> u64 {
        claim.amount(ResourceClass::AccountedMemoryBytes)
    }

    /// Removing the registry entry cannot release the charge carried by a
    /// dispatch clone; dropping the last clone releases exactly that charge.
    ///
    /// The engine integration control exercises forget, replacement and
    /// gateway close and proves the clone remains callable after each. This
    /// supplies its accounting discriminator over the exact stored
    /// `HandlerEntry`, production entry-retention claim and real `LeasedMap`
    /// node. After removal, the dispatch clone is the sole possible owner of
    /// the reservation being observed.
    #[tokio::test]
    async fn v4_f4_c_live_invocation_clone_retains_the_handler_entry_charge_until_drop() {
        let (provider, grant, scope) = test_handler_scope_with_provider();
        let baseline = provider.in_use();
        let method = "funded-clone";
        let call = |_call: RpcCall| -> RpcHandlerFuture {
            Box::pin(async { Ok(RpcResponse::from_value(serde_json::json!("predecessor"))) })
        };
        let retention_claim = entry_retention_claim(
            method,
            CaptureFunding::Declared(ResourceClaim::ZERO),
            funded_handler_layout(&call),
        )
        .expect("the production handler-entry claim is representable");
        let retention_charge =
            crate::resource::FiniteResourceProvider::reservation_charge_for_test(retention_claim)
                .expect("the production handler-entry reservation charge is representable");
        let retention = scope
            .acquire(retention_claim)
            .expect("the isolated scope funds the predecessor handler");
        let handler: Arc<FundedRpcHandler> = Arc::new(FundedRpcHandler {
            registration: RegistrationIdentity(7),
            call,
        });
        let handler: RpcHandler = FundedArc::from_admitted_arc(handler, retention)
            .expect("an admitted handler lease may be shared");
        let node = scope
            .acquire(
                LeasedMap::<String, HandlerEntry>::entry_claim()
                    .expect("the production handler-map node is representable"),
            )
            .expect("the isolated scope funds the handler-map node");
        let mut handlers = LeasedMap::new();
        handlers
            .insert(method.to_string(), HandlerEntry::Single { handler }, node)
            .expect("the fresh handler name is vacant");

        let clone = match handlers
            .get(method)
            .expect("the predecessor is installed before dispatch clones it")
        {
            HandlerEntry::Single { handler } => handler.clone(),
            HandlerEntry::Stream { .. } => panic!("the predecessor is single-shot"),
        };
        handlers.remove(method);
        assert_eq!(handlers.len(), 0, "the registry no longer owns the handler");
        assert_eq!(
            provider.in_use(),
            baseline
                .checked_add(retention_charge)
                .expect("the baseline and one handler charge are representable"),
            "after removal the dispatch clone solely owns the handler-entry charge"
        );

        // Consume every unrelated unit. The seal itself needs one provider
        // reservation record, which is left before the seal is acquired.
        let record = crate::resource::FiniteResourceProvider::reservation_charge_for_test(
            ResourceClaim::ZERO,
        )
        .expect("the provider reservation record is representable");
        let unused = grant
            .checked_sub(provider.in_use())
            .expect("the provider cannot use more than its grant");
        let seal_claim = unused
            .checked_sub(record)
            .expect("the isolated grant funds the seal's own record");
        let seal = scope
            .acquire(seal_claim)
            .expect("all capacity unrelated to the live clone is sealed");
        let full = provider.in_use();
        assert_eq!(full, grant, "the seal leaves no unowned provider slack");
        assert!(
            matches!(
                scope.acquire(retention_claim),
                Err(crate::resource::ResourceUnavailable::Pressure(_))
            ),
            "a second identical charge meets provider pressure while the clone owns the first"
        );
        assert_eq!(
            provider.in_use(),
            full,
            "the refused probe retains no fragment of a second handler charge"
        );

        let response = clone
            .invoke(RpcCall {
                from: "peer".into(),
                request_id: "rid".into(),
                method: method.into(),
                payload: serde_json::Value::Null,
                streaming: false,
            })
            .await
            .expect("the funded predecessor clone remains callable");
        assert_eq!(response.body, serde_json::json!("predecessor"));

        drop(clone);
        let after_clone = full
            .checked_sub(retention_charge)
            .expect("the full provider use contains the handler charge");
        assert_eq!(
            provider.in_use(),
            after_clone,
            "dropping the last clone releases exactly its production charge"
        );
        let probe = scope
            .acquire(retention_claim)
            .expect("the same charge is admitted after the last clone drops");
        assert_eq!(
            provider.in_use(),
            full,
            "the probe consumes exactly the charge the clone released"
        );
        drop(probe);
        assert_eq!(provider.in_use(), after_clone);
        drop(seal);
        assert_eq!(
            provider.in_use(),
            baseline,
            "the control releases every handler and sealing reservation"
        );
    }

    /// A longer name costs what the longer name actually retains — twice for
    /// the request id, once for the peer.
    ///
    /// This is the arithmetic the finding was about. The claim used to take a
    /// single `request_id_bytes` and charge it once, while a filed operation
    /// keeps *two* buffers of it alive — the map's key and the copy the caller's
    /// cancellation holds so it can withdraw the exact entry it filed. It also
    /// charged nothing at all for the peer name that same cancellation copies.
    /// So a caller could grow both without the session's owner ever seeing it.
    ///
    /// Stated as deltas rather than as absolute figures on purpose: an absolute
    /// assertion would have to restate the formula, and would then pass for any
    /// formula that restated itself the same wrong way. A delta says only that
    /// growing an input grows the charge by the amount that input retains, which
    /// is the property, and it stays true as other terms are added.
    #[test]
    fn v4_f1_a_pending_claim_covers_both_request_id_copies_and_the_peer_name() {
        let base = pending_operation_claim(0, 0, PendingClass::Single)
            .expect("the empty pending claim is representable");
        let longer_id = pending_operation_claim(64, 0, PendingClass::Single)
            .expect("a 64-byte request id is representable");
        let longer_peer = pending_operation_claim(0, 64, PendingClass::Single)
            .expect("a 64-byte peer name is representable");

        assert_eq!(
            accounted_bytes(longer_id) - accounted_bytes(base),
            128,
            "a request id is retained twice — the map's key and the cancellation's copy"
        );
        assert_eq!(
            accounted_bytes(longer_peer) - accounted_bytes(base),
            64,
            "the peer name the cancellation copies is retained once"
        );

        let stream = pending_operation_claim(0, 0, PendingClass::Stream)
            .expect("the streaming pending claim is representable");
        assert!(
            accounted_bytes(stream) > accounted_bytes(base),
            "a stream additionally retains its inbox allocation, whose size this \
             module can take — unlike a oneshot's, which stays a residual"
        );
    }

    /// One short request id per operation, every id the same width.
    ///
    /// The claim charges the request id *twice*, so an id one byte longer costs
    /// two bytes more. Any control that fills a session with ids of one width
    /// and then probes it with another is measuring the difference between the
    /// two widths as much as the release it meant to measure — a shorter probe
    /// can slip into capacity a longer one could not. Every key below comes from
    /// here, so the only variable is the number of operations.
    fn fixed_width_id(index: u32) -> String {
        format!("id-{index:010}")
    }

    /// A request id that is deliberately longer, and nothing else different.
    ///
    /// The extra width is a parameter rather than a constant here because the
    /// margin this control needs is a property of what the session has left at
    /// the moment it probes, not of the id. It is measured at the call site;
    /// see [`accounted_bytes_free`] and the comment where it is used.
    fn wide_id(index: u32, extra: usize) -> String {
        format!("{}{}", fixed_width_id(index), "x".repeat(extra))
    }

    /// How much accounted memory this session can still hand out.
    ///
    /// Asked of the provider by requesting something it cannot give: the answer
    /// wanted is not a lease but the pressure report, which names the dimension
    /// that bound and the exact numbers it bound on. The provider accounts one
    /// flat `in_use` against one flat grant, so `capacity - in_use` in a
    /// dimension is that dimension's free amount and not an upper bound on it.
    fn accounted_bytes_free(session: &crate::runtime::session_broker::SessionCapability) -> u64 {
        use crate::resource::{ResourceClaim, ResourceUnavailable};

        match session.reserve_retained(ResourceClaim::single(
            ResourceClass::AccountedMemoryBytes,
            u64::MAX,
        )) {
            Ok(_) => panic!("a claim of u64::MAX accounted bytes cannot be satisfied"),
            Err(ResourceUnavailable::Pressure(pressure)) => {
                assert_eq!(
                    pressure.dimension,
                    ResourceClass::AccountedMemoryBytes,
                    "the probe asks for one byte of every other dimension at most, \
                     so anything but accounted memory refusing it means the session \
                     is out of something this control is not measuring"
                );
                pressure.capacity.checked_sub(pressure.in_use).expect(
                    "a provider reports no more accounted memory in use than it has \
                     capacity for",
                )
            }
            Err(other) => panic!("the probe was refused for an unusable reason: {other:?}"),
        }
    }

    /// What one short pending operation costs this session in accounted memory.
    ///
    /// Both of them: `claim_request_id` takes two reservations, one for the
    /// operation's own retention and one for the map node, and each carries the
    /// provider's bookkeeping record. Adding them here rather than measuring
    /// the operation alone is what makes the slack below the *whole* difference
    /// between the free amount and one more filing.
    fn short_operation_accounted_bytes() -> u64 {
        use crate::resource::FiniteResourceProvider;

        let operation = FiniteResourceProvider::reservation_planning_charge(
            pending_operation_claim(
                fixed_width_id(0).len(),
                "peer-under-test".len(),
                PendingClass::Single,
            )
            .expect("one ordinary pending operation is representable"),
        )
        .expect("one ordinary reservation is representable");
        let node = FiniteResourceProvider::reservation_planning_charge(
            crate::resource::LeasedMap::<String, PendingOp>::entry_claim()
                .expect("one map node is representable"),
        )
        .expect("one node reservation is representable");
        operation
            .amount(ResourceClass::AccountedMemoryBytes)
            .checked_add(node.amount(ResourceClass::AccountedMemoryBytes))
            .expect("two fixture reservations are representable together")
    }

    /// Settling one operation frees exactly one operation's worth of capacity,
    /// and a longer coordinate does not fit in what a shorter one released.
    ///
    /// Deliberately not written as "the report returns to its previous value":
    /// there is no report to read, and a control asserting one would be
    /// asserting about the accountant rather than about this module. What is
    /// observable is admission, so admission is what is measured.
    ///
    /// Three probes after the release, in this order, and each rules out a
    /// different failure:
    ///
    /// 1. **A wide id is refused.** How much wider is measured from the session
    ///    itself, so that one copy of the extra width fits in what is left and
    ///    two do not. If the request id were charged once instead of twice — or
    ///    not charged at all past the map key — the wide id would fit here, and
    ///    this is the assertion that catches that. It is the long-vs-short
    ///    admission pair, run against the production claim through the
    ///    production filing path rather than against the formula in isolation.
    /// 2. **A short id is admitted.** So the release happened at all, and the
    ///    refusal above was about the width and not about an empty session.
    /// 3. **A second short id is refused.** So the release was *one* operation's
    ///    worth and not more — a leak returning capacity nobody had charged
    ///    would pass (2) on its own.
    #[tokio::test]
    async fn v4_f1_b_settling_one_pending_operation_releases_exactly_one_short_operation() {
        let session =
            crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test());
        let mut pending = SessionRpcState::new();
        let peer = "peer-under-test";

        let mut filed = Vec::new();
        // Bounded so a fixture that funded everything fails as an assertion
        // rather than as a test that never returns.
        for index in 0..4096u32 {
            let (tx, _rx) = oneshot::channel();
            match pending.claim_request_id(
                &fixed_width_id(index),
                peer,
                &session,
                PendingEntry::Single(tx),
            ) {
                Ok(request) => filed.push(request),
                Err(_refusal) => break,
            }
        }
        assert!(
            !filed.is_empty(),
            "the fixture session funds at least one pending operation"
        );
        assert!(
            filed.len() < 4096,
            "the fixture session's grant is finite, so filling it must end in a refusal"
        );

        // Settle exactly one, releasing its node and its own retention.
        let settled = filed.pop().expect("at least one was filed");
        drop(
            pending
                .take_single_response(&settled.request_id)
                .expect("the operation this control filed is still pending"),
        );
        drop(settled);

        // (1) The wider coordinate does not fit in what a short one released.
        //
        // How much wider is measured here rather than fixed, and the earlier
        // fixed width is why. The fill loop above stops at its *first* refusal,
        // in whichever dimension binds first — which need not be accounted
        // memory at all. When it is not, the accounted bytes left over are
        // unrelated to one operation's size and can exceed it by any amount, so
        // a width chosen from the operation's own cost was simply paid for out
        // of the leftovers and admitted.
        //
        // So the boundary is read off the session instead. `slack` is exactly
        // what remains after one more short filing, and the extra width is set
        // so that the *second* copy of the id is what does not fit:
        //
        // - charged twice, as production charges it, the wide filing costs
        //   `2 × extra` more than a short one, and `2 × (slack / 2 + 1) > slack`
        //   for every `slack`, so it is refused;
        // - charged once, which is the regression this control exists to catch,
        //   it costs `extra` more, and `slack / 2 + 1 ≤ slack` whenever
        //   `slack ≥ 2`, so it would be admitted and this assertion would fail.
        //
        // Both arms compare against the same measured numbers, so the boundary
        // moves with the accounting rather than restating a version of it.
        let free = accounted_bytes_free(&session);
        let short = short_operation_accounted_bytes();
        let slack = free.checked_sub(short).expect(
            "settling one short operation leaves room for exactly one more, so the \
             free accounted bytes cover one short filing",
        );
        assert!(
            slack >= 2,
            "non-vacuity: the width below discriminates one copy from two only \
             when at least two accounted bytes separate the free amount from one \
             short filing, and {slack} do not"
        );
        let extra = usize::try_from(slack / 2 + 1).expect("a fixture slack fits a usize");

        let (tx, _rx) = oneshot::channel();
        // Matched rather than `is_err`: which dimension refused is the whole
        // claim. A refusal on residual allocations would be a different fact
        // about a session that had run out of something else — the wide and
        // short ids allocate identically, two id buffers and one peer buffer
        // each, so the only dimension their costs differ in is this one.
        let refusal = match pending.claim_request_id(
            &wide_id(9000, extra),
            peer,
            &session,
            PendingEntry::Single(tx),
        ) {
            Ok(_) => panic!(
                "one short operation's retention does not fund a longer request id — \
                 which it would appear to if the id were charged once rather than for \
                 both the map key and the caller's cancellation copy"
            ),
            Err(refused) => refused,
        };
        assert!(
            matches!(
                refusal,
                RpcRegistrationRefusal::ResourceUnavailable(
                    crate::resource::ResourceUnavailable::Pressure(pressure)
                ) if pressure.dimension == ResourceClass::AccountedMemoryBytes
            ),
            "the wider id is refused for the accounted bytes its second copy needs"
        );

        // (2) The same-width coordinate does.
        let (tx, _rx) = oneshot::channel();
        // Matched rather than `expect`: the refusal hands back the
        // `PendingEntry` it could not file, which owns the caller's oneshot, and
        // giving that a `Debug` so a test can print one is production surface
        // added for a test's benefit.
        let readmitted = match pending.claim_request_id(
            &fixed_width_id(9001),
            peer,
            &session,
            PendingEntry::Single(tx),
        ) {
            Ok(readmitted) => readmitted,
            Err(_) => {
                panic!("settling one short operation funds exactly one short operation")
            }
        };

        // (3) And only one.
        let (tx, _rx) = oneshot::channel();
        assert!(
            pending
                .claim_request_id(
                    &fixed_width_id(9002),
                    peer,
                    &session,
                    PendingEntry::Single(tx)
                )
                .is_err(),
            "settling one operation released one operation's retention, not more"
        );
        drop(readmitted);
    }

    /// Local insertion never displaces an existing pending owner.
    ///
    /// The unsafe shape this rules out is `pending.insert(id, ..)`,
    /// which overwrites silently: the displaced caller's oneshot is
    /// dropped, so it resolves to `NetworkDown` for a request that
    /// was in fact sent and may well be answered, and the reply that
    /// does arrive is then handed to the wrong receiver.
    ///
    /// Production draws the id randomly. The control supplies it
    /// directly, so the collision is certain rather than
    /// astronomically improbable, and it drives the same
    /// `claim_request_id` step every local registration drives.
    #[tokio::test]
    async fn v4_arc04_session_request_id_collision_never_displaces_existing_owner() {
        let session =
            crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test());
        let mut pending = SessionRpcState::new();

        // The incumbent: one pending single-response call bound to A.
        let (incumbent_tx, incumbent_rx) = oneshot::channel();
        let request_id = pending
            .register_local_request(
                "peer-under-test",
                &session,
                PendingEntry::Single(incumbent_tx),
            )
            .expect("the session funds the incumbent")
            .request_id;

        // A second local call collides on that exact id through the prepared
        // form production uses.
        let refusal = match pending.claim_request_id_prepared::<Streaming>(
            &request_id.clone(),
            "peer-under-test",
            &session,
        ) {
            Ok(_) => panic!("an already-owned request id is never claimed twice"),
            Err(refusal) => refusal,
        };
        assert!(
            matches!(refusal, RpcRegistrationRefusal::RequestIdCollision),
            "and it is told the id collided — not that the session was gone or \
             that the owner was short, which are the two facts this refusal used \
             to be reported as"
        );

        // The incumbent still owns the id, under its original
        // binding and class.
        settle_funded(
            pending
                .take_single_response(&request_id)
                .expect("the incumbent was not displaced by the collision"),
            &session,
            serde_json::json!("mine"),
        );
        // Bound rather than guarded: `into_result` consumes the funded
        // payload, and a match guard may not move out of its binding.
        let funded = incumbent_rx
            .await
            .expect("the incumbent's caller is still waiting");
        let response = funded.into_result().expect("a body, not an error");
        assert_eq!(
            response.body,
            serde_json::json!("mine"),
            "and its own caller receives its own response"
        );
    }

    /// The funded class and the stored entry are the same operation, on both
    /// shapes.
    ///
    /// The invariant [`PendingShape`] exists to make unrepresentable, asserted
    /// where it is observable. Before the shape, the filing took a
    /// [`PendingClass`] beside a closure returning an arbitrary
    /// [`PendingEntry`], and only a `debug_assert_eq!` stood between them — so a
    /// release build could fund a `Single` and store a `Stream`, and the entry
    /// would then be settled by frames the claim never paid for. `accepts` is
    /// the observable: it answers on the stored entry's class, so a filing whose
    /// two halves disagreed would answer for the class it was *not* funded as.
    #[tokio::test]
    async fn a_filed_operation_is_stored_as_the_class_it_was_funded_as() {
        let session =
            crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test());
        let mut pending = SessionRpcState::new();
        let peer = "peer-under-test";

        let (unary, _rx) = pending
            .claim_request_id_prepared::<Unary>(&fixed_width_id(0), peer, &session)
            .expect("the fixture session funds one unary operation");
        let (streaming, _inbox) = pending
            .claim_request_id_prepared::<Streaming>(&fixed_width_id(1), peer, &session)
            .expect("and one streaming operation");

        assert!(
            pending.accepts(&unary.request_id, PendingClass::Single)
                && !pending.accepts(&unary.request_id, PendingClass::Stream),
            "a unary filing is stored as a unary operation and nothing else"
        );
        assert!(
            pending.accepts(&streaming.request_id, PendingClass::Stream)
                && !pending.accepts(&streaming.request_id, PendingClass::Single),
            "and a streaming filing as a streaming one"
        );
    }

    /// The bound device survives a collision unchanged: a colliding
    /// draw must not repoint an existing entry at the new caller's
    /// peer, which would let that peer settle the incumbent's call.
    #[tokio::test]
    async fn v4_arc04_session_collision_preserves_incumbent_class() {
        let session =
            crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test());
        let mut pending = SessionRpcState::new();

        let (incumbent_tx, _incumbent_rx) = oneshot::channel();
        let request_id = pending
            .register_local_request(
                "peer-under-test",
                &session,
                PendingEntry::Single(incumbent_tx),
            )
            .expect("the session funds the incumbent")
            .request_id;

        let (challenger_tx, _challenger_rx) = oneshot::channel();
        let _ = pending.claim_request_id(
            &request_id.clone(),
            "peer-under-test",
            &session,
            PendingEntry::Single(challenger_tx),
        );

        assert!(
            pending.take_single_response(&request_id).is_some(),
            "the incumbent entry and class survive the collision"
        );
    }

    /// Each refusal reaches the caller as its own error.
    ///
    /// The mapping *is* the finding. Registration always knew which of these
    /// had happened; `call` and `call_stream` threw that away and reported
    /// [`RpcError::RequestIdUnavailable`] for all of them. So an embedder whose
    /// peer had no session yet, and one whose resource owner was full, were
    /// both told to worry about a 96-bit request-id draw — specific, actionable
    /// and wrong in both cases.
    ///
    /// Asserted as three distinct discriminants rather than three exact
    /// strings: what must hold is that a caller can tell them apart, not how
    /// they are worded.
    #[test]
    fn each_registration_refusal_reaches_the_caller_as_its_own_error() {
        let session_gone = RpcRegistrationRefusal::SessionNotCurrent.into_rpc_error("peer-a");
        let collided = RpcRegistrationRefusal::RequestIdCollision.into_rpc_error("peer-a");
        // `Unrepresentable` rather than `ResourceUnavailable(_)`, which would
        // need a provider refusal constructed by hand. They share an arm, so
        // this covers the same discriminant without a fabricated refusal.
        let unfunded = RpcRegistrationRefusal::Unrepresentable.into_rpc_error("peer-a");

        assert!(matches!(session_gone, RpcError::SessionNotCurrent(ref p) if p == "peer-a"));
        assert!(matches!(collided, RpcError::RequestIdUnavailable));
        assert!(matches!(unfunded, RpcError::ResourceUnavailable(_)));

        // And the one that used to answer for all three still answers for
        // exactly one. Without this the control would pass against a mapping
        // that had merely renamed the single answer.
        assert_eq!(
            [&session_gone, &collided, &unfunded]
                .into_iter()
                .filter(|e| matches!(e, RpcError::RequestIdUnavailable))
                .count(),
            1,
            "only the collision is a request-id problem"
        );
    }

    /// A stale abandonment never removes the reinstalled owner of a
    /// recycled request id.
    ///
    /// The shape this rules out: operation A files an entry and its
    /// outbound send fails, but by the time the abandonment runs A's
    /// entry has already left the map — a response raced the failing
    /// send and settled it — and the id has been redrawn by a fresh
    /// operation C to the *same* device in the *same* response
    /// class. Every coordinate the old removal predicate looked at,
    /// key and bound device and class, is identical between A and C,
    /// so it removed C: a live operation, whose caller was then left
    /// on a oneshot no inbound frame could reach any more. That is a
    /// local caller silently losing its own call, and the peer that
    /// can trigger it is whichever one answers fast enough to win
    /// the race against a failing send.
    ///
    /// Everything but the identity is deliberately held equal here,
    /// so identity is the only thing that can tell A from C.
    /// Production draws the id randomly; the control supplies it, so
    /// the recycling is certain rather than astronomically
    /// improbable, and both registrations go through the same
    /// `claim_request_id` step production goes through.
    #[tokio::test]
    async fn v4_arc04g1_a_stale_abandonment_never_removes_the_reinstalled_owner_of_a_recycled_id() {
        let session =
            crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test());
        let mut pending = SessionRpcState::new();
        let request_id = "recycled-request-id".to_string();

        // A: filed, and about to have its send fail. Unwrapped by
        // hand rather than with `expect`, which would format the
        // error: the refusal case hands back a `PendingEntry`, and
        // that is a live oneshot or mpsc sender, not something with
        // a `Debug` rendering to print.
        let (stale_tx, stale_rx) = oneshot::channel();
        let Ok(stale) = pending.claim_request_id(
            &request_id.clone(),
            "peer-under-test",
            &session,
            PendingEntry::Single(stale_tx),
        ) else {
            panic!("the id starts free");
        };

        // A's entry leaves the map before the abandonment runs.
        drop(
            pending
                .take_single_response(&request_id)
                .expect("A's own entry settles under A's own binding"),
        );
        assert!(
            stale_rx.await.is_err(),
            "A is gone, and its caller is resolved either way — the failed send \
             is about to answer it with a transport error"
        );

        // C: a fresh call redraws the same id, to the same device,
        // in the same class.
        let (fresh_tx, fresh_rx) = oneshot::channel();
        let Ok(reinstalled) = pending.claim_request_id(
            &request_id.clone(),
            "peer-under-test",
            &session,
            PendingEntry::Single(fresh_tx),
        ) else {
            panic!("the recycled id is free again");
        };
        assert!(
            !stale.op_id.names(&reinstalled.op_id),
            "two registrations never share an identity — A is still holding its \
             own, so C could not have been given it — and here that is the only \
             coordinate that differs at all"
        );

        // A's abandonment finally runs, naming A's entry.
        pending.abandon_local_request(&stale);

        // C survives it, still bound as it was filed, and settles.
        settle_funded(
            pending
                .take_single_response(&request_id)
                .expect("C is still pending: the stale abandonment named A's entry, not C's"),
            &session,
            serde_json::json!("mine"),
        );
        let funded = fresh_rx.await.expect("C's caller is still waiting");
        let response = funded.into_result().expect("a body, not an error");
        assert_eq!(
            response.body,
            serde_json::json!("mine"),
            "and C's own caller receives C's own response"
        );
    }

    /// Abandonment still withdraws the entry that filed it.
    ///
    /// The guard on the control above: a predicate that matched
    /// nothing at all would satisfy it just as well. This pins the
    /// other half — a caller whose send failed still removes its own
    /// entry, so a failed call leaves nothing pending behind it.
    #[tokio::test]
    async fn v4_arc04g1_abandonment_withdraws_the_operation_that_filed_it() {
        let session =
            crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test());
        let mut pending = SessionRpcState::new();

        let (tx, _rx) = oneshot::channel();
        let filed = pending
            .register_local_request("peer-under-test", &session, PendingEntry::Single(tx))
            .expect("the call is filed");

        pending.abandon_local_request(&filed);

        assert!(
            pending.take_single_response(&filed.request_id).is_none(),
            "the abandoned entry is gone, so a late response finds nothing to settle"
        );
    }
}

#[cfg(test)]
mod session_ownership_tests {
    use super::*;

    fn session() -> crate::runtime::session_broker::SessionCapability {
        crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test())
    }

    /// **Review control 4 of 4.** An effect taken out of the pending map stays
    /// funded until it is answered, and equally until it is dropped unanswered.
    ///
    /// Extraction and use are two steps with the map's guard released between
    /// them, so for that whole interval the operation's claim is held by
    /// nothing but the `Extracted` value in flight. The shape this replaced
    /// handed back a `(sender, PendingOpId)` pair and asked in a comment that
    /// the second half be bound to a live name; a caller that wrote `_` instead
    /// released the claim while still holding the sender, and no type said
    /// otherwise.
    ///
    /// What is in flight is the *operation's* claim and not the map's. Filing
    /// charges both the pending entry's node and the operation, and
    /// `take_single_response` removes the entry — so it hands the node back at
    /// the same moment it hands the effect out. The reading this control follows
    /// is therefore taken after the extraction, not before it: an `Extracted`
    /// that still owed the node would be a claim on storage the map no longer
    /// has.
    ///
    /// And "held by nothing but the `Extracted`" has to be made true before it
    /// can be observed. [`PendingOpId`] is a `FundedArc`, so the filing hands
    /// the caller a second handle on the same reservation; a control that kept
    /// its `LocalRequest` alive to the end would be watching a claim two owners
    /// were holding and could never see it returned. The caller's handle is
    /// therefore dropped as soon as the extraction that needed its `request_id`
    /// has returned, which is also what a real caller does: it files, sends
    /// under the routing key, and stops naming the operation once something
    /// else owns the answer.
    ///
    /// Both arms are here because they fail differently. The answered arm would
    /// pass even if `answer` released the funding *before* the send, and it
    /// cannot be sharpened from the ledger: the settled result carries a
    /// *different* claim — a body retention the fixture reserves separately —
    /// so a reading taken with the response in the caller's channel is not
    /// comparable to the one taken with the effect in flight. The dropped arm
    /// is the one that catches a funding released only on the success path: a
    /// caller that extracts and then abandons the operation must return exactly
    /// what it took.
    #[tokio::test]
    async fn v4_r3_core_f1_an_extracted_effect_stays_funded_until_it_is_answered_or_dropped() {
        for answer_it in [true, false] {
            let (session, provider) = crate::runtime::session_broker::session_and_provider_for_test(
                crate::runtime::runtime_for_test(),
                ResourceClaim::ZERO,
            );
            let mut pending = SessionRpcState::new();
            let idle = provider.in_use();
            let (tx, rx) = oneshot::channel();
            let filed = pending
                .register_local_request("peer-under-test", &session, PendingEntry::Single(tx))
                .expect("the session funds one pending unary");
            let filed_charge = provider.in_use();
            assert_ne!(
                filed_charge, idle,
                "filing must actually charge something, or this control observes \
                 nothing"
            );

            let extracted = pending
                .take_single_response(&filed.request_id)
                .expect("the exact session owns the response");
            // The caller's own handle is released here, and this line is the
            // control rather than tidiness. `PendingOpId` is a `FundedArc`, so
            // the map entry, the caller's `LocalRequest` and the extracted
            // effect all held clones of *one* reservation, which goes back only
            // when the last of them is gone. Left alive, `filed` would make this
            // control's own subject false — the claim would be held by two
            // owners across the guard gap, and the arms below could not tell a
            // funding the effect returned from one `filed` was still paying for.
            drop(filed);

            // The map entry is gone and its node went back with it, so this is
            // no longer `filed_charge`. What remains is the operation's own
            // claim, held by nothing but the `Extracted` value in flight. Named
            // rather than compared inline because the two facts worth asserting
            // about it are different: that it is not nothing, and that it is not
            // the filed total.
            let extracted_live = provider.in_use();
            assert_ne!(
                extracted_live, idle,
                "the map entry is gone but the operation's claim is not — the \
                 extracted effect is what holds it now"
            );
            assert_ne!(
                extracted_live, filed_charge,
                "non-vacuity: and the take really did release the entry's node, \
                 so this is the in-flight claim rather than the filed total"
            );

            if answer_it {
                super::tests::settle_funded(extracted, &session, serde_json::json!(1));
                let funded = rx.await.expect("the caller is still waiting");
                drop(funded);
            } else {
                drop(extracted);
                assert!(
                    rx.await.is_err(),
                    "an abandoned operation closes its caller's channel"
                );
            }
            assert_eq!(
                provider.in_use(),
                idle,
                "the operation returns exactly what it took, whether it was \
                 answered or abandoned"
            );
        }
    }

    /// A stream terminal is still funded after the inbox has handed it over, and
    /// stops being funded exactly where its owner says so.
    ///
    /// The blocker this closes is an interval, not a leak. `finish_owned` funds
    /// peer-chosen text and stores it; taking the terminal used to call
    /// `into_owned()` and drop the lease in one expression, so from that instant
    /// the text was live in whatever task had received it — a daemon about to
    /// forward it — with no owner at all. The writer mailbox that would
    /// eventually pay for it does not measure until later, so the unfunded
    /// window was exactly the forwarding path.
    ///
    /// Both halves are asserted because only together do they say the boundary
    /// moved rather than disappeared: the charge survives the pop, and the
    /// documented public conversion still ends it. A wrapper that never released
    /// would pass the first and fail the second, and is not the shape the review
    /// asked for — applications are not required to hold a resource wrapper
    /// forever.
    #[tokio::test]
    async fn v4_r4_core_f3_a_stream_terminal_stays_funded_until_its_owner_releases_it() {
        for convert in [true, false] {
            let (session, provider) = crate::runtime::session_broker::session_and_provider_for_test(
                crate::runtime::runtime_for_test(),
                ResourceClaim::ZERO,
            );
            let inbox = RpcStreamInbox::new();
            let idle = provider.in_use();

            // Owned, and long enough to be worth funding: a borrowed reason this
            // module wrote carries no lease, and a control built on one would
            // observe nothing.
            let reason = "the peer ended this stream with a reason it chose the length of";
            inbox.finish_owned(&session, reason.to_string());
            let funded = provider.in_use();
            assert_ne!(
                funded, idle,
                "non-vacuity: the terminal text must actually have been charged, \
                 or the fixture funded nothing and every assertion below is \
                 about a lease that does not exist"
            );

            let terminal = inbox
                .recv_funded()
                .await
                .expect("a settled stream yields its terminal")
                .expect_err("and the terminal is the error half, not a chunk");
            assert_eq!(
                provider.in_use(),
                funded,
                "the pop did not release the charge — this is the interval the \
                 forwarding path lives in, and the wrapper is what holds it now"
            );
            assert_eq!(
                terminal.reason(),
                reason,
                "and the reason is readable by borrow while it is still funded, \
                 which is what lets a forwarder measure and encode it"
            );

            if convert {
                let owned = terminal.into_reason();
                assert_eq!(
                    owned, reason,
                    "the application-owned conversion yields the same text"
                );
                assert_eq!(
                    provider.in_use(),
                    idle,
                    "and that conversion is the declared end of core's ownership"
                );
            } else {
                drop(terminal);
                assert_eq!(
                    provider.in_use(),
                    idle,
                    "a terminal dropped unconverted returns exactly what it held"
                );
            }
        }
    }

    /// What a chunk reports as already funded is what the provider is already
    /// holding for it.
    ///
    /// The work-conservation half. A forwarder queues an admitted chunk onward
    /// inside a larger frame, and the payload graph is *moved* into that frame
    /// rather than copied — so an outer mailbox that measures the whole frame
    /// and charges all of it bills the process grant twice for one live tree.
    /// `funded_claim` is what the outer owner subtracts, and it is only safe to
    /// subtract if it is exactly the reservation still outstanding.
    ///
    /// Measured against the provider rather than against a restatement of the
    /// formula: comparing `funded_claim` to a second copy of the same arithmetic
    /// would pass however wrong both were. The node is deliberately not in the
    /// comparison — `pop` already returned it — so this reads the retention
    /// alone, which is the part that is still live and therefore the part a
    /// second charge would duplicate.
    #[tokio::test]
    async fn v4_r4_core_f3_a_chunks_funded_claim_is_what_the_provider_still_holds() {
        // The payload exists before the grant that funds it, and the grant is
        // measured from that exact payload by the exact path `push` measures it
        // with. Sizing it any other way would be sizing the fixture to the
        // assertion: a guessed margin makes the control pass whether or not
        // `funded_claim` agrees with what was reserved, which is the one thing
        // it is here to check.
        //
        // The retention alone, and no node. `session_and_provider_for_test`
        // already composes `fixture_stream_retention_claim()` into its baseline,
        // so the queue node is funded; the payload's own retention was the
        // reservation the provider refused. It is passed bare because that
        // helper wraps it in `reservation_charge_for_test` itself, so adding the
        // provider record here would charge it twice.
        let payload = serde_json::json!({"chunk": [1, 2, 3]});
        type ChunkMailbox = crate::application_gateway::GatewayMailbox<serde_json::Value>;
        let (retained, queued, allocations) =
            mailbox_measure_serialized(&payload).expect("a payload that exists is measurable");
        let payload_retention = ChunkMailbox::retention_claim(retained, queued, allocations)
            .expect("a measured payload has a representable claim");
        let (session, provider) = crate::runtime::session_broker::session_and_provider_for_test(
            crate::runtime::runtime_for_test(),
            payload_retention,
        );
        let inbox = RpcStreamInbox::new();
        let idle = provider.in_use();
        inbox
            .push(&session, payload)
            .expect("the fixture session funds one stream chunk");

        let chunk = inbox
            .recv_funded()
            .await
            .expect("the pushed chunk is delivered")
            .expect("and it is a chunk, not a terminal");
        let held = provider.in_use();
        assert_ne!(
            held, idle,
            "non-vacuity: the delivered chunk is still funded, so there is a \
             reservation for the outer owner to avoid charging twice"
        );
        // Two different quantities, and the difference between them is the
        // point rather than an inconvenience. `funded_claim` is the *bare*
        // payload claim — what a second owner would duplicate if it charged the
        // tree again — while the provider's ledger also carries its own
        // per-reservation bookkeeping record, one `OpaqueDependencyResidual`
        // that exists because a reservation exists and not because the payload
        // does. So the comparison is against the canonical charge for that bare
        // claim, computed by the provider's own function rather than by adding a
        // constant here.
        //
        // The bare form is the one the seam must expose. A forwarder subtracts
        // `funded_claim` from its outer claim, and the outer claim contains the
        // payload it is about to stop double-charging — it does not contain this
        // provider's reservation record, which belongs to a reservation the
        // forwarder never took. Subtracting the charged form there would remove
        // a residual nothing in the outer claim ever added.
        let bare = chunk
            .funded_claim()
            .expect("a delivered chunk's payload is measurable");
        let charged = crate::resource::FiniteResourceProvider::reservation_charge_for_test(bare)
            .expect("one reservation of a measured payload is representable");
        assert_eq!(
            held.checked_sub(idle)
                .expect("the outstanding charge is the difference from idle"),
            charged,
            "what a forwarder must not charge again is exactly what is still \
             outstanding for this chunk, once the provider's own record of \
             holding it is accounted for"
        );

        drop(chunk);
        assert_eq!(
            provider.in_use(),
            idle,
            "and it was the chunk holding it: the amount it reported is the \
             amount that goes back"
        );
    }

    #[tokio::test]
    async fn pending_unary_settles_only_from_its_session_record() {
        let session = session();
        let mut pending = SessionRpcState::new();
        let (tx, rx) = oneshot::channel();
        let filed = pending
            .register_local_request("peer-under-test", &session, PendingEntry::Single(tx))
            .expect("the session funds one pending unary");
        super::tests::settle_funded(
            pending
                .take_single_response(&filed.request_id)
                .expect("the exact session owns the response"),
            &session,
            serde_json::json!(7),
        );
        let funded = rx.await.expect("the caller is still waiting");
        let response = funded.into_result().expect("a body, not an error");
        assert_eq!(response.body, serde_json::json!(7));
    }

    #[tokio::test]
    async fn pending_quiescence_observation_preserves_exact_requests() {
        let session = session();
        let mut pending = SessionRpcState::new();
        assert!(pending.pending_is_empty());
        let (tx_a, rx_a) = oneshot::channel();
        let first = pending
            .register_local_request("peer-under-test", &session, PendingEntry::Single(tx_a))
            .expect("existing session funds the first request");
        let (tx_b, rx_b) = oneshot::channel();
        let second = pending
            .register_local_request("peer-under-test", &session, PendingEntry::Single(tx_b))
            .expect("existing session funds the second request");
        assert!(!pending.pending_is_empty());
        assert!(
            !pending.pending_is_empty(),
            "observation does not consume state"
        );
        assert!(pending.still_holds(&first));
        assert!(pending.still_holds(&second));
        pending.abandon_local_request(&first);
        assert!(
            !pending.pending_is_empty(),
            "the other exact request is live"
        );
        assert!(rx_a.await.is_err());
        pending.abandon_local_request(&second);
        assert!(pending.pending_is_empty());
        assert!(rx_b.await.is_err());
    }

    #[tokio::test]
    async fn dropping_replaced_session_rpc_state_resolves_pending_call() {
        let session = session();
        let (tx, rx) = oneshot::channel();
        let mut pending = SessionRpcState::new();
        pending
            .register_local_request("peer-under-test", &session, PendingEntry::Single(tx))
            .expect("the session funds one pending unary");
        drop(pending);
        assert!(rx.await.is_err(), "retirement drops the exact sender");
    }

    #[tokio::test]
    async fn caller_cancellation_removes_only_the_filed_operation() {
        let session = session();
        let (tx, rx) = oneshot::channel();
        let mut pending = SessionRpcState::new();
        let filed = pending
            .register_local_request("peer-under-test", &session, PendingEntry::Single(tx))
            .expect("the session funds one pending unary");
        let request_id = filed.request_id.clone();
        pending.abandon_local_request(&filed);
        assert!(pending.take_single_response(&request_id).is_none());
        assert!(rx.await.is_err(), "cancellation drops the exact sender");
    }

    #[tokio::test]
    async fn stream_is_ordered_and_popped_value_keeps_its_lease() {
        let session = session();
        let inbox = Arc::new(RpcStreamInbox::new());
        let mut pending = SessionRpcState::new();
        let filed = pending
            .register_local_request(
                "peer-under-test",
                &session,
                PendingEntry::Stream(Arc::clone(&inbox)),
            )
            .expect("the session funds one pending stream");
        let first = pending
            .stream_chunk_sender(&filed.request_id, 1)
            .expect("sequence one is accepted");
        assert!(first.push(&session, serde_json::json!("one")).is_ok());
        assert!(
            pending.stream_chunk_sender(&filed.request_id, 3).is_none(),
            "a gap is not delivered as ordinary data"
        );
        let delivery = inbox.recv_funded().await.expect("one item").expect("chunk");
        assert_eq!(delivery, serde_json::json!("one"));
        drop(delivery);
    }

    #[tokio::test]
    async fn stream_finish_in_the_check_to_wait_window_cannot_be_lost() {
        let inbox = RpcStreamInbox::new();
        let finisher = &inbox;
        let terminal = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            inbox.recv_funded_with_before_wait(move || {
                finisher.finish_borrowed(Some("terminal in the wait window"));
            }),
        )
        .await
        .expect("the registered stream waiter observes terminal state");
        assert!(matches!(
            terminal,
            Some(Err(ref terminal)) if terminal.reason() == "terminal in the wait window"
        ));
    }

    /// An oversized payload is refused, and refused **for its size**.
    ///
    /// The two pushes around the refusal are what make that attributable. This
    /// control used to assert the refusal alone, against a fixture whose grant
    /// named no `QueuedBytes` at all: a five-byte payload was refused there for
    /// exactly the same reason a sixteen-mebibyte one was, so it passed while
    /// proving nothing about pressure. It would have kept passing under any
    /// repair.
    ///
    /// So: a small payload must be admitted first, from the same session and
    /// the same funded fixture, and a second small payload must still be
    /// admitted *after* the refusal. The first rules out a grant that funds no
    /// retention; the second rules out a grant whose last slot the first push
    /// consumed — the only two ways this refusal could be about something other
    /// than the payload's size. The fixture funds exactly two retained items
    /// (`FIXTURE_STREAM_ITEMS`), which is what leaves the second push room.
    ///
    /// The refusal is asserted **by kind**, not merely as a failure. `push`
    /// answers `Pressure` and `Malformed` separately, and only `Pressure` says
    /// what this control is named for; asserting the negation alone would keep
    /// passing if an oversized payload started being reported as unrepresentable
    /// instead of unfunded.
    #[test]
    fn stream_pressure_refuses_without_queueing() {
        use crate::application_gateway::GatewayRefusal;

        let session = session();
        let inbox = RpcStreamInbox::new();

        assert!(
            inbox.push(&session, serde_json::json!("small")).is_ok(),
            "a payload inside the fixture's stated retention capacity is queued"
        );

        let oversized = serde_json::Value::String("x".repeat(16 * 1024 * 1024));
        assert!(
            matches!(
                inbox.push(&session, oversized),
                Err(GatewayRefusal::Pressure(_))
            ),
            "a payload far past that capacity is refused, and refused as \
             pressure: the provider saw it and would not fund it"
        );

        assert!(
            inbox
                .push(&session, serde_json::json!("also small"))
                .is_ok(),
            "and the refusal was about the payload's size, not a slot: the \
             session still admits another small payload afterwards"
        );

        // Nothing the refused push touched was queued: exactly the two admitted
        // payloads are in the mailbox, in order, and then it is empty.
        let mut mailbox = inbox.mailbox.lock();
        assert_eq!(
            mailbox
                .pop()
                .expect("the first admitted payload")
                .into_parts()
                .0,
            serde_json::json!("small")
        );
        assert_eq!(
            mailbox
                .pop()
                .expect("the second admitted payload")
                .into_parts()
                .0,
            serde_json::json!("also small")
        );
        assert!(
            mailbox.is_empty(),
            "the refused push left no entry behind it"
        );
    }

    #[test]
    fn attach_elects_one_owner_and_rpc_does_not_keep_network_alive() {
        let state = crate::engine::build_test_state("rpc-weak-owner");
        let weak = Arc::downgrade(&state);
        let first = Rpc::attach(&state).expect("the fixture funds one dispatcher");
        let second = Rpc::attach(&state).expect("attach reuses the funded dispatcher");
        assert!(crate::resource::FundedArc::ptr_eq(
            &first.inner,
            &second.inner
        ));
        drop(state);
        assert!(weak.upgrade().is_none());
        assert!(first.inner.network.upgrade().is_none());
    }

    #[test]
    fn stale_registration_drop_cannot_remove_a_live_successor() {
        let state = crate::engine::build_test_state("rpc-registration-successor");
        let rpc = Rpc::attach(&state).expect("the fixture funds one dispatcher");

        let first = rpc
            .prepare_serve("successor", |_call| async {
                Ok(RpcResponse::from_value(serde_json::json!("first")))
            })
            .expect("the predecessor registration is funded");
        let first = first
            .commit()
            .into_result()
            .expect("the predecessor registration commits");

        let second = rpc
            .prepare_serve("successor", |_call| async {
                Ok(RpcResponse::from_value(serde_json::json!("second")))
            })
            .expect("the successor registration is funded");
        let second = second
            .commit()
            .into_result()
            .expect("the successor registration commits");

        drop(first);
        assert_eq!(
            rpc.registered_methods(),
            vec!["successor".to_string()],
            "dropping a stale registration cannot remove its live successor"
        );
        drop(second);
        assert!(
            rpc.registered_methods().is_empty(),
            "dropping the current registration removes exactly its own entry"
        );
    }
}
