//! Bytes on the wire, in both of the shapes this socket carries, and the
//! admission that funds them.
//!
//! Two framings, deliberately together. A control connection speaks
//! line-delimited JSON until it becomes a `realtime_pipe`, after which it speaks
//! `[u32 len][body]` and nothing else — so a connection uses one or the other,
//! never both at once, and the thing they share is the only interesting part:
//! every inbound byte is acquired from the process owner's grant before this
//! module buffers it. The one allocation that rule cannot reach is the reader's
//! own window, which the runtime has already filled before any code here runs;
//! it is funded once by the caller, before the reader exists, and named as such
//! rather than folded into this sentence. Splitting the two framings would have
//! put one admission rule in two files.
//!
//! Nothing here knows what a request means, what a network is, or which client
//! is asking. It reads bytes, refuses the ones nobody funded, and hands the rest
//! up. That is the whole of its authority: it decides *how much*, never *what*.

use anyhow::{Context, Result};
use tokio::io::AsyncBufReadExt;

/// Read one optional owner-selected byte ceiling.
///
/// Absent is a valid answer and the ordinary one: it means the owner has not
/// chosen to bound inbound frames more tightly than the grant already does.
/// Present but unparseable is not — an owner who set the value meant something
/// by it, and starting anyway would silently ignore a stated policy.
pub(super) fn optional_nonzero_bytes(name: &str) -> Result<Option<usize>> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        // Set, and not text. That is a stated policy this daemon cannot read,
        // which is a different thing from no policy — matching it against
        // `NotPresent` would start the daemon with the owner's bound silently
        // discarded, in the one case where they had definitely set one.
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{name} is set but is not valid Unicode")
        }
    };
    value
        .parse::<std::num::NonZeroUsize>()
        .with_context(|| format!("{name} must be a nonzero integer"))
        .map(|bytes| Some(bytes.get()))
}

/// What bounds the inbound frames of one control connection.
///
/// Two independent bounds, and only one of them is optional. The resource bound
/// always applies: nothing this connection retains is held without a lease, so
/// an absent ceiling means *admitted*, never *unbounded*. An explicit ceiling is
/// an additional owner policy layered on top, and it can only refuse more — a
/// number here can never admit something the provider would not.
///
/// "Admitted" is not one rule, because the inbound bytes are not one kind of
/// allocation. A *frame's* growth is funded per step at the capacity that step
/// is about to request, which tracks what the sender actually sent; the
/// connection's fixed read window is funded once, in full, before a single byte
/// has been read, because `fill_buf` copies into it before any code here can see
/// them. See [`AdmittedReader`] for the second, and [`read_bounded_json_line`]
/// for the first. Both pair their byte claim with an opaque residual, since
/// neither can state what an allocator will really reserve.
///
/// A ceiling alone would not be accounting: it says how large one frame may be
/// and nothing at all about how much the process is holding, so a thousand
/// connections each one byte under it would pass every check. That is why the
/// funding above is unconditional and the ceiling is optional owner policy.
#[derive(Clone)]
pub(super) struct FrameAdmission {
    owner: FrameOwner,
    ceiling: Option<usize>,
}

/// Where one connection's inbound funding comes from.
///
/// Production has exactly one answer: the local-application scope the daemon
/// issued for this connection. The second arm exists so a control can own a
/// provider small enough to refuse, which the production arm cannot give it --
/// the daemon test binary installs one process-global provider by design, so a
/// test that cornered it would starve every other test drawing on the same pool.
/// A locally constructed provider races nothing and is installed nowhere.
#[derive(Clone)]
enum FrameOwner {
    Application(myownmesh_core::LocalApplicationResourceScope),
    /// A provider this control owns outright. `Arc` because [`FrameAdmission`]
    /// is cloned per connection and neither half of the pair needs to be.
    #[cfg(test)]
    Direct(
        std::sync::Arc<(
            myownmesh_core::ResourceProviderPort,
            myownmesh_core::ResourceScope,
        )>,
    ),
}

/// Why one inbound frame was not admitted.
///
/// Three arms because an operator reads them differently: a ceiling refusal is
/// their own policy answering, a provider refusal is the daemon at the edge of
/// its grant, and an unrepresentable claim is a defect here. Reporting a
/// too-large frame and an out-of-capacity daemon as the same thing would send an
/// operator to change the wrong number.
#[derive(Debug, thiserror::Error)]
pub(super) enum FrameRefusal {
    #[error("frame of {frame} bytes exceeds the owner-selected ceiling of {ceiling} bytes")]
    Ceiling { frame: usize, ceiling: usize },
    #[error("frame byte claim is not representable: {0}")]
    Claim(myownmesh_core::ResourceClaimArithmeticError),
    #[error("frame bytes were refused by the resource provider: {0:?}")]
    Resources(myownmesh_core::ResourceUnavailable),
}

impl FrameAdmission {
    pub(super) fn new(
        resources: myownmesh_core::LocalApplicationResourceScope,
        ceiling: Option<usize>,
    ) -> Self {
        Self {
            owner: FrameOwner::Application(resources),
            ceiling,
        }
    }

    /// A connection funded by a provider this control owns.
    ///
    /// `grant` is the whole budget: sizing it just above or just below the claim
    /// under test is what makes a refusal attributable to that claim rather than
    /// to slack the fixture happened to have.
    #[cfg(test)]
    pub(super) fn over_grant(grant: myownmesh_core::ResourceClaim, ceiling: Option<usize>) -> Self {
        Self::over_grant_probed(grant, ceiling).0
    }

    /// [`Self::over_grant`], with the provider handed back so a control can read
    /// the ledger it is asserting about.
    ///
    /// The provider is *cloned*, not moved out: this admission keeps spending
    /// through its own port, and what comes back is a second handle onto the
    /// same accounting. A control that had to build its own provider to observe
    /// one would be observing a different provider than the one under test.
    #[cfg(test)]
    pub(super) fn over_grant_probed(
        grant: myownmesh_core::ResourceClaim,
        ceiling: Option<usize>,
    ) -> (Self, myownmesh_core::FiniteResourceProvider) {
        let provider = myownmesh_core::FiniteResourceProvider::new(grant);
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the control grant funds its own process scope");
        let scope = port.process_scope();
        (
            Self {
                owner: FrameOwner::Direct(std::sync::Arc::new((port, scope))),
                ceiling,
            },
            provider,
        )
    }

    /// Admit one whole frame of `bytes` and answer the funding that holds it.
    ///
    /// The lease must be held for as long as the frame's bytes are, and dropped
    /// when they are — that is the whole of the accounting, and holding it
    /// longer would report the daemon as fuller than it is.
    pub(super) fn admit(
        &self,
        bytes: usize,
    ) -> std::result::Result<myownmesh_core::ResourceLease, FrameRefusal> {
        self.admit_growth(0, bytes)
    }

    /// Admit `more` further bytes of a frame already holding `held` of them.
    ///
    /// The ceiling is checked against the total, because it bounds a frame and
    /// not a read; the claim is taken for the growth alone, because that is what
    /// is newly held. Checking the ceiling per chunk would let a line arrive in
    /// pieces and pass a bound it exceeded.
    pub(super) fn admit_growth(
        &self,
        held: usize,
        more: usize,
    ) -> std::result::Result<myownmesh_core::ResourceLease, FrameRefusal> {
        let overflow = || {
            FrameRefusal::Claim(myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            })
        };
        let frame = held.checked_add(more).ok_or_else(overflow)?;
        if let Some(ceiling) = self.ceiling {
            if frame > ceiling {
                return Err(FrameRefusal::Ceiling { frame, ceiling });
            }
        }
        let more = u64::try_from(more).map_err(|_| overflow())?;
        let claim = myownmesh_core::ResourceClaim::try_from_entries([(
            myownmesh_core::ResourceClass::AccountedMemoryBytes,
            more,
        )])
        .map_err(FrameRefusal::Claim)?;
        self.acquire_claim(claim)
    }

    /// Admit one growth step of a line under construction.
    ///
    /// Two quantities, deliberately not the same one. The **ceiling** is checked
    /// against `frame`, the logical length the line will have, because that is
    /// what an owner bounds. The **claim** is taken for `capacity`, the growth
    /// the caller is about to *request*, because that is what it is about to ask
    /// the allocator for. [`Self::admit_growth`] charges the logical length
    /// instead, which ignores the lease vector growing beside the line and says
    /// nothing about capacity at all.
    ///
    /// It does not claim to know what the allocator will really reserve; that is
    /// [`Self::admit_allocator_residual`]'s job, and keeping the two apart is
    /// what stops this one from inflating a byte count with a guess.
    pub(super) fn admit_buffer_growth(
        &self,
        frame: usize,
        capacity: usize,
    ) -> std::result::Result<myownmesh_core::ResourceLease, FrameRefusal> {
        if let Some(ceiling) = self.ceiling {
            if frame > ceiling {
                return Err(FrameRefusal::Ceiling { frame, ceiling });
            }
        }
        self.admit_allocation(capacity)
    }

    /// Fund one allocation this connection is about to make, with no ceiling.
    ///
    /// The owner's ceiling bounds a *frame*; it is not a statement about the
    /// substrate a connection needs in order to read one. Applying it here would
    /// mean a 1 KiB owner ceiling refused an 8 KiB socket read buffer, which is
    /// an operator setting one number and changing a different thing.
    ///
    /// Zero is admitted as a real, free lease rather than special-cased away:
    /// the caller then holds one lease per growth step unconditionally and has
    /// no branch in which funding is skipped.
    pub(super) fn admit_allocation(
        &self,
        bytes: usize,
    ) -> std::result::Result<myownmesh_core::ResourceLease, FrameRefusal> {
        let bytes = u64::try_from(bytes).map_err(|_| {
            FrameRefusal::Claim(myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            })
        })?;
        let claim = myownmesh_core::ResourceClaim::try_from_entries([(
            myownmesh_core::ResourceClass::AccountedMemoryBytes,
            bytes,
        )])
        .map_err(FrameRefusal::Claim)?;
        self.acquire_claim(claim)
    }

    /// Fund `allocations` live allocations whose exact size the allocator picks.
    ///
    /// Deliberately not a byte claim. The bytes a container is *asked* to hold
    /// are funded as bytes, before it is asked; what this names is the separate
    /// fact that an allocation exists at all and that its true size is not this
    /// code's to state. `OpaqueDependencyResidual` is the class for exactly that
    /// — a dependency the owner accounts for without claiming to have measured
    /// it — and using it here is what keeps the byte claims honest instead of
    /// inflating them with a guess at allocator behaviour.
    pub(super) fn admit_allocator_residual(
        &self,
        allocations: u64,
    ) -> std::result::Result<myownmesh_core::ResourceLease, FrameRefusal> {
        let claim = myownmesh_core::ResourceClaim::try_from_entries([(
            myownmesh_core::ResourceClass::OpaqueDependencyResidual,
            allocations,
        )])
        .map_err(FrameRefusal::Claim)?;
        self.acquire_claim(claim)
    }

    /// Fund the buffers one long-lived value owns, before it is built.
    ///
    /// The pair [`Self::admit_allocation`] and [`Self::admit_allocator_residual`]
    /// always travel together for a value that will be retained — the bytes it
    /// asks for, and the separate fact that they live in `allocations` separate
    /// heap blocks whose true size the allocator picks. Spelled once here so a
    /// caller cannot take one and forget the other, which is the shape of the
    /// under-charge this whole module exists to prevent.
    ///
    /// Two leases and not one, because the caller may need them to end at
    /// different moments; a caller that does not can drop them together.
    pub(super) fn admit_retained(
        &self,
        bytes: usize,
        allocations: u64,
    ) -> std::result::Result<
        (myownmesh_core::ResourceLease, myownmesh_core::ResourceLease),
        FrameRefusal,
    > {
        let bytes = self.admit_allocation(bytes)?;
        let allocations = self.admit_allocator_residual(allocations)?;
        Ok((bytes, allocations))
    }

    /// Acquire one already-derived claim against this connection's scope.
    ///
    /// For funding whose shape is decided elsewhere — the structural parse claim
    /// is core's derivation, not this module's — so the byte-only helpers above
    /// stay the only place that builds a claim out of a length.
    pub(super) fn acquire_claim(
        &self,
        claim: myownmesh_core::ResourceClaim,
    ) -> std::result::Result<myownmesh_core::ResourceLease, FrameRefusal> {
        match &self.owner {
            FrameOwner::Application(scope) => scope.acquire(claim),
            #[cfg(test)]
            FrameOwner::Direct(owned) => {
                let (port, scope) = owned.as_ref();
                port.acquire(
                    scope,
                    myownmesh_core::ResourceAuthorityClass::Admitted,
                    claim,
                )
            }
        }
        .map_err(FrameRefusal::Resources)
    }

    /// The widest frame this connection's framing may express.
    ///
    /// Only the owner's ceiling, because this answers a *representation*
    /// question — can the encoder write a length prefix for it — and the
    /// provider does not answer that one. With no owner ceiling the only bound
    /// is the wire's own `u32`, which the encoder checks separately and always.
    pub(super) fn framing_ceiling(&self) -> usize {
        self.ceiling.unwrap_or(usize::MAX)
    }
}

/// The read window one control connection holds while it is reading.
///
/// **A substrate cost, not a policy ceiling and not tunable.** It is the
/// capacity handed to the connection's `BufReader`, and it exists as a named
/// constant for one reason: `fill_buf` copies bytes into that allocation before
/// any admission code can see them, so it is the one inbound allocation that
/// cannot honestly be charged at the moment it is used. Naming it here means the
/// capacity is *requested* at a size this daemon chose and funded before the
/// reader exists -- rather than being an unmeasured library allocation the
/// daemon claims to have accounted for.
///
/// It is a request, not a measurement. `BufReader::with_capacity` reserves *at
/// least* this much and the allocator may round up, so the byte claim is paired
/// with one `OpaqueDependencyResidual` for the allocation itself, exactly as the
/// line buffers are. Neither half alone would be true.
///
/// It bounds no request. A line longer than this is read in several passes, each
/// funding the capacity it asks for; see [`read_bounded_json_line`].
pub(super) const CONTROL_READ_BUFFER_BYTES: usize = 8 * 1024;

/// The live allocations one control connection's reader holds: its single
/// buffer. Named rather than spelled `1` at the construction site so the number
/// and the thing it counts stay together, on the same pattern as the line
/// reader's pair.
const CONTROL_READ_ALLOCATIONS: u64 = 1;

/// A `BufReader` that owns the funding for its own buffer.
///
/// This type exists so that the acquire-then-construct sequence has exactly one
/// spelling. Both claims are taken *before* `BufReader::with_capacity` runs, and
/// refusal is a return value of the same constructor production calls, so a
/// control reaches the ordering that matters rather than building its own
/// unadmitted `BufReader`.
///
/// The two leases are separate because they fund two different things. The byte
/// lease funds the capacity this daemon *asks* for; the residual names the
/// allocation itself, whose real size `with_capacity` is free to round up and
/// which no code here can measure. Both are declared after the reader, so the
/// buffer is dropped before the funding that paid for it is released.
pub(super) struct AdmittedReader<R> {
    reader: tokio::io::BufReader<R>,
    _bytes: myownmesh_core::ResourceLease,
    _allocation: myownmesh_core::ResourceLease,
}

impl<R: tokio::io::AsyncRead> AdmittedReader<R> {
    /// Fund the buffer, then build it.
    ///
    /// On refusal nothing is constructed and `reader` is dropped with the
    /// error: the `?`s are above `with_capacity`, so a connection the daemon
    /// cannot afford to read never gets an eight-kilobyte buffer allocated for
    /// it and is never polled. That is the whole point of the ordering -- a
    /// claim taken after the buffer existed would be funding storage that
    /// already existed, which admission cannot refuse.
    pub(super) fn admit(reader: R, admission: &FrameAdmission) -> Result<Self, FrameRefusal> {
        Self::admit_building(reader, admission, |capacity, inner| {
            tokio::io::BufReader::with_capacity(capacity, inner)
        })
    }

    /// [`Self::admit`] with the buffer's construction passed in.
    ///
    /// `build` is not a hook placed near the allocation; it *is* the allocation.
    /// A control can therefore count constructions and know the count is exact,
    /// because there is no other expression in this function that could build a
    /// buffer. A hook next to a `with_capacity` call would prove less: moving
    /// the construction above the two `?`s would leave the hook where it was
    /// and the count would stay honest-looking while the ordering had broken.
    /// Moving *this* construction means moving the observation with it.
    fn admit_building<B>(
        reader: R,
        admission: &FrameAdmission,
        build: B,
    ) -> Result<Self, FrameRefusal>
    where
        B: FnOnce(usize, R) -> tokio::io::BufReader<R>,
    {
        let bytes = admission.admit_allocation(CONTROL_READ_BUFFER_BYTES)?;
        let allocation = admission.admit_allocator_residual(CONTROL_READ_ALLOCATIONS)?;
        Ok(Self {
            reader: build(CONTROL_READ_BUFFER_BYTES, reader),
            _bytes: bytes,
            _allocation: allocation,
        })
    }

    /// The funded buffer, for [`read_bounded_json_line`] to read lines from.
    pub(super) fn frames(&mut self) -> &mut tokio::io::BufReader<R> {
        &mut self.reader
    }
}

/// One admitted line of the control protocol, and the funding that holds it.
///
/// The two travel together because they have to. The line's bytes are alive
/// until the caller drops the line, and the caller does not drop it at once —
/// it parses a `Request` out of it first, which is precisely the moment the
/// daemon is holding the most on that connection's behalf. Releasing the
/// funding when the reader returned would have reported the daemon as holding
/// nothing over exactly that window.
///
/// So the leases live in here, are never read, and exist to be dropped with the
/// bytes they paid for. Field order matters and is not incidental: `line` is
/// destroyed before `_held`, so the funding outlives what it funds rather than
/// the other way round.
pub(super) struct AdmittedLine {
    line: String,
    _held: crate::ipc::LeasedList<myownmesh_core::ResourceLease>,
    /// The allocator residual for the buffers the line was assembled in, held
    /// until the line itself goes. Separate from `_held` because it is not a
    /// growth step: it was taken before the byte buffer existed and covers it
    /// for its whole life. Each list node has its own separate node lease.
    /// Declared last so it is released last.
    _residual: myownmesh_core::ResourceLease,
}

/// The one shared allocation a line read holds: its byte buffer. The growth
/// leases sit in independently funded list nodes rather than a shared vector.
const LINE_READ_ALLOCATIONS: u64 = 1;

impl AdmittedLine {
    /// The bytes this line admitted, as text.
    ///
    /// Controls only, and gated rather than left open: production never reads
    /// the line as a string. It decodes it through [`Self::decode_request`],
    /// which is the one seam that funds what the parse retains. A reader that
    /// could reach the text directly could parse it some other way, and that
    /// parse would be unfunded.
    #[cfg(test)]
    pub(super) fn as_str(&self) -> &str {
        &self.line
    }

    /// Parse this line, funding what the parse will retain *before* it runs.
    ///
    /// The claim comes from [`myownmesh_core::application_gateway::json_input_work_claim`],
    /// which is core's own derivation for exactly this question — the structural
    /// cost of a JSON input of a given encoded length — so the daemon does not
    /// restate a formula it does not own and the two cannot drift.
    ///
    /// It is acquired first and deliberately: a claim taken after
    /// `serde_json::from_str` returned would be funding an allocation that
    /// already exists, which is the thing this exists to stop.
    ///
    /// Returns the lease *before* the value, and that order is load-bearing.
    /// Bindings from one destructuring pattern drop in reverse order, so
    /// `let (lease, value) = ...` drops `value` first and the funding second —
    /// the decoded state is gone before the lease that paid for it is returned.
    /// The obvious `(value, lease)` spelling would release the funding while the
    /// value it accounts for was still live, which is the defect one layer up.
    ///
    /// **The parse work does not come back with it.** Core's claim covers two
    /// different things with two different lifetimes: the CPU the parse spends,
    /// which is over the instant `from_str` returns, and the tree that parse
    /// built, which lives as long as the caller holds the value. Handing both
    /// back as one lease made a client able to pin the first by holding the
    /// second — a whitespace-padded line decoding to a tiny variant, followed by
    /// a subscription that never ends, reserved the padded line's worst-case
    /// parse and CPU capacity for the whole life of that subscription. The work
    /// lease is therefore acquired here, held across `from_str` and dropped on
    /// the way out; only the retention travels.
    ///
    /// The split is by *class* and not by a second formula. The whole claim is
    /// core's, taken from the same function as before; what leaves in the work
    /// lease is exactly its [`ResourceClass::ParsingOrCpuWork`] dimension and
    /// what stays is exactly the remainder, so the two together are still the
    /// claim core derived and neither half can drift from it.
    ///
    /// [`ResourceClass::ParsingOrCpuWork`]: myownmesh_core::ResourceClass::ParsingOrCpuWork
    ///
    /// Concrete in `Request` on purpose, rather than generic over
    /// `DeserializeOwned`. The claim bounds the cost of the *structure*
    /// `serde_json` builds out of an input of this length; a `Deserialize` impl
    /// is free to allocate anything it likes on the way past that — a short
    /// numeric field can name a capacity, and a custom impl could reserve it —
    /// so a generic seam would apply a bound derived for one representation to
    /// deserializers that do not obey it. Production decodes exactly one type
    /// here. Naming it is what makes the lease's promise true rather than
    /// approximately true, and adding a second callee is then a deliberate act
    /// with this paragraph attached to it.
    pub(super) fn decode_request(
        &self,
        admission: &FrameAdmission,
    ) -> std::result::Result<super::AdmittedRequest, DecodeRefusal> {
        let whole = myownmesh_core::application_gateway::json_input_work_claim(self.line.len())
            .map_err(|error| DecodeRefusal::Admission(FrameRefusal::Claim(error)))?;
        let work = myownmesh_core::ResourceClaim::single(
            myownmesh_core::ResourceClass::ParsingOrCpuWork,
            whole.amount(myownmesh_core::ResourceClass::ParsingOrCpuWork),
        );
        let retained = whole
            .checked_sub(work)
            .map_err(|error| DecodeRefusal::Admission(FrameRefusal::Claim(error)))?;
        // Retention first, so a refusal of it costs no parse capacity, and so
        // the pair is acquired before either is spent. Both are acquired before
        // `from_str` runs, which is the ordering the whole seam exists for.
        let retained = admission
            .acquire_claim(retained)
            .map_err(DecodeRefusal::Admission)?;
        let work = admission
            .acquire_claim(work)
            .map_err(DecodeRefusal::Admission)?;
        let value = serde_json::from_str(&self.line).map_err(DecodeRefusal::Malformed)?;
        // The parse is over. Anything still held for it from here would be
        // capacity this daemon reports as spent on work that has finished.
        drop(work);
        Ok(super::AdmittedRequest::new(value, retained))
    }
}

/// Why one admitted line did not become a request.
///
/// Two arms because the caller answers them differently and always has: a
/// malformed line is the client's own error and is reported back on that same
/// connection so it can try again, while a refused parse is the daemon at the
/// edge of its grant and is not something the client can fix by resending.
/// Collapsing them would tell a client its well-formed request was a parse
/// error.
#[derive(Debug, thiserror::Error)]
pub(super) enum DecodeRefusal {
    #[error("control request parse was not admitted: {0}")]
    Admission(#[from] FrameRefusal),
    #[error("control request is not valid JSON: {0}")]
    Malformed(serde_json::Error),
}

/// One outbound control line, funded before it is encoded.
///
/// Every answer this socket writes is a second live allocation beside whatever
/// produced it. An event frame's mailbox lease funds the *typed* frame and the
/// work of serializing it; it says nothing about the encoded bytes, which exist
/// simultaneously and are sized by the frame rather than by anything the daemon
/// chose. A peer-controlled channel payload fanned out to many subscribers is
/// that allocation once per subscriber, and none of them was admitted.
///
/// The measurement cannot be the buffer. `serde_json` has no way to answer "how
/// long will this be" other than by writing it, so the length is taken by
/// writing the value into a sink that counts and allocates nothing, and only
/// then is the buffer funded and built. Encoding twice is the price of being
/// able to refuse; the alternative — encode, then charge — is funding storage
/// that already exists, which is not an admission at all. What makes the
/// counting pass allocation-free is [`ControlOut`](super::reply::ControlOut)
/// being closed.
///
/// Field order is the usual one: `line` is destroyed before the leases that
/// paid for it.
pub(super) struct AdmittedLineOut {
    line: Vec<u8>,
    _bytes: myownmesh_core::ResourceLease,
    _allocation: myownmesh_core::ResourceLease,
}

/// Encoded-line capacity acquired before a source commit may allocate.
pub(super) struct PreparedLineCapacity {
    capacity: usize,
    _bytes: myownmesh_core::ResourceLease,
    _allocation: myownmesh_core::ResourceLease,
}

pub(super) fn prepare_typed_and_line_building<T, E, B>(
    typed_claim: myownmesh_core::ResourceClaim,
    line_capacity: usize,
    admission: &FrameAdmission,
    build: B,
) -> std::result::Result<(Result<T, E>, PreparedLineCapacity), FrameRefusal>
where
    B: FnOnce(myownmesh_core::ResourceLease) -> Result<T, E>,
{
    let typed = admission.acquire_claim(typed_claim)?;
    let output = AdmittedLineOut::prepare_capacity(line_capacity, admission)?;
    Ok((build(typed), output))
}

/// The live allocations one outbound line holds: its single byte buffer.
const LINE_WRITE_ALLOCATIONS: u64 = 1;

/// The line terminator this protocol's framing is defined by, as the one byte
/// the encoder appends. Named rather than written as an escape at the append,
/// so the capacity funded above and the byte written below cannot disagree.
const NEWLINE: u8 = b'\n';

/// An `io::Write` that keeps only the count.
///
/// The whole point is that it never allocates: it is how a value's encoded
/// length is learned without first paying for the encoding. Overflow is an
/// error rather than a saturation, on the same reasoning as
/// [`FrameAdmission::admit_growth`] — a saturated length is a smaller number
/// than the truth, and a smaller number is a smaller charge.
#[derive(Default)]
pub(super) struct CountingSink {
    bytes: usize,
}

impl CountingSink {
    /// The width measured so far. The counting pass is framing's, and this is
    /// the only thing a caller needs from it.
    pub(super) fn measured(&self) -> usize {
        self.bytes
    }
}

impl std::io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.checked_add(buf.len()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encoded control line length is not representable",
            )
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Why one outbound control line was not produced.
///
/// Apart for the same reason [`DecodeRefusal`]'s arms are: a value this daemon
/// cannot encode is a defect here, and a refused buffer is the daemon at the
/// edge of its grant. An operator reading one as the other would go looking in
/// the wrong place.
#[derive(Debug, thiserror::Error)]
pub(super) enum EncodeRefusal {
    #[error("control response buffer was not admitted: {0}")]
    Admission(#[from] FrameRefusal),
    #[error("control response could not be encoded: {0}")]
    Malformed(serde_json::Error),
}

impl AdmittedLineOut {
    pub(super) fn prepare_capacity(
        capacity: usize,
        admission: &FrameAdmission,
    ) -> std::result::Result<PreparedLineCapacity, FrameRefusal> {
        let bytes = admission.admit_allocation(capacity)?;
        let allocation = admission.admit_allocator_residual(LINE_WRITE_ALLOCATIONS)?;
        Ok(PreparedLineCapacity {
            capacity,
            _bytes: bytes,
            _allocation: allocation,
        })
    }

    /// Fill a funded line with an encoded value, and refuse if what was written
    /// outgrew what was paid for.
    ///
    /// The bound is `Serialize` here and closed at the *measuring* pass instead,
    /// which is the only place a generic bound would be unsafe: an impl free to
    /// allocate on its way past would allocate before the refusal. By this point
    /// the capacity is already funded and the only question left is whether the
    /// bytes fit inside it.
    ///
    /// `build` is not a hook placed near the allocation; it *is* the allocation.
    /// A control can therefore count constructions and know the count is exact,
    /// because there is no other expression here that allocates an output
    /// buffer. Moving the construction means moving the observation with it.
    pub(super) fn encode_into_funded_line<B>(
        value: &impl serde::Serialize,
        prepared: PreparedLineCapacity,
        build: B,
    ) -> std::result::Result<Self, EncodeRefusal>
    where
        B: FnOnce(usize) -> Vec<u8>,
    {
        let PreparedLineCapacity {
            capacity,
            _bytes,
            _allocation,
        } = prepared;
        let mut line = build(capacity);
        serde_json::to_writer(&mut line, value).map_err(EncodeRefusal::Malformed)?;
        line.push(NEWLINE);
        // The measuring pass and this one wrote the same value through the same
        // encoder, so this cannot differ for any arm the reply envelope admits.
        debug_assert!(
            line.len() <= capacity,
            "the encoded line is {} bytes against {capacity} funded",
            line.len()
        );
        Ok(Self {
            line,
            _bytes,
            _allocation,
        })
    }

    /// The encoded line, newline included, for one `write_all`.
    pub(super) fn bytes(&self) -> &[u8] {
        &self.line
    }
}

/// Read one line of the control protocol, admitting each growth step before it
/// is allocated.
///
/// **What this does and does not claim.** Nothing here is funded after it
/// exists. The capacity each growth step *requests* — the line buffer and the
/// lease vector beside it — is acquired as bytes before the request is made, and
/// the two allocations themselves are acquired as one opaque residual before
/// either buffer has allocated at all. The two are separate on purpose:
/// `reserve_exact` guarantees *at least* the capacity asked for, so the amount
/// an allocator really reserves is not a number this code can state, and the
/// residual says that rather than pretending to a byte count. It does not claim
/// the same of the reader's own internal buffer: `fill_buf` has already copied bytes into that
/// allocation by the time this sees them, so a claim taken here would be funding
/// storage that already exists. That allocation is a fixed, connection-scoped
/// substrate cost and is funded once, by the caller, before the reader is
/// constructed — see `CONTROL_READ_BUFFER_BYTES` at the call site.
///
/// The bound on a line is therefore the grant plus the reader's fixed window,
/// not an owner ceiling; an absent ceiling means measured admission, not
/// unbounded growth.
///
/// The funding leaves with the line rather than with this function; see
/// [`AdmittedLine`].
pub(super) async fn read_bounded_json_line<R>(
    reader: &mut R,
    admission: &FrameAdmission,
) -> Result<Option<AdmittedLine>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    // One opaque dependency for the live byte Vec below, taken before it has
    // allocated anything and held for its whole life.
    //
    // This is the honest name for what a `Vec` costs beyond its contents. The
    // capacity each growth step *requests* is funded as bytes, before the
    // request; but `reserve_exact` promises only "at least", so the amount an
    // allocator actually reserves is not a number this code can state. Charging
    // a byte count for it would be inventing a measurement, and re-measuring
    // after the growth would be funding storage that already exists. An opaque
    // residual says what is true: this allocation's exact excess is the
    // allocator's to choose. List nodes are admitted independently below.
    let residual = admission
        .admit_allocator_residual(LINE_READ_ALLOCATIONS)
        .context("control request buffer allocations were not admitted")?;
    let mut bytes: Vec<u8> = Vec::new();
    // Accumulated beside the buffer and handed out with it. On the error paths
    // it is dropped here instead, together with the buffer it paid for — a line
    // that never became one funds nothing.
    //
    // Each list node is funded before it exists. A client can choose one growth
    // step per byte, so even the storage holding the growth leases must be
    // resource-backed rather than hidden in an expanding Vec.
    let mut held = crate::ipc::LeasedList::<myownmesh_core::ResourceLease>::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            return admitted_line(bytes, held, residual).map(Some);
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |at| at + 1);
        // What the daemon will *hold* after this step, not what it will contain.
        let frame = bytes
            .len()
            .checked_add(take)
            .context("control request length overflowed")?;
        let byte_capacity = frame.saturating_sub(bytes.capacity());
        let node_claim = crate::ipc::LeasedList::<myownmesh_core::ResourceLease>::node_claim()
            .context("control request lease-node claim is not representable")?;
        let node = admission
            .acquire_claim(node_claim)
            .context("control request lease-node was not admitted")?;
        let lease = admission
            .admit_buffer_growth(frame, byte_capacity)
            .context("control request was not admitted")?;
        // Past every refusal, so the capacity is funded before it is requested.
        // `reserve_exact` guarantees *at least* what is asked for, so what these
        // two calls do is request; the discretionary excess an allocator may add
        // is not a byte count this code can know, and is named once as an opaque
        // dependency by `residual` above rather than measured after the fact. A
        // claim taken after growth would be funding an allocation that already
        // exists, which is the whole defect this function was rewritten for.
        bytes.reserve_exact(take);
        held.push(lease, node);
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            return admitted_line(bytes, held, residual).map(Some);
        }
    }
}

/// Pair the decoded line with the funding that has been holding its bytes.
///
/// The trailing newline and any carriage return are popped before this, so the
/// line is a little shorter than what was admitted. That slack is not reclaimed
/// and should not be: it was really held while the line was being read, and
/// re-acquiring the exact remainder would mean releasing funding and asking for
/// it back — a window in which a concurrent connection could take it and this
/// one would fail on bytes it already had.
fn admitted_line(
    bytes: Vec<u8>,
    held: crate::ipc::LeasedList<myownmesh_core::ResourceLease>,
    residual: myownmesh_core::ResourceLease,
) -> Result<AdmittedLine> {
    let line = String::from_utf8(bytes).context("control request is not UTF-8")?;
    Ok(AdmittedLine {
        line,
        _held: held,
        _residual: residual,
    })
}

// ---- binary realtime pipe frame codec ---------------------------------------
//
// The frames a [`Request::RealtimePipe`] connection carries. Each frame on the
// wire is `[u32 len LE][body]`; `body` is what these encode and parse.
// Round-trip tested below.
//
// This codec is defined here and answers to nothing outside this crate. A
// client's encoder is a consumer of this format, not its specification:
// clients are held to this wire; it is not held to theirs.

/// Defensive cap on one frame body — a corrupt length never allocates more.
#[cfg(test)]
const TEST_REALTIME_FRAME_CEILING: usize = 64 * 1024 * 1024;

/// Fixed prefix width of a realtime frame body, identical in both directions:
/// the label's length, a one-byte slot, a four-byte slot, and the payload
/// length. The label's bytes and then the payload's follow it, in that order.
///
/// Both slots are named by direction rather than here, because both mean
/// different things each way: the one-byte slot is the marker inbound and
/// reserved zero outbound, and the four-byte slot is an absolute timestamp
/// inbound and a duration outbound. Equal width is what lets the two encoders be
/// read against each other; it is not a shared meaning.
///
/// The leading byte is a *length*, not a label. A label is opaque bytes chosen
/// by the application, so it cannot be a fixed-width field, and length-prefixing
/// it with one byte is what makes [`MAX_REALTIME_FLOW_LABEL_BYTES`] 255 —
/// the bound is the field's width, not a policy. Both variable-length runs are
/// counted, so a body's total width is fully determined by its prefix, and a
/// body whose bytes disagree with its own prefix is refused rather than
/// resolved.
pub(super) const REALTIME_FRAME_HEADER: usize = 1 + 1 + 4 + 4;

/// The longest label the frame above can carry, and therefore the longest core
/// will accept.
///
/// Re-exported rather than restated. The bound is a representation fact about
/// the single length byte in this frame, and the frame encoder here, the
/// provider edge that refuses an over-long open, and the name constructor in the
/// connector all have to agree on it — so there is one constant, in the basal
/// vocabulary, and this is a second spelling of that one value rather than a
/// second value.
pub use myownmesh_core::realtime::MAX_REALTIME_FLOW_LABEL_BYTES;

/// One unit read off an **outbound** pipe, on its way to a flow.
///
/// The pipe is bound to a session, so the body carries no network, peer, or
/// codec — only which flow of that session, and what the connector needs to
/// pace it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeSendUnit {
    /// The flow's opaque name, exactly as the application chose it. Never
    /// parsed, ordered, or ranged over here; it is carried to core, which
    /// resolves it by equality against one session's own table. Empty is
    /// refused rather than accepted as a degenerate name, so the binary and
    /// JSON paths cannot disagree about what an absent label means.
    pub flow_label: Vec<u8>,
    /// Presentation duration of this unit. Paces the flow clock on the way
    /// out; it is *not* a timestamp, and deliberately does not share a type
    /// with one.
    pub duration_us: u32,
    pub payload: Vec<u8>,
}

pub(super) struct RealtimeSendView {
    pub(super) flow_label: std::ops::Range<usize>,
    pub(super) duration_us: u32,
    pub(super) payload: std::ops::Range<usize>,
}

/// Inspect one body without copying either byte run. Production converts the
/// body allocation into the connector payload owner after comparing the label.
pub(super) fn inspect_realtime_send_unit(body: &[u8]) -> Option<RealtimeSendView> {
    let header = body.get(..REALTIME_FRAME_HEADER)?;
    let label_len = header[0] as usize;
    if label_len == 0 || header[1] != 0 {
        return None;
    }
    let payload_len = u32::from_le_bytes(header[6..10].try_into().ok()?) as usize;
    let payload_start = REALTIME_FRAME_HEADER.checked_add(label_len)?;
    let end = payload_start.checked_add(payload_len)?;
    if end != body.len() {
        return None;
    }
    Some(RealtimeSendView {
        flow_label: REALTIME_FRAME_HEADER..payload_start,
        duration_us: u32::from_le_bytes(header[2..6].try_into().ok()?),
        payload: payload_start..end,
    })
}

// There is no `marker` on an outbound unit, and the byte that would hold it is
// reserved zero on the wire.
//
// It was never the application's to set. Under `AnnexB` framing the app hands
// over whole access units and the transport library sets the RTP marker on the
// last packet of each — the unit boundary IS the marker, so a field here would
// be an input nothing reads. Keeping it would have been an invitation to set it
// and to reason about what it did.
//
// The byte stays so both directions keep one header width, which is what lets
// the two encoders be reviewed against each other. It is reserved rather than
// free: a sender that writes anything but zero is refused, because a nonzero
// value there means either a client that believes it is setting something or a
// body from an encoder whose second byte means something else.

/// One unit written to an **inbound** pipe, as received from a flow.
///
/// Deliberately a distinct type from [`RealtimeSendUnit`] even though the two
/// bodies are the same width. The 4-byte slot means different things in each
/// direction — a duration going out, an absolute timestamp coming in — and one
/// shared `timestamp` field would let a value from one direction be used as
/// the other with nothing to catch it. The layout is shared; the meaning is
/// not, so the types are not either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeRecvUnit {
    /// The flow's opaque name, as core reported it on arrival. A copy of the
    /// bytes, not a handle: it grants nothing and outlives nothing.
    pub flow_label: Vec<u8>,
    pub marker: bool,
    /// Absolute, at the flow's declared `clock_rate`. Uninterpretable without
    /// it, which is why that is a field on the flow rather than a codec detail.
    pub rtp_timestamp: u32,
    pub payload: Vec<u8>,
}

/// Parse an outbound unit body (the bytes after the `u32` length prefix).
///
/// Returns `None` on any truncation or a payload length that disagrees with
/// the frame — a malformed frame is dropped, never panics, and never trusts a
/// length it did not check against the bytes actually present.
pub fn decode_realtime_send_unit(body: &[u8]) -> Option<RealtimeSendUnit> {
    let view = inspect_realtime_send_unit(body)?;
    let header = body.get(..REALTIME_FRAME_HEADER)?;
    let label_len = view.flow_label.len();
    // Zero is refused rather than read as "no label". A flow is always named,
    // and a body that named nothing could only be resolved by guessing which
    // flow it meant.
    if label_len == 0 {
        return None;
    }
    let payload_len = view.payload.len();
    // Byte 1 is reserved and must be zero. Every other value is refused, which
    // is the strongest check available at this offset: the encoders
    // neighbouring this one put a stream index, a payload type or a keyframe
    // flag here, and those are usually nonzero, so a body that arrived from the
    // wrong encoder fails on its second byte rather than being interpreted.
    //
    // It also refuses a client that writes a marker it believes in. Nothing
    // downstream would read it, and accepting the byte would let that belief
    // survive indefinitely without ever being contradicted.
    if header[1] != 0 {
        return None;
    }
    // The two counted runs must account for the body exactly. Not `>=`: a body
    // longer than its own prefix describes is as malformed as a short one, and
    // accepting the excess would let a trailing tail ride along unread. This is
    // also the check a one-byte-shifted body from a neighbouring encoder cannot
    // survive, which is why it is arithmetic on both lengths rather than a
    // bounds test on one.
    let rest = body.get(REALTIME_FRAME_HEADER..)?;
    if rest.len() != label_len.checked_add(payload_len)? {
        return None;
    }
    let (label, payload) = rest.split_at(label_len);
    Some(RealtimeSendUnit {
        flow_label: label.to_vec(),
        duration_us: u32::from_le_bytes(header[2..6].try_into().ok()?),
        payload: payload.to_vec(),
    })
}

/// Serialize an inbound unit body (no length prefix).
///
/// Layout, integers little-endian:
/// `label_len u8 · marker u8 · rtp_timestamp u32 · payload_len u32 · label… ·
/// payload…`
///
/// Both lengths are redundant with the frame's own `u32` prefix and both are
/// kept anyway, because the redundancy is the check. Every neighbouring encoder
/// in the tree starts with a `kind u8` this one does not have, so a sender that
/// reaches for the wrong one produces a body shifted by exactly one byte —
/// where `label_len` reads a kind, `marker` reads a stream index, and every
/// field is plausible. The two counted runs are what cannot survive that shift:
/// they must account for the body exactly, and a shifted body's do not. Five
/// bytes a unit is cheap for turning a silent misinterpretation into a refusal.
///
/// See `a_neighbouring_encoders_frame_is_refused_not_reinterpreted`.
pub fn encode_realtime_recv_unit_with_ceiling(
    unit: &RealtimeRecvUnit,
    frame_ceiling: usize,
) -> Option<Vec<u8>> {
    encode_realtime_recv_fields_with_ceiling(
        &unit.flow_label,
        unit.marker,
        unit.rtp_timestamp,
        &unit.payload,
        frame_ceiling,
    )
}

pub(super) fn encode_realtime_recv_fields_with_ceiling(
    flow_label: &[u8],
    marker: bool,
    rtp_timestamp: u32,
    payload: &[u8],
    frame_ceiling: usize,
) -> Option<Vec<u8>> {
    encode_realtime_recv_fields_building(
        flow_label,
        marker,
        rtp_timestamp,
        payload,
        frame_ceiling,
        Vec::with_capacity,
    )
}

fn encode_realtime_recv_fields_building<B>(
    flow_label: &[u8],
    marker: bool,
    rtp_timestamp: u32,
    payload: &[u8],
    frame_ceiling: usize,
    build: B,
) -> Option<Vec<u8>>
where
    B: FnOnce(usize) -> Vec<u8>,
{
    // Every check happens before anything is allocated, and every one is
    // checked rather than cast. `payload.len() as u32` would truncate a payload
    // past 4 GiB and produce a body whose inner length disagreed with its own
    // contents — the exact malformation the decoder on the other side refuses,
    // manufactured by us. A frame that cannot be encoded correctly must not be
    // half-encoded.
    //
    // The label bound is the same rule the decoder enforces, applied here so a
    // name that could not be framed is never half-written: empty is refused,
    // and so is anything the one-byte length prefix could not count.
    if flow_label.is_empty() || flow_label.len() > MAX_REALTIME_FLOW_LABEL_BYTES {
        return None;
    }
    let label_len = u8::try_from(flow_label.len()).ok()?;
    let payload_len = u32::try_from(payload.len()).ok()?;
    let total = REALTIME_FRAME_HEADER
        .checked_add(flow_label.len())?
        .checked_add(payload.len())?;
    if total > frame_ceiling || total > u32::MAX as usize {
        return None;
    }
    let mut out = build(total);
    out.push(label_len);
    out.push(marker as u8);
    out.extend_from_slice(&rtp_timestamp.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(flow_label);
    out.extend_from_slice(payload);
    Some(out)
}

#[cfg(test)]
fn encode_realtime_recv_unit(unit: &RealtimeRecvUnit) -> Option<Vec<u8>> {
    encode_realtime_recv_unit_with_ceiling(unit, TEST_REALTIME_FRAME_CEILING)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::control::Request;
    // The reply vocabulary these controls exercise now lives next door. They
    // stayed here because they are about admission arriving before
    // construction, which is this module's rule; what they measure is the
    // reply boundary's.
    use crate::control::reply::{
        prepare_reply_then, ControlOut, FundedVariableReply, PreparedReply, PreparedText,
        ResponseOwner,
    };

    struct CountingReader {
        remaining: &'static [u8],
        polls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl tokio::io::AsyncRead for CountingReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.polls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let count = self.remaining.len().min(buffer.remaining());
            let (read, remaining) = self.remaining.split_at(count);
            buffer.put_slice(read);
            self.remaining = remaining;
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A label of two or more bytes, used everywhere a fixture needs one.
    ///
    /// Deliberately not one byte. A single-byte label makes the length prefix
    /// and the label indistinguishable in width, so a body built by hand would
    /// pass several of the checks below by coincidence — the shift control in
    /// particular would stop testing what it exists to test. It is also not
    /// valid UTF-8, because the binary path carries bytes and must not quietly
    /// acquire a text assumption from the JSON path that happens to sit beside
    /// it.
    const LABEL: &[u8] = &[b's', b'c', b'r', 0xff];

    /// A frame from a *neighbouring* encoder must be refused, never reinterpreted.
    ///
    /// The hazard is structural rather than particular to any one client. A
    /// layout of `kind u8 · stream u8 · key u8 · timestamp u32 · len u32 ·
    /// payload` — our fixed prefix behind one extra leading byte — is a shape
    /// encoders in this problem space converge on, and a sender that reaches for
    /// one produces a body shifted by exactly one byte where every field stays
    /// plausible: `label_len` reads a kind (1 or 2, both perfectly good label
    /// lengths), the reserved byte reads a stream index, and the u32 slots read
    /// a keyframe flag glued to three bytes of timestamp and then a length
    /// glued to a byte of its own.
    ///
    /// Nothing is acknowledged per unit, so if this were interpreted rather than
    /// refused the failure would be one hundred percent of media going nowhere
    /// with no signal on the sending side. The two counted runs are what make
    /// that impossible: `label_len + payload_len` must account for the body
    /// exactly, and a shifted body's cannot.
    #[test]
    fn a_neighbouring_encoders_frame_is_refused_not_reinterpreted() {
        let payload = [7u8, 7, 7, 7, 7, 7];
        // The shifted layout: our prefix plus one leading `kind` byte.
        //
        // `kind` is 1 and `stream` is 0, and neither choice is incidental.
        // After the shift `kind` lands in `label_len`, so it must be nonzero or
        // the empty-label check rejects the body before the arithmetic runs;
        // `stream` lands in the reserved byte, which accepts only zero, so a
        // nonzero stream index would be refused there instead. Both are the
        // commonest values a real sender writes, and both are chosen here so the
        // body reaches the one check this control exists to prove.
        let mut foreign = Vec::new();
        foreign.push(1u8); // kind
        foreign.push(0u8); // stream
        foreign.push(1u8); // key
        foreign.extend_from_slice(&90_000u32.to_le_bytes()); // timestamp
        foreign.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        foreign.extend_from_slice(&payload);

        assert_eq!(
            foreign.len(),
            REALTIME_FRAME_HEADER + 1 + payload.len(),
            "the foreign body is our prefix plus exactly one leading byte — if \
             this ever stops holding, the shift this test protects against has \
             changed shape and the assertion below is no longer testing it"
        );
        assert!(
            decode_realtime_send_unit(&foreign).is_none(),
            "a one-byte-shifted body must be refused: with the reserved byte \
             zeroed and the label length nonzero, the counted-run arithmetic is \
             the only thing standing between it and silently misrouted media"
        );
        // Non-vacuity, both halves. Neither cheap check may be what rejected
        // this body, or the control would keep passing after the arithmetic it
        // exists to protect was deleted.
        assert_ne!(
            foreign[0], 0,
            "the shifted body must reach the length arithmetic, not stop at the \
             empty-label check"
        );
        assert_eq!(
            foreign[1], 0,
            "the shifted body must reach the length arithmetic, not stop at the \
             reserved byte"
        );
        // And the arithmetic really is what disagrees: the shifted body claims
        // one label byte plus six payload bytes, and carries eleven after the
        // prefix.
        let shifted_claim = foreign[0] as usize
            + u32::from_le_bytes(foreign[6..10].try_into().expect("ten bytes present")) as usize;
        assert_ne!(
            shifted_claim,
            foreign.len() - REALTIME_FRAME_HEADER,
            "if a shifted body's counted runs ever add up, this control proves \
             nothing and the layout must be reconsidered"
        );
    }

    /// Local copy of the client's writer, so the round-trip is asserted
    /// against the exact layout the client produces rather than against our
    /// own decoder's assumptions.
    ///
    /// `reserved` is a raw byte rather than a `bool`, because the field it
    /// occupies is reserved zero and the interesting cases are the values a
    /// correct client never writes. `label_len` is taken separately from
    /// `label` so a fixture can state a length its bytes do not back, which is
    /// the malformation the decoder has to refuse.
    fn encode_send_unit_parts(
        label_len: u8,
        label: &[u8],
        reserved: u8,
        duration_us: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(REALTIME_FRAME_HEADER + label.len() + payload.len());
        out.push(label_len);
        out.push(reserved);
        out.extend_from_slice(&duration_us.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(label);
        out.extend_from_slice(payload);
        out
    }

    /// The well-formed case: the stated length is the label's own.
    fn encode_send_unit(label: &[u8], reserved: u8, duration_us: u32, payload: &[u8]) -> Vec<u8> {
        encode_send_unit_parts(
            u8::try_from(label.len()).expect("a fixture label is within the prefix width"),
            label,
            reserved,
            duration_us,
            payload,
        )
    }

    #[test]
    fn send_units_round_trip_without_naming_a_codec() {
        let body = encode_send_unit(LABEL, 0, 33_333, &[1, 2, 3, 9]);
        let unit = decode_realtime_send_unit(&body).expect("decode");
        // Exact opaque bytes, not a rendering of them: the label is four bytes
        // and the last is not valid UTF-8, so anything that went through a
        // string on the way here would come back changed.
        assert_eq!(unit.flow_label, LABEL.to_vec());
        assert_eq!(unit.duration_us, 33_333);
        assert_eq!(unit.payload, vec![1, 2, 3, 9]);

        // An empty payload is a legitimate unit, and the same decode path. An
        // empty *label* is not — see `a_frame_naming_no_flow_is_refused`.
        let empty = decode_realtime_send_unit(&encode_send_unit(LABEL, 0, 20_000, &[]))
            .expect("decode empty");
        assert!(empty.payload.is_empty());
        assert_eq!(empty.flow_label, LABEL.to_vec());

        // The longest label the prefix can count still round-trips whole.
        let longest = vec![0xab; MAX_REALTIME_FLOW_LABEL_BYTES];
        let long = decode_realtime_send_unit(&encode_send_unit(&longest, 0, 1, &[4]))
            .expect("a 255-byte label is within the prefix width");
        assert_eq!(long.flow_label, longest);
    }

    /// A body that names no flow is refused rather than read as naming none.
    ///
    /// Zero is the one label length that would otherwise decode into something
    /// — a unit with an empty name, which core could only resolve by guessing.
    /// Refusing it here is also what keeps the binary path and the JSON path
    /// agreeing: neither has a spelling for "a flow with no name".
    #[test]
    fn a_frame_naming_no_flow_is_refused() {
        let body = encode_send_unit_parts(0, &[], 0, 1, &[7, 7, 7]);
        assert!(
            decode_realtime_send_unit(&body).is_none(),
            "a zero-length label must be refused, not read as an absent one"
        );
        // Non-vacuity: with a real label of the same shape the body decodes, so
        // it is the zero that was rejected and not the rest of the frame.
        let ok = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        assert!(decode_realtime_send_unit(&ok).is_some());
    }

    #[test]
    fn truncation_is_none_not_panic() {
        let body = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        for cut in 0..body.len() {
            assert!(
                decode_realtime_send_unit(&body[..cut]).is_none(),
                "short {cut}"
            );
        }
    }

    /// The two counted runs are redundant with the frame's own prefix, which is
    /// exactly why a disagreement between them must be refused rather than
    /// resolved: silently trusting any one of them lets a corrupt frame hand a
    /// truncated or over-long payload — or a label sliced out of a payload — to
    /// a decoder as if it were whole.
    #[test]
    fn a_length_that_disagrees_with_the_frame_is_refused() {
        // A payload length larger than the bytes present.
        let mut body = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        body[6] = 9;
        assert!(decode_realtime_send_unit(&body).is_none());

        // A body longer than its own counted runs describe. The excess is not
        // ignored: accepting it would let a trailing tail ride along unread.
        let mut over = encode_send_unit(LABEL, 0, 1, &[7, 7, 7]);
        over.push(0);
        assert!(decode_realtime_send_unit(&over).is_none());

        // A label length longer than the label actually written. Every field
        // after the prefix stays plausible — the decoder would simply take
        // payload bytes as name bytes — so only the total can catch it.
        let overlong_label = encode_send_unit_parts(
            u8::try_from(LABEL.len() + 1).expect("fits"),
            LABEL,
            0,
            1,
            &[7, 7, 7],
        );
        assert!(
            decode_realtime_send_unit(&overlong_label).is_none(),
            "a label length its bytes do not back must be refused, not filled \
             from the payload"
        );

        // And shorter, which would otherwise silently rename the flow and
        // prepend the leftover byte to its payload.
        let short_label = encode_send_unit_parts(
            u8::try_from(LABEL.len() - 1).expect("fits"),
            LABEL,
            0,
            1,
            &[7, 7, 7],
        );
        assert!(
            decode_realtime_send_unit(&short_label).is_none(),
            "a label length shorter than its bytes must be refused, not read as \
             a different flow"
        );
    }

    /// Byte 1 of an outbound body is reserved: zero decodes, everything else is
    /// refused.
    ///
    /// Not pedantry about an unused field. The byte is the one position where a
    /// body from a neighbouring encoder differs most reliably — a stream index,
    /// a payload type or a keyframe flag lands here after the one-byte shift,
    /// and those are usually nonzero. Requiring zero turns that offset into a
    /// check rather than a place to store a value nothing reads.
    ///
    /// It also refuses a client that writes a marker it believes in. Under
    /// `AnnexB` framing the transport library sets the RTP marker from the unit
    /// boundary, so an application-supplied one was never an input; accepting
    /// the byte would let that belief survive without ever being contradicted.
    #[test]
    fn a_nonzero_reserved_byte_is_refused() {
        let ok = encode_send_unit(LABEL, 0, 1, &[7]);
        let unit = decode_realtime_send_unit(&ok).expect("a zeroed reserved byte decodes");
        assert_eq!(unit.flow_label, LABEL.to_vec());
        assert_eq!(unit.payload, vec![7]);

        // Every nonzero value, not a sample. 1 is the important one — it is
        // what a client that still thinks it is sending a marker would write,
        // and the value most likely to be waved through by a `!= 0` reading.
        for byte in 1u8..=255 {
            let body = encode_send_unit(LABEL, byte, 1, &[7]);
            assert!(
                decode_realtime_send_unit(&body).is_none(),
                "reserved byte {byte} must be refused"
            );
        }
    }

    /// A unit too large to frame yields `None` rather than a malformed body.
    ///
    /// The failure this prevents is not the loss of one unit. An encoder that
    /// cast the length would write an inner length disagreeing with its own
    /// contents — precisely what the decoder at the far end refuses — so the
    /// client could neither use that frame nor resynchronise after it, and one
    /// unusable unit would cost every unit behind it.
    #[test]
    fn a_unit_too_large_to_frame_is_not_half_encoded() {
        let ok = encode_realtime_recv_unit(&RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: true,
            rtp_timestamp: 90_000,
            payload: vec![1, 2, 3],
        })
        .expect("an ordinary unit encodes");
        assert_eq!(ok.len(), REALTIME_FRAME_HEADER + LABEL.len() + 3);

        // One byte past what the framing may carry. The label counts toward the
        // ceiling too, which is why it is subtracted here: a bound that only
        // considered the payload would emit bodies a byte over. Allocated rather
        // than faked, so the bound under test is the real one.
        let headroom = TEST_REALTIME_FRAME_CEILING - REALTIME_FRAME_HEADER - LABEL.len();
        let oversize = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: false,
            rtp_timestamp: 0,
            payload: vec![0u8; headroom + 1],
        };
        assert!(
            encode_realtime_recv_unit(&oversize).is_none(),
            "a body over the selected frame ceiling must not be encoded at all"
        );

        // The largest unit that still fits is accepted — the check is a ceiling,
        // not an off-by-one that also rejects the boundary.
        let exact = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: false,
            rtp_timestamp: 0,
            payload: vec![0u8; headroom],
        };
        assert_eq!(
            encode_realtime_recv_unit(&exact).map(|body| body.len()),
            Some(TEST_REALTIME_FRAME_CEILING)
        );
    }

    /// A label the framing cannot express is refused outright, not truncated.
    ///
    /// Both ends of the rule, because both are reachable: an empty name would
    /// produce a body the decoder must refuse, and a name past the one-byte
    /// prefix would have its length silently wrapped into a different, valid
    /// number — which is worse than a dropped unit, since it names a real flow
    /// that is not this one.
    #[test]
    fn a_label_the_frame_cannot_carry_is_not_half_encoded() {
        let unnamed = RealtimeRecvUnit {
            flow_label: Vec::new(),
            marker: false,
            rtp_timestamp: 0,
            payload: vec![1],
        };
        assert!(encode_realtime_recv_unit(&unnamed).is_none());

        let overlong = RealtimeRecvUnit {
            flow_label: vec![b'x'; MAX_REALTIME_FLOW_LABEL_BYTES + 1],
            marker: false,
            rtp_timestamp: 0,
            payload: vec![1],
        };
        assert!(encode_realtime_recv_unit(&overlong).is_none());

        // The boundary itself encodes, so the rule is a ceiling and not an
        // off-by-one that also rejects the longest usable name.
        let longest = RealtimeRecvUnit {
            flow_label: vec![b'x'; MAX_REALTIME_FLOW_LABEL_BYTES],
            marker: false,
            rtp_timestamp: 0,
            payload: vec![1],
        };
        assert!(encode_realtime_recv_unit(&longest).is_some());
    }

    /// Pins the exact bytes, because this body is shared with the
    /// applications' decoder: a silent layout change here desynchronises the
    /// two ends rather than failing a build. Note there is no peer and no
    /// codec on the wire — the pipe's session binding supplies the first and
    /// the flow's declared encoding the second.
    #[test]
    fn recv_unit_layout_is_pinned() {
        let body = encode_realtime_recv_unit(&RealtimeRecvUnit {
            flow_label: vec![b'a', b'b', 0xff],
            marker: true,
            rtp_timestamp: 0x0001_0203,
            payload: vec![9, 8],
        })
        .expect("a two-byte payload is within the frame ceiling");
        assert_eq!(
            body,
            vec![
                3, // label_len
                1, // marker
                0x03, 0x02, 0x01, 0x00, // rtp_timestamp LE
                2, 0, 0, 0, // payload len LE
                b'a', b'b', 0xff, // label, verbatim and not text
                9, 8, // payload
            ]
        );
    }

    /// Demonstrates the hazard the type split exists to remove: the two
    /// directions share a body width, so an inbound unit's bytes can parse as an
    /// outbound one, with the absolute timestamp landing silently in the
    /// duration field. That is exactly why `RealtimeSendUnit` and
    /// `RealtimeRecvUnit` are distinct types with distinct functions, so the
    /// compiler catches what the bytes cannot. If they are ever merged back into
    /// one type with a shared `timestamp`, this misreading becomes expressible
    /// in ordinary code.
    ///
    /// The reserved outbound byte narrows this without closing it. An inbound
    /// unit carrying a real marker has 1 where an outbound body must have 0, so
    /// that half is now caught — which is a side benefit of the reserved rule
    /// and not a reason to rely on it. Unmarked units are the ordinary case,
    /// and they still cross undetected, as the second half of this asserts.
    #[test]
    fn wire_bytes_alone_cannot_distinguish_the_two_directions() {
        // A marked inbound unit is now refused: its marker byte is 1 where the
        // outbound reserved byte must be 0.
        let marked = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: true,
            rtp_timestamp: 90_000,
            payload: vec![1],
        };
        let marked_body = encode_realtime_recv_unit(&marked).expect("encodes");
        assert!(
            decode_realtime_send_unit(&marked_body).is_none(),
            "the reserved byte catches a marked inbound unit read as outbound"
        );

        // An unmarked one still crosses silently, which is the case the type
        // split has to cover, because no byte distinguishes it.
        let recv = RealtimeRecvUnit {
            flow_label: LABEL.to_vec(),
            marker: false,
            rtp_timestamp: 90_000,
            payload: vec![1],
        };
        let body = encode_realtime_recv_unit(&recv).expect("a one-byte payload encodes");
        let decoded = decode_realtime_send_unit(&body).expect("same width, so the bytes parse");
        assert_eq!(decoded.flow_label, recv.flow_label);
        assert_eq!(
            decoded.duration_us, recv.rtp_timestamp,
            "a 90 kHz timestamp read as a 90-millisecond duration, undetectably"
        );
    }

    /// An admission bounded only by the process owner's grant — no owner
    /// ceiling — which is what a daemon started with no `MYOWNMESH_IPC_*` value
    /// now has.
    fn granted_admission() -> FrameAdmission {
        FrameAdmission::new(crate::test_application_scope(), None)
    }

    /// The same grant with an owner policy layered over it.
    fn admission_capped_at(ceiling: usize) -> FrameAdmission {
        FrameAdmission::new(crate::test_application_scope(), Some(ceiling))
    }

    #[tokio::test]
    async fn json_reader_refuses_before_crossing_selected_ceiling() {
        let input = b"123456789\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let error = match read_bounded_json_line(&mut reader, &admission_capped_at(8)).await {
            Err(error) => error,
            Ok(_) => panic!("nine bytes exceed eight"),
        };
        // Alternate form, so the assertion reads the whole chain. Plain
        // `to_string` on an `anyhow::Error` answers only the outermost context,
        // which would pass this test for any refusal at all — including a
        // provider refusal, which is the other thing this reader can report and
        // is not what is under test here.
        assert!(
            format!("{error:#}").contains("owner-selected ceiling"),
            "the ceiling's own reason has to survive to the caller: {error:#}"
        );
    }

    #[tokio::test]
    async fn json_reader_accepts_exact_ceiling_without_hidden_slack() {
        let input = b"12345678\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let line = read_bounded_json_line(&mut reader, &admission_capped_at(9))
            .await
            .unwrap()
            .expect("eight bytes and a newline are exactly nine");
        assert_eq!(line.as_str(), "12345678");
    }

    /// No owner ceiling does not mean no bound.
    ///
    /// This is the property the whole optional-ceiling change turns on: a daemon
    /// started with neither `MYOWNMESH_IPC_*` value set still reads only what its
    /// grant funds, at the size actually read. The line is admitted here because
    /// the test grant covers it — what is being asserted is that absence took
    /// the funded path at all, not that nothing was checked.
    #[tokio::test]
    async fn an_absent_owner_ceiling_still_funds_every_byte_it_reads() {
        let input = b"12345678\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let line = read_bounded_json_line(&mut reader, &granted_admission())
            .await
            .unwrap()
            .expect("a complete line");
        assert_eq!(line.as_str(), "12345678");
    }

    /// The funding leaves the reader with the line, and leaves with the line.
    ///
    /// Two things, against a provider this control owns so that both are
    /// observable rather than argued from shape. First, the line outlives the
    /// reader that produced it and still carries its own storage -- nothing
    /// about it depends on the connection buffer that is gone. Second, that
    /// storage is *charged* for exactly that long: while the line is alive a
    /// further claim the remaining grant cannot cover is refused, and the same
    /// claim succeeds once the line is dropped.
    ///
    /// The second half is the one that matters. A held lease that released
    /// early would leave the line's bytes in memory funded by nobody, and no
    /// assertion about the line's *contents* would notice.
    #[tokio::test]
    async fn an_admitted_line_carries_its_own_storage_past_its_reader() {
        // The probe is sized so the arithmetic holds without this control
        // knowing what a `ResourceLease` weighs: the line's fifteen bytes alone
        // put the probe out of reach, and the whole grant covers it once the
        // line is gone.
        let admission = admission_granting_bytes(320);
        let input = b"{\"op\":\"status\"}\n";
        let line = {
            let mut reader = tokio::io::BufReader::new(&input[..]);
            read_bounded_json_line(&mut reader, &admission)
                .await
                .unwrap()
                .expect("a complete line")
        };
        assert_eq!(line.as_str(), "{\"op\":\"status\"}");
        let request: Request = serde_json::from_str(line.as_str()).expect("a status request");
        assert!(matches!(request, Request::Status));

        admission
            .admit_allocation(318)
            .expect_err("the live line is still holding its share of the grant");
        drop(line);
        let probe = admission
            .admit_allocation(318)
            .expect("dropping the line returned its share");
        drop(probe);
    }

    /// A ceiling bounds the frame, not one read of it.
    ///
    /// Checked directly, because the incremental reader is the place this is
    /// easy to get wrong: charging each chunk against the ceiling separately
    /// would let a line arrive in pieces and pass a bound it exceeded.
    #[test]
    fn a_ceiling_bounds_the_whole_frame_and_not_one_read_of_it() {
        let admission = admission_capped_at(8);
        let first = admission.admit_growth(0, 5).expect("five of eight");
        let refusal = admission
            .admit_growth(5, 4)
            .expect_err("five already held plus four more is nine");
        assert!(refusal.to_string().contains("owner-selected ceiling"));
        assert!(
            admission.admit_growth(5, 3).is_ok(),
            "and the eighth byte is still admitted"
        );
        drop(first);
    }

    #[test]
    fn realtime_length_refusal_is_checked_before_body_allocation() {
        let admission = admission_capped_at(8);
        assert!(admission.admit(8).is_ok());
        assert!(admission.admit(9).is_err());
    }

    #[test]
    fn inbound_realtime_encoding_constructs_exactly_one_output_buffer() {
        let mut constructions = 0;
        let body = encode_realtime_recv_fields_building(
            b"flow",
            true,
            7,
            b"payload",
            usize::MAX,
            |capacity| {
                constructions += 1;
                Vec::with_capacity(capacity)
            },
        )
        .expect("an ordinary borrowed arrival is encodable");
        assert_eq!(constructions, 1);
        assert_eq!(body.len(), REALTIME_FRAME_HEADER + 4 + 7);

        let mut refused_constructions = 0;
        assert!(encode_realtime_recv_fields_building(
            b"flow",
            false,
            0,
            b"payload",
            body.len() - 1,
            |_| {
                refused_constructions += 1;
                Vec::new()
            },
        )
        .is_none());
        assert_eq!(
            refused_constructions, 0,
            "the structural ceiling refuses before buffer construction"
        );
    }

    /// The growth claim names the allocation, not the bytes that will sit in it.
    ///
    /// Load-bearing and easy to lose: `admit_growth` charges the logical length,
    /// so a buffer that has rounded its capacity up is under-reported by exactly
    /// the slack. This asserts the two helpers really do differ, which is the
    /// only thing that makes the reader's switch to `admit_buffer_growth`
    /// meaningful rather than a rename.
    #[test]
    fn buffer_growth_is_admitted_for_capacity_and_the_ceiling_for_the_frame() {
        let admission = admission_capped_at(8);
        // Frame within the ceiling, capacity larger than the frame: admitted,
        // and the claim taken is the capacity one.
        assert!(
            admission.admit_buffer_growth(4, 64).is_ok(),
            "a buffer may hold more than the frame it is carrying"
        );
        // Frame over the ceiling refuses regardless of how small the allocation
        // is, because the ceiling is a statement about the frame.
        let refusal = admission
            .admit_buffer_growth(9, 0)
            .expect_err("nine exceeds the ceiling of eight");
        assert!(refusal.to_string().contains("owner-selected ceiling"));
        // And the substrate path is deliberately outside the ceiling: a read
        // window is not a frame, so an owner's frame bound must not refuse it.
        assert!(
            admission.admit_allocation(64).is_ok(),
            "the read window is not bounded by the frame ceiling"
        );
    }

    /// A provider this control owns, granting exactly `bytes` of accounted
    /// memory and enough of everything else not to be the reason for a refusal.
    ///
    /// The point of the split is attribution. Byte capacity is the subject, so
    /// it is tight; the provider's own bookkeeping records and the opaque
    /// residuals every allocation carries are not, so they are generous. A
    /// fixture that starved those too would refuse for a reason the control is
    /// not about, and would still go green.
    fn admission_granting_bytes(bytes: u64) -> FrameAdmission {
        let grant = myownmesh_core::ResourceClaim::try_from_entries([
            (myownmesh_core::ResourceClass::AccountedMemoryBytes, bytes),
            (myownmesh_core::ResourceClass::ParsingOrCpuWork, 1 << 20),
            (
                myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                1 << 20,
            ),
        ])
        .expect("the control grant is representable");
        FrameAdmission::over_grant(grant, None)
    }

    /// [`admission_granting_bytes`], with the provider it spends from.
    fn probed_admission_granting_bytes(
        bytes: u64,
    ) -> (FrameAdmission, myownmesh_core::FiniteResourceProvider) {
        let grant = myownmesh_core::ResourceClaim::try_from_entries([
            (myownmesh_core::ResourceClass::AccountedMemoryBytes, bytes),
            (myownmesh_core::ResourceClass::ParsingOrCpuWork, 1 << 20),
            (
                myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                1 << 20,
            ),
        ])
        .expect("the control grant is representable");
        FrameAdmission::over_grant_probed(grant, None)
    }

    /// A provider granting exactly the process-scope record and the requested
    /// reservation sequence, including the provider's own record per lease.
    fn probed_admission_for_reservations(
        claims: impl IntoIterator<Item = myownmesh_core::ResourceClaim>,
    ) -> (FrameAdmission, myownmesh_core::FiniteResourceProvider) {
        let mut grant = myownmesh_core::FiniteResourceProvider::scope_planning_charge();
        for claim in claims {
            grant = grant
                .checked_add(
                    myownmesh_core::FiniteResourceProvider::reservation_planning_charge(claim)
                        .expect("the control reservation is representable"),
                )
                .expect("the exact control grant is representable");
        }
        FrameAdmission::over_grant_probed(grant, None)
    }

    /// One parse-work reading off a provider.
    fn parse_work(provider: &myownmesh_core::FiniteResourceProvider) -> u64 {
        provider
            .in_use()
            .amount(myownmesh_core::ResourceClass::ParsingOrCpuWork)
    }

    /// One accounted-bytes reading off a provider.
    fn held_bytes(provider: &myownmesh_core::FiniteResourceProvider) -> u64 {
        provider
            .in_use()
            .amount(myownmesh_core::ResourceClass::AccountedMemoryBytes)
    }

    /// A padded request's parse capacity is released by `decode_request` itself,
    /// while the value it decoded to is still held.
    ///
    /// **The unit half of the padded-subscribe finding, and deliberately only
    /// that.** It does not open a stream and cannot: what it drives is one
    /// decode, and what it observes is that the two halves of core's claim have
    /// the two different lifetimes this seam split them into. The connection
    /// branch that must not re-retain the work half is a different subject, with
    /// a different control, at the `handle_client` level.
    ///
    /// The attack behind the split is cheap and quiet: send a tiny request
    /// behind a lot of whitespace, then keep the connection open forever. The
    /// structural claim is derived from the *line's* length, because that is
    /// what bounds what `serde_json` may build out of it — so a padded line
    /// reserves a large parse and CPU figure. If that figure travelled with the
    /// decoded value, one subscription that never ends would hold the padded
    /// line's worst case for the daemon's lifetime, and a handful of such
    /// clients would report the daemon as out of parse capacity while it was
    /// doing nothing at all.
    ///
    /// Three readings, and the middle one is load-bearing. Parse work is back at
    /// its baseline while the decoded request and its retention are still held;
    /// accounted bytes are *above* baseline at the same instant, which is what
    /// makes the first reading a release rather than a decode that never
    /// happened; and the padded line's claim really did carry parse work worth
    /// releasing, which is what stops the whole control passing vacuously on a
    /// claim that was zero.
    #[tokio::test]
    async fn v4_r2_daemon_a_padded_decode_releases_its_parse_work_and_keeps_its_retention() {
        // Whitespace, so the line is long and the value is small: exactly the
        // asymmetry the claim is derived over.
        let padded = format!("{}{{\"op\":\"events_subscribe\"}}\n", " ".repeat(4096));
        let (admission, provider) = probed_admission_granting_bytes(1 << 20);
        let baseline_work = parse_work(&provider);
        let baseline_bytes = held_bytes(&provider);

        // Non-vacuity: the claim this line is admitted under really does reserve
        // parse capacity, so there is something for the release to be about.
        let padded_claim =
            myownmesh_core::application_gateway::json_input_work_claim(padded.len() - 1)
                .expect("the padded line's claim is representable");
        assert!(
            padded_claim.amount(myownmesh_core::ResourceClass::ParsingOrCpuWork) > 0,
            "non-vacuity: a padded line reserves parse capacity"
        );

        let mut reader = tokio::io::BufReader::new(padded.as_bytes());
        let line = read_bounded_json_line(&mut reader, &admission)
            .await
            .expect("the padded line is funded")
            .expect("a complete line");
        let admitted = line
            .decode_request(&admission)
            .expect("this grant funds the padded line's decode");
        // The raw line goes exactly where `handle_client` drops it. Past here,
        // what is held is what a live subscription holds.
        drop(line);
        assert!(
            matches!(admitted.request, Request::EventsSubscribe),
            "and it decoded to the small variant the padding was hiding"
        );

        assert_eq!(
            parse_work(&provider),
            baseline_work,
            "the padded line's parse capacity came back when the parse finished, \
             not when the subscription it opened finally ends"
        );
        assert!(
            held_bytes(&provider) > baseline_bytes,
            "and the decoded request is still funded at that same instant, so \
             what came back was the work and not the retention"
        );

        drop(admitted);
        assert_eq!(
            held_bytes(&provider),
            baseline_bytes,
            "and the retention comes back with the value it accounted for"
        );
    }

    /// Refusing to encode an outbound line constructs no buffer, writes nothing,
    /// and returns to the exact baseline.
    ///
    /// The measurement pass is a serializer run into a counting sink, which is
    /// the concession this seam makes: it invokes `Serialize`, because there is
    /// no way to know an encoded length without encoding. What it must not do is
    /// *allocate* — a refusal that had already built the output buffer would be
    /// a daemon taking the memory it was about to decline, at whatever rate a
    /// peer chose to make it decline.
    ///
    /// The buffer's construction is the closure, so the count is exact: there is
    /// no other expression in `encode_building` that allocates an output buffer,
    /// and both refusals return through the `?`s above it. No socket appears
    /// here at all, and that is not an omission — `encode_building` is handed no
    /// writer, so "writes nothing on refusal" is a property of its signature
    /// rather than of this control's luck.
    ///
    /// Positive and negative on the same value, because "constructed nothing"
    /// is only interesting if the same input on a sufficient grant constructs
    /// exactly one.
    #[test]
    fn v4_r2_daemon_encoded_output_pressure_builds_no_buffer_and_returns_to_baseline() {
        let response = crate::control::wire::Response::ok(serde_json::json!({
            "answer": "a payload long enough that its encoded length is not zero",
            "items": [1, 2, 3, 4, 5, 6, 7, 8],
        }));

        // A grant of no accounted bytes: the counting pass still runs, and the
        // first acquisition after it cannot be met.
        let (starved, provider) = probed_admission_granting_bytes(0);
        let baseline = provider.in_use();
        let mut built = 0usize;
        let refusal = match AdmittedLineOut::encode_building(
            ControlOut::Response(&response),
            &starved,
            |capacity| {
                built += 1;
                Vec::with_capacity(capacity)
            },
        ) {
            Ok(_) => panic!("a grant of no accounted bytes cannot fund an encoded line"),
            Err(refusal) => refusal,
        };
        assert!(
            matches!(
                refusal,
                EncodeRefusal::Admission(FrameRefusal::Resources(_))
            ),
            "refused as pressure, not as a malformed value: {refusal:?}"
        );
        assert_eq!(
            built, 0,
            "and no output buffer was constructed on the way to being refused"
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "and the refusal left the ledger exactly where it found it"
        );

        // Non-vacuity: the same value, on a grant that fits.
        let (funded, provider) = probed_admission_granting_bytes(1 << 16);
        let baseline = provider.in_use();
        let mut built = 0usize;
        let line = AdmittedLineOut::encode_building(
            ControlOut::Response(&response),
            &funded,
            |capacity| {
                built += 1;
                Vec::with_capacity(capacity)
            },
        )
        .expect("a sufficient grant funds this line");
        assert_eq!(built, 1, "exactly one buffer, built after its funding");
        assert!(
            line.bytes().ends_with(b"\n"),
            "and it is a whole line, terminator included"
        );
        assert!(
            held_bytes(&provider)
                > baseline.amount(myownmesh_core::ResourceClass::AccountedMemoryBytes),
            "held while the line is"
        );
        drop(line);
        assert_eq!(provider.in_use(), baseline, "and returned with it");
    }

    /// Typed reply ownership is admitted before the first owned field exists.
    #[test]
    fn v4_r2_daemon_prepared_reply_pressure_invokes_no_typed_builder() {
        let (typed_starved, provider) = probed_admission_granting_bytes(0);
        let baseline = provider.in_use();
        let mut commits = 0usize;
        let typed_claim = myownmesh_core::ResourceClaim::single(
            myownmesh_core::ResourceClass::AccountedMemoryBytes,
            1,
        );
        let refusal =
            match prepare_typed_and_line_building(typed_claim, 64, &typed_starved, |typed| {
                commits += 1;
                drop(typed);
                Ok::<_, ()>(())
            }) {
                Ok(_) => panic!("the typed claim must refuse before output preparation"),
                Err(refusal) => refusal,
            };
        assert!(matches!(refusal, FrameRefusal::Resources(_)));
        assert_eq!(commits, 0, "typed pressure invokes no source commit");
        assert_eq!(
            provider.in_use(),
            baseline,
            "typed refusal prepares no output and restores the exact ledger"
        );

        let (starved_commit, provider) = probed_admission_granting_bytes(0);
        let baseline = provider.in_use();
        let mut commits = 0usize;
        let refusal = match prepare_typed_and_line_building(
            myownmesh_core::ResourceClaim::ZERO,
            64,
            &starved_commit,
            |typed| {
                commits += 1;
                drop(typed);
                Ok::<_, ()>(())
            },
        ) {
            Ok(_) => panic!("an unfunded response line must refuse before source commit"),
            Err(refusal) => refusal,
        };
        assert!(matches!(refusal, FrameRefusal::Resources(_)));
        assert_eq!(commits, 0, "output pressure wins before source commit");
        assert_eq!(provider.in_use(), baseline);

        let (funded_commit, provider) = probed_admission_granting_bytes(1 << 16);
        let baseline = provider.in_use();
        let mut commits = 0usize;
        let (built, output) = prepare_typed_and_line_building(
            myownmesh_core::ResourceClaim::ZERO,
            64,
            &funded_commit,
            |typed| {
                commits += 1;
                drop(typed);
                Ok::<_, ()>(7_u8)
            },
        )
        .expect("the positive grant funds typed and line preparation");
        assert_eq!(built, Ok(7));
        assert_eq!(
            commits, 1,
            "the source commits exactly once after both claims"
        );
        drop(output);
        assert_eq!(provider.in_use(), baseline);

        let scalar = PreparedReply::Bool {
            key: "completed",
            value: true,
        };
        let (starved_scalar, provider) = probed_admission_granting_bytes(0);
        let baseline = provider.in_use();
        let mut output_builds = 0usize;
        let refusal = match AdmittedLineOut::encode_building(
            ControlOut::Prepared(&scalar),
            &starved_scalar,
            |capacity| {
                output_builds += 1;
                Vec::with_capacity(capacity)
            },
        ) {
            Ok(_) => panic!("a zero-byte grant refuses the scalar line"),
            Err(refusal) => refusal,
        };
        assert!(matches!(
            refusal,
            EncodeRefusal::Admission(FrameRefusal::Resources(_))
        ));
        assert_eq!(
            output_builds, 0,
            "scalar output is not built before admission"
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "scalar refusal retains nothing"
        );

        let mut scalar_commits = 0usize;
        let refusal = match prepare_reply_then(&scalar, &starved_scalar, || scalar_commits += 1) {
            Ok(_) => panic!("a zero-byte grant refuses before the scalar operation"),
            Err(refusal) => refusal,
        };
        assert!(matches!(
            refusal,
            EncodeRefusal::Admission(FrameRefusal::Resources(_))
        ));
        assert_eq!(
            scalar_commits, 0,
            "the operation is not invoked until its result line is admitted"
        );

        // Owned response text, on the cause a peer can actually reach. The
        // response owner is one broad residual rather than a byte figure, so
        // the grant that refuses it is one with nothing left at all: a
        // scope-only grant funds its own process scope and no reservation
        // after it.
        let text = "a response field chosen outside the daemon";
        let (starved, provider) = probed_admission_for_reservations([]);
        let baseline = provider.in_use();
        let refusal = match PreparedText::acquiring(text.to_owned(), &starved) {
            Ok(_) => panic!("a scope-only grant cannot fund a response owner"),
            Err(refusal) => refusal,
        };
        assert!(matches!(refusal, FrameRefusal::Resources(_)));
        assert_eq!(provider.in_use(), baseline, "refusal retains no claim");

        let (funded, provider) = probed_admission_granting_bytes(1 << 16);
        let baseline = provider.in_use();
        let value = PreparedText::acquiring(text.to_owned(), &funded)
            .expect("the positive grant funds the owned response string");
        let reply = PreparedReply::Error(value);
        let line = AdmittedLineOut::encode(ControlOut::Prepared(&reply), &funded)
            .expect("the same grant funds encoded output beside the owned text");
        assert!(line
            .bytes()
            .windows(text.len())
            .any(|bytes| bytes == text.as_bytes()));
        drop((line, reply));
        assert_eq!(
            provider.in_use(),
            baseline,
            "both the response owner and the encoded claim return"
        );
    }

    /// The generated network id follows the shape `dispatch::identity` uses:
    /// the typed retention is admitted first, the id is committed only past
    /// that admission, and the line is measured over the committed id.
    #[test]
    fn network_id_pressure_precedes_generation_and_the_exact_line_build() {
        let plan = myownmesh_core::identity::prepare_generated_network_id()
            .expect("network-id generation can be planned without drawing randomness");
        let (starved, provider) = probed_admission_granting_bytes(0);
        let baseline = provider.in_use();
        let refusal = match starved.acquire_claim(plan.typed_retention_claim()) {
            Ok(_) => panic!("a zero-byte grant cannot fund a generated network id"),
            Err(refusal) => refusal,
        };
        assert!(matches!(refusal, FrameRefusal::Resources(_)));
        assert_eq!(provider.in_use(), baseline, "refusal retains nothing");
        // The refusal reached no randomness: `commit` consumes the typed lease
        // this acquisition did not produce, so it is unreachable from here.
        drop(plan);

        let plan = myownmesh_core::identity::prepare_generated_network_id()
            .expect("the positive generation plan is representable");
        let (funded, provider) = probed_admission_granting_bytes(1 << 16);
        let baseline = provider.in_use();
        let typed = funded
            .acquire_claim(plan.typed_retention_claim())
            .expect("the positive grant funds the typed id");
        let network_id = plan.commit(typed).expect("the admitted plan commits");
        let reply = PreparedReply::NetworkId(network_id);
        let line = AdmittedLineOut::encode(ControlOut::Prepared(&reply), &funded)
            .expect("the same grant funds the generated response line");
        assert_eq!(
            line.bytes().last().copied(),
            Some(NEWLINE),
            "the measured line is the encoded one, terminator included"
        );
        drop((line, reply));
        assert_eq!(
            provider.in_use(),
            baseline,
            "both funded owners release exactly"
        );
    }

    #[test]
    fn status_pressure_invokes_no_snapshot_builder_and_the_full_grant_builds_once() {
        let registry = crate::registry::NetworkRegistry::new();
        let identity = myownmesh_core::Identity::ephemeral();
        let realtime = crate::control::RealtimeAdvert {
            supported: false,
            encodings: Vec::new(),
        };
        let source = registry.status_source(&identity, &realtime);
        let typed_claim = source.typed_claim().expect("status is representable");
        let line_ceiling = source.line_ceiling().expect("status line is representable");
        let (starved, provider) = probed_admission_granting_bytes(0);
        let baseline = provider.in_use();
        let mut commits = 0usize;
        let refusal =
            match prepare_typed_and_line_building(typed_claim, line_ceiling, &starved, |typed| {
                commits += 1;
                source.commit(typed)
            }) {
                Ok(_) => panic!("a zero-byte grant cannot fund Status"),
                Err(refusal) => refusal,
            };
        assert!(matches!(refusal, FrameRefusal::Resources(_)));
        assert_eq!(commits, 0, "pressure constructs no status snapshot");
        assert_eq!(provider.in_use(), baseline, "refusal retains nothing");

        let source = registry.status_source(&identity, &realtime);
        let typed_claim = source.typed_claim().expect("status remains representable");
        let line_ceiling = source
            .line_ceiling()
            .expect("status line remains representable");
        let line_bytes_claim = myownmesh_core::ResourceClaim::single(
            myownmesh_core::ResourceClass::AccountedMemoryBytes,
            u64::try_from(line_ceiling).expect("the Status line fits the resource model"),
        );
        let line_allocation_claim = myownmesh_core::ResourceClaim::single(
            myownmesh_core::ResourceClass::OpaqueDependencyResidual,
            LINE_WRITE_ALLOCATIONS,
        );
        let (funded, provider) = probed_admission_for_reservations([
            typed_claim,
            line_bytes_claim,
            line_allocation_claim,
        ]);
        let baseline = provider.in_use();
        let mut commits = 0usize;
        let (status, output) =
            prepare_typed_and_line_building(typed_claim, line_ceiling, &funded, |typed| {
                commits += 1;
                source.commit(typed)
            })
            .expect("the full grant funds Status");
        let reply = PreparedReply::Status(status.expect("the exact claim commits"));
        let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
            .expect("the measured ceiling carries Status");
        assert_eq!(commits, 1, "the snapshot is built exactly once");
        assert_eq!(line.bytes().len(), line_ceiling);
        drop((line, reply));
        assert_eq!(provider.in_use(), baseline, "all Status funding returns");
    }

    #[test]
    fn v4_r3_daemon_networks_pressure_precedes_snapshot_build_and_exact_line() {
        let registry = crate::registry::NetworkRegistry::new();
        let plan = registry
            .prepare_networks_list()
            .expect("an empty registry has a representable NetworksList plan");
        let (typed_starved, provider) = probed_admission_for_reservations([]);
        let baseline = provider.in_use();
        let refusal = match typed_starved.acquire_claim(plan.typed_claim()) {
            Ok(_typed) => panic!("a scope-only grant cannot fund typed NetworksList retention"),
            Err(refusal) => refusal,
        };
        assert!(matches!(refusal, FrameRefusal::Resources(_)));
        assert_eq!(provider.in_use(), baseline, "typed refusal retains nothing");

        let registry = crate::registry::NetworkRegistry::new();
        let plan = registry
            .prepare_networks_list()
            .expect("the work-pressure plan is representable");
        let typed_claim = plan.typed_claim();
        let (work_starved, provider) = probed_admission_for_reservations([typed_claim]);
        let baseline = provider.in_use();
        let typed = work_starved
            .acquire_claim(typed_claim)
            .expect("the exact typed reservation is available");
        let refusal = match work_starved.acquire_claim(plan.work_claim()) {
            Ok(_work) => panic!("a typed-only grant cannot fund NetworksList work"),
            Err(refusal) => refusal,
        };
        drop((typed, plan));
        assert!(matches!(refusal, FrameRefusal::Resources(_)));
        assert_eq!(
            provider.in_use(),
            baseline,
            "work refusal returns typed funding"
        );

        let registry = crate::registry::NetworkRegistry::new();
        let plan = registry
            .prepare_networks_list()
            .expect("the line-pressure plan is representable");
        let typed_claim = plan.typed_claim();
        let work_claim = plan.work_claim();
        let (line_bytes_starved, provider) =
            probed_admission_for_reservations([typed_claim, work_claim]);
        let baseline = provider.in_use();
        let typed = line_bytes_starved
            .acquire_claim(typed_claim)
            .expect("typed retention is funded before line pressure");
        let work = line_bytes_starved
            .acquire_claim(work_claim)
            .expect("work is funded before line pressure");
        let plan = plan
            .measure_line_ceiling(&work)
            .expect("the funded empty line is measurable");
        let empty_line_ceiling = plan.line_ceiling();
        let refusal =
            match AdmittedLineOut::prepare_capacity(empty_line_ceiling, &line_bytes_starved) {
                Ok(_output) => panic!("typed and work reservations cannot also fund line bytes"),
                Err(refusal) => refusal,
            };
        drop((plan, work, typed));
        assert!(matches!(refusal, FrameRefusal::Resources(_)));
        assert_eq!(
            provider.in_use(),
            baseline,
            "line refusal returns earlier leases"
        );

        let line_bytes_claim = myownmesh_core::ResourceClaim::single(
            myownmesh_core::ResourceClass::AccountedMemoryBytes,
            u64::try_from(empty_line_ceiling).expect("the line fits the resource model"),
        );
        let line_allocation_claim = myownmesh_core::ResourceClaim::single(
            myownmesh_core::ResourceClass::OpaqueDependencyResidual,
            1,
        );
        let registry = crate::registry::NetworkRegistry::new();
        let plan = registry
            .prepare_networks_list()
            .expect("the allocation-pressure plan is representable");
        let typed_claim = plan.typed_claim();
        let work_claim = plan.work_claim();
        let (line_allocation_starved, provider) =
            probed_admission_for_reservations([typed_claim, work_claim, line_bytes_claim]);
        let baseline = provider.in_use();
        let typed = line_allocation_starved
            .acquire_claim(typed_claim)
            .expect("typed retention is funded");
        let work = line_allocation_starved
            .acquire_claim(work_claim)
            .expect("work is funded");
        let plan = plan
            .measure_line_ceiling(&work)
            .expect("line measurement is funded");
        assert_eq!(plan.line_ceiling(), empty_line_ceiling);
        let refusal = match AdmittedLineOut::prepare_capacity(
            plan.line_ceiling(),
            &line_allocation_starved,
        ) {
            Ok(_output) => panic!("the byte-only line grant cannot fund its allocation"),
            Err(refusal) => refusal,
        };
        drop((plan, work, typed));
        assert!(matches!(refusal, FrameRefusal::Resources(_)));
        assert_eq!(
            provider.in_use(),
            baseline,
            "the admitted line bytes return when allocation pressure refuses"
        );

        let registry = crate::registry::NetworkRegistry::new();
        let plan = registry
            .prepare_networks_list()
            .expect("the funded NetworksList plan is representable");
        let typed_claim = plan.typed_claim();
        let work_claim = plan.work_claim();
        let (funded, provider) = probed_admission_for_reservations([
            typed_claim,
            work_claim,
            line_bytes_claim,
            line_allocation_claim,
        ]);
        let baseline = provider.in_use();
        let baseline_work = parse_work(&provider);
        let typed = funded
            .acquire_claim(typed_claim)
            .expect("the exact typed claim is funded");
        let work = funded
            .acquire_claim(work_claim)
            .expect("the exact work ceiling is funded");
        assert!(
            parse_work(&provider) > baseline_work,
            "the work lease is genuinely held before measurement"
        );
        let plan = plan
            .measure_line_ceiling(&work)
            .expect("the admitted work funds exact line measurement");
        assert_eq!(plan.line_ceiling(), empty_line_ceiling);
        let output = AdmittedLineOut::prepare_capacity(plan.line_ceiling(), &funded)
            .expect("the exact line claims are funded");
        let networks = match plan.commit(typed, work) {
            Ok(networks) => networks,
            Err((_typed, _work)) => panic!("the unchanged authoritative snapshot commits"),
        };
        let reply = PreparedReply::Networks(networks);
        let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
            .expect("the exact empty NetworksList ceiling carries the line");
        assert_eq!(line.bytes().len(), empty_line_ceiling);
        drop((line, reply));
        assert_eq!(
            provider.in_use(),
            baseline,
            "typed, work, line bytes, and line allocation all return"
        );
    }
    #[tokio::test]
    async fn a_funded_connection_reader_is_built_once() {
        let admission = admission_granting_bytes(CONTROL_READ_BUFFER_BYTES as u64 + 512);
        let polls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let built = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reader = CountingReader {
            remaining: b"{\"op\":\"status\"}\n",
            polls: polls.clone(),
        };
        let counted = built.clone();
        let mut admitted =
            AdmittedReader::admit_building(reader, &admission, move |capacity, inner| {
                counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::io::BufReader::with_capacity(capacity, inner)
            })
            .expect("the grant covers one read buffer");
        assert_eq!(
            built.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the funded path builds the buffer exactly once"
        );
        assert_eq!(
            polls.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "and building it reads nothing"
        );
        let line = read_bounded_json_line(admitted.frames(), &admission)
            .await
            .unwrap()
            .expect("a complete line");
        assert_eq!(line.as_str(), "{\"op\":\"status\"}");
        assert!(
            polls.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "non-vacuity: the funded reader really is the one being read"
        );
    }

    /// A connection whose read buffer is refused never reads a byte.
    ///
    /// Negative half, and the construction count is the assertion that matters.
    ///
    /// "Returned an error" is cheap: a version that built the eight-kilobyte
    /// buffer first and claimed afterwards would satisfy it, and would satisfy a
    /// poll count too, because `BufReader::with_capacity` does not poll what it
    /// wraps. What discriminates is that the buffer was never *built* -- and
    /// since `admit_building` takes the construction itself rather than a hook
    /// beside it, a zero count is that fact and not a proxy for it.
    #[tokio::test]
    async fn a_refused_connection_reader_is_never_built() {
        // One byte short of the buffer this connection would ask for.
        let admission = admission_granting_bytes(CONTROL_READ_BUFFER_BYTES as u64 - 1);
        let polls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let built = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reader = CountingReader {
            remaining: b"{\"op\":\"status\"}\n",
            polls: polls.clone(),
        };
        let counted = built.clone();
        // Matched rather than `expect_err`, here and below: the success types
        // carry a `ResourceLease` and an `AdmittedLine`, and giving
        // resource-bearing types a `Debug` so that a test can print one is
        // production surface added for a test's benefit.
        let refusal =
            match AdmittedReader::admit_building(reader, &admission, move |capacity, inner| {
                counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::io::BufReader::with_capacity(capacity, inner)
            }) {
                Ok(_) => panic!("the grant is one byte short of a read buffer"),
                Err(refusal) => refusal,
            };
        assert!(
            matches!(refusal, FrameRefusal::Resources(_)),
            "refused by the provider: {refusal}"
        );
        assert_eq!(
            built.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a connection the daemon cannot afford is given no buffer at all"
        );
        assert_eq!(
            polls.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "and is never read"
        );
    }

    /// Buffer capacity is refused by the *provider*, before the line grows.
    ///
    /// Positive first, then negative, against a provider this control owns: the
    /// same admission that funded a short line refuses a longer one for want of
    /// accounted memory, with no owner ceiling involved anywhere. That is the
    /// difference between this and the ceiling control below — a ceiling is the
    /// owner's policy answering, and it would still pass if provider admission
    /// were removed entirely.
    #[tokio::test]
    async fn provider_pressure_refuses_a_line_before_its_buffer_grows() {
        // Comfortably funds the short line and its two buffer allocations.
        let admission = admission_granting_bytes(512);
        let short = b"{\"op\":\"status\"}\n";
        let mut reader = tokio::io::BufReader::new(&short[..]);
        let line = read_bounded_json_line(&mut reader, &admission)
            .await
            .expect("the short line is funded")
            .expect("a complete line");
        assert_eq!(line.as_str(), "{\"op\":\"status\"}");

        // Same admission, now holding the short line's funding, and a line that
        // does not fit in what is left.
        let long = vec![b'x'; 4096];
        let mut reader = tokio::io::BufReader::new(&long[..]);
        let error = match read_bounded_json_line(&mut reader, &admission).await {
            Ok(_) => panic!("four kilobytes do not fit in the remaining grant"),
            Err(error) => error,
        };
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("refused by the resource provider"),
            "refused by the provider rather than by an owner ceiling: {rendered}"
        );
        assert!(
            !rendered.contains("owner-selected ceiling"),
            "this admission has no ceiling at all: {rendered}"
        );
        drop(line);
    }

    /// The structural parse claim is refused before the `Request` is allocated.
    ///
    /// Positive then negative on one owned provider: a line whose structural
    /// claim fits decodes, and a line whose structural claim does not is refused
    /// as `Admission` — not as `Malformed`, which is what a decode that ran
    /// anyway and then failed would look like. The line itself is well-formed
    /// JSON in both halves, so shape is not what separates them.
    #[tokio::test]
    async fn structural_parse_pressure_refuses_before_the_request_is_allocated() {
        let admission = admission_granting_bytes(1 << 16);
        let input = b"{\"op\":\"status\"}\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let line = read_bounded_json_line(&mut reader, &admission)
            .await
            .expect("the line is funded")
            .expect("a complete line");
        let admitted = line
            .decode_request(&admission)
            .expect("the structural claim fits this grant");
        assert!(matches!(admitted.request, Request::Status));

        // A second decode of the same line, against a provider whose accounted
        // memory is now too small to carry another decoded tree. `json_input_work_claim`
        // charges several bytes per input byte, so a grant this tight refuses.
        let tight = admission_granting_bytes(8);
        let refusal = match line.decode_request(&tight) {
            Ok(_) => panic!("eight bytes cannot fund a decoded request"),
            Err(refusal) => refusal,
        };
        assert!(
            matches!(refusal, DecodeRefusal::Admission(_)),
            "refused before the parse, not reported as malformed"
        );
        drop((admitted, line));
    }

    /// Refusal happens before the line buffer grows.
    ///
    /// The reader must decide whether it may hold the next chunk *before* it
    /// allocates room for it. This is the *ceiling* half of that: an owner's
    /// bound refusing a line the connection is not allowed to hold. The
    /// provider half is
    /// [`provider_pressure_refuses_a_line_before_its_buffer_grows`], which does
    /// the same thing under a grant too small rather than a policy too tight.
    /// Both refusals leave `admit_buffer_growth` by the same `?`, ahead of the
    /// same `reserve_exact`, so the two are the same ordering reached by the two
    /// different reasons a chunk can be turned away.
    #[tokio::test]
    async fn the_reader_refuses_a_chunk_before_reserving_room_for_it() {
        let input = b"123456789\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let error = match read_bounded_json_line(&mut reader, &admission_capped_at(8)).await {
            Ok(_) => panic!("nine bytes exceed eight"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("owner-selected ceiling"),
            "refused by the owner's bound rather than by the provider"
        );
    }

    /// A malformed line is the client's error and stays distinguishable from a
    /// refused one.
    ///
    /// The two arms of [`DecodeRefusal`] are answered differently on the wire —
    /// one is reported back so the client can retry, the other is the daemon at
    /// the edge of its grant — so collapsing them would tell a client its
    /// well-formed request was a parse error.
    ///
    /// The second half also pins the acquire-*before*-parse ordering, which is
    /// otherwise only a matter of which line of `decode` comes first. The very
    /// same malformed line, offered to a provider too small to fund a decode,
    /// comes back as `Admission` -- a parse that ran first would have reached
    /// the syntax error and reported `Malformed` no matter how tight the grant
    /// was, so the two arms swapping under pressure is the ordering.
    #[tokio::test]
    async fn a_malformed_line_is_reported_as_malformed_and_not_as_pressure() {
        let input = b"{ this is not json
";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let line = read_bounded_json_line(&mut reader, &granted_admission())
            .await
            .unwrap()
            .expect("a complete line");
        let refusal = match line.decode_request(&granted_admission()) {
            Ok(_) => panic!("the line is not a request"),
            Err(refusal) => refusal,
        };
        assert!(matches!(refusal, DecodeRefusal::Malformed(_)));

        let starved = admission_granting_bytes(8);
        let refusal = match line.decode_request(&starved) {
            Ok(_) => panic!("eight bytes cannot fund a decode"),
            Err(refusal) => refusal,
        };
        assert!(
            matches!(refusal, DecodeRefusal::Admission(_)),
            "funding is taken before the parse, so pressure answers first"
        );
    }

    /// The decoded request outlives the bytes it was parsed from, and its
    /// funding outlives it.
    ///
    /// The raw line is dropped here exactly as `handle_client` drops it, while
    /// the structural lease and the decoded value stay live. The drop order is
    /// the other half and is compile-visible rather than asserted: `AdmittedRequest` declares the
    /// request before its retention, so the request is destroyed before the
    /// lease that accounts for it.
    #[tokio::test]
    async fn the_decoded_request_carries_its_own_funding_past_the_line() {
        let input = b"{\"op\":\"status\"}\n";
        let admission = granted_admission();
        let admitted = {
            let mut reader = tokio::io::BufReader::new(&input[..]);
            let line = read_bounded_json_line(&mut reader, &admission)
                .await
                .unwrap()
                .expect("a complete line");
            let decoded = line.decode_request(&admission).expect("a status request");
            drop(line);
            decoded
        };
        assert!(matches!(admitted.request, Request::Status));
    }

    /// A large unary RPC body stays funded by core while daemon output
    /// pressure answers, and the daemon does not build a response buffer until
    /// the exact line has been admitted.
    #[test]
    fn v4_r4_daemon_large_funded_rpc_pressure_precedes_reply_construction() {
        let scope = crate::test_application_scope();
        let body = serde_json::json!({ "payload": "x".repeat(32 * 1024) });
        let funded = myownmesh_core::rpc::FundedRpcCallResult::transport_lab_funded(
            &scope,
            Ok(myownmesh_core::rpc::RpcResponse::from_value(body)),
        )
        .expect("the real RPC settlement claim funds the large fixture");

        let (typed_starved, provider) = FrameAdmission::over_grant_probed(
            myownmesh_core::FiniteResourceProvider::scope_planning_charge(),
            None,
        );
        let baseline = provider.in_use();
        let refusal = match ResponseOwner::acquire(&typed_starved) {
            Ok(_) => panic!("the daemon provider has no response owner to give"),
            Err(refusal) => refusal,
        };
        assert!(matches!(refusal, FrameRefusal::Resources(_)));
        assert_eq!(
            provider.in_use(),
            baseline,
            "a refused typed acquisition returns the exact daemon ledger baseline"
        );
        assert!(
            funded.body().is_some(),
            "the independently funded upstream body remains live after daemon refusal"
        );

        let owner = ResponseOwner::acquire(&granted_admission())
            .expect("an ordinary application grant funds the daemon response owner");
        let reply = PreparedReply::Variable(FundedVariableReply::rpc_call(Ok(funded), owner));

        // The writer's measuring pass, run here against framing's own counting
        // sink so this control can name the exact width it starves by one byte.
        let mut counted = CountingSink::default();
        serde_json::to_writer(&mut counted, &ControlOut::Prepared(&reply))
            .expect("the sealed reply encodes");
        let line_len = counted.measured() + 1;

        let starved = admission_granting_bytes((line_len - 1) as u64);
        assert!(
            matches!(
                AdmittedLineOut::prepare_capacity(line_len, &starved),
                Err(FrameRefusal::Resources(_))
            ),
            "one byte short refuses before a response Vec exists"
        );

        let output = AdmittedLineOut::prepare_capacity(line_len, &granted_admission())
            .expect("the ordinary application grant funds the exact line");
        let line = AdmittedLineOut::encode_prepared(ControlOut::Prepared(&reply), output)
            .expect("the funded body encodes without changing width");
        assert_eq!(line.bytes().len(), line_len);
        let parsed: serde_json::Value = serde_json::from_slice(&line.bytes()[..line_len - 1])
            .expect("the compact wire is JSON");
        assert_eq!(parsed["ok"], true);
        assert_eq!(
            parsed["data"]["response"]["payload"]
                .as_str()
                .unwrap()
                .len(),
            32 * 1024
        );
    }
}
