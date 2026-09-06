# Evidence, local observations, and Hub maintenance

This unit has three separate contracts. Implementation and verification status
belong in the exact-head qualification record, not in this design document.

## Authority stays in the mesh evidence graph

Canonical signed facts, their full Ed25519 author keys, causal dependencies,
and verified network context remain the authority inputs. Local observations,
configured Hub roles, transport addresses, clocks, and routing advertisements
cannot grant membership or authorize another device's statements.

Replacing an identity does not rewrite old history. An old signature remains
attributed to the old key. A new key cannot claim that it authored or witnessed
old statements, and it does not inherit the old key's permissions. A valid
grant can authorize new statements by the new key; it cannot retroactively
change an old statement's author. Local data corruption or an intentional wipe
cannot be made impossible by this design. Nor can a peer learn about an
unannounced identity replacement instantaneously.

The graph performance work narrows subject-specific impact lookup and pending
proof reads. It does not prune historical signatures or change FactIds. An
additional lookup index costs retained space; reducing scratch allocations or
rows decoded is not automatically a net memory or disk reduction. Old live
checkpoints remain acceleration caches: a rejected cache must fall back to
verified canonical history rather than erase it.

## Node-local observation framework

The optional observation owner belongs to one joined network. It keeps bounded
aggregates about local sightings, attributed referrals, and outcomes such as
failure, stale information, or a key mismatch. A failed referral is not proof
of a dishonest referrer. A claimed locator and an authenticated observation
remain distinguishable.

Keys use full device identities. Times come from a local monotonic clock, not
a remote timestamp. Repeated observations update a bounded aggregate instead
of appending an event log. Explicit record, per-subject, age, and maintenance
limits govern retention. Expired records are not usable merely because a
maintenance pass has not reached them yet. Late outcomes must not update an
expired, retired, or replaced record.

This first framework is internal and ephemeral: no wire format, persistence,
mesh evidence import/export, reputation authority, or automatic tuning action.
Observation failure must not change normal mesh processing. A later tuner can
consume diagnostic summaries under its own reviewed policy; this unit does not
add that consumer.

## Existing sparse Hub topology and bounded maintenance

Hub identities remain explicitly configured. Spokes select redundant hubs by
deterministic rendezvous ranking; routing uses the existing exact-session
authenticated transport. With `N` total members, `H` distinct configured hubs,
and spoke redundancy `R <= H`, the configured topology has at most

`(N - H) * R + H * (H - 1) / 2`

undirected edges, excluding deliberate sticky/direct connections. For a
5,000-member planner workload with 16 hubs and redundancy 2, that is 10,088
edges rather than 12,497,500 full-mesh edges. These are test inputs and
arithmetic bounds, not product defaults or 5,000-device network measurements.
The Hub tier itself is still full mesh. Selecting every member as a hub does
not scale; each hub also needs capacity for its assigned spokes.

The optional Hub maintenance policy bounds parallel dials and work per pass.
Rotation through eligible work must prevent a repeatedly unavailable early
candidate from starving later candidates. Resource admission and existing
session promotion remain mandatory. A Hub role is neither a trust root nor a
promise of unlimited relay capacity.

Trickle applies only to idempotent Hub configuration advertisements. The
consistency digest binds the network context through its envelope and binds
the canonical Hub set, redundancy, and scheduler profile through a
domain-separated digest. It is not a semantic commitment. The receiver checks
the exact current authenticated owner, configured Hub eligibility, context,
and replay sequence before allowing an advertisement to influence suppression.
Remote configuration is never installed from an advertisement.

These advertisements are not forwarded and do not carry transferable
signatures or address authority. Their authenticity comes from the existing
endpoint-authenticated session. They must not be repurposed as globally signed
peer records.

Fact anti-entropy, requests, ACKs, application payloads, authentication,
revocation processing, connection repair, and close/shutdown do not pass through
this suppression mechanism. Neither do ICE candidates or end-of-candidates.
Optional owner policies default to absent, preserving existing configurations.
Changing a funded Hub policy or its Hub topology requires replacing the exact
runtime so old replay cursors and capacity reservations cannot survive into a
new configuration.

## Tree direction and continued discovery

The operator's requested uNET-style mechanism is a parent/child attachment
protocol, not just a different ranking of hub candidates. The tree extension
must keep one accepted primary parent, bounded child slots, and a separate
small set of backup candidates. A prospective parent rechecks its capacity
when accepting a registration. A candidate being visible is not a completed
registration or an authenticated connection.

The first proposed shape is deliberately shallow: a configured routing root,
its hub children, and leaf peers attached to those hubs. The root is a topology
role, never a semantic authority. The longest primary route is
leaf -> hub -> root -> hub -> leaf, within the existing four-hop envelope.
Deeper trees require separate protocol work; increasing the TTL silently is
not an implementation of this contract. The legacy Hubs mode above remains
unchanged. The bounded local runtime controls now pass authenticated attachment,
bidirectional four-hop delivery, lower-ranked fallback, discovery and accepted
relation expiry. See [the local verification record](qualification/graph-hub-local-evidence.md)
for exact source/binary evidence and limits. Pushed-head audit and operator
approval remain separate; no shipped-process or field qualification follows.

The tree is a preferred sparse route, not an exclusive connectivity or
permission hierarchy. A hub can refuse resources or forwarding service that
it owns; it cannot veto a separately permitted direct connection or a route
through another hub or relay. Parent refusal, failure, or exhaustion must
leave bounded alternate attempts available. A failed hub is a connectivity
dead end only when it was the only usable way out and no alternative route
exists. Authentication, membership rules, and each participant's resource
limits still apply; this is not a promise of unlimited capacity or reachability.

Preferred candidate ranking must agree between attachment and routing.
Retaining only a small preferred set must not permanently hide other eligible
candidates from paced exploration. Accepted parent slots and independently
admitted alternate forwarding are distinct services: neither a raw referral
nor an absent parent relation alone decides whether an alternate connection
is authorized. Retrying a payload after an ambiguous write also requires the
existing delivery/deduplication contract, not an unconditional second send.

Healthy routes must not disable exploration. Discovery has its own paced,
jittered budget, independent of Trickle suppression and connection health.
A peer can request a bounded identity page over an existing authenticated
session. Returned identities are attributed hints, not permission to connect,
membership evidence, or changes to the configured hub set. They may enter a
separate bounded connection-attempt policy which obtains its own resource
admission and completes the full authentication flow. Existing mDNS and Nostr
discovery remain independent of this directory.

Storm prevention applies at both ends: bounded sends and outstanding queries,
rate admission before producing a reply, bounded page size, exact request and
session matching, and replay/expiry checks. A reply must not trigger an
immediate next query. Advertisements and directory messages are never forwarded
or answered by broadcasts. Delayed timers skip missed work rather than replay
a backlog. Full pages continue from the last included identity, so exploration
neither skips records nor loops on a repeated cursor. Receiving a new hint
does not automatically create a permanent connection.

## Research used and deliberate boundaries

Chris Paul's uNET work separates knowing about an endpoint from maintaining a
connection to it. Its parent selection, backup relationships, and next-hop
state provide useful design guidance for sparse connectivity. Here, stable
device keys remain independent of locators, while existing authenticated
admission replaces the patent's trust machinery. The operator has confirmed
permission to use the applicable uNET mechanisms. This is a technical design
reference, not a separate patent-clearance opinion.
[uNET architecture patent](https://patents.google.com/patent/US20160182350A1/en)

Trickle contributes randomized interval scheduling, redundancy suppression,
bounded interval growth, and explicit consistency semantics. This application
adds a local reset budget and retains a repair-needed indication; it does not
treat unauthenticated traffic as a reset event.
[RFC 6206](https://www.rfc-editor.org/rfc/rfc6206.html)

The libp2p influence is bounded neighbor fanout and separation of dissemination
from content validation. This is not a claim of Gossipsub wire compatibility.
[Gossipsub specification](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md)

QUIC illustrates the distinction between connection-wide and per-stream work
and the need to validate paths independently of address hints. This unit keeps
WebRTC/SCTP and its existing admission/backpressure boundaries; it does not
implement QUIC or claim QUIC delivery semantics over SCTP.
[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)

Permanent keys do not by themselves establish honest behavior, one identity
per physical device, Sybil resistance, or sufficient network capacity. Those
are not assumptions used to authorize mesh evidence.
