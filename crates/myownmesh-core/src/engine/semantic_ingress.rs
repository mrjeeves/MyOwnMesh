//! The Semantic Node's ingress: one transport-independent port for durable
//! semantic exchange.
//!
//! # Two ingresses, and why they are two
//!
//! `signaling_ingress` admits **ephemeral transport signals** — presence,
//! withdrawal, and the offer/answer/candidate exchange — from carriers nobody
//! authenticated. Everything it can emit is reachability evidence about one
//! connection attempt, and the closure of that union is what makes a relay
//! unable to touch a durable fact however it is fed.
//!
//! This module is the other half. It is not "the authenticated lane": it is the
//! lane where the *content* carries its own authority.
//!
//! | | ephemeral carrier ingress | durable semantic exchange |
//! |---|---|---|
//! | what it carries | evidence about one attempt | facts, pages, inventories, requests |
//! | what makes it actionable | nothing — it grants nothing | the embedded author, signature and domain context |
//! | who may deliver it | any carrier | any carrier, cache, file or medium |
//! | may change the roster | never | that is what it is for |
//! | admitted by | [`super::signaling_ingress`] | [`DurableSemanticPort::admit`] |
//!
//! # Fact authority is content, not carrier
//!
//! ```text
//! fact authority = canonical content
//!                + embedded author and signature
//!                + exact mesh/domain context
//!                + causal/domain validation
//!
//! fact authority != the current carrier
//!                != the current session sender
//! ```
//!
//! An earlier revision of this module said the opposite — that a durable fact is
//! worth acting on because of *who stated it* — and the reducers enforced it:
//! a proposal, ack or split whose embedded author differed from the delivering
//! session's own pubkey was refused. That made a peer unable to relay a valid
//! signed fact authored by a Device this node cannot reach, and it made a cache,
//! a file, a serial link, removable media or a future durable carrier unable to
//! feed the same reducer without first minting a Peer Session. Endpoint
//! authentication protects a live session; it was never what makes a fact true.
//!
//! So [`reduce`] takes the session — when there is one — as a **reply route and
//! nothing else**. For [`Exchange::SignedFact`] that is a type property rather
//! than a promise: those arms are never handed the token, so the compiler is
//! what enforces it (see [`Exchange`]). [`Exchange::FactPage`] does receive a
//! device id derived from the route, and it is diagnostics only — a
//! session-scoped label on a trace and a log line, never consulted to decide
//! whether the page is true. The page authenticates itself the same way a
//! single fact does.
//!
//! **What would be a defect, stated precisely.** Adding a durable body to the
//! *ephemeral* union would be one: it would put a fact on a carrier that cannot
//! say who sent it and has no signature to check. Adding a separate typed
//! durable-exchange carrier — a cache adapter, a file replay, a store — is the
//! opposite, and is the architecture this port exists to make possible.
//!
//! # What "closed" means here
//!
//! [`DurableSemanticExchange`] wraps a private enum. Nothing outside this module
//! can name a variant, so nothing outside can build one — the only way to obtain
//! the type is [`DurableSemanticPort::admit`], which is total over [`MeshMessage`] with no `_` arm. A
//! future durable message reaches this module or it reaches nothing.
//!
//! # Why the outcome is its own enum and not a `Result`
//!
//! "Not a durable exchange" is not an error — it is the ordinary case, and the
//! frame comes back whole for the engine to dispatch. A `Result` would have said
//! the opposite, and it would also have put a `MeshMessage` in an `Err`, which is
//! large: boxing the non-durable frame keeps the enum layout bounded by the
//! durable exchange arm while the classifier still moves that frame exactly
//! once.

use std::sync::Arc;

use tracing::trace;

use crate::protocol::{
    FactInventory, FactPageMessage, FactRequest, MeshMessage, ProofDeliveryMessage,
};
use crate::semantic::{Admission, DeviceId, SignedFact};

use super::governance;
use super::peer_registry::LogicalSessionOperation;
use super::state::NetworkState;

/// One admitted durable semantic exchange.
///
/// The private field is the point: see the module documentation for why this
/// type is obtainable only through [`DurableSemanticPort::admit`].
pub(crate) struct DurableSemanticExchange {
    exchange: Exchange,
}

/// The closed set of things a durable semantic exchange can be.
///
/// Five classes, because these messages are not one semantic kind and
/// calling them all "facts" hid the difference that matters: only two of these
/// classes are things to content-address, store, compact or project, and only
/// the other two have anyone to answer.
///
/// **The split is load-bearing for the reply route.** [`reduce`] hands the
/// optional [`LogicalSessionOperation`] itself to the inventory and request
/// arms only. Governance carries that workerless route to the final reply
/// sender and never turns it into a channel-local route.
/// [`Self::SignedFact`] is not merely trusted not to read it — it is never
/// passed it, so for signed facts "a fact does not depend on its courier" is
/// checked by the compiler rather than by review.
///
/// [`Self::FactPage`] is the one arm where that is a review property instead
/// of a type property, and the difference is worth stating plainly rather than
/// rounding off. It is passed a `&str` device id read off the route only as a
/// diagnostic label in a trace and log line, scoped to the session it arrived
/// on. It is not an input to verification, not compared against any author,
/// and not able to make a page acceptable or unacceptable — the log walk
/// from genesis decides that alone.
enum Exchange {
    /// A fact that carries its own author, signature and domain context.
    ///
    /// Verified by [`super::governance`] against the embedded signature over a
    /// canonical payload that names this network and the state signing domain.
    /// Nothing about the delivery is consulted.
    SignedFact(Box<SignedFact>),
    /// A bounded page of signed semantic facts.
    ///
    /// Self-authenticating the same way, in bulk: each fact is verified and
    /// reduced through the canonical graph, and a bad signature or invalid
    /// causal relation is refused rather than treated as authority.
    ///
    /// The unsigned `entries` list is carrier material only, not an
    /// authority-bearing membership fact. Signed governance/member logs are
    /// the canonical state source; inventories and requests remain exchanges.
    FactPage(FactPageMessage),
    /// A typed durable stand-down proof. Its identity is bound to the exact
    /// context, target, and canonical FactIds and may receive a verified ACK
    /// only after admission and projection succeed.
    ProofDelivery(ProofDeliveryMessage),
    /// A summary of what the sender has, so the two sides can find a difference.
    ///
    /// Counts and digests. Nothing here is stored or projected; its whole use is
    /// deciding whether to ask for something, which is why it needs a route back
    /// and a fact does not.
    Inventory(Inventory),
    /// A request for what the sender is missing.
    ///
    /// Carries no content to validate. It exists to be answered, so the reply
    /// route is the only thing it needs — and the answer must go to the exact
    /// installation that asked, not to whoever holds that device id by the time
    /// the reply is built.
    DependencyRequest(DependencyRequest),
}

/// A summary of the sender's state, for comparison.
enum Inventory {
    /// Exact-context FactIds known by the sender. This is coordination only;
    /// it carries no signed body and therefore cannot authorize anything.
    Facts(FactInventory),
}

/// A request for rows the sender is missing.
enum DependencyRequest {
    /// Exact-context FactIds whose signed bodies the sender requests. The
    /// response is a FactPage; this request cannot install a fact.
    Facts(FactRequest),
}

/// The durable-semantic port.  It admits only the closed durable exchange set
/// and returns every other wire frame untouched for the temporary engine
/// supervisor.  Keeping this port separate from the compatibility result makes
/// the durable lane available to a future store/file carrier without giving it
/// an ephemeral transport value to parse.
pub(crate) struct DurableSemanticPort;

impl DurableSemanticPort {
    /// Admit a wire frame before any domain reducer parsing.  The error is the
    /// original frame, not a second representation or a generic envelope.
    pub(crate) fn admit(message: MeshMessage) -> Result<DurableSemanticExchange, Box<MeshMessage>> {
        let exchange = match message {
            MeshMessage::Fact(m) => Exchange::SignedFact(Box::new(m)),
            MeshMessage::FactPage(m) => {
                if m.validate().is_err() {
                    return Err(Box::new(MeshMessage::FactPage(m)));
                }
                Exchange::FactPage(m)
            }
            MeshMessage::ProofDelivery(m) => Exchange::ProofDelivery(m),
            MeshMessage::FactInventory(m) => Exchange::Inventory(Inventory::Facts(m)),
            MeshMessage::FactRequest(m) => Exchange::DependencyRequest(DependencyRequest::Facts(m)),
            other => return Err(Box::new(other)),
        };
        Ok(DurableSemanticExchange { exchange })
    }
}

/// What a delivery is called in a log line when no session carried it.
///
/// A cache replay, a file, a future durable carrier: there is a source, but not
/// a peer. Diagnostics need a word for it; nothing reads it.
const NO_SESSION: &str = "(no session)";

impl DurableSemanticExchange {
    /// The exchange's kind, for diagnostics. Names the shape and never the
    /// content.
    pub(crate) fn kind_name(&self) -> &'static str {
        match self.exchange {
            Exchange::SignedFact(_) => "signed_fact",
            Exchange::FactPage(_) => "fact_page",
            Exchange::ProofDelivery(_) => "proof_delivery",
            Exchange::Inventory(Inventory::Facts(_)) => "fact_inventory",
            Exchange::DependencyRequest(DependencyRequest::Facts(_)) => "fact_request",
        }
    }
}

/// The Semantic Node's reducer: apply one durable semantic exchange.
///
/// # The route is optional, and the facts cannot see it
///
/// `reply` is where an answer would go, and it is the exact logical session the
/// input arrived on — not a device id to re-resolve, so a replacement that
/// landed mid-reduction does not receive the answer to a question its
/// predecessor asked. It is `Option` because a durable exchange does not need
/// one: a fact replayed from a cache or a file has nobody to answer, and that is
/// an ordinary case rather than an error. Governance receives this workerless
/// logical route and carries it to the final reply sender; channel identity
/// never enters this reducer.
///
/// It is **not** authority. The [`Exchange::SignedFact`] arms below are not
/// passed it at all, which is the whole reason [`Exchange`] separates them:
/// for those, transport-independence is checked by the compiler here rather
/// than asserted in a comment.
///
/// [`Exchange::FactPage`] is passed a device id derived from the route, and
/// only as a diagnostic label scoped to the logical session it arrived on. Nothing in
/// the page's acceptance reads it, so the property still holds there — it is
/// simply held by the reducer rather than by the type, and that distinction is
/// stated instead of glossed.
///
/// An inventory or a request that arrives with no route back is dropped with a
/// trace. There is nothing else honest to do with "tell me what you have" when
/// there is no-one to tell.
pub(super) async fn reduce(
    state: &Arc<NetworkState>,
    exchange: DurableSemanticExchange,
    reply: Option<&LogicalSessionOperation>,
) {
    let kind = exchange.kind_name();
    trace!(
        source = reply
            .map(|route| route.owner().device_id())
            .unwrap_or(NO_SESSION),
        kind,
        "reducing a durable semantic exchange"
    );
    match exchange.exchange {
        // Signed facts. No route, by construction — these three arms cannot
        // name `reply`, so the compiler is what keeps a courier out of the
        // decision.
        Exchange::SignedFact(m) => reduce_signed_fact(state, *m).await,
        // The page does see a device id off the route as a label for the trace
        // and log, scoped to this session, and never as a reason to accept or
        // reject anything; `source` does not appear in that decision.
        Exchange::FactPage(m) => {
            let facts = m.facts;
            let batch_admitted = reduce_signed_facts(state, facts.clone()).await;
            // The inventory is a durable exchange acknowledgement: it is the
            // receiver's exact post-admission fact set, sent back through the
            // same logical operation that delivered this page. A carrier,
            // heartbeat, or session observation cannot acknowledge a signed
            // proof, and a replacement cannot steal this reply route. Do not
            // call this an ACK until every fact in the page is present in the
            // authoritative graph. A quarantined, malformed, or empty page
            // must remain eligible for a later inventory/request repair; an
            // inventory emitted for it would be indistinguishable from a
            // verified acceptance to a sender that already has the same IDs.
            // Eviction proofs add one more check: their exact target must be
            // stood down by the resulting canonical projection.
            if batch_admitted
                && page_is_admitted(state, &facts)
                && governance::fact_page_projection_is_verified(state, &facts)
            {
                if let Some(route) = reply {
                    governance::acknowledge_fact_page(state, route).await;
                }
            } else {
                trace!(kind, "withholding semantic ACK for incomplete fact page");
            }
        }
        Exchange::ProofDelivery(delivery) => {
            if delivery.context_id != state.mesh_context_id() {
                trace!(kind, "withholding proof ACK for foreign mesh context");
                return;
            }
            if let Err(error) = delivery.validate() {
                trace!(kind, %error, "withholding proof ACK for invalid delivery");
                return;
            }
            let facts = delivery.facts.clone();
            let batch_admitted = reduce_signed_facts(state, facts).await;
            if batch_admitted && proof_delivery_is_verified(state, &delivery) {
                if let Some(route) = reply {
                    governance::acknowledge_proof_delivery(state, route, &delivery).await;
                }
            } else {
                trace!(
                    kind,
                    "withholding proof ACK for incomplete or unresolved delivery"
                );
            }
        }
        // Comparisons and questions. These are the ones with somebody to answer.
        Exchange::Inventory(inventory) => {
            let Some(route) = reply else {
                trace!(
                    kind,
                    "inventory with no route back; nothing to compare against"
                );
                return;
            };
            match inventory {
                Inventory::Facts(m) => {
                    if m.context_id() != state.mesh_context_id() {
                        trace!(kind, "discarding fact inventory for a foreign mesh context");
                        return;
                    }
                    governance::on_fact_inventory(state, route, m).await;
                }
            }
        }
        Exchange::DependencyRequest(request) => {
            let Some(route) = reply else {
                trace!(kind, "request with no route back; nothing to answer");
                return;
            };
            match request {
                DependencyRequest::Facts(m) => {
                    if m.context_id() != state.mesh_context_id() {
                        trace!(kind, "discarding fact request for a foreign mesh context");
                        return;
                    }
                    governance::on_fact_request(state, route, m).await;
                }
            }
        }
    }
}

/// Return whether a page is fully and exactly present in the authoritative
/// graph after reduction. The graph comparison is intentional rather than a
/// count check: a duplicate FactId with a different body must never turn into
/// an apparently successful ACK, and a quarantined fact is not admitted merely
/// because it has durable provisional custody.
fn page_is_admitted(state: &Arc<NetworkState>, facts: &[SignedFact]) -> bool {
    if facts.is_empty() {
        return false;
    }
    facts.iter().all(|fact| {
        state
            .admitted_semantic_fact(fact.id)
            .ok()
            .flatten()
            .as_ref()
            == Some(fact)
    })
}

/// Return whether a proof delivery is complete enough to acknowledge.  This
/// predicate is shared by the promoted reply route and the pending direct
/// worker route so neither path can emit a receipt merely because reduction
/// ran: the exact local target must be stood down by the resulting projection,
/// and every signed fact must be present in the authoritative graph.
pub(super) fn proof_delivery_is_verified(
    state: &Arc<NetworkState>,
    delivery: &ProofDeliveryMessage,
) -> bool {
    let Ok(local) = DeviceId::from_canonical_str(state.identity.public_id()) else {
        return false;
    };
    delivery.validate().is_ok()
        && delivery.context_id == state.mesh_context_id()
        && delivery.target == local
        && page_is_admitted(state, &delivery.facts)
        && governance::proof_delivery_projection_is_verified(state, delivery)
}

/// Admit a fact through the state's journaled publication boundary. The graph
/// write lock is held only inside that boundary and is released before any
/// semantic reducer runs; `AlreadyPresent` never enters durable storage or
/// returns a fact to reduce, so replaying a wire frame cannot apply it twice.
async fn admit_journaled_durably(
    state: &Arc<NetworkState>,
    fact: SignedFact,
) -> Result<(Admission, Vec<SignedFact>, crate::semantic::SemanticDelta), AdmissionError> {
    state
        .admit_fact_durably_with_delta_async(fact)
        .await
        .map_err(AdmissionError::Durable)
}

enum AdmissionError {
    Durable(crate::error::Error),
}

async fn reduce_signed_fact(state: &Arc<NetworkState>, fact: SignedFact) {
    match admit_journaled_durably(state, fact).await {
        Ok((Admission::Inserted, newly_inserted, delta)) => {
            governance::on_committed_facts(state, newly_inserted, delta).await;
        }
        Ok((Admission::AlreadyPresent | Admission::Quarantined { .. }, _, _)) => {}
        Err(AdmissionError::Durable(error)) => {
            trace!(error = %error, "journaled semantic admission refused")
        }
    }
}

/// Reduce one bounded page through one graph journal and one SQLite
/// transaction. Per-input outcomes decide the ACK, while the aggregate delta
/// is published exactly once after the durable commit.
async fn reduce_signed_facts(state: &Arc<NetworkState>, facts: Vec<SignedFact>) -> bool {
    if facts.is_empty() {
        trace!("withholding semantic ACK for empty fact batch");
        return false;
    }
    let expected = facts.len();
    let batch = match state.admit_facts_durably_with_delta_async(facts).await {
        Ok(batch) => batch,
        Err(error) => {
            trace!(%error, "withholding semantic ACK for failed aggregate admission");
            return false;
        }
    };
    let crate::engine::state::DurableAdmissionBatch {
        outcomes,
        changed_admitted,
        delta,
    } = batch;
    let mut all_admitted = outcomes.len() == expected;
    for (index, result) in outcomes.into_iter().enumerate() {
        match result {
            Ok(Admission::Inserted | Admission::AlreadyPresent) => {}
            Ok(Admission::Quarantined { .. }) => {
                all_admitted = false;
                trace!(index, "withholding semantic ACK for quarantined fact");
            }
            Err(error) => {
                all_admitted = false;
                trace!(index, %error, "withholding semantic ACK for refused fact");
            }
        }
    }
    if !changed_admitted.is_empty() {
        governance::on_committed_facts(state, changed_admitted, delta).await;
    }
    all_admitted
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical durable port's classification, as a comparable word.
    fn class(message: MeshMessage) -> &'static str {
        match DurableSemanticPort::admit(message) {
            Ok(exchange) => match exchange.exchange {
                Exchange::SignedFact(_) => "signed_fact",
                Exchange::FactPage(_) => "fact_page",
                Exchange::ProofDelivery(_) => "proof_delivery",
                Exchange::Inventory(_) => "inventory",
                Exchange::DependencyRequest(_) => "dependency_request",
            },
            Err(message) => {
                // The durable port returns the original frame unchanged.
                // Consume it here so the owned hand-back is explicit.
                drop(message);
                "not_durable"
            }
        }
    }

    /// **Every durable message is admitted here, into the class it actually
    /// belongs to, and nothing else is admitted at all.**
    ///
    /// The classification half is the correction. Durable semantic exchanges
    /// are separated from transport controls: an inventory is a comparison
    /// and a request is a question, while facts and proof deliveries carry the
    /// content that the canonical reducer can verify and admit.
    ///
    /// The closure half is the other's non-vacuity: a classifier that admitted
    /// everything would pass the first alone, and one that admitted nothing
    /// would pass the second.
    #[test]
    fn the_durable_set_is_classified_by_what_authenticates_each_message() {
        let expected = [
            (
                "fact_page",
                MeshMessage::FactPage(FactPageMessage {
                    context_id: crate::semantic::MeshContextId::from_bytes([0; 32]),
                    facts: Vec::new(),
                    next_cursor: None,
                    complete: true,
                }),
            ),
            (
                "inventory",
                MeshMessage::FactInventory(FactInventory::new(
                    crate::semantic::MeshContextId::from_bytes([0; 32]),
                    [],
                )),
            ),
        ];
        for (want, message) in expected {
            assert_eq!(
                class(message),
                want,
                "a durable message must reach the Semantic Node in the class \
                 that says what authenticates it"
            );
        }

        // A transport control and an application frame: neither is a durable
        // exchange, and both must come back untouched for the engine's own match.
        assert_eq!(
            class(MeshMessage::SessionControl(
                crate::protocol::SessionControl::Depart {
                    correlation: crate::protocol::DepartureCorrelation::from_bytes(
                        [0x22; crate::protocol::DEPARTURE_CORRELATION_BYTES]
                    ),
                }
            )),
            "not_durable",
            "a session-lifecycle control is the Peer Session owner's, not the \
             Semantic Node's"
        );
        assert_eq!(
            class(MeshMessage::Channel {
                channel: "chat".into(),
                payload: serde_json::Value::Null,
            }),
            "not_durable",
            "an application frame carries no durable content"
        );
    }
}
