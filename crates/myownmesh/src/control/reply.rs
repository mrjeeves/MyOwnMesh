//! One sealed reply envelope, and the exact line admission that funds it.
//!
//! `framing.rs` knows nothing about request meaning: bytes and admission are
//! its subject, and the vocabulary of what a reply *is* is this module's.
//!
//! What this module may do: describe a reply, measure its encoded line before
//! that line exists, and keep the owner that funds it alive until the bytes are
//! written. What it may not do: perform an operation. Every value here is
//! constructed by a domain module that knows what it is answering — see
//! `dispatch/network.rs` for the shape — and this module only says what such an
//! answer costs and how it encodes.
//!
//! There is one admission vocabulary and one measuring pass. [`ResponseOwner`]
//! is taken before the operation runs and covers the whole answer; the writer
//! measures the sealed reply once, on its way to funding the buffer.
//!
//! `pub(super)` here means `pub(in crate::control)`, exactly as it did in
//! `framing.rs`, so the domain modules already reach these names and nothing
//! widened on the way across.

use anyhow::Result;

use super::framing::{
    AdmittedLineOut, CountingSink, EncodeRefusal, FrameAdmission, FrameRefusal,
    PreparedLineCapacity,
};

/// Everything this control socket writes, as a closed set.
///
/// Closed, and not `impl Serialize`, and that is what makes the admission below
/// enforceable rather than merely intended. The measurement is taken by running
/// the encoder into a sink that counts, so the promise the seam depends on is
/// that *counting allocates nothing* — and a generic `Serialize` bound cannot
/// promise that. A caller's impl is free to build a `String`, collect a `Vec` or
/// do arbitrary work on its way past, and the refusal path would then have
/// allocated before it refused.
///
/// Every arm here is one this module can check. [`Response`] and [`ServerOut`]
/// are derived impls over scalars, `String`s and `serde_json::Value`s; `Value`'s
/// own impl walks the tree it already holds; [`ConnTrace`] is a derived impl
/// over scalars, `String`s and `Vec<String>`. None of them allocates to
/// serialize. Adding an arm is a deliberate act with that sentence attached to
/// it.
///
/// [`Response`]: super::wire::Response
/// [`ServerOut`]: crate::ipc::ServerOut
/// [`ConnTrace`]: myownmesh_core::ConnTrace
pub(super) enum ControlOut<'a> {
    /// One request's answer as the untyped envelope, which production does not
    /// write: every live arm answers through [`Self::Prepared`], where the
    /// reply's width is admitted before any owned field exists. The variant
    /// exists for the controls that assert this end still encodes as the wire
    /// contract `Response` describes, and is gated so a release build does not
    /// carry a shape nothing constructs.
    #[cfg(test)]
    Response(&'a super::wire::Response),
    /// One pushed frame on an events subscription.
    Frame(&'a crate::ipc::ServerOut),
    /// One connection-state record on a trace subscription.
    Trace(&'a myownmesh_core::ConnTrace),
    /// The trace stream's lag marker, which is a bare JSON object rather than
    /// one of the protocol's own shapes.
    Marker(&'a serde_json::Value),
    /// A response whose typed representation was admitted before any owned
    /// field was constructed.
    Prepared(&'a PreparedReply),
}

impl serde::Serialize for ControlOut<'_> {
    /// Delegates, and adds nothing. The wire shape of each arm is the arm's own
    /// and this wrapper must not change it: a client parses a `Response`, not a
    /// `ControlOut`.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            #[cfg(test)]
            Self::Response(value) => value.serialize(serializer),
            Self::Frame(value) => value.serialize(serializer),
            Self::Trace(value) => value.serialize(serializer),
            Self::Marker(value) => value.serialize(serializer),
            Self::Prepared(value) => value.serialize(serializer),
        }
    }
}

/// The allocation-free and exactly funded response shapes migrated to the
/// prepared boundary. New variants must remain closed and must serialize
/// without constructing a `Value`, `String`, or collection.
pub(super) enum PreparedReply {
    StaticError(&'static str),
    Error(PreparedText),
    Bool { key: &'static str, value: bool },
    Usize { key: &'static str, value: usize },
    TraceSubscribed { network: PreparedText },
    EventsSubscribed(myownmesh_core::FundedArc<crate::ipc::ClientHandle>),
    ServicesStatus(crate::services::FundedServicesStatus),
    Config(myownmesh_core::config::FundedMeshConfig),
    NetworkId(myownmesh_core::identity::FundedNetworkId),
    Status(crate::registry::FundedStatus),
    Networks(crate::registry::FundedNetworksList),
    Peers(FundedDiagnostic<Vec<myownmesh_core::PeerInfo>>),
    Roster(FundedDiagnostic<Vec<myownmesh_core::AuthorizedPeer>>),
    Bootstrap(FundedDiagnostic<myownmesh_core::semantic::BootstrapRecord>),
    SemanticFactPage(FundedDiagnostic<myownmesh_core::semantic::SemanticFactPage>),
    SemanticStateIdentity(FundedDiagnostic<myownmesh_core::semantic::SemanticStateIdentity>),
    SemanticRecentFacts(FundedDiagnostic<myownmesh_core::semantic::SemanticRecentFacts>),
    Variable(FundedVariableReply),
}

/// One broad response owner, acquired before the operation it answers for.
///
/// One `OpaqueDependencyResidual` covers the entire reply: the owned text it may
/// carry, the diagnostic value it may hold, and the sealed envelope the writer
/// serializes once.
///
/// **Intentionally broad.** This is not a byte budget and does not stand in for
/// one. What bounds the bytes is the encoded-line admission the writer takes
/// over the finished reply, before it allocates the buffer; this owner is only
/// the right to begin forming an answer. It does not replace that later,
/// fallible line admission. An effect whose reply carries its only usable
/// capability or secret still needs rollback ownership until the writer reports
/// [`crate::control::Wrote::Sent`].
///
/// A newtype rather than a bare lease because only [`Self::acquire`] builds one,
/// so a reply constructor needs no runtime check that the lease it was handed
/// carries this claim.
pub(super) struct ResponseOwner {
    _owner: myownmesh_core::ResourceLease,
}

const RESPONSE_OWNER_CLAIM: myownmesh_core::ResourceClaim = myownmesh_core::ResourceClaim::single(
    myownmesh_core::ResourceClass::OpaqueDependencyResidual,
    1,
);

impl ResponseOwner {
    /// Take the right to answer, before the operation that will be answered.
    pub(super) fn acquire(admission: &FrameAdmission) -> std::result::Result<Self, FrameRefusal> {
        Ok(Self {
            _owner: admission.acquire_claim(RESPONSE_OWNER_CLAIM)?,
        })
    }

    /// Seal one operation's outcome into the reply this owner funds.
    ///
    /// Consuming, so one owner cannot fund two answers, and the sealed value is
    /// the only thing that leaves. The operation modules hand this back and the
    /// connection loop writes it; there is no second place a reply is made.
    pub(super) fn finish(
        self,
        result: std::result::Result<OperationReplyData, String>,
    ) -> FundedVariableReply {
        FundedVariableReply::Operation(FundedOperationReply {
            result,
            _owner: self,
        })
    }
}

/// One diagnostic value retained beside the response owner that funds it.
pub(super) struct FundedDiagnostic<T> {
    value: T,
    _owner: ResponseOwner,
}

impl<T> FundedDiagnostic<T> {
    pub(super) fn new(value: T, owner: ResponseOwner) -> Self {
        Self {
            value,
            _owner: owner,
        }
    }
}

/// One owned response string, held under the response owner that funds it.
///
/// Every string this carries is formatted from values the request admission
/// already bounded, and the encoded line is measured exactly once, by the
/// writer, over the sealed reply this text is part of.
pub(super) struct PreparedText {
    value: String,
    _owner: ResponseOwner,
}

impl PreparedText {
    /// Take owned text under an owner already acquired for this response.
    pub(super) fn owned(value: String, owner: ResponseOwner) -> Self {
        Self {
            value,
            _owner: owner,
        }
    }

    /// The same, for a refusal with nothing else to fund: the operation either
    /// already failed or was never reached, so this is the response's only
    /// owner.
    pub(super) fn acquiring(
        value: String,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, FrameRefusal> {
        Ok(Self::owned(value, ResponseOwner::acquire(admission)?))
    }
}

impl serde::Serialize for PreparedReply {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        struct Field<'a, T: ?Sized> {
            key: &'static str,
            value: &'a T,
        }
        impl<T: serde::Serialize + ?Sized> serde::Serialize for Field<'_, T> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut data = serializer.serialize_struct("ResponseData", 1)?;
                data.serialize_field(self.key, self.value)?;
                data.end()
            }
        }

        match self {
            Self::StaticError(message) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &false)?;
                response.serialize_field("error", message)?;
                response.end()
            }
            Self::Error(message) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &false)?;
                response.serialize_field("error", &message.value)?;
                response.end()
            }
            Self::Bool { key, value } => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field("data", &Field { key, value })?;
                response.end()
            }
            Self::Usize { key, value } => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field("data", &Field { key, value })?;
                response.end()
            }
            Self::TraceSubscribed { network } => {
                #[derive(serde::Serialize)]
                struct TraceData<'a> {
                    subscribed: bool,
                    stream: &'static str,
                    network: &'a str,
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &TraceData {
                        subscribed: true,
                        stream: "conn_trace",
                        network: &network.value,
                    },
                )?;
                response.end()
            }
            Self::EventsSubscribed(client) => {
                #[derive(serde::Serialize)]
                struct EventsData<'a> {
                    subscribed: bool,
                    client_id: crate::ipc::ClientId,
                    client_capability: &'a str,
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &EventsData {
                        subscribed: true,
                        client_id: client.id,
                        client_capability: client.capability(),
                    },
                )?;
                response.end()
            }
            Self::ServicesStatus(status) => {
                #[derive(serde::Serialize)]
                struct ServicesData<'a> {
                    status: &'a crate::services::ServicesReport,
                    config: &'a myownmesh_core::ServicesConfig,
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &ServicesData {
                        status: status.report(),
                        config: status.config(),
                    },
                )?;
                response.end()
            }
            Self::Config(config) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &Field {
                        key: "config",
                        value: config.get(),
                    },
                )?;
                response.end()
            }
            Self::NetworkId(network_id) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &Field {
                        key: "network_id",
                        value: network_id.get(),
                    },
                )?;
                response.end()
            }
            Self::Status(status) => {
                #[derive(serde::Serialize)]
                struct StatusData<'a> {
                    version: &'static str,
                    device_id: &'a str,
                    joined_networks: &'a [String],
                    realtime: &'a crate::control::RealtimeAdvert,
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &StatusData {
                        version: status.version(),
                        device_id: status.device_id(),
                        joined_networks: status.joined_networks(),
                        realtime: status.realtime(),
                    },
                )?;
                response.end()
            }
            Self::Networks(networks) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field("data", networks)?;
                response.end()
            }
            Self::Peers(peers) => {
                #[derive(serde::Serialize)]
                struct PeersData<'a> {
                    peers: &'a [myownmesh_core::PeerInfo],
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &PeersData {
                        peers: &peers.value,
                    },
                )?;
                response.end()
            }
            Self::Roster(roster) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &RosterData {
                        roster: &roster.value,
                    },
                )?;
                response.end()
            }
            Self::Bootstrap(bootstrap) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &Field {
                        key: "bootstrap",
                        value: &bootstrap.value,
                    },
                )?;
                response.end()
            }
            Self::SemanticFactPage(page) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &Field {
                        key: "semantic_fact_page",
                        value: &page.value,
                    },
                )?;
                response.end()
            }
            Self::SemanticStateIdentity(identity) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &Field {
                        key: "semantic_state_identity",
                        value: &identity.value,
                    },
                )?;
                response.end()
            }
            Self::SemanticRecentFacts(facts) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field(
                    "data",
                    &Field {
                        key: "semantic_recent_facts",
                        value: &facts.value,
                    },
                )?;
                response.end()
            }
            Self::Variable(variable) => variable.serialize(serializer),
        }
    }
}

#[derive(serde::Serialize)]
struct RosterData<'a> {
    roster: &'a [myownmesh_core::AuthorizedPeer],
}

pub(super) enum FundedVariableReply {
    UpdaterStatus(myownmesh_updater::FundedUpdaterResult<myownmesh_updater::UpdateStatus>),
    UpdaterCheck(myownmesh_updater::FundedUpdaterResult<myownmesh_updater::CheckOutcome>),
    RpcCall(FundedRpcCallOutcome),
    MfaEnrollment(FundedMfaEnrollment),
    MfaTransaction(FundedMfaTransaction),
    Operation(FundedOperationReply),
}

pub(super) enum OperationReplyData {
    Removed(String),
    Topology(String),
    ProposalId(String),
    Reconnecting(String),
    Connecting {
        peer: String,
        network: String,
        pinned: bool,
        active: bool,
    },
    Forgotten(Vec<String>),
    Reset,
    UpdatedId {
        id: String,
        restarted: bool,
    },
    Added(NetworkLifecycleSummary),
    Updated(NetworkLifecycleSummary),
    Identity {
        device_id: String,
        pubkey: String,
        label: String,
    },
    Applied(Option<String>),
    RealtimeOpened {
        flow_label: String,
        capability: String,
    },
    OpaqueChanged {
        flow_capability: String,
        max_unit_bytes: u32,
    },
    Closed,
    RpcStreamStarted(String),
    ServicesStatus(crate::services::ServicesReport),
    RealtimeRefused {
        error: String,
        code: String,
    },
    GovernanceRefused {
        error: String,
        code: String,
    },
}

/// Stable wire classes for security-sensitive governance failures. The
/// diagnostic remains in `error`, but clients do not have to parse that text
/// to distinguish MFA from authority or transport failure.
pub(super) fn governance_error_code(error: &myownmesh_core::Error) -> &'static str {
    match error {
        myownmesh_core::Error::Custody(_) => "mfa",
        myownmesh_core::Error::Roster(_) => "authority",
        myownmesh_core::Error::SignatureInvalid => "signature_invalid",
        myownmesh_core::Error::PeerDenied => "peer_denied",
        myownmesh_core::Error::Network(_) => "network",
        _ => "governance",
    }
}

#[derive(serde::Serialize)]
pub(super) struct NetworkLifecycleSummary {
    pub(super) config_id: String,
    pub(super) network_id: String,
    pub(super) label: String,
    pub(super) phase: myownmesh_core::MeshPhase,
    pub(super) topology: myownmesh_core::TopologyMode,
    #[serde(skip)]
    pub(super) restarted: bool,
}

pub(super) struct FundedOperationReply {
    result: std::result::Result<OperationReplyData, String>,
    _owner: ResponseOwner,
}

pub(super) struct FundedRpcCallOutcome {
    result: std::result::Result<
        myownmesh_core::rpc::FundedRpcCallResult,
        myownmesh_core::rpc::RpcError,
    >,
    _owner: ResponseOwner,
}

pub(super) struct FundedMfaEnrollment {
    result: myownmesh_core::Result<myownmesh_core::custody::Enrolled>,
    transaction_id: Option<String>,
    _owner: ResponseOwner,
}

pub(super) struct FundedMfaTransaction {
    network: String,
    transaction_id: String,
    state: &'static str,
    material: Option<myownmesh_core::custody::Enrolled>,
    _owner: ResponseOwner,
}

impl FundedVariableReply {
    pub(super) fn updater_status(
        value: myownmesh_updater::FundedUpdaterResult<myownmesh_updater::UpdateStatus>,
    ) -> Self {
        Self::UpdaterStatus(value)
    }

    pub(super) fn updater_check(
        value: myownmesh_updater::FundedUpdaterResult<myownmesh_updater::CheckOutcome>,
    ) -> Self {
        Self::UpdaterCheck(value)
    }

    pub(super) fn rpc_call(
        result: std::result::Result<
            myownmesh_core::rpc::FundedRpcCallResult,
            myownmesh_core::rpc::RpcError,
        >,
        owner: ResponseOwner,
    ) -> Self {
        Self::RpcCall(FundedRpcCallOutcome {
            result,
            _owner: owner,
        })
    }

    pub(super) fn mfa_enrollment(
        result: myownmesh_core::Result<myownmesh_core::custody::Enrolled>,
        transaction_id: Option<String>,
        owner: ResponseOwner,
    ) -> Self {
        Self::MfaEnrollment(FundedMfaEnrollment {
            result,
            transaction_id,
            _owner: owner,
        })
    }

    pub(super) fn mfa_transaction(
        network: String,
        transaction_id: String,
        state: &'static str,
        material: Option<myownmesh_core::custody::Enrolled>,
        owner: ResponseOwner,
    ) -> Self {
        Self::MfaTransaction(FundedMfaTransaction {
            network,
            transaction_id,
            state,
            material,
            _owner: owner,
        })
    }
}

impl serde::Serialize for FundedVariableReply {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::UpdaterStatus(value) => serialize_updater_result(serializer, value),
            Self::UpdaterCheck(value) => serialize_updater_result(serializer, value),
            Self::RpcCall(value) => serialize_rpc_call(serializer, value),
            Self::MfaEnrollment(value) => serialize_mfa_enrollment(serializer, value),
            Self::MfaTransaction(value) => serialize_mfa_transaction(serializer, value),
            Self::Operation(value) => serialize_operation_reply(serializer, value),
        }
    }
}

fn serialize_operation_reply<S: serde::Serializer>(
    serializer: S,
    value: &FundedOperationReply,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct as _;
    match &value.result {
        Ok(OperationReplyData::RealtimeRefused { error, code })
        | Ok(OperationReplyData::GovernanceRefused { error, code }) => {
            #[derive(serde::Serialize)]
            struct RefusalData<'a> {
                code: &'a str,
            }
            let mut response = serializer.serialize_struct("Response", 3)?;
            response.serialize_field("ok", &false)?;
            response.serialize_field("error", error)?;
            response.serialize_field("data", &RefusalData { code })?;
            response.end()
        }
        Ok(data) => {
            #[derive(serde::Serialize)]
            #[serde(untagged)]
            enum OperationField<'a> {
                Removed {
                    removed: &'a str,
                },
                Topology {
                    topology: &'a str,
                },
                ProposalId {
                    proposal_id: &'a str,
                },
                Reconnecting {
                    reconnecting: &'a str,
                },
                Connecting {
                    connecting: &'a str,
                    network: &'a str,
                    pinned: bool,
                    active: bool,
                },
                Forgotten {
                    forgotten: &'a [String],
                    restarting: bool,
                },
                Reset {
                    reset: bool,
                    restarting: bool,
                },
                UpdatedId {
                    updated: &'a str,
                    restarted: bool,
                },
                Added {
                    added: &'a NetworkLifecycleSummary,
                },
                Updated {
                    updated: &'a NetworkLifecycleSummary,
                    restarted: bool,
                },
                Identity {
                    device_id: &'a str,
                    pubkey: &'a str,
                    label: &'a str,
                },
                Applied {
                    applied: &'a Option<String>,
                },
                RealtimeOpened {
                    flow_label: &'a str,
                    flow_capability: &'a str,
                },
                OpaqueChanged {
                    flow_capability: &'a str,
                    max_unit_bytes: u32,
                },
                Closed {
                    closed: bool,
                },
                RpcStreamStarted {
                    request_id: &'a str,
                },
                ServicesStatus {
                    status: &'a crate::services::ServicesReport,
                },
            }
            let field = match data {
                OperationReplyData::Removed(value) => OperationField::Removed { removed: value },
                OperationReplyData::Topology(value) => OperationField::Topology { topology: value },
                OperationReplyData::ProposalId(value) => {
                    OperationField::ProposalId { proposal_id: value }
                }
                OperationReplyData::Reconnecting(value) => OperationField::Reconnecting {
                    reconnecting: value,
                },
                OperationReplyData::Connecting {
                    peer,
                    network,
                    pinned,
                    active,
                } => OperationField::Connecting {
                    connecting: peer,
                    network,
                    pinned: *pinned,
                    active: *active,
                },
                OperationReplyData::Forgotten(values) => OperationField::Forgotten {
                    forgotten: values,
                    restarting: true,
                },
                OperationReplyData::Reset => OperationField::Reset {
                    reset: true,
                    restarting: true,
                },
                OperationReplyData::UpdatedId { id, restarted } => OperationField::UpdatedId {
                    updated: id,
                    restarted: *restarted,
                },
                OperationReplyData::Added(summary) => OperationField::Added { added: summary },
                OperationReplyData::Updated(summary) => OperationField::Updated {
                    updated: summary,
                    restarted: summary.restarted,
                },
                OperationReplyData::Identity {
                    device_id,
                    pubkey,
                    label,
                } => OperationField::Identity {
                    device_id,
                    pubkey,
                    label,
                },
                OperationReplyData::Applied(applied) => OperationField::Applied { applied },
                OperationReplyData::RealtimeOpened {
                    flow_label,
                    capability,
                } => OperationField::RealtimeOpened {
                    flow_label,
                    flow_capability: capability,
                },
                OperationReplyData::OpaqueChanged {
                    flow_capability,
                    max_unit_bytes,
                } => OperationField::OpaqueChanged {
                    flow_capability,
                    max_unit_bytes: *max_unit_bytes,
                },
                OperationReplyData::Closed => OperationField::Closed { closed: true },
                OperationReplyData::RpcStreamStarted(request_id) => {
                    OperationField::RpcStreamStarted { request_id }
                }
                OperationReplyData::ServicesStatus(status) => {
                    OperationField::ServicesStatus { status }
                }
                OperationReplyData::RealtimeRefused { .. }
                | OperationReplyData::GovernanceRefused { .. } => {
                    unreachable!("handled above")
                }
            };
            let mut response = serializer.serialize_struct("Response", 3)?;
            response.serialize_field("ok", &true)?;
            response.serialize_field("data", &field)?;
            response.end()
        }
        Err(error) => {
            let mut response = serializer.serialize_struct("Response", 3)?;
            response.serialize_field("ok", &false)?;
            response.serialize_field("error", error)?;
            response.end()
        }
    }
}

fn serialize_mfa_enrollment<S: serde::Serializer>(
    serializer: S,
    value: &FundedMfaEnrollment,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct as _;
    struct DisplayRef<'a, T>(&'a T);
    impl<T: std::fmt::Display> serde::Serialize for DisplayRef<'_, T> {
        fn serialize<R: serde::Serializer>(&self, serializer: R) -> Result<R::Ok, R::Error> {
            serializer.collect_str(self.0)
        }
    }
    match &value.result {
        Ok(enrollment) => {
            #[derive(serde::Serialize)]
            struct EnrollmentData<'a> {
                secret: &'a str,
                otpauth_uri: &'a str,
                recovery_codes: &'a [String],
                transaction_id: &'a str,
            }
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &true)?;
            response.serialize_field(
                "data",
                &EnrollmentData {
                    secret: &enrollment.secret_b32,
                    otpauth_uri: &enrollment.otpauth_uri,
                    recovery_codes: &enrollment.recovery_codes,
                    transaction_id: value.transaction_id.as_deref().unwrap_or_default(),
                },
            )?;
            response.end()
        }
        Err(error) => {
            let mut response = serializer.serialize_struct("Response", 3)?;
            response.serialize_field("ok", &false)?;
            response.serialize_field("error", &DisplayRef(error))?;
            #[derive(serde::Serialize)]
            struct RefusalData<'a> {
                code: &'a str,
            }
            response.serialize_field(
                "data",
                &RefusalData {
                    code: governance_error_code(error),
                },
            )?;
            response.end()
        }
    }
}

fn serialize_mfa_transaction<S: serde::Serializer>(
    serializer: S,
    value: &FundedMfaTransaction,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct as _;
    #[derive(serde::Serialize)]
    struct TransactionData<'a> {
        network: &'a str,
        transaction_id: &'a str,
        state: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        secret: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        otpauth_uri: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recovery_codes: Option<&'a [String]>,
    }
    let mut response = serializer.serialize_struct("Response", 2)?;
    response.serialize_field("ok", &true)?;
    response.serialize_field(
        "data",
        &TransactionData {
            network: &value.network,
            transaction_id: &value.transaction_id,
            state: value.state,
            secret: value
                .material
                .as_ref()
                .map(|material| material.secret_b32.as_str()),
            otpauth_uri: value
                .material
                .as_ref()
                .map(|material| material.otpauth_uri.as_str()),
            recovery_codes: value
                .material
                .as_ref()
                .map(|material| material.recovery_codes.as_slice()),
        },
    )?;
    response.end()
}

fn serialize_rpc_call<S: serde::Serializer>(
    serializer: S,
    value: &FundedRpcCallOutcome,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct as _;
    struct DisplayRef<'a, T>(&'a T);
    impl<T: std::fmt::Display> serde::Serialize for DisplayRef<'_, T> {
        fn serialize<R: serde::Serializer>(&self, serializer: R) -> Result<R::Ok, R::Error> {
            serializer.collect_str(self.0)
        }
    }
    match &value.result {
        Ok(funded) => match (funded.body(), funded.error()) {
            (Some(body), None) => {
                #[derive(serde::Serialize)]
                struct RpcData<'a> {
                    response: &'a serde_json::Value,
                }
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &true)?;
                response.serialize_field("data", &RpcData { response: body })?;
                response.end()
            }
            (None, Some(error)) => {
                let mut response = serializer.serialize_struct("Response", 2)?;
                response.serialize_field("ok", &false)?;
                response.serialize_field("error", error)?;
                response.end()
            }
            _ => Err(serde::ser::Error::custom(
                "funded RPC result had neither or both body and error",
            )),
        },
        Err(error) => {
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &false)?;
            response.serialize_field("error", &DisplayRef(error))?;
            response.end()
        }
    }
}

fn serialize_updater_result<S: serde::Serializer, T: serde::Serialize>(
    serializer: S,
    value: &myownmesh_updater::FundedUpdaterResult<T>,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct as _;
    struct DisplayRef<'a, T>(&'a T);
    impl<T: std::fmt::Display> serde::Serialize for DisplayRef<'_, T> {
        fn serialize<R: serde::Serializer>(&self, serializer: R) -> Result<R::Ok, R::Error> {
            serializer.collect_str(self.0)
        }
    }
    match value.get() {
        Ok(success) => {
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &true)?;
            response.serialize_field("data", success)?;
            response.end()
        }
        Err(error) => {
            let mut response = serializer.serialize_struct("Response", 2)?;
            response.serialize_field("ok", &false)?;
            response.serialize_field("error", &DisplayRef(error))?;
            response.end()
        }
    }
}

/// Maximum encoded EventsSubscribe success line, derived by running the real
/// closed serializer over the widest id and then adding the capability's fixed
/// encoded width. No client or response value is constructed to answer it.
///
/// Taken *before* `ClientRegistry::register` installs the client, because the
/// line it funds carries the freshly minted client capability and that
/// capability is not queryable afterwards. Measuring after the register instead
/// admits a reachable order — register succeeds, the line is refused under
/// memory pressure — that leaves a client installed in the registry holding a
/// secret no one received and no one can ask for again. The invariant is that
/// every installed client's capability reaches exactly one recipient.
pub(super) fn events_subscribed_line_ceiling() -> std::result::Result<usize, FrameRefusal> {
    #[derive(serde::Serialize)]
    struct EventsData<'a> {
        subscribed: bool,
        client_id: crate::ipc::ClientId,
        client_capability: &'a str,
    }
    #[derive(serde::Serialize)]
    struct Envelope<'a> {
        ok: bool,
        data: EventsData<'a>,
    }

    let mut counted = CountingSink::default();
    serde_json::to_writer(
        &mut counted,
        &Envelope {
            ok: true,
            data: EventsData {
                subscribed: true,
                client_id: crate::ipc::ClientId(u64::MAX),
                client_capability: "",
            },
        },
    )
    .map_err(|_| {
        FrameRefusal::Claim(myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
        })
    })?;
    counted
        .measured()
        .checked_add(crate::ipc::ClientHandle::capability_encoded_len())
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or(FrameRefusal::Claim(
            myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            },
        ))
}

/// Fund one prepared reply's line, then build whatever the caller is answering
/// with — in that order, so the answer is constructed only past admission.
pub(super) fn prepare_reply_then<R, B>(
    reply: &PreparedReply,
    admission: &FrameAdmission,
    build: B,
) -> std::result::Result<(R, PreparedLineCapacity), EncodeRefusal>
where
    B: FnOnce() -> R,
{
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(reply), admission)?;
    Ok((build(), output))
}

/// Exact encoded-line admission for a reply.
///
/// The buffer type is framing's — it owns the bytes and the leases that paid
/// for them. What lives here is the half that has to know what a reply is: the
/// measuring pass runs over the closed [`ControlOut`] envelope, which is what
/// makes counting allocation-free and therefore makes the refusal arrive before
/// the allocation rather than after it.
impl AdmittedLineOut {
    /// Measure and fund an encoded line without constructing its byte buffer.
    pub(super) fn prepare(
        value: &ControlOut<'_>,
        admission: &FrameAdmission,
    ) -> std::result::Result<PreparedLineCapacity, EncodeRefusal> {
        let mut counted = CountingSink::default();
        serde_json::to_writer(&mut counted, &value).map_err(EncodeRefusal::Malformed)?;
        let capacity = counted.measured().checked_add(1).ok_or({
            EncodeRefusal::Admission(FrameRefusal::Claim(
                myownmesh_core::ResourceClaimArithmeticError::Overflow {
                    dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
                },
            ))
        })?;
        Self::prepare_capacity(capacity, admission).map_err(EncodeRefusal::Admission)
    }

    pub(super) fn encode_prepared(
        value: ControlOut<'_>,
        prepared: PreparedLineCapacity,
    ) -> std::result::Result<Self, EncodeRefusal> {
        Self::encode_into_funded_line(&value, prepared, Vec::with_capacity)
    }

    /// Measure, fund, then encode — in that order and no other.
    pub(super) fn encode(
        value: ControlOut<'_>,
        admission: &FrameAdmission,
    ) -> std::result::Result<Self, EncodeRefusal> {
        Self::encode_building(value, admission, Vec::with_capacity)
    }

    /// [`Self::encode`] with the buffer's construction passed in, so a control
    /// can count constructions. See [`Self::encode_into_funded_line`], which is
    /// where the single allocating expression lives.
    pub(super) fn encode_building<B>(
        value: ControlOut<'_>,
        admission: &FrameAdmission,
        build: B,
    ) -> std::result::Result<Self, EncodeRefusal>
    where
        B: FnOnce(usize) -> Vec<u8>,
    {
        let prepared = Self::prepare(&value, admission)?;
        Self::encode_into_funded_line(&value, prepared, build)
    }
}
