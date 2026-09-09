//! Network lifecycle: join, leave, update, reconnect, reset — and the
//! on-disk config each of them has to keep in step.
//!
//! Every one of these is reversible up to the last point it touches
//! `config.json`, which is why the persist helpers live here rather than
//! beside the router: the ordering between a live mutation and its saved
//! form is the thing these functions exist to get right.

use std::future::Future;
use std::sync::Arc;
use std::sync::OnceLock;

use anyhow::{anyhow, Context, Result};
use myownmesh_core::{MeshConfig, NetworkConfig, TopologyMode};
use tokio::sync::{Mutex, MutexGuard};
use tracing::{info, warn};

use crate::registry::RemoveResult;

use super::super::{ConnectionCancel, ControlState};
use super::{funded, unknown_network, Answer};
use crate::control::framing::{prepare_typed_and_line_building, AdmittedLineOut, FrameAdmission};
use crate::control::reply::{
    prepare_reply_then, ClosedRelayReply, FundedDiagnostic, FundedVariableReply,
    NetworkLifecycleSummary, OperationReplyData, PreparedReply, ResponseOwner,
};

/// Serialize control-surface mutations that pair a registry transition with
/// its config-file read-modify-write. The registry's exact-current fence
/// remains the lifecycle authority; this gate prevents independent dispatch
/// operations from losing each other's config-file updates.
static NETWORK_MUTATION_GATE: OnceLock<Mutex<()>> = OnceLock::new();

async fn network_mutation_guard() -> MutexGuard<'static, ()> {
    NETWORK_MUTATION_GATE
        .get_or_init(Mutex::default)
        .lock()
        .await
}

/// Preserve the operation's primary failure while still surfacing a failure
/// from the mandatory joined-network teardown. The control reply API carries
/// errors as text, so keep both causes unambiguously in that one response.
fn preserve_shutdown_failure(primary: impl Into<String>, shutdown: Result<()>) -> String {
    let primary = primary.into();
    match shutdown {
        Ok(()) => primary,
        Err(error) => format!("{primary}; shutdown failed: {error:#}"),
    }
}

/// Report purge, on-disk persistence, and runtime-teardown outcomes together.
/// All operations have already completed when this is called, so no later
/// failure hides an earlier one.
fn combine_remove_failures(
    config_id: String,
    purge_error: Option<String>,
    persistence_error: Option<String>,
    teardown_error: Option<String>,
) -> std::result::Result<String, String> {
    let mut failures = Vec::new();
    if let Some(error) = purge_error {
        failures.push(error);
    }
    if let Some(error) = persistence_error {
        failures.push(error);
    }
    if let Some(error) = teardown_error {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(config_id)
    } else {
        Err(failures.join("; "))
    }
}

/// Persist the config after a runtime has been inserted, and if persistence
/// fails, retire that exact insertion before withdrawing its service advert.
/// The injected operations are the same ordering used by [`network_add`], so
/// failure-injection tests can observe registry retirement and withdrawal
/// without manufacturing a second lifecycle implementation.
async fn persist_or_rollback_added_network<P, R, RFut, W, WFut>(
    persist: P,
    remove: R,
    withdraw: W,
) -> Option<String>
where
    P: FnOnce() -> Result<()>,
    R: FnOnce() -> RFut,
    RFut: Future<Output = RemoveResult>,
    W: FnOnce() -> WFut,
    WFut: Future<Output = ()>,
{
    let persistence_error = match persist() {
        Ok(()) => return None,
        Err(error) => error,
    };
    let teardown_error = match remove().await {
        RemoveResult::Removed(Ok(())) => None,
        RemoveResult::Removed(Err(error)) => Some(format!(
            "network add rollback teardown reported failure: {error}"
        )),
        RemoveResult::AlreadyClosing(observation) => observation
            .outcome
            .err()
            .map(|error| format!("network add rollback teardown reported failure: {error}")),
        RemoveResult::NotFound => {
            Some("network add rollback could not find the joined runtime owner".to_string())
        }
    };
    withdraw().await;
    let message = format!("network joined but config.json save failed: {persistence_error}");
    Some(match teardown_error {
        Some(teardown_error) => format!("{message}; {teardown_error}"),
        None => message,
    })
}

/// Join a fresh network through the live mesh, attach signaling,
/// register the result, and persist the new config to disk. Each
/// step that mutates daemon-visible state is reversible up to the
/// last point we touch the on-disk config — config.json is updated
/// after the join + attach succeeds so a failed join leaves the
/// saved config untouched.
pub(in crate::control) async fn network_add(
    state: &Arc<ControlState>,
    config: NetworkConfig,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let _mutation_guard = network_mutation_guard().await;
    // Reject duplicates against the running registry. We rely on
    // the registry's two-key indexing — checking both the local
    // config id and the wire-level network id covers the user
    // trying to add the same network twice (under any alias).
    match state.registry.classify_join(&config.id, &config.network_id) {
        crate::registry::JoinAdmission::Existing(existing) => {
            return owner.finish(Err(format!(
                "network is already joined by config id '{}'",
                existing.config_id()
            )));
        }
        crate::registry::JoinAdmission::Collision(state) => {
            return owner.finish(Err(format!(
                "network identity collision: requested pair ({}, {}), owner is in {state:?} state",
                config.id, config.network_id
            )));
        }
        crate::registry::JoinAdmission::Empty => {}
    }

    // Join the live mesh first — if the engine refuses (bad
    // network id, etc.) we want to know before we touch disk.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => return owner.finish(Err(format!("join: {e}"))),
    };

    // Take a summary BEFORE handing ownership to the registry so we
    // can return it in the response payload without re-locking.
    let summary = NetworkLifecycleSummary {
        config_id: joined.config_id().to_owned(),
        network_id: joined.network_id().to_owned(),
        label: joined.label().to_owned(),
        phase: joined.current_phase(),
        topology: joined.current_topology(),
        restarted: false,
    };

    // Attach the signaling driver(s) the network's config selects
    // (Nostr and/or mDNS).
    //
    // Two outcomes, and they are not the same. `Ok(None)` means the outbound
    // receiver was already taken — an in-process test driver holds it — and the
    // network still works. `Err` means the attach itself was refused, which is a
    // startup failure and is reported as one: a joined network left
    // installed with no signaling and no explanation would look identical to
    // the benign case from every later request's point of view.
    let drivers = {
        match joined.attach_signaling() {
            Ok(drivers) => drivers,
            Err(error) => {
                let message = preserve_shutdown_failure(
                    format!("signaling attach failed: {error}"),
                    joined.shutdown().await.map_err(|error| anyhow!("{error}")),
                );
                return owner.finish(Err(message));
            }
        }
    };
    if drivers.is_none() {
        warn!(
            network = %config.network_id,
            "signaling outbound receiver was already taken — this network keeps no driver handle"
        );
    }
    if let Some(refused) = state.registry.insert(joined, drivers).into_refusal() {
        let refusal_state = refused.state;
        if let Some(drivers) = refused.drivers {
            drivers.shutdown().await;
        }
        let message = preserve_shutdown_failure(
            format!("network id is held by a runtime in {refusal_state:?} state"),
            refused
                .joined
                .shutdown()
                .await
                .map_err(|error| anyhow!("{error}")),
        );
        return owner.finish(Err(message));
    }

    // Refresh the service-role advert so the new network advertises what
    // this device hosts. The registry owner is captured immediately after
    // insertion: if the durable advert commit fails, only this exact runtime
    // may be rolled back, never whatever successor later answers by key.
    let inserted_owner = match state.registry.get(&config.id) {
        Some(owner) => owner,
        None => {
            return owner.finish(Err(
                "network joined but its registry owner was lost before advert refresh".to_string(),
            ));
        }
    };
    if let Err(advert_error) = state.services.on_network_added(&config.id).await {
        let rollback_error = match state
            .registry
            .remove_if_current(&config.id, &inserted_owner)
            .await
        {
            RemoveResult::Removed(Ok(())) => None,
            RemoveResult::Removed(Err(error)) => Some(format!(
                "network advert rollback teardown reported failure: {error}"
            )),
            RemoveResult::AlreadyClosing(observation) => observation
                .outcome
                .err()
                .map(|error| format!("network advert rollback teardown reported failure: {error}")),
            RemoveResult::NotFound => Some(
                "network advert rollback lost the exact registry owner before retirement"
                    .to_string(),
            ),
        };
        state.services.on_network_removed(&config.id).await;
        let message = format!("network joined but service advert save failed: {advert_error}");
        return owner.finish(Err(match rollback_error {
            Some(rollback_error) => format!("{message}; {rollback_error}"),
            None => message,
        }));
    }

    // Persist to disk. We re-load the config rather than rely on
    // the in-memory copy from startup so concurrent edits (a user
    // hand-editing config.json) survive — we append to whatever's
    // on disk now. If the save fails, remove the just-inserted runtime before
    // answering so a live network cannot diverge from the persisted config.
    // Surface both the disk error and any teardown error to the caller.
    let persist_config = config.clone();
    let remove_state = Arc::clone(state);
    let remove_id = config.id.clone();
    let withdraw_state = Arc::clone(state);
    let withdraw_id = config.id.clone();
    if let Some(message) = persist_or_rollback_added_network(
        move || persist_network_add(&persist_config),
        move || async move { remove_state.registry.remove(&remove_id).await },
        move || async move {
            withdraw_state
                .services
                .on_network_removed(&withdraw_id)
                .await
        },
    )
    .await
    {
        return owner.finish(Err(message));
    }

    owner.finish(Ok(OperationReplyData::Added(summary)))
}

/// Register a network that was created or imported through a dedicated core
/// lifecycle API. This keeps the shipped Closed paths distinct from
/// `NetworkAdd` while sharing the same attach, advert, rollback, and config
/// persistence fence.
async fn register_new_network(
    state: &Arc<ControlState>,
    config: NetworkConfig,
    joined: myownmesh_core::JoinedNetwork,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let summary = NetworkLifecycleSummary {
        config_id: joined.config_id().to_owned(),
        network_id: joined.network_id().to_owned(),
        label: joined.label().to_owned(),
        phase: joined.current_phase(),
        topology: joined.current_topology(),
        restarted: false,
    };
    let drivers = match joined.attach_signaling() {
        Ok(drivers) => drivers,
        Err(error) => {
            let message = preserve_shutdown_failure(
                format!("signaling attach failed: {error}"),
                joined.shutdown().await.map_err(|error| anyhow!("{error}")),
            );
            return owner.finish(Err(message));
        }
    };
    if let Some(refused) = state.registry.insert(joined, drivers).into_refusal() {
        let refusal_state = refused.state;
        if let Some(drivers) = refused.drivers {
            drivers.shutdown().await;
        }
        let message = preserve_shutdown_failure(
            format!("network id is held by a runtime in {refusal_state:?} state"),
            refused
                .joined
                .shutdown()
                .await
                .map_err(|error| anyhow!("{error}")),
        );
        return owner.finish(Err(message));
    }
    let inserted_owner = match state.registry.get(&config.id) {
        Some(owner) => owner,
        None => {
            return owner.finish(Err(
                "network joined but its registry owner was lost before advert refresh".to_string(),
            ));
        }
    };
    if let Err(advert_error) = state.services.on_network_added(&config.id).await {
        let rollback_error = match state
            .registry
            .remove_if_current(&config.id, &inserted_owner)
            .await
        {
            RemoveResult::Removed(Ok(())) => None,
            RemoveResult::Removed(Err(error)) => Some(format!(
                "network advert rollback teardown reported failure: {error}"
            )),
            RemoveResult::AlreadyClosing(observation) => observation
                .outcome
                .err()
                .map(|error| format!("network advert rollback teardown reported failure: {error}")),
            RemoveResult::NotFound => Some(
                "network advert rollback lost the exact registry owner before retirement"
                    .to_string(),
            ),
        };
        state.services.on_network_removed(&config.id).await;
        let message = format!("network joined but service advert save failed: {advert_error}");
        return owner.finish(Err(match rollback_error {
            Some(rollback_error) => format!("{message}; {rollback_error}"),
            None => message,
        }));
    }
    let persist_config = config.clone();
    let remove_state = Arc::clone(state);
    let remove_id = config.id.clone();
    let withdraw_state = Arc::clone(state);
    let withdraw_id = config.id.clone();
    if let Some(message) = persist_or_rollback_added_network(
        move || persist_network_add(&persist_config),
        move || async move { remove_state.registry.remove(&remove_id).await },
        move || async move {
            withdraw_state
                .services
                .on_network_removed(&withdraw_id)
                .await
        },
    )
    .await
    {
        return owner.finish(Err(message));
    }
    owner.finish(Ok(OperationReplyData::Added(summary)))
}

pub(in crate::control) async fn network_create_closed(
    state: &Arc<ControlState>,
    config: NetworkConfig,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let _mutation_guard = network_mutation_guard().await;
    if !matches!(config.kind, myownmesh_core::config::NetworkKind::Closed) {
        return owner.finish(Err("Closed network creation requires kind=closed".into()));
    }
    match state.registry.classify_join(&config.id, &config.network_id) {
        crate::registry::JoinAdmission::Existing(existing) => {
            return owner.finish(Err(format!(
                "network is already joined by config id '{}'",
                existing.config_id()
            )));
        }
        crate::registry::JoinAdmission::Collision(runtime) => {
            return owner.finish(Err(format!(
                "network identity collision: requested pair ({}, {}), owner is in {runtime:?} state",
                config.id, config.network_id
            )));
        }
        crate::registry::JoinAdmission::Empty => {}
    }
    let mut creation_id = [0u8; 32];
    if let Err(error) = getrandom::getrandom(&mut creation_id) {
        return owner.finish(Err(format!("Closed bootstrap nonce unavailable: {error}")));
    }
    let joined = match state.mesh.create_network(config.clone(), creation_id).await {
        Ok(joined) => joined,
        Err(error) => return owner.finish(Err(format!("Closed network creation: {error}"))),
    };
    register_new_network(state, config, joined, owner).await
}

pub(in crate::control) async fn network_import_closed(
    state: &Arc<ControlState>,
    config: NetworkConfig,
    expected_context_id: myownmesh_core::semantic::MeshContextId,
    bootstrap: myownmesh_core::semantic::BootstrapRecord,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let _mutation_guard = network_mutation_guard().await;
    if !matches!(config.kind, myownmesh_core::config::NetworkKind::Closed) {
        return owner.finish(Err("Closed network import requires kind=closed".into()));
    }
    match state.registry.classify_join(&config.id, &config.network_id) {
        crate::registry::JoinAdmission::Existing(existing) => {
            return owner.finish(Err(format!(
                "network is already joined by config id '{}'",
                existing.config_id()
            )));
        }
        crate::registry::JoinAdmission::Collision(runtime) => {
            return owner.finish(Err(format!(
                "network identity collision: requested pair ({}, {}), owner is in {runtime:?} state",
                config.id, config.network_id
            )));
        }
        crate::registry::JoinAdmission::Empty => {}
    }
    let joined = match state
        .mesh
        .import_network(config.clone(), expected_context_id, bootstrap)
        .await
    {
        Ok(joined) => joined,
        Err(error) => return owner.finish(Err(format!("Closed network import: {error}"))),
    };
    register_new_network(state, config, joined, owner).await
}

fn relay_failure(admission: &FrameAdmission, message: String) -> Result<Answer> {
    super::refused_text(message, admission)
}

fn relay_open_reply(
    capability: crate::registry::ClosedRelayCapability,
    active_allocations: usize,
    owner: ResponseOwner,
    admission: &FrameAdmission,
    accepted: bool,
) -> Result<Answer> {
    let snapshot = capability.snapshot;
    let reply = if accepted {
        ClosedRelayReply::Accepted {
            handle: capability.handle,
            generation: snapshot.generation,
            network: snapshot.network,
            peer: snapshot.peer,
            relay: snapshot.relay,
            session_id: snapshot.session_id,
            allocation_epoch: snapshot.allocation_epoch,
            active_allocations,
            max_allocations: snapshot.max_allocations,
            max_frame_bytes: snapshot.max_frame_bytes,
        }
    } else {
        ClosedRelayReply::Opened {
            handle: capability.handle,
            generation: snapshot.generation,
            network: snapshot.network,
            peer: snapshot.peer,
            relay: snapshot.relay,
            session_id: snapshot.session_id,
            allocation_epoch: snapshot.allocation_epoch,
            active_allocations,
            max_allocations: snapshot.max_allocations,
            max_frame_bytes: snapshot.max_frame_bytes,
        }
    };
    funded(
        PreparedReply::ClosedRelay(FundedDiagnostic::new(reply, owner)),
        admission,
    )
}

pub(in crate::control) async fn closed_relay_open(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    relay: String,
    target: String,
) -> Result<Answer> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let owner =
        ResponseOwner::acquire(admission).context("Closed relay open response was not admitted")?;
    let resources = match state.mesh.local_application_resource_scope() {
        Ok(resources) => resources,
        Err(error) => {
            return relay_failure(admission, format!("Closed relay custody scope: {error}"))
        }
    };
    let reservation = match state.closed_relays.reserve(&resources, &joined) {
        Ok(reservation) => reservation,
        Err(error) => return relay_failure(admission, error.to_string()),
    };
    let channel = match joined.open_closed_relay(&relay, &target).await {
        Ok(channel) => channel,
        Err(error) => return relay_failure(admission, format!("Closed relay open: {error}")),
    };
    let capability = match reservation.commit(channel) {
        Ok(capability) => capability,
        Err(error) => {
            let close_error = error.channel.close().await.err();
            let message = match close_error {
                Some(close_error) => format!("{}; cleanup failed: {close_error}", error.message),
                None => error.message.to_string(),
            };
            return relay_failure(admission, message);
        }
    };
    let active_allocations = state
        .closed_relays
        .state(&capability.handle)
        .await
        .map(|(_, active)| active)
        .unwrap_or(0);
    relay_open_reply(capability, active_allocations, owner, admission, false)
        .context("Closed relay open response line was not admitted")
}

pub(in crate::control) async fn closed_relay_accept(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    wait_ms: u64,
) -> Result<Answer> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let owner = ResponseOwner::acquire(admission)
        .context("Closed relay accept response was not admitted")?;
    let resources = match state.mesh.local_application_resource_scope() {
        Ok(resources) => resources,
        Err(error) => {
            return relay_failure(admission, format!("Closed relay custody scope: {error}"))
        }
    };
    let reservation = match state.closed_relays.reserve(&resources, &joined) {
        Ok(reservation) => reservation,
        Err(error) => return relay_failure(admission, error.to_string()),
    };
    let channel = match tokio::time::timeout(
        std::time::Duration::from_millis(wait_ms),
        joined.accept_closed_relay(),
    )
    .await
    {
        Ok(Ok(channel)) => channel,
        Ok(Err(error)) => return relay_failure(admission, format!("Closed relay accept: {error}")),
        Err(_) => return relay_failure(admission, "Closed relay accept wait expired".into()),
    };
    let capability = match reservation.commit(channel) {
        Ok(capability) => capability,
        Err(error) => {
            let close_error = error.channel.close().await.err();
            let message = match close_error {
                Some(close_error) => format!("{}; cleanup failed: {close_error}", error.message),
                None => error.message.to_string(),
            };
            return relay_failure(admission, message);
        }
    };
    let active_allocations = state
        .closed_relays
        .state(&capability.handle)
        .await
        .map(|(_, active)| active)
        .unwrap_or(0);
    relay_open_reply(capability, active_allocations, owner, admission, true)
        .context("Closed relay accept response line was not admitted")
}

pub(in crate::control) async fn closed_relay_send(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    handle: String,
    payload: Vec<u8>,
) -> Result<Answer> {
    let owner =
        ResponseOwner::acquire(admission).context("Closed relay send response was not admitted")?;
    let (snapshot, bytes) = match state.closed_relays.send(&handle, &payload).await {
        Ok(result) => result,
        Err(error) => return relay_failure(admission, format!("Closed relay send: {error}")),
    };
    let reply = ClosedRelayReply::Sent {
        handle,
        generation: snapshot.generation,
        allocation_epoch: snapshot.allocation_epoch,
        bytes,
    };
    funded(
        PreparedReply::ClosedRelay(FundedDiagnostic::new(reply, owner)),
        admission,
    )
    .context("Closed relay send response line was not admitted")
}

pub(in crate::control) async fn closed_relay_recv(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    handle: String,
    wait_ms: u64,
) -> Result<Answer> {
    let owner = ResponseOwner::acquire(admission)
        .context("Closed relay receive response was not admitted")?;
    let (snapshot, payload) = match state.closed_relays.recv(&handle, wait_ms).await {
        Ok(result) => result,
        Err(error) => return relay_failure(admission, format!("Closed relay receive: {error}")),
    };
    let reply = ClosedRelayReply::Received {
        handle,
        generation: snapshot.generation,
        allocation_epoch: snapshot.allocation_epoch,
        payload,
    };
    funded(
        PreparedReply::ClosedRelay(FundedDiagnostic::new(reply, owner)),
        admission,
    )
    .context("Closed relay receive response line was not admitted")
}

pub(in crate::control) async fn closed_relay_close(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    handle: String,
) -> Result<Answer> {
    let owner = ResponseOwner::acquire(admission)
        .context("Closed relay close response was not admitted")?;
    let snapshot = match state.closed_relays.close(&handle).await {
        Ok(snapshot) => snapshot,
        Err(error) => return relay_failure(admission, format!("Closed relay close: {error}")),
    };
    let reply = ClosedRelayReply::Closed {
        handle,
        generation: snapshot.generation,
        allocation_epoch: snapshot.allocation_epoch,
    };
    funded(
        PreparedReply::ClosedRelay(FundedDiagnostic::new(reply, owner)),
        admission,
    )
    .context("Closed relay close response line was not admitted")
}

pub(in crate::control) async fn closed_relay_state(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    handle: String,
) -> Result<Answer> {
    let owner = ResponseOwner::acquire(admission)
        .context("Closed relay state response was not admitted")?;
    let (snapshot, active_allocations) = match state.closed_relays.state(&handle).await {
        Ok(result) => result,
        Err(error) => return relay_failure(admission, format!("Closed relay state: {error}")),
    };
    let reply = ClosedRelayReply::State {
        handle,
        generation: snapshot.generation,
        network: snapshot.network,
        allocation_epoch: snapshot.allocation_epoch,
        active_allocations,
        max_allocations: snapshot.max_allocations,
        max_frame_bytes: snapshot.max_frame_bytes,
    };
    funded(
        PreparedReply::ClosedRelay(FundedDiagnostic::new(reply, owner)),
        admission,
    )
    .context("Closed relay state response line was not admitted")
}

/// Complete the on-disk half of forgetting a network under its exact owner.
///
/// The generic owner and injected operations keep the production order and
/// failure contract directly testable without constructing a live network: no
/// owner or failed semantic purge can be turned into a successful removal.
fn purge_owned_state<T>(
    network_id: &str,
    owner: Option<&T>,
    purge_semantic: impl FnOnce(&T) -> Result<()>,
    delete_roster: impl FnOnce(&str) -> Result<()>,
) -> std::result::Result<(), String> {
    let owner = owner.ok_or_else(|| {
        format!("purge refused for {network_id}: canonical semantic snapshot owner unavailable")
    })?;
    purge_semantic(owner).map_err(|error| {
        format!(
            "purge refused for {network_id}: canonical semantic snapshot purge failed: {error:#}"
        )
    })?;
    delete_roster(network_id).map_err(|error| {
        format!("purge refused for {network_id}: roster delete failed: {error:#}")
    })?;
    Ok(())
}

fn purge_network_projection(network_id: &str) -> Result<()> {
    myownmesh_core::roster::delete(network_id).map_err(|error| anyhow!("{error:#}"))
}

/// Leave a live network and remove it from the on-disk config. The registry
/// owns signaling and engine teardown through completion and reports its exact
/// outcome.
pub(in crate::control) async fn network_remove(
    state: &Arc<ControlState>,
    key: &str,
    purge: bool,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let result = network_remove_result(state, key, purge, &owner).await;
    owner.finish(result.map(OperationReplyData::Removed))
}

async fn network_remove_result(
    state: &Arc<ControlState>,
    key: &str,
    purge: bool,
    _owner: &ResponseOwner,
) -> std::result::Result<String, String> {
    let _mutation_guard = network_mutation_guard().await;
    let key_owned = key.to_string();
    let (ids, joined_for_purge, removal) = if let Some(joined) = state.registry.get(key) {
        let ids = (
            joined.config_id().to_string(),
            joined.network_id().to_string(),
        );
        // Start the authenticated departure and registry removal together.
        // A silent peer's DepartObserved waiter is cancelled by teardown;
        // awaiting the announcement first would deadlock this removal.
        let departure = joined.announce_leave();
        let removal = state.registry.remove(key);
        let (_, removal) = tokio::join!(departure, removal);
        (Some(ids), Some(joined), Some(removal))
    } else {
        (None, None, None)
    };
    let removal = match removal {
        Some(removal) => removal,
        None => state.registry.remove(key).await,
    };
    match removal {
        RemoveResult::Removed(outcome) => {
            let (config_id, network_id) =
                ids.unwrap_or_else(|| (key_owned.clone(), key_owned.clone()));
            state.services.on_network_removed(&config_id).await;
            let purge_error = if purge {
                purge_owned_state(
                    &network_id,
                    joined_for_purge.as_ref(),
                    |joined| {
                        joined
                            .purge_durable_semantic_state()
                            .map_err(|error| anyhow!("{error}"))
                    },
                    purge_network_projection,
                )
                .err()
            } else {
                None
            };
            let persistence_error = persist_network_remove(&config_id, &network_id)
                .err()
                .map(|error| format!("network left but config.json save failed: {error}"));
            let teardown_error = outcome.err().map(|error| {
                format!("network removed but runtime teardown reported failure: {error}")
            });
            combine_remove_failures(config_id, purge_error, persistence_error, teardown_error)
        }
        RemoveResult::AlreadyClosing(observation) => match observation.outcome {
            Ok(()) => Err(format!(
                "network teardown already completed (state {:?}); purge was not attempted",
                observation.state
            )),
            Err(error) => Err(format!(
                "network teardown already in progress but reported failure: {error}"
            )),
        },
        RemoveResult::NotFound => Err(format!("unknown network: {key_owned}")),
    }
}

/// Forget every joined network at once — the bulk `NetworkRemove{purge:true}`.
/// Each network is torn down live and its canonical semantic snapshot plus
/// roster projection are deleted from disk; the device identity is kept.
/// Snapshots the set first so removing as we
/// go can't skip an entry.
///
/// The runtime shutdown that drops every in-memory cache around the wipe is not
/// this function's to start: the connection loop submits it once the response to
/// this request has actually been attempted, so no cache is dropped while the
/// answer is still unwritten and no duration stands in for the write.
pub(in crate::control) async fn forget_all_networks(
    state: &Arc<ControlState>,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let mut forgotten = Vec::new();
    let mut failures = Vec::new();
    for n in state.registry.summaries() {
        // `network_remove` resolves either alias; the config id is stable.
        match network_remove_result(state, &n.config_id, true, &owner).await {
            Ok(config_id) => forgotten.push(config_id),
            Err(error) => failures.push(format!("{}: {error}", n.config_id)),
        }
    }
    if !failures.is_empty() {
        let mut message = format!(
            "forget all failed for {} network(s): {}",
            failures.len(),
            failures.join("; ")
        );
        if !forgotten.is_empty() {
            message.push_str(&format!("; completed: {}", forgotten.join(", ")));
        }
        return owner.finish(Err(message));
    }
    owner.finish(Ok(OperationReplyData::Forgotten(forgotten)))
}

/// Factory reset — return this device to a brand-new state. First quiesce every
/// network (tear it down + purge its files) so nothing re-persists mid-wipe,
/// then remove the whole state directory (identity, config, and any leftovers),
/// so a fresh runtime mints a new identity on empty state. Every destructive
/// step is reported: a partial wipe is not reported as a successful reset. The
/// connection loop still submits the one runtime shutdown request after this
/// answer has been attempted either way, rather than leaving a half-wiped
/// daemon re-persisting stale caches.
pub(in crate::control) async fn factory_reset(
    state: &Arc<ControlState>,
    owner: ResponseOwner,
) -> FundedVariableReply {
    // Quiesce writers first: tearing each network down stops its engine driver
    // from writing a roster/state file back out while we're deleting the tree.
    let mut failures = Vec::new();
    for n in state.registry.summaries() {
        if let Err(error) = network_remove_result(state, &n.config_id, true, &owner).await {
            failures.push(format!("{}: {error}", n.config_id));
        }
    }
    let dir = match myownmesh_core::dirs::data_dir() {
        Ok(d) => d,
        Err(e) => {
            // The networks above are already torn down and purged, so the
            // connection loop's shutdown request still follows this answer: a
            // half-done reset must not go on running either.
            return owner.finish(Err(format!("factory reset: resolve state dir: {e}")));
        }
    };
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        // A missing dir already reads as reset. Any other failure means the
        // requested wipe did not happen and must not be acknowledged as one.
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(dir = %dir.display(), "factory reset: remove_dir_all: {e:#}");
            failures.push(format!("remove state directory: {e}"));
        }
    }
    if !failures.is_empty() {
        return owner.finish(Err(format!(
            "factory reset failed: {}",
            failures.join("; ")
        )));
    }
    owner.finish(Ok(OperationReplyData::Reset))
}

/// Reconnect a joined network in place — the non-destructive twin of
/// [`network_remove`] + [`network_add`]. Hands the live `JoinedNetwork` a
/// reconnect request (redial signaling + renegotiate ICE) without leaving the
/// room, so peers keep their sessions and app-level state. `peer` omitted
/// reconnects every peer; `peer` set reconnects just that one (a per-node
/// refresh). Fire-and-forget — the engine driver runs the reconnect, so this
/// returns as soon as the request is queued.
pub(in crate::control) fn network_reconnect(
    state: &Arc<ControlState>,
    key: &str,
    peer: Option<String>,
    owner: ResponseOwner,
) -> FundedVariableReply {
    match state.registry.get(key) {
        Some(joined) => {
            joined.reconnect(peer);
            owner.finish(Ok(OperationReplyData::Reconnecting(key.to_owned())))
        }
        None => owner.finish(Err(format!("unknown network: {key}"))),
    }
}

/// One client-requested dial, exactly as the request stated it.
///
/// A carrier for the fields the `Connect` arm destructured. `wait_ms` is the
/// client's own bound on how long it will wait for an answer; it is not
/// resource authority and creates or releases nothing.
pub(in crate::control) struct ConnectPeer {
    pub network: String,
    pub peer: String,
    pub pin: bool,
    pub wait_ms: u64,
}

/// Deliberately dial one peer on a joined network, and answer.
///
/// The `Option` is the truthful shape for an operation the connection can
/// outlive: a dial cancelled by the socket draining produced no outcome, so
/// there is nothing to say and the loop ends. Every other result — including
/// a refused or timed-out dial — is a reply.
///
/// The right to answer is taken *before* the dial starts, which is why the
/// owner is acquired here rather than after the `select!`: a dial that succeeds
/// must not then discover it has nowhere to report the success.
pub(in crate::control) async fn connect_peer(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    cancel: &ConnectionCancel,
    connect: ConnectPeer,
) -> Result<Option<Answer>> {
    let ConnectPeer {
        network,
        peer,
        pin,
        wait_ms,
    } = connect;
    let owner =
        ResponseOwner::acquire(admission).context("network connect result was not admitted")?;
    let variable = tokio::select! {
        biased;
        () = cancel.cancelled() => return Ok(None),
        result = connect_peer_funded(state, &network, &peer, pin, wait_ms, owner) => result,
    };
    funded(PreparedReply::Variable(variable), admission)
        .context("network connect response line was not admitted")
        .map(Some)
}

/// The dial itself — the control-socket wrapper around
/// [`myownmesh_core::JoinedNetwork::connect_peer`]. Single-shot: queues the
/// offerer-side dial on the engine and returns at once (the outcome rides the
/// event stream), so a daemon client on a `Silent` network can open exactly
/// one connection after matching a peer's Support ID.
async fn connect_peer_funded(
    state: &Arc<ControlState>,
    key: &str,
    peer: &str,
    pin: bool,
    wait_ms: u64,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let Some(joined) = state.registry.get(key) else {
        return owner.finish(Err(format!("unknown network: {key}")));
    };
    let result = if pin || wait_ms > 0 {
        // Waited/pinned dial: resolves on ACTIVE (or the caller's exact
        // deadline). A zero wait is intentionally zero; this layer must not
        // invent a timing policy for a caller that supplied none.
        let deadline = std::time::Duration::from_millis(wait_ms);
        match joined.connect_peer_wait(peer, pin, deadline).await {
            Ok(()) => Ok(true),
            Err(e) if wait_ms == 0 => {
                // Caller didn't ask to wait — a deadline miss is not
                // an error, just "still connecting".
                let msg = e.to_string();
                if msg.contains("still pending") {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    } else {
        joined.connect_peer(peer).await.map(|_| false)
    };
    owner.finish(match result {
        Ok(active) => Ok(OperationReplyData::Connecting {
            peer: peer.to_owned(),
            network: key.to_owned(),
            pinned: pin,
            active,
        }),
        Err(e) => Err(e.to_string()),
    })
}

/// Re-establish the exact predecessor after a replacement failed after the
/// predecessor had already been removed. Every successful restoration is
/// persisted under the restored runtime's exact registry owner; a successor
/// or a lost owner never gets to overwrite the config record.
async fn rollback_old_network(state: &Arc<ControlState>, old_config: &NetworkConfig) -> String {
    let restored = match state.mesh.join(old_config.clone()).await {
        Ok(restored) => restored,
        Err(error) => {
            warn!(network = %old_config.id, "network update rollback failed: {error:#}");
            return " — AND rollback failed; re-add it from the Networks tab".to_string();
        }
    };
    let attached = restored.attach_signaling();
    let drivers = match attached {
        Ok(drivers) => drivers,
        Err(error) => {
            return preserve_shutdown_failure(
                format!(" — AND the rollback join could not attach signaling: {error}"),
                restored
                    .shutdown()
                    .await
                    .map_err(|error| anyhow!("{error}")),
            );
        }
    };
    if let Some(refused) = state.registry.insert(restored, drivers).into_refusal() {
        let refusal_state = refused.state;
        if let Some(drivers) = refused.drivers {
            drivers.shutdown().await;
        }
        return preserve_shutdown_failure(
            format!(
                " — rollback join was refused by a {refusal_state:?} runtime; config was not overwritten"
            ),
            refused
                .joined
                .shutdown()
                .await
                .map_err(|error| anyhow!("{error}")),
        );
    }

    let restored_owner = match state.registry.get(&old_config.id) {
        Some(owner) => owner,
        None => {
            return " — rollback runtime lost its lifecycle owner; config was not overwritten"
                .to_string();
        }
    };
    let persisted = state
        .registry
        .with_current(&old_config.id, &restored_owner, |_| {
            persist_network_update(old_config)
        });
    match persisted {
        Some(Ok(())) => {
            if let Err(advert_error) = state.services.on_network_added(&old_config.id).await {
                return format!("rollback advert refresh failed: {advert_error}");
            }
            " — restored the previous config".to_string()
        }
        Some(Err(error)) => {
            let advert_error = state.services.on_network_added(&old_config.id).await.err();
            if let Some(advert_error) = advert_error {
                return format!(
                    "rollback runtime restored but config.json save failed: {error}; advert refresh failed: {advert_error}"
                );
            }
            format!(" — rollback runtime restored but config.json save failed: {error}")
        }
        None => {
            " — rollback runtime lost its lifecycle owner; config was not overwritten".to_string()
        }
    }
}

/// Apply a hot-reloadable change and keep the live runtime and config file
/// atomic from the caller's perspective. If persistence fails after the live
/// mutation, restore both representations and report every rollback failure.
fn apply_hot_and_persist_with_rollback(
    current: &myownmesh_core::JoinedNetwork,
    next: &NetworkConfig,
    old: &NetworkConfig,
) -> Result<()> {
    validate_network_update(old, next)?;
    run_hot_update_with_rollback(
        || {
            current
                .apply_hot(next.clone())
                .map_err(|error| anyhow!("{error}"))
        },
        || persist_network_update(next),
        || {
            current
                .apply_hot(old.clone())
                .map_err(|error| anyhow!("{error}"))
        },
        || persist_network_update(old),
    )
}

/// Execute a hot update and its persistence commit. Once the commit fails,
/// both live and disk rollback operations are attempted in that fixed order;
/// neither failure can hide the save failure or the other rollback failure.
fn run_hot_update_with_rollback<A, P, L, D>(
    apply: A,
    persist: P,
    live_rollback: L,
    disk_rollback: D,
) -> Result<()>
where
    A: FnOnce() -> Result<()>,
    P: FnOnce() -> Result<()>,
    L: FnOnce() -> Result<()>,
    D: FnOnce() -> Result<()>,
{
    apply()?;
    if let Err(persist_error) = persist() {
        let live_rollback = live_rollback().err();
        let disk_rollback = disk_rollback().err();
        let mut failures = vec![format!(
            "hot update config.json save failed: {persist_error}"
        )];
        if let Some(error) = live_rollback {
            failures.push(format!("live hot-update rollback failed: {error}"));
        }
        if let Some(error) = disk_rollback {
            failures.push(format!("disk config rollback failed: {error}"));
        }
        return Err(anyhow!(failures.join("; ")));
    }
    Ok(())
}

/// Retire a replacement only when the registry still holds the exact Arc that
/// failed its persistence commit. This intentionally does not fall back to a
/// key-only remove: a stale update must never tear down a successor. The
/// registry implementation owns the compare-and-claim fence and waits for an
/// already-claimed exact owner to finish.
async fn retire_failed_replacement(
    state: &Arc<ControlState>,
    key: &str,
    expected: &Arc<myownmesh_core::JoinedNetwork>,
) -> Option<String> {
    replacement_retirement_failure(state.registry.remove_if_current(key, expected).await)
}

fn replacement_retirement_failure(result: RemoveResult) -> Option<String> {
    match result {
        RemoveResult::Removed(Ok(())) => None,
        RemoveResult::Removed(Err(error)) => Some(format!(
            "replacement runtime teardown reported failure: {error}"
        )),
        RemoveResult::AlreadyClosing(observation) => observation
            .outcome
            .err()
            .map(|error| format!("replacement runtime teardown reported failure: {error}")),
        RemoveResult::NotFound => Some(
            "replacement runtime retirement lost the exact registry owner before teardown"
                .to_string(),
        ),
    }
}

/// Validate an edit before teardown or persistence. Label, auto-approve and
/// ICE edits preserve live sessions; construction-time routing, pins and owner
/// capacities use exact runtime replacement. Kind edits cannot mint authority.
pub(in crate::control) async fn network_update(
    state: &Arc<ControlState>,
    config: NetworkConfig,
    owner: ResponseOwner,
) -> FundedVariableReply {
    let _mutation_guard = network_mutation_guard().await;
    // This is update, not add: the network must already be joined. Resolve
    // both aliases before teardown. If they name different live runtimes,
    // this is an id collision rather than an update and the disk must remain
    // untouched while both owners stay current.
    let by_config_id = state.registry.get(&config.id);
    let by_network_id = state.registry.get(&config.network_id);
    let joined = match (by_config_id, by_network_id) {
        (Some(config_owner), Some(network_owner)) if Arc::ptr_eq(&config_owner, &network_owner) => {
            config_owner
        }
        (Some(_), Some(_)) => {
            return owner.finish(Err(format!(
                "network update refused: config id '{}' and network id '{}' belong to different live networks",
                config.id, config.network_id
            )));
        }
        (Some(owner), None) | (None, Some(owner)) => owner,
        (None, None) => {
            return owner.finish(Err(format!(
                "unknown network '{}' — join it with network_add first",
                config.id
            )));
        }
    };
    if joined.config_id() != config.id.as_str() {
        return owner.finish(Err(format!(
            "network update refused: config id '{}' does not match current owner '{}'",
            config.id,
            joined.config_id()
        )));
    }

    let old_config = joined.config_snapshot();
    if let Err(error) = validate_network_update(&old_config, &config) {
        return owner.finish(Err(format!("network update refused: {error}")));
    }

    // Compare the incoming config against the engine's live config to
    // decide hot-apply vs. transport restart.
    let restart = joined.reconcile_status(&config);
    // Name the path taken so a config-driven flap is greppable: a hot-apply
    // keeps every live peer; a restart drops them. Network identity,
    // signaling, routing/pins, closed-relay profile, semantic policy, scheduler, and
    // broadcaster capacities force the restart; STUN/TURN remain hot (see
    // `reconcile`).
    info!(
        network = %config.network_id,
        needs_restart = restart.needs_restart,
        signaling_changed = restart.signaling_changed,
        network_id_changed = restart.network_id_changed,
        closed_relay_changed = restart.closed_relay_changed,
        semantic_policy_changed = restart.semantic_policy_changed,
        routing_policy_changed = old_config.routing_policy != config.routing_policy,
        pinned_peers_changed = old_config.pinned_peers != config.pinned_peers,
        scheduler_changed = restart.scheduler_changed,
        event_capacity_changed = restart.event_capacity_changed,
        connection_trace_capacity_changed = restart.connection_trace_capacity_changed,
        "network_update: {}",
        if restart.needs_restart {
            "transport restart (drops live peers)"
        } else {
            "hot-applied in place"
        }
    );

    if !restart.needs_restart {
        // STUN/TURN / topology / label / auto_approve — apply in
        // place, no peers dropped. ICE servers are read fresh on the next
        // connect, so a credential rotation reaches new connections without
        // tearing down the live ones (see `reconcile::apply_hot`). A disk
        // failure rolls both the live fields and the saved record back.
        let hot_result = state.registry.with_current(&config.id, &joined, |current| {
            apply_hot_and_persist_with_rollback(current, &config, &old_config)
        });
        let hot_result = match hot_result {
            Some(result) => Some(result),
            None => state
                .registry
                .with_current(&config.network_id, &joined, |current| {
                    apply_hot_and_persist_with_rollback(current, &config, &old_config)
                }),
        };
        match hot_result {
            None => {
                return owner.finish(Err(
                    "network update refused: lifecycle owner is no longer current".to_string(),
                ));
            }
            Some(Err(e)) => {
                return owner.finish(Err(format!("apply or persist config: {e}")));
            }
            Some(Ok(())) => {}
        }
        drop(joined);
        return owner.finish(Ok(OperationReplyData::UpdatedId {
            id: config.id,
            restarted: false,
        }));
    }

    // Transport restart path. Snapshot the live config FIRST so that if
    // the rejoin under the new config is rejected (a bad TURN URL the
    // daemon won't parse, say) we can restore the network exactly as it
    // was rather than leaving the user with nothing — the roster file
    // survives on disk regardless, but a vanished network with no
    // recovery surface is a footgun. Then release our Arc clones so the
    // registry can begin its single owned teardown.
    // Start the authenticated departure and teardown together so teardown can
    // cancel a silent peer's DepartObserved waiter. The carrier hint remains
    // part of the departure future.
    let departure = joined.announce_leave();
    let removal = state.registry.remove_if_current(&old_config.id, &joined);
    let (_, removal) = tokio::join!(departure, removal);
    drop(joined);

    match removal {
        RemoveResult::Removed(Ok(())) => {}
        RemoveResult::Removed(Err(error)) => {
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(format!(
                "old runtime teardown failed: {error}{rollback}"
            )));
        }
        RemoveResult::AlreadyClosing(observation) => {
            let error = match observation.outcome {
                Ok(()) => format!(
                    "network update refused after teardown completed (state {:?})",
                    observation.state
                ),
                Err(error) => format!(
                    "network update refused because prior teardown reported failure: {error}"
                ),
            };
            return owner.finish(Err(error));
        }
        RemoveResult::NotFound => {
            if let Some(runtime) = state.registry.state(&old_config.id) {
                return owner.finish(Err(format!(
                    "network update refused while prior runtime is {runtime:?}"
                )));
            }
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(format!(
                "network update lost the predecessor during teardown{rollback}"
            )));
        }
    }

    // Re-join under the new transport config. If the daemon rejects it,
    // roll back to the snapshot so the network (and its live session) is
    // restored instead of silently disappearing.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => {
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(format!("rejoin with new config: {e}{rollback}")));
        }
    };
    let summary = NetworkLifecycleSummary {
        config_id: joined.config_id().to_owned(),
        network_id: joined.network_id().to_owned(),
        label: joined.label().to_owned(),
        phase: joined.current_phase(),
        topology: joined.current_topology(),
        restarted: true,
    };
    let drivers = {
        match joined.attach_signaling() {
            Ok(drivers) => drivers,
            Err(error) => {
                let attach_error = preserve_shutdown_failure(
                    format!("signaling attach failed after update: {error}"),
                    joined.shutdown().await.map_err(|error| anyhow!("{error}")),
                );
                let rollback = rollback_old_network(state, &old_config).await;
                return owner.finish(Err(format!("{attach_error}{rollback}")));
            }
        }
    };
    if drivers.is_none() {
        warn!(
            network = %config.network_id,
            "signaling outbound receiver was already taken after update — \
             this network keeps no driver handle"
        );
    }
    if let Some(refused) = state.registry.insert(joined, drivers).into_refusal() {
        let refusal_state = refused.state;
        if let Some(drivers) = refused.drivers {
            drivers.shutdown().await;
        }
        let replacement_error = preserve_shutdown_failure(
            format!("replacement runtime refused while predecessor is {refusal_state:?}"),
            refused
                .joined
                .shutdown()
                .await
                .map_err(|error| anyhow!("{error}")),
        );
        let rollback = rollback_old_network(state, &old_config).await;
        return owner.finish(Err(format!("{replacement_error}{rollback}")));
    }

    // The insert is the replacement's ownership boundary. Resolve the exact
    // current Arc and commit persistence under the registry fence; a
    // refusal/successor path above deliberately never reaches this write.
    let replacement_owner = match state.registry.get(&config.id) {
        Some(owner) => owner,
        _ => {
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(
                format!(
                    "replacement runtime lost its lifecycle owner; config was not overwritten{rollback}"
                ),
            ));
        }
    };

    // The replacement must publish its durable service advert before the
    // config commit is acknowledged. A refusal therefore takes the same
    // exact-owner rollback path as a persistence failure.
    if let Err(advert_error) = state.services.on_network_added(&config.id).await {
        let retirement_error = retire_failed_replacement(state, &config.id, &replacement_owner)
            .await
            .map(|error| format!("; {error}"))
            .unwrap_or_default();
        let rollback = rollback_old_network(state, &old_config).await;
        return owner.finish(Err(format!(
            "replacement service advert save failed: {advert_error}{retirement_error}{rollback}"
        )));
    }

    let persisted = state
        .registry
        .with_current(&config.id, &replacement_owner, |_| {
            persist_network_update(&config)
        });
    match persisted {
        None => {
            let retirement_error = retire_failed_replacement(state, &config.id, &replacement_owner)
                .await
                .map(|error| format!("; {error}"))
                .unwrap_or_default();
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(format!(
                "replacement runtime lost its lifecycle owner before persistence{retirement_error}{rollback}"
            )));
        }
        Some(Err(e)) => {
            let retirement_error = retire_failed_replacement(state, &config.id, &replacement_owner)
                .await
                .map(|error| format!("; {error}"))
                .unwrap_or_default();
            let rollback = rollback_old_network(state, &old_config).await;
            return owner.finish(Err(format!(
                "network updated but config.json save failed: {e}{retirement_error}{rollback}"
            )));
        }
        Some(Ok(())) => {}
    }
    // The old network was torn down and a fresh one registered under the
    // same id. Its advert was committed before the fenced persistence above.
    state.services.on_network_removed(&config.id).await;
    owner.finish(Ok(OperationReplyData::Updated(summary)))
}

fn validate_network_update(current: &NetworkConfig, next: &NetworkConfig) -> Result<()> {
    myownmesh_core::engine::reconcile::validate_update(current, next)
        .map_err(|error| anyhow!("{error}"))
}

fn persist_network_add(net: &NetworkConfig) -> Result<()> {
    MeshConfig::transaction(|cfg| {
        // Append only if not already present — covers the case where
        // the user edited config.json by hand between daemon start and
        // this add, and added the same network there too.
        if !cfg
            .networks
            .iter()
            .any(|n| n.id == net.id || n.network_id == net.network_id)
        {
            cfg.networks.push(net.clone());
        }
        Ok(())
    })
    .map_err(anyhow::Error::msg)?;
    Ok(())
}

fn persist_network_remove(config_id: &str, network_id: &str) -> Result<()> {
    MeshConfig::transaction(|cfg| {
        cfg.networks
            .retain(|n| n.id != config_id && n.network_id != network_id);
        Ok(())
    })
    .map_err(anyhow::Error::msg)?;
    Ok(())
}

#[cfg(test)]
tokio::task_local! {
    // Only the scoped update future can consume this exact-config fault.
    // Rollback sees None; unrelated tasks and child processes cannot inherit it.
    static UPDATE_SAVE_FAULT: std::cell::RefCell<Option<NetworkConfig>>;
}

fn persist_network_update(net: &NetworkConfig) -> Result<()> {
    #[cfg(test)]
    if UPDATE_SAVE_FAULT
        .try_with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref() == Some(net) {
                slot.take();
                true
            } else {
                false
            }
        })
        .unwrap_or(false)
    {
        return Err(anyhow!("injected exact-update pre-save failure"));
    }
    MeshConfig::transaction(|cfg| {
        // Replace the matching record in place (by either alias). If it's
        // somehow absent — e.g. the user hand-deleted it between join and
        // this update — append so the on-disk config still agrees with the
        // now-running engine rather than silently dropping it.
        if let Some(slot) = cfg
            .networks
            .iter_mut()
            .find(|n| n.id == net.id || n.network_id == net.network_id)
        {
            *slot = net.clone();
        } else {
            cfg.networks.push(net.clone());
        }
        Ok(())
    })
    .map_err(anyhow::Error::msg)?;
    Ok(())
}

pub(in crate::control) fn parse_topology(
    name: &str,
    hub: Option<&str>,
) -> std::result::Result<TopologyMode, String> {
    match name {
        "ring" => Ok(TopologyMode::Ring { n_preferred: None }),
        "star" => {
            let hub = hub.ok_or_else(|| "star topology requires --hub <device_id>".to_string())?;
            Ok(TopologyMode::Star {
                hub: hub.to_string(),
            })
        }
        "full_mesh" | "fullmesh" => Ok(TopologyMode::FullMesh),
        "hubs" => {
            let list = hub.ok_or_else(|| {
                "hubs topology requires --hub <id[,id…][:redundancy]>".to_string()
            })?;
            let (ids, redundancy) = match list.rsplit_once(':') {
                Some((ids, r)) => (
                    ids,
                    Some(r.parse::<u32>().map_err(|_| {
                        format!("invalid spoke redundancy '{r}' — expected a number")
                    })?),
                ),
                None => (list, None),
            };
            let hubs: Vec<String> = ids
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            if hubs.is_empty() {
                return Err("hubs topology requires at least one hub id".into());
            }
            Ok(TopologyMode::Hubs {
                hubs,
                spoke_redundancy: redundancy,
            })
        }
        other => Err(format!(
            "unknown topology '{other}' — expected ring | star | hubs | full_mesh"
        )),
    }
}

/// This node's overall status: identity, networks, realtime, all at once.
///
/// The snapshot is taken behind one admission rather than field by field, so
/// the answer describes a single moment instead of a walk across several.
pub(in crate::control) fn node_status(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let source = state
        .registry
        .status_source(state.mesh.identity(), &state.realtime);
    let typed_claim = source
        .typed_claim()
        .context("status typed claim was not representable")?;
    let line_ceiling = source
        .line_ceiling()
        .context("status line ceiling was not representable")?;
    let (committed, output) =
        prepare_typed_and_line_building(typed_claim, line_ceiling, admission, |typed| {
            source.commit(typed)
        })
        .context("status snapshot or response line was not admitted")?;
    let status = committed.map_err(|_| anyhow!("status typed claim changed before commit"))?;
    Ok((PreparedReply::Status(status), output))
}

/// Every network this device has joined.
pub(in crate::control) fn networks_list(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let plan = state
        .registry
        .prepare_networks_list()
        .context("NetworksList capacity was not representable")?;
    let typed = admission
        .acquire_claim(plan.typed_claim())
        .context("NetworksList typed snapshot was not admitted")?;
    let work = admission
        .acquire_claim(plan.work_claim())
        .context("NetworksList snapshot work was not admitted")?;
    let plan = plan
        .measure_line_ceiling(&work)
        .context("NetworksList line capacity was not representable")?;
    let output = AdmittedLineOut::prepare_capacity(plan.line_ceiling(), admission)
        .context("NetworksList response line was not admitted")?;
    let networks = plan
        .commit(typed, work)
        .map_err(|_| anyhow!("NetworksList changed shape while its funded snapshot was built"))?;
    Ok((PreparedReply::Networks(networks), output))
}

/// Advertise what this device can do on one network.
pub(in crate::control) async fn capabilities_set(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    capabilities: myownmesh_core::protocol::CapabilityAdvert,
) -> Result<Answer> {
    let Some(net) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let reply = PreparedReply::Bool {
        key: "advertised",
        value: true,
    };
    let (advertised, output) =
        prepare_reply_then(&reply, admission, || net.advertise(capabilities))
            .context("capability-advert response capacity was not admitted")?;
    match advertised {
        Ok(()) => Ok((reply, output)),
        Err(error) => {
            drop(output);
            super::refused_text(
                format!(
                    "capabilities were not advertised; the node is still publishing its \
                     previous ones: {error}"
                ),
                admission,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::combine_remove_failures;
    use super::persist_or_rollback_added_network;
    use super::preserve_shutdown_failure;
    use super::purge_owned_state;
    use super::replacement_retirement_failure;
    use super::run_hot_update_with_rollback;
    use super::validate_network_update;
    use super::RemoveResult;

    const UPDATE_CHILD: &str = "MYOWNMESH_NETWORK_UPDATE_CHILD";
    const UPDATE_SELECTOR: &str =
        "control::dispatch::network::tests::actual_network_update_isolated_lifecycle";

    // A child-only fixture: no test changes the parent process's HOME or
    // MYOWNMESH_HOME. It uses the production global-path adapter unchanged.
    #[test]
    #[ignore = "isolated real daemon dispatch/SQLite/driver lifecycle"]
    fn actual_network_update_isolated_lifecycle() {
        if let Some(root) = std::env::var_os(UPDATE_CHILD) {
            assert_eq!(std::env::var_os("MYOWNMESH_HOME"), Some(root.clone()));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("fixture runtime");
            let report = runtime.block_on(actual_update_child(tokio::time::Instant::from_std(
                deadline,
            )));
            drop(runtime);
            // Synchronous destruction is not preempted by timeout_at. A late
            // Ready or runtime drop must never turn into successful evidence.
            assert!(
                std::time::Instant::now() < deadline,
                "child runtime teardown deadline"
            );
            let report = report.expect("actual update lifecycle");
            std::fs::write(
                std::path::PathBuf::from(root).join("result.json"),
                serde_json::to_vec(&report).unwrap(),
            )
            .expect("child evidence");
            return;
        }
        let root = tempfile::tempdir().expect("isolated instance root");
        let stdout = tempfile::tempfile().expect("child stdout");
        let stderr = tempfile::tempfile().expect("child stderr");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let stop_work = deadline - std::time::Duration::from_secs(2);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                UPDATE_SELECTOR,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(UPDATE_CHILD, root.path())
            .env("MYOWNMESH_HOME", root.path())
            .stdin(std::process::Stdio::null())
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap())
            .spawn()
            .expect("isolated test child");
        let mut forced = None;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let observed = std::time::Instant::now();
                    if observed >= deadline {
                        forced = Some("child terminal exceeded absolute hang guard".into());
                    } else if observed >= stop_work && forced.is_none() {
                        forced = Some("child terminal observed after work cutoff".into());
                    }
                    break status;
                }
                Ok(None) => {}
                Err(error) => {
                    forced = Some(format!("child observation failed: {error}"));
                    let _ = child.kill();
                    break child.wait().expect("reap child after observation failure");
                }
            }
            let oversized = stdout
                .metadata()
                .map(|m| m.len() > 1024 * 1024)
                .unwrap_or(true)
                || stderr
                    .metadata()
                    .map(|m| m.len() > 1024 * 1024)
                    .unwrap_or(true);
            if forced.is_none() && (oversized || std::time::Instant::now() >= stop_work) {
                forced = Some(
                    if oversized {
                        "bounded child output exceeded"
                    } else {
                        "child deadline"
                    }
                    .into(),
                );
                if let Err(error) = child.kill() {
                    forced = Some(format!("exact child termination failed: {error}"));
                }
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                // Reap the already-killed child even when the bounded observation
                // missed terminal; this path is a failure, never qualification.
                let status = child.wait().expect("reap killed child");
                forced = Some("child terminal exceeded absolute hang guard".into());
                break status;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        use std::io::{Read, Seek};
        let read_log = |mut file: std::fs::File| {
            file.rewind().unwrap();
            let mut bytes = Vec::new();
            file.take(1024 * 1024).read_to_end(&mut bytes).unwrap();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        assert!(
            stdout.metadata().unwrap().len() <= 1024 * 1024
                && stderr.metadata().unwrap().len() <= 1024 * 1024,
            "child output bound exceeded"
        );
        assert!(
            forced.is_none() && status.success(),
            "{forced:?} {status}; stdout={} stderr={}",
            read_log(stdout),
            read_log(stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.path().join("result.json")).expect("completed child report"),
        )
        .unwrap();
        assert_eq!(report["cleanup_joined"], true);
        let records = report["records"].as_array().unwrap();
        assert_eq!(records.len(), 7);
        for record in &records[..3] {
            assert_eq!(record["reply"]["ok"], false);
            assert_eq!(record["disk_before"], record["disk_after"]);
            assert_eq!(record["same_owner"], true);
        }
        for record in &records[3..5] {
            assert_eq!(record["reply"]["ok"], true);
            assert_eq!(record["same_owner"], false);
            assert_eq!(record["predecessor_joined"], true);
        }
        assert_eq!(records[5]["reply"]["ok"], true);
        assert_eq!(records[5]["same_owner"], true);
        assert_eq!(records[6]["reply"]["ok"], false);
        assert_eq!(records[6]["fault_consumed"], true);
        assert_eq!(records[6]["disk_before"], records[6]["disk_after"]);
        let saved: myownmesh_core::MeshConfig =
            serde_json::from_slice(&std::fs::read(root.path().join("config.json")).unwrap())
                .unwrap();
        assert_eq!(
            serde_json::to_value(&saved.networks[0]).unwrap(),
            report["final_config"]
        );
    }

    async fn actual_update_child(
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<serde_json::Value> {
        use crate::control::{
            ClosedRelayRegistry, ControlState, RealtimeAdvert, RuntimeSupervisor,
        };
        use myownmesh_core::{Mesh, MeshConfig, NetworkConfig};
        let work_deadline = deadline - std::time::Duration::from_secs(2);
        let _exclusive =
            tokio::time::timeout_at(work_deadline, crate::exclusive_connector_fixture()).await?;
        let mesh = tokio::time::timeout_at(
            deadline,
            Mesh::open_connector_capable_with_identity(
                MeshConfig::default(),
                Arc::new(myownmesh_core::Identity::ephemeral()),
                myownmesh_core::WebRtcConnectorCapablePolicy::new(
                    crate::test_resource_provider(),
                    myownmesh_core::WebRtcConnectorProfile::new(
                        myownmesh_core::ConnectorCallbackPolicy::elastic_data_only(),
                    ),
                ),
            ),
        )
        .await??;
        let registry = crate::registry::NetworkRegistry::new();
        let services = crate::services::ServiceManager::new(mesh.clone(), registry.clone());
        let clients = crate::ipc::ClientRegistry::new(mesh.local_application_resource_scope()?)?;
        let state = Arc::new(ControlState {
            finished: tokio::sync::Notify::new(),
            ended: std::sync::atomic::AtomicUsize::new(0),
            abnormal_connections: std::sync::atomic::AtomicUsize::new(0),
            mesh,
            registry,
            services,
            clients,
            closed_relays: ClosedRelayRegistry::new(),
            realtime: RealtimeAdvert {
                supported: false,
                encodings: Vec::new(),
            },
            supervisor: RuntimeSupervisor::new(),
            json_line_bytes: None,
            realtime_frame_bytes: None,
            before_events_subscribe_commit: None,
            at_events_stream_entry: None,
            before_rpc_call: None,
            before_begin_closing: None,
            before_provisional_settle: None,
            before_mfa_response_write: None,
            #[cfg(feature = "transport-lab")]
            mfa_transport_lab_barrier: None,
        });
        let result = tokio::time::timeout_at(work_deadline, async {
            let mut config = NetworkConfig::from_network_id("actual-update", "actualupdate");
            config.stun_servers.clear();
            config.turn_servers.clear();
            config.signaling.servers.clear();
            config.signaling.strategy = "none".into();
            config.signaling.mdns = false;
            let joined = state.mesh.join(config.clone()).await?;
            if let Some(refusal) = state.registry.insert(joined, None).into_refusal() {
                if let Some(drivers) = refusal.drivers { drivers.shutdown().await; }
                refusal.joined.shutdown().await?;
                anyhow::bail!("initial exact registry insertion refused");
            }
            super::persist_network_update(&config)?;
            let path = myownmesh_core::dirs::config_path()?;
            let frames = super::FrameAdmission::new(state.mesh.local_application_resource_scope()?, None);
            let mut records = Vec::new();
            for index in 0..7 {
                let current = state.registry.get(&config.id).ok_or_else(|| anyhow::anyhow!("missing owner"))?;
                let before = current.config_snapshot();
                let context = current.semantic_state_identity()?.context_id();
                let disk_before = std::fs::read(&path)?;
                let mut next = before.clone();
                match index {
                    0 => next.routing_policy.max_next_hops = 0,
                    1 => next.kind = myownmesh_core::NetworkKind::Closed,
                    2 => next.pinned_peers = vec!["invalid-peer".into()],
                    3 => next.routing_policy.max_next_hops += 1,
                    4 => next.pinned_peers = vec![myownmesh_core::Identity::ephemeral().public_id().into()],
                    5 => {
                        next.label = "actual-hot".into();
                        next.auto_approve = !before.auto_approve;
                        next.stun_servers = vec![myownmesh_core::StunServer { urls: vec!["stun:example.com:3478".into()] }];
                        next.turn_servers = vec![myownmesh_core::TurnServer {
                            urls: vec!["turn:example.com:3478".into()], username: Some("fixture".into()),
                            credential: Some("fixture".into()),
                        }];
                    }
                    6 => next.label = "must-rollback".into(),
                    _ => unreachable!(),
                }
                let owner = super::ResponseOwner::acquire(&frames)?;
                let (reply, fault_consumed) = if index == 6 {
                    super::UPDATE_SAVE_FAULT.scope(std::cell::RefCell::new(Some(next.clone())), async {
                        let reply = super::network_update(&state, next.clone(), owner).await;
                        (reply, super::UPDATE_SAVE_FAULT.with(|slot| slot.borrow().is_none()))
                    }).await
                } else { (super::network_update(&state, next.clone(), owner).await, false) };
                let reply = serde_json::to_value(reply)?;
                let successor = state.registry.get(&config.id).ok_or_else(|| anyhow::anyhow!("owner lost"))?;
                let same_owner = Arc::ptr_eq(&current, &successor);
                anyhow::ensure!(successor.semantic_state_identity()?.context_id() == context,
                    "config update changed cryptographic context");
                let disk_after = std::fs::read(&path)?;
                let expected = if index < 3 || index == 6 { &before } else { &next };
                anyhow::ensure!(successor.config_snapshot() == *expected, "live config mismatch at {index}");
                let saved: MeshConfig = serde_json::from_slice(&disk_after)?;
                anyhow::ensure!(saved.networks.as_slice() == [expected.clone()], "saved config mismatch at {index}");
                anyhow::ensure!(reply["ok"] == (3..6).contains(&index), "unexpected reply at {index}: {reply}");
                anyhow::ensure!(same_owner != (index == 3 || index == 4), "wrong exact owner at {index}");
                if index < 3 || index == 6 {
                    anyhow::ensure!(disk_before == disk_after, "refusal/rollback changed saved bytes");
                }
                if index == 3 || index == 4 {
                    // Do not infer termination from MeshPhase: it is not a
                    // driver-join witness. Observe the exact retained owner's
                    // idempotent shutdown without waiting for new work.
                    use std::future::Future;
                    let shutdown = current.shutdown();
                    tokio::pin!(shutdown);
                    let first = std::future::poll_fn(|cx| {
                        std::task::Poll::Ready(shutdown.as_mut().poll(cx))
                    }).await;
                    match first {
                        std::task::Poll::Ready(result) => result?,
                        std::task::Poll::Pending => {
                            shutdown.await?;
                            anyhow::bail!("predecessor join still pending after replacement reply");
                        }
                    }
                }
                anyhow::ensure!(index != 6 || fault_consumed, "save fault not exercised");
                records.push(serde_json::json!({"index":index, "reply":reply,
                    "same_owner":same_owner, "predecessor_joined":index == 3 || index == 4,
                    "fault_consumed":fault_consumed, "disk_before":disk_before, "disk_after":disk_after}));
                config = expected.clone();
            }
            Ok::<_, anyhow::Error>(serde_json::json!({"records":records,"final_config":config}))
        }).await;
        // timeout_at may accept a synchronously late Ready. Record the original
        // work cutoff now, but still own cleanup before reporting that failure.
        let work_late = tokio::time::Instant::now() >= work_deadline;
        // Own cleanup even when a stage returns Err or its absolute deadline fires.
        let cleanup = tokio::time::timeout_at(deadline, async {
            let results = state.registry.shutdown_all().await;
            let services = state.services.shutdown().await;
            let relays = state.closed_relays.shutdown_all().await;
            state.clients.begin_closing();
            let abnormal = state.clients.drain_watchdogs().await;
            state.clients.wait_for_tasks().await;
            let terminal = state.clients.finish_closed();
            anyhow::ensure!(
                results.into_iter().all(|result| result.is_ok()),
                "driver cleanup failed"
            );
            services?;
            relays.map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                abnormal == 0 && terminal == crate::ipc::Lifecycle::Closed,
                "client cleanup failed"
            );
            Ok::<_, anyhow::Error>(())
        })
        .await;
        let cleanup_late = tokio::time::Instant::now() >= deadline;
        drop(state);
        anyhow::ensure!(
            !cleanup_late && tokio::time::Instant::now() < deadline,
            "child cleanup/state teardown deadline"
        );
        cleanup??;
        anyhow::ensure!(!work_late, "child work completed after original deadline");
        let mut report = result??;
        report["cleanup_joined"] = serde_json::json!(true);
        Ok(report)
    }

    #[test]
    fn network_update_validation_covers_kind_routes_pins_before_persistence() {
        use myownmesh_core::{NetworkConfig, NetworkKind};
        let current = NetworkConfig::from_network_id("edit-validation", "edit-validation");
        let mut route = current.clone();
        route.routing_policy.max_next_hops += 1;
        validate_network_update(&current, &route).expect("valid routing replacement");
        assert!(myownmesh_core::engine::reconcile::requires_restart(
            &current, &route
        ));
        let peer = myownmesh_core::Identity::ephemeral()
            .public_id()
            .to_string();
        let mut pins = current.clone();
        pins.pinned_peers = vec![peer];
        validate_network_update(&current, &pins).expect("valid pin replacement");
        assert!(myownmesh_core::engine::reconcile::requires_restart(
            &current, &pins
        ));

        let mut kind = current.clone();
        kind.kind = NetworkKind::Closed;
        let mut invalid_route = current.clone();
        invalid_route.routing_policy.max_parallel_routes =
            invalid_route.routing_policy.max_next_hops + 1;
        let mut invalid_pin = current.clone();
        invalid_pin.pinned_peers = vec!["invalid".into()];
        for next in [kind, invalid_route, invalid_pin] {
            let saved = std::cell::RefCell::new(current.clone());
            let result = run_hot_update_with_rollback(
                || validate_network_update(&current, &next),
                || {
                    *saved.borrow_mut() = next.clone();
                    Ok(())
                },
                || panic!("validation refusal must not require live rollback"),
                || panic!("validation refusal must not touch disk"),
            );
            assert!(result.is_err());
            assert_eq!(*saved.borrow(), current);
        }
    }

    #[test]
    fn hot_update_full_config_parity_and_save_failure_restore_both_copies() {
        use myownmesh_core::NetworkConfig;
        let old = NetworkConfig::from_network_id("edit-parity", "edit-parity");
        let mut next = old.clone();
        next.label = "edited".into();
        next.auto_approve = !old.auto_approve;
        next.stun_servers.clear();
        next.turn_servers.clear();
        validate_network_update(&old, &next).expect("valid hot fields");
        assert!(!myownmesh_core::engine::reconcile::requires_restart(
            &old, &next
        ));
        // This controls persistence/rollback orchestration with complete values.
        // Core reconcile controls separately exercise the actual live hot mutation.
        for fail_save in [false, true] {
            let live = std::cell::RefCell::new(old.clone());
            let disk = std::cell::RefCell::new(old.clone());
            let result = run_hot_update_with_rollback(
                || {
                    *live.borrow_mut() = next.clone();
                    Ok(())
                },
                || {
                    *disk.borrow_mut() = next.clone();
                    if fail_save {
                        Err(anyhow::anyhow!("injected save failure"))
                    } else {
                        Ok(())
                    }
                },
                || {
                    *live.borrow_mut() = old.clone();
                    Ok(())
                },
                || {
                    *disk.borrow_mut() = old.clone();
                    Ok(())
                },
            );
            assert_eq!(result.is_err(), fail_save);
            let expected = if fail_save { &old } else { &next };
            assert_eq!(&*live.borrow(), expected);
            assert_eq!(&*disk.borrow(), expected);
        }
    }

    #[derive(Default)]
    struct AddRollbackProbe {
        inserted: bool,
        retired: bool,
        teardown_observed: bool,
        withdrawn: bool,
        order: Vec<&'static str>,
    }

    #[test]
    fn network_add_save_failure_retires_inserted_owner_before_withdrawal() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("single-thread test runtime");
        runtime.block_on(async {
            let probe = Arc::new(Mutex::new(AddRollbackProbe {
                inserted: true,
                ..Default::default()
            }));
            let persist_probe = Arc::clone(&probe);
            let remove_probe = Arc::clone(&probe);
            let withdraw_probe = Arc::clone(&probe);
            let message = persist_or_rollback_added_network(
                move || {
                    persist_probe.lock().unwrap().order.push("persist");
                    Err(anyhow::anyhow!("disk full"))
                },
                move || async move {
                    let mut probe = remove_probe.lock().unwrap();
                    assert!(probe.inserted, "rollback must see the inserted owner");
                    probe.order.push("remove");
                    probe.inserted = false;
                    probe.retired = true;
                    probe.teardown_observed = true;
                    RemoveResult::Removed(Err("driver teardown failed".to_string()))
                },
                move || async move {
                    let mut probe = withdraw_probe.lock().unwrap();
                    assert!(
                        probe.retired,
                        "service withdrawal follows registry retirement"
                    );
                    probe.order.push("withdraw");
                    probe.withdrawn = true;
                },
            )
            .await
            .expect("persistence failure must return a rollback message");

            let probe = probe.lock().unwrap();
            assert!(!probe.inserted);
            assert!(probe.retired);
            assert!(probe.teardown_observed);
            assert!(probe.withdrawn);
            assert_eq!(probe.order, ["persist", "remove", "withdraw"]);
            assert_eq!(
                message,
                "network joined but config.json save failed: disk full; \
                 network add rollback teardown reported failure: driver teardown failed"
            );
        });
    }

    #[test]
    fn replacement_teardown_failure_is_preserved_for_old_network_rollback() {
        let failure = replacement_retirement_failure(RemoveResult::Removed(Err(
            "driver teardown failed".to_string(),
        )))
        .expect("replacement teardown failure must be observable");
        assert_eq!(
            failure,
            "replacement runtime teardown reported failure: driver teardown failed"
        );
        assert!(replacement_retirement_failure(RemoveResult::Removed(Ok(()))).is_none());
    }

    #[derive(Debug)]
    struct HotRollbackProbe {
        live: &'static str,
        disk: &'static str,
        order: Vec<&'static str>,
    }

    fn hot_rollback_control(live_failure: bool, disk_failure: bool) -> (String, HotRollbackProbe) {
        let probe = Arc::new(Mutex::new(HotRollbackProbe {
            live: "old",
            disk: "old",
            order: Vec::new(),
        }));
        let apply_probe = Arc::clone(&probe);
        let persist_probe = Arc::clone(&probe);
        let live_probe = Arc::clone(&probe);
        let disk_probe = Arc::clone(&probe);
        let result = run_hot_update_with_rollback(
            move || {
                let mut probe = apply_probe.lock().unwrap();
                probe.order.push("apply");
                probe.live = "new";
                Ok(())
            },
            move || {
                let mut probe = persist_probe.lock().unwrap();
                probe.order.push("persist");
                probe.disk = "new";
                Err(anyhow::anyhow!("disk full"))
            },
            move || {
                let mut probe = live_probe.lock().unwrap();
                probe.order.push("live rollback");
                if live_failure {
                    Err(anyhow::anyhow!("live rollback refused"))
                } else {
                    probe.live = "old";
                    Ok(())
                }
            },
            move || {
                let mut probe = disk_probe.lock().unwrap();
                probe.order.push("disk rollback");
                if disk_failure {
                    Err(anyhow::anyhow!("disk rollback refused"))
                } else {
                    probe.disk = "old";
                    Ok(())
                }
            },
        )
        .expect_err("the injected save failure must enter rollback");
        let probe = Arc::try_unwrap(probe)
            .expect("all rollback closures have completed")
            .into_inner()
            .unwrap();
        (result.to_string(), probe)
    }

    #[test]
    fn hot_update_save_failure_attempts_both_rollbacks_in_order() {
        let (message, probe) = hot_rollback_control(false, false);
        assert_eq!(probe.live, "old");
        assert_eq!(probe.disk, "old");
        assert_eq!(
            probe.order,
            ["apply", "persist", "live rollback", "disk rollback"]
        );
        assert_eq!(message, "hot update config.json save failed: disk full");

        let (message, probe) = hot_rollback_control(true, false);
        assert_eq!(probe.live, "new");
        assert_eq!(probe.disk, "old");
        assert_eq!(
            probe.order,
            ["apply", "persist", "live rollback", "disk rollback"]
        );
        assert_eq!(
            message,
            "hot update config.json save failed: disk full; \
             live hot-update rollback failed: live rollback refused"
        );

        let (message, probe) = hot_rollback_control(false, true);
        assert_eq!(probe.live, "old");
        assert_eq!(probe.disk, "new");
        assert_eq!(
            probe.order,
            ["apply", "persist", "live rollback", "disk rollback"]
        );
        assert_eq!(
            message,
            "hot update config.json save failed: disk full; \
             disk config rollback failed: disk rollback refused"
        );

        let (message, probe) = hot_rollback_control(true, true);
        assert_eq!(probe.live, "new");
        assert_eq!(probe.disk, "new");
        assert_eq!(
            probe.order,
            ["apply", "persist", "live rollback", "disk rollback"]
        );
        assert_eq!(
            message,
            "hot update config.json save failed: disk full; \
             live hot-update rollback failed: live rollback refused; \
             disk config rollback failed: disk rollback refused"
        );
    }

    #[test]
    fn mandatory_shutdown_failure_preserves_each_primary_response_cause() {
        for primary in [
            "signaling attach failed: attach refused",
            "network id is held by a runtime in Closing state",
            "rollback join was refused by a Closing runtime; config was not overwritten",
            "replacement runtime refused while predecessor is Closing",
        ] {
            let combined =
                preserve_shutdown_failure(primary, Err(anyhow::anyhow!("driver teardown failed")));
            assert_eq!(
                combined,
                format!("{primary}; shutdown failed: driver teardown failed")
            );
            assert_eq!(combined.matches("shutdown failed").count(), 1);
        }

        let primary = "signaling attach failed: attach refused";
        assert_eq!(preserve_shutdown_failure(primary, Ok(())), primary);
    }

    #[test]
    fn remove_failures_preserve_exact_single_and_combined_order() {
        let purge = "purge refused for network-a: semantic state is busy".to_string();
        let persistence = "network left but config.json save failed: disk full".to_string();
        let teardown =
            "network removed but runtime teardown reported failure: driver stopped with error"
                .to_string();

        assert_eq!(
            combine_remove_failures("network-a".into(), None, Some(persistence.clone()), None),
            Err(persistence.clone())
        );
        assert_eq!(
            combine_remove_failures("network-a".into(), None, None, Some(teardown.clone())),
            Err(teardown.clone())
        );
        assert_eq!(
            combine_remove_failures(
                "network-a".into(),
                None,
                Some(persistence.clone()),
                Some(teardown.clone())
            ),
            Err(format!("{persistence}; {teardown}"))
        );
        assert_eq!(
            combine_remove_failures("network-a".into(), Some(purge.clone()), None, None),
            Err(purge.clone())
        );
        assert_eq!(
            combine_remove_failures(
                "network-a".into(),
                Some(purge.clone()),
                Some(persistence.clone()),
                None
            ),
            Err(format!("{purge}; {persistence}"))
        );
        assert_eq!(
            combine_remove_failures(
                "network-a".into(),
                Some(purge.clone()),
                None,
                Some(teardown.clone())
            ),
            Err(format!("{purge}; {teardown}"))
        );
        assert_eq!(
            combine_remove_failures(
                "network-a".into(),
                Some(purge.clone()),
                Some(persistence.clone()),
                Some(teardown.clone())
            ),
            Err(format!("{purge}; {persistence}; {teardown}"))
        );
        assert_eq!(
            combine_remove_failures("network-a".into(), None, None, None),
            Ok("network-a".to_string())
        );
    }

    #[test]
    fn purge_without_the_joined_owner_is_refused() {
        let error = purge_owned_state(
            "network-a",
            None::<&()>,
            |_| panic!("semantic purge must not run without its owner"),
            |_| panic!("roster purge must not run without its owner"),
        )
        .expect_err("missing owner must not report a successful purge");
        assert!(error.contains("canonical semantic snapshot owner unavailable"));
    }

    #[test]
    fn semantic_writer_refusal_is_not_reported_as_removed() {
        let owner = ();
        let error = purge_owned_state(
            "network-a",
            Some(&owner),
            |_| Err(anyhow::anyhow!("WriterBusy: semantic writer is busy")),
            |_| panic!("roster purge must wait for semantic success"),
        )
        .expect_err("a semantic writer refusal must fail the purge");
        assert!(error.contains("WriterBusy"));
        assert!(error.contains("purge refused"));
    }

    #[test]
    fn roster_io_failure_is_not_reported_as_forgotten() {
        let owner = ();
        let error = purge_owned_state(
            "network-a",
            Some(&owner),
            |_| Ok(()),
            |_| Err(anyhow::anyhow!("I/O error removing roster")),
        )
        .expect_err("a roster I/O refusal must fail the purge");
        assert!(error.contains("roster delete failed"));
        assert!(error.contains("I/O error"));
    }

    #[test]
    fn successful_purge_requires_both_owned_steps() {
        let owner = ();
        let mut semantic_called = false;
        let mut roster_called = false;
        purge_owned_state(
            "network-a",
            Some(&owner),
            |_| {
                semantic_called = true;
                Ok(())
            },
            |_| {
                roster_called = true;
                Ok(())
            },
        )
        .expect("both owned purge steps succeeded");
        assert!(semantic_called);
        assert!(roster_called);
    }
}
