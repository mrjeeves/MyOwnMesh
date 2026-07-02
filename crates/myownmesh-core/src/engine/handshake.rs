//! Hello → auth_response state machine.
//!
//! On data channel open:
//!   - Local generates nonce + verification code.
//!   - Sends `hello { device_id, label, nonce, verification_code,
//!     capabilities, app_version, features }`.
//!   - Watchdog scheduled at `HANDSHAKE_TIMEOUT_MS`; up to three
//!     hello retries on the [`HANDSHAKE_HELLO_RETRY_SCHEDULE_MS`].
//!
//! On inbound hello:
//!   - Record peer's nonce + verification code.
//!   - Build the payload (`SIGN_DOMAIN_TAG || nonce || my_id ||
//!     their_id`) and ed25519-sign it.
//!   - Reply with `auth_response { signature }`.
//!
//! On inbound auth_response:
//!   - Verify the signature against the peer's claimed device id
//!     using the nonce *we* sent in our hello.
//!   - On success: emit `PeerAuthenticated`, decide approval
//!     (roster auto-approve or wait for user), send `approve`
//!     when cleared.
//!
//! On inbound approve:
//!   - If we've also sent ours, transition to `Active` and emit
//!     `PeerApproved`.

use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, warn};

use crate::events::{DropReason, MeshEvent, PeerEvent};
use crate::protocol::{
    features::ADVERTISED_FEATURES,
    handshake::{ApproveMessage, AuthResponseMessage, DenyMessage, HelloMessage},
    MeshMessage,
};
use crate::signing;
use crate::verification;
use crate::PROTOCOL_VERSION;

use super::connection::PeerStatus;
use super::ladder::ConnectionTier;
use super::scheduler::{HANDSHAKE_HELLO_RETRY_SCHEDULE_MS, HANDSHAKE_TIMEOUT_MS};
use super::state::NetworkState;
use super::{phase, send_to_peer};

/// Generate a fresh nonce: 32 random bytes, base32-lowercase.
fn fresh_nonce() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes[..]);
    data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
}

/// Kick off the handshake — called once the data channel opens.
/// Sends the first hello and schedules the timeout watchdog.
pub async fn initiate(state: &Arc<NetworkState>, device_id: &str) {
    let nonce = fresh_nonce();
    let code = verification::generate_code();
    let caps = state
        .rpc
        .read()
        .as_ref()
        .map(|r| r.capability.lock().clone())
        .unwrap_or_default();
    let hello = HelloMessage {
        protocol: PROTOCOL_VERSION,
        device_id: state.identity.public_id().to_string(),
        label: state.identity.label().to_string(),
        nonce: nonce.clone(),
        verification_code: code.clone(),
        capabilities: Some(caps),
        max_connections: None,
        features: ADVERTISED_FEATURES.iter().map(|s| s.to_string()).collect(),
        app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        data.status = PeerStatus::Handshaking;
        data.nonce_sent = Some(nonce);
        data.verification_code_sent = Some(code.clone());
        data.handshake_started_at = Some(Instant::now());
        data.hello_attempt = 1;
        data.diag.hellos_sent += 1;
    }
    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "handshake",
        format!(
            "sending hello to {} (code: {code})",
            super::short_peer(device_id)
        ),
        serde_json::json!({ "peer": device_id, "code": code }),
    );
    let hello_msg = MeshMessage::Hello(hello);
    if let Err(e) = send_to_peer(state, device_id, &hello_msg).await {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!("send hello to {} failed: {e}", super::short_peer(device_id)),
            serde_json::json!({ "peer": device_id, "error": e.to_string() }),
        );
        warn!(peer = %device_id, "send hello failed: {e}");
    }
    schedule_hello_retries(state.clone(), device_id.to_string(), hello_msg);
    schedule_watchdog(state.clone(), device_id.to_string());
}

/// Re-send the same hello at each tick of
/// [`HANDSHAKE_HELLO_RETRY_SCHEDULE_MS`] until the peer authenticates
/// or the watchdog tears down. Replaying the hello is safe: the
/// receiver overwrites its `nonce_received` slot unconditionally and
/// the signature in `auth_response` is deterministic, so a duplicate
/// just yields a duplicate (idempotent) reply.
fn schedule_hello_retries(state: Arc<NetworkState>, device_id: String, hello: MeshMessage) {
    tokio::spawn(async move {
        for &delay_ms in HANDSHAKE_HELLO_RETRY_SCHEDULE_MS {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            let still_handshaking = {
                let Some(peer) = state.peers.get(&device_id) else {
                    return;
                };
                let data = peer.state.read();
                matches!(data.status, PeerStatus::Handshaking) && !data.authenticated
            };
            if !still_handshaking {
                return;
            }
            if let Err(e) = send_to_peer(&state, &device_id, &hello).await {
                debug!(peer = %device_id, "hello retry send failed: {e}");
            }
            if let Some(peer) = state.peers.get(&device_id) {
                let mut data = peer.state.write();
                data.hello_attempt = data.hello_attempt.saturating_add(1);
                data.diag.hellos_sent = data.diag.hellos_sent.saturating_add(1);
            }
        }
    });
}

fn schedule_watchdog(state: Arc<NetworkState>, device_id: String) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(HANDSHAKE_TIMEOUT_MS)).await;
        let should_fail = {
            let Some(peer) = state.peers.get(&device_id) else {
                return;
            };
            let data = peer.state.read();
            !data.authenticated
                && matches!(data.status, PeerStatus::Handshaking)
                && data
                    .handshake_started_at
                    .map(|t| t.elapsed().as_millis() as u64 >= HANDSHAKE_TIMEOUT_MS)
                    .unwrap_or(false)
        };
        if should_fail {
            state.log_diag_with(
                crate::events::DiagLevel::Warn,
                "handshake",
                format!("handshake watchdog fired for {device_id} — tearing down"),
                serde_json::json!({ "peer": device_id }),
            );
            super::drop_peer(&state, &device_id, DropReason::HeartbeatTimeout).await;
        }
    });
}

pub async fn on_hello(state: &Arc<NetworkState>, device_id: &str, hello: HelloMessage) {
    // Sanity-check: the device id the peer claimed in the hello
    // must match the connection id we're using to route this
    // frame. If a peer claims to be someone else, refuse — the
    // signature check would catch this anyway, but failing early
    // surfaces a clearer diagnostic.
    if signing::pubkey_part(&hello.device_id) != signing::pubkey_part(device_id) {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!(
                "hello from {} claimed a different id ({}) — dropping",
                super::short_peer(device_id),
                super::short_peer(&hello.device_id)
            ),
            serde_json::json!({
                "connection_peer": device_id,
                "claimed_peer": hello.device_id,
            }),
        );
        warn!(
            peer = %device_id,
            claimed = %hello.device_id,
            "hello claimed a different device id than the connection — dropping"
        );
        super::drop_peer(state, device_id, DropReason::AuthFailed).await;
        return;
    }

    // Record the peer's nonce / verification code and capabilities.
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        data.nonce_received = Some(hello.nonce.clone());
        data.verification_code_received = Some(hello.verification_code.clone());
        data.label = hello.label.clone();
        if let Some(caps) = &hello.capabilities {
            data.capabilities = Some(caps.clone());
        }
    }

    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "handshake",
        format!(
            "hello received from {} (label: {:?}, code: {})",
            super::short_peer(device_id),
            hello.label,
            hello.verification_code,
        ),
        serde_json::json!({
            "peer": device_id,
            "label": hello.label,
            "code": hello.verification_code,
        }),
    );

    // Build the signed payload and reply.
    let payload = signing::handshake_payload(
        &hello.nonce,
        state.identity.public_id(),
        signing::pubkey_part(device_id),
    );
    let signature = signing::sign_with(state.identity.signing_key(), &payload);
    if let Err(e) = send_to_peer(
        state,
        device_id,
        &MeshMessage::AuthResponse(AuthResponseMessage { signature }),
    )
    .await
    {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!(
                "send auth_response to {} failed: {e}",
                super::short_peer(device_id)
            ),
            serde_json::json!({ "peer": device_id, "error": e.to_string() }),
        );
        warn!(peer = %device_id, "send auth_response failed: {e}");
        return;
    }
    debug!(peer = %device_id, "responded to hello");
}

pub async fn on_auth_response(
    state: &Arc<NetworkState>,
    device_id: &str,
    resp: AuthResponseMessage,
) {
    // Verify the signature against the nonce we sent. The peer's
    // signature covers `SIGN_DOMAIN_TAG || nonce_we_sent ||
    // peer_id || my_id` — peer is the signer, so the order is
    // their-id-first from their perspective. Match that exactly.
    let (my_nonce, peer_label, verification_code) = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let data = peer.state.read();
        (
            data.nonce_sent.clone(),
            data.label.clone(),
            data.verification_code_received.clone().unwrap_or_default(),
        )
    };
    let Some(my_nonce) = my_nonce else {
        warn!(peer = %device_id, "received auth_response without having sent hello");
        return;
    };
    let payload = signing::handshake_payload(
        &my_nonce,
        signing::pubkey_part(device_id),
        state.identity.public_id(),
    );
    let ok = match signing::verify(device_id, &payload, &resp.signature) {
        Ok(v) => v,
        Err(e) => {
            warn!(peer = %device_id, "verify failed: {e}");
            false
        }
    };
    if !ok {
        warn!(peer = %device_id, "auth_response signature did not verify");
        super::drop_peer(state, device_id, DropReason::AuthFailed).await;
        return;
    }

    // Authentication succeeded.
    let (auto_approve, rostered, caps) = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let mut data = peer.state.write();
        data.authenticated = true;
        data.status = PeerStatus::PendingApproval;
        let rostered = state.is_rostered(device_id);
        let cfg = state.config.read();
        let auto = cfg.auto_approve || rostered;
        (
            auto,
            rostered,
            data.capabilities.clone().unwrap_or_default(),
        )
    };

    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "handshake",
        format!(
            "auth ok with {} ({})",
            super::short_peer(device_id),
            if auto_approve {
                if rostered {
                    "rostered → auto-approve"
                } else {
                    "auto-approve enabled"
                }
            } else {
                "awaiting user approval"
            }
        ),
        serde_json::json!({
            "peer": device_id,
            "rostered": rostered,
            "auto_approve": auto_approve,
        }),
    );

    state.emit(MeshEvent::Peer(PeerEvent::Authenticated {
        network_id: state.network_id.clone(),
        device_id: device_id.to_string(),
        label: peer_label.clone(),
        verification_code,
        capabilities: caps,
        rostered,
    }));

    if auto_approve {
        send_local_approve(state, device_id).await;
    }
}

pub async fn on_approve(state: &Arc<NetworkState>, device_id: &str) {
    let (became_active, label) = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let mut data = peer.state.write();
        data.remote_approve_seen = true;
        // Guard the transition edge: a peer that re-sends Approve after
        // we're already ACTIVE shouldn't re-fire the on-active side
        // effects (roster persist, gossip, Approved event).
        let was_active = matches!(data.status, PeerStatus::Active);
        let active = data.local_approve_sent && data.remote_approve_seen;
        if active && !was_active {
            data.status = PeerStatus::Active;
            data.tier = ConnectionTier::Steady;
            // Successful Active reset: clear the no-TURN diagnostic
            // guards so a future failure cycle gets a fresh chance
            // to emit (and so the failure count doesn't carry over
            // from a previous bad spell).
            data.ice_failed_count = 0;
            data.no_turn_diag_emitted = false;
        }
        (active && !was_active, data.label.clone())
    };
    if became_active {
        // Both sides have now approved — the bilateral double handshake is
        // complete and the link is ACTIVE. THIS is the moment a peer
        // becomes a confirmed member, so persist them into the roster
        // (idempotent: the manual-approve path already added them; the
        // auto-approve path had not) and gossip the new membership so the
        // rest of the network converges. Without this an auto-approved
        // peer would reach ACTIVE but never be remembered, and no member
        // beyond the two endpoints would ever learn the peer exists —
        // exactly the "we keep losing our roster" symptom.
        if let Err(e) = state.approve_roster(device_id, &label).await {
            state.log_diag(
                crate::events::DiagLevel::Warn,
                "roster",
                format!(
                    "persist {} after mutual approve failed: {e}",
                    super::short_peer(device_id)
                ),
            );
        }
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "peer",
            format!("{} ACTIVE", super::short_peer(device_id)),
            serde_json::json!({ "peer": device_id }),
        );
        state.emit(MeshEvent::Peer(PeerEvent::Approved {
            network_id: state.network_id.clone(),
            device_id: device_id.to_string(),
            label,
        }));
        phase::recompute(state);
        super::ladder::reevaluate_topology(state).await;
        // Advertise both anti-entropy channels to the freshly-active link.
        // The roster summary carries only the *membership* root, which is blind
        // to role changes by design — so a peer that missed a promote/demote or
        // any other governance transition while offline wouldn't detect it from
        // the summary alone. Also emitting the governance snapshot (transition +
        // member-log counts) lets `on_state_broadcast` notice the divergence and
        // pull the log, so roles converge on reconnect, not just membership.
        super::governance::broadcast_roster_summary(state).await;
        super::governance::broadcast_state(state).await;
    }
}

pub async fn on_deny(state: &Arc<NetworkState>, device_id: &str, deny: DenyMessage) {
    state.log_diag_with(
        crate::events::DiagLevel::Warn,
        "auth",
        format!("peer denied us: {device_id} (reason: {:?})", deny.reason),
        serde_json::json!({ "peer": device_id, "reason": format!("{:?}", deny.reason) }),
    );
    super::drop_peer(state, device_id, DropReason::Denied).await;
}

/// Send the local approve frame for a peer. Called from the
/// auto-approve path and from the user-facing
/// [`crate::MeshHandle::approve_peer`] action.
pub async fn send_local_approve(state: &Arc<NetworkState>, device_id: &str) {
    let already = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let mut data = peer.state.write();
        if data.local_approve_sent {
            true
        } else {
            data.local_approve_sent = true;
            false
        }
    };
    if already {
        return;
    }
    if let Err(e) = send_to_peer(state, device_id, &MeshMessage::Approve(ApproveMessage {})).await {
        warn!(peer = %device_id, "send approve failed: {e}");
        // Un-latch: the frame never left. Leaving `local_approve_sent` true
        // here was a one-way trust wedge — every later call short-circuited
        // on "already sent", the peer never received our approve and sat in
        // PendingApproval refusing our app traffic, while *we* went Active
        // the moment their approve landed (the flag said we'd answered).
        // Roster-driven approves fire the instant a session exists, which
        // can be before its data channel opens ("DataChannel is not
        // opened") — with the flag reset, the handshake that starts when
        // the channel *does* open re-runs auto-approve and delivers it.
        if let Some(peer) = state.peers.get(device_id) {
            peer.state.write().local_approve_sent = false;
        }
        return;
    }
    // If the peer already sent us their approve, transitioning
    // happens via `on_approve`; otherwise we just wait.
    on_approve(state, device_id).await;
}
