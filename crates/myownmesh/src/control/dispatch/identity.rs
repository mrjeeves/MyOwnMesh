//! This device's identity, and the network ids it can mint or check.
//!
//! Nothing here touches a joined network. Identity is local state and the two
//! network-id operations are pure functions over text, which is why they sit
//! apart from the governance module that decides who is *in* a network.
//!
//! The network-id pair is the clearest case in the daemon of measuring before
//! producing: `prepare_*` walks the input and reports what the answer could
//! occupy, the typed retention and the exact line are admitted together, and
//! only then is the value committed. A refusal at any of those points releases
//! what the previous one took.

use std::sync::Arc;

use anyhow::{Context, Result};

use super::{funded, refused_text, Answer};
use crate::control::framing::FrameAdmission;
use crate::control::reply::{OperationReplyData, PreparedReply, ResponseOwner};
use crate::control::ControlState;

/// This device's identity as the control protocol reports it.
fn current(state: &Arc<ControlState>) -> OperationReplyData {
    OperationReplyData::Identity {
        device_id: state.mesh.identity().display_id(),
        pubkey: state.mesh.identity().public_id().to_owned(),
        label: state.mesh.identity().label().to_owned(),
    }
}

/// Seal an outcome into the identity reply and fund the line it encodes into.
fn answered(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    owner: ResponseOwner,
    outcome: std::result::Result<(), String>,
) -> Result<Answer> {
    funded(
        PreparedReply::Variable(owner.finish(outcome.map(|()| current(state)))),
        admission,
    )
}

/// Report this device's id, public key and label.
pub(in crate::control) fn show(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let owner = ResponseOwner::acquire(admission).context("identity response was not admitted")?;
    answered(state, admission, owner, Ok(()))
}

/// Rename this device, persisting the label before the in-memory identity
/// takes it.
///
/// The response owner is taken before the write: a rename that reaches disk
/// under a connection that cannot fund an answer still changes this device's
/// label, and the caller is told nothing.
pub(in crate::control) fn set_label(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    label: String,
) -> Result<Answer> {
    let owner = ResponseOwner::acquire(admission).context("identity response was not admitted")?;
    let outcome = match myownmesh_core::identity::set_label(&label) {
        Err(error) => Err(error.to_string()),
        Ok(()) => {
            state.mesh.identity().set_label(&label);
            Ok(())
        }
    };
    answered(state, admission, owner, outcome)
}

/// Mint a fresh network id.
///
/// The typed retention is admitted before the id is committed, because
/// committing is what allocates. The response line is then measured over the
/// committed id itself. Nothing outside this process has observed anything by
/// that point, so a refused line leaves nothing to undo.
pub(in crate::control) fn network_id_generate(admission: &FrameAdmission) -> Result<Answer> {
    let plan = match myownmesh_core::identity::prepare_generated_network_id() {
        Ok(plan) => plan,
        Err(error) => return refused_text(error.to_string(), admission),
    };
    let typed = admission
        .acquire_claim(plan.typed_retention_claim())
        .context("generated network id was not admitted")?;
    match plan.commit(typed) {
        Ok(network_id) => funded(PreparedReply::NetworkId(network_id), admission),
        Err(error) => refused_text(error.to_string(), admission),
    }
}

/// Check and canonicalise a network id the caller supplied.
pub(in crate::control) fn network_id_normalize(
    admission: &FrameAdmission,
    input: String,
) -> Result<Answer> {
    let plan = match myownmesh_core::identity::prepare_normalized_network_id(&input) {
        Ok(plan) => plan,
        Err(refusal) => return refused_text(refusal.to_string(), admission),
    };
    let typed = admission
        .acquire_claim(plan.typed_retention_claim())
        .context("normalized network id was not admitted")?;
    let network_id = match plan.commit(typed) {
        Ok(network_id) => network_id,
        Err(error) => return refused_text(error.to_string(), admission),
    };
    // The caller's text is held until here because the plan borrowed it; the
    // committed id is the only thing that outlives this point.
    drop(input);
    funded(PreparedReply::NetworkId(network_id), admission)
}
