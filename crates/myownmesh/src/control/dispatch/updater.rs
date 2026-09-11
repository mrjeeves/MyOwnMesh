//! The four updater operations.
//!
//! The updater crate hands out its own operation plan, so these do not take the
//! shared response owner for the two that read updater state:
//! `prepare_operation` reports what its own work will cost, the connection
//! admits exactly that, and the lease goes back into `run`. `apply` is the
//! exception — it answers with a plain outcome rather than an updater value,
//! so it uses the ordinary operation residual like every other operation.

use anyhow::{anyhow, Context, Result};

use super::{funded, Answer};
use crate::control::framing::FrameAdmission;
use crate::control::reply::{
    FundedVariableReply, OperationReplyData, PreparedReply, ResponseOwner,
};

/// Fund the line a finished updater reply encodes into.
fn lined(variable: FundedVariableReply, admission: &FrameAdmission, what: &str) -> Result<Answer> {
    funded(PreparedReply::Variable(variable), admission)
        .with_context(|| format!("updater {what} response line was not admitted"))
}

/// What the updater knows without going to the network.
pub(in crate::control) fn status(admission: &FrameAdmission) -> Result<Answer> {
    let plan = myownmesh_updater::prepare_operation();
    let lease = admission
        .acquire_claim(plan.claim())
        .context("updater status operation was not admitted")?;
    let funded = plan
        .run(lease, myownmesh_updater::status)
        .map_err(|_| anyhow!("updater operation lease did not match its plan"))?;
    lined(
        FundedVariableReply::updater_status(funded),
        admission,
        "status",
    )
}

/// Ask the update source what is available.
pub(in crate::control) async fn check(admission: &FrameAdmission) -> Result<Answer> {
    let plan = myownmesh_updater::prepare_operation();
    let lease = admission
        .acquire_claim(plan.claim())
        .context("updater check operation was not admitted")?;
    let funded = plan
        .run_async(lease, myownmesh_updater::check_now(true))
        .await
        .map_err(|_| anyhow!("updater operation lease did not match its plan"))?;
    lined(
        FundedVariableReply::updater_check(funded),
        admission,
        "check",
    )
}

/// Install what has already been staged.
pub(in crate::control) fn apply(admission: &FrameAdmission) -> Result<Answer> {
    let owner =
        ResponseOwner::acquire(admission).context("updater apply result was not admitted")?;
    let variable = owner.finish(match myownmesh_updater::apply_now() {
        Ok(applied) => Ok(OperationReplyData::Applied(applied)),
        Err(error) => Err(error.to_string()),
    });
    lined(variable, admission, "apply")
}

/// Replace the update preferences, refusing text that is not a preferences
/// object.
///
/// The parse happens inside the updater's own operation rather than before it,
/// so a malformed body is refused by the same funded path that would have
/// carried a real change.
pub(in crate::control) fn set_prefs(
    admission: &FrameAdmission,
    prefs: serde_json::Value,
) -> Result<Answer> {
    let plan = myownmesh_updater::prepare_operation();
    let lease = admission
        .acquire_claim(plan.claim())
        .context("updater preferences operation was not admitted")?;
    let funded = plan
        .run(lease, || {
            let prefs = serde_json::from_value::<myownmesh_updater::UpdatePrefs>(prefs).map_err(
                |error| myownmesh_updater::Error::Other(format!("bad update prefs: {error}")),
            )?;
            myownmesh_updater::set_prefs(prefs)
        })
        .map_err(|_| anyhow!("updater operation lease did not match its plan"))?;
    lined(
        FundedVariableReply::updater_status(funded),
        admission,
        "preferences",
    )
}
