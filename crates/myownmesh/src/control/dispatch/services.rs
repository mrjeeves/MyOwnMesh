//! The device services config: validate it against the live runtime, persist
//! it, then reconcile what is running.
//!
//! Persist-before-reconcile is deliberate and is the reason this is its own
//! module rather than an arm: a daemon restart must re-apply the config the
//! caller was told was saved, even when the live reconcile only partly took.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use myownmesh_core::{MeshConfig, ServicesConfig};

use super::super::ControlState;
use super::{funded, refused_text, Answer};
use crate::control::framing::{prepare_typed_and_line_building, FrameAdmission};
use crate::control::reply::{
    FundedVariableReply, OperationReplyData, PreparedReply, ResponseOwner,
};

/// Replace the device services config: persist it, then reconcile the
/// running services. Persist first so a daemon restart re-applies the same
/// desired config even if live reconciliation partly fails. The persisted
/// value is restart intent, not proof that every requested service is running;
/// `apply` returns a reconciliation error for any unobserved transition.
pub(in crate::control) async fn services_set(
    state: &Arc<ControlState>,
    services: ServicesConfig,
    owner: ResponseOwner,
) -> FundedVariableReply {
    // Validate against the live daemon before persistence. In particular, an
    // infrastructure-only runtime must not save node participation as enabled
    // when it has no connector resource owner capable of admitting that state.
    if let Err(e) = state.services.validate_config_for_runtime(&services) {
        return owner.finish(Err(format!("services policy rejected: {e}")));
    }
    if let Err(e) = persist_services(&services) {
        return owner.finish(Err(format!("services config save failed: {e}")));
    }
    let status = match state.services.apply(services).await {
        Ok(status) => status,
        Err(e) => return owner.finish(Err(format!("services reconciliation failed: {e}"))),
    };
    owner.finish(Ok(OperationReplyData::ServicesStatus(status)))
}

fn persist_services(services: &ServicesConfig) -> Result<()> {
    MeshConfig::transaction(|cfg| {
        cfg.services = services.clone();
        Ok(())
    })
    .map_err(anyhow::Error::msg)
}

/// What the device services are doing right now.
pub(in crate::control) async fn status(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
) -> Result<Answer> {
    let source = state.services.status_source().await;
    let typed_claim = source
        .typed_claim()
        .context("services-status typed claim was not representable")?;
    let line_ceiling = source
        .line_ceiling()
        .context("services-status line ceiling was not representable")?;
    let (committed, output) =
        prepare_typed_and_line_building(typed_claim, line_ceiling, admission, |typed| {
            source.commit(typed)
        })
        .context("services-status typed snapshot or response line was not admitted")?;
    let committed =
        committed.map_err(|_| anyhow!("services-status typed claim changed before commit"))?;
    Ok((PreparedReply::ServicesStatus(committed), output))
}

/// Read the on-disk mesh config.
///
/// Three admissions, in the order the load actually spends them: the parse
/// work, what the loader holds while it parses, and the line the result
/// encodes into - the last measured from the committed config's own compact
/// width rather than a guess.
pub(in crate::control) fn config_show(admission: &FrameAdmission) -> Result<Answer> {
    let plan = match myownmesh_core::MeshConfig::prepare_load() {
        Ok(plan) => plan,
        Err(error) => return refused_text(error.to_string(), admission),
    };
    let work = admission
        .acquire_claim(plan.load_work_claim())
        .context("ConfigShow load work was not admitted")?;
    let loader_residual = admission
        .acquire_claim(plan.loader_residual_claim())
        .context("ConfigShow loader residual was not admitted")?;
    let config = match plan.commit(loader_residual, work) {
        Ok(config) => config,
        Err(error) => return refused_text(error.to_string(), admission),
    };
    // Measured over the loaded config itself, by the writer's single pass over
    // the sealed reply.
    funded(PreparedReply::Config(config), admission)
        .context("ConfigShow response line was not admitted")
}
