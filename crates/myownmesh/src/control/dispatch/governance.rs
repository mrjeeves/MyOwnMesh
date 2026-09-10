//! Governance control dispatch for the canonical semantic authority model.
//!
//! Durable authority is represented by verified `SignedFact` records in the
//! semantic `FactGraph`; this module only authorizes bounded control replies
//! and forwards typed authoring requests to the joined-network facade.
//!
//! Roster data is a read-only projection and never a source of membership or
//! role authority. Response ownership is acquired before any variable-size
//! result is traversed, encoded, or sealed.
//!

use std::sync::Arc;

use anyhow::{Context, Result};

use super::{funded, unknown_network, Answer};
use crate::control::framing::FrameAdmission;
use crate::control::reply::{
    governance_error_code, FundedDiagnostic, FundedVariableReply, OperationReplyData,
    PreparedReply, ResponseOwner,
};
use crate::control::ControlState;

/// What an operation says when the network is not joined.
///
/// Deliberately the operation reply's own error string rather than the shared
/// [`unknown_network`] refusal: these answer inside a result the caller is
/// already parsing as an operation outcome.
fn no_such_network(network: &str) -> String {
    format!("unknown network: {network}")
}

/// Take the right to answer, before the operation that will be answered.
fn operation_owner(admission: &FrameAdmission) -> Result<ResponseOwner> {
    ResponseOwner::acquire(admission)
        .context("governance/network operation result was not admitted")
}

/// Seal a finished operation result into the reply its owner funds, and fund
/// the line that reply encodes into.
fn answered(
    result: std::result::Result<OperationReplyData, String>,
    owner: ResponseOwner,
    admission: &FrameAdmission,
) -> Result<Answer> {
    funded(PreparedReply::Variable(owner.finish(result)), admission)
        .context("governance/network response line was not admitted")
}

fn governance_refusal(error: myownmesh_core::Error) -> OperationReplyData {
    OperationReplyData::GovernanceRefused {
        code: governance_error_code(&error).to_owned(),
        error: error.to_string(),
    }
}

fn governance_message(message: String, code: &'static str) -> OperationReplyData {
    OperationReplyData::GovernanceRefused {
        error: message,
        code: code.to_owned(),
    }
}

fn refused_governance(error: myownmesh_core::Error, admission: &FrameAdmission) -> Result<Answer> {
    answered(
        Ok(governance_refusal(error)),
        operation_owner(admission)?,
        admission,
    )
}

/// The authorized-device roster, measured before it is walked.
pub(in crate::control) async fn roster_list(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
) -> Result<Answer> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let owner = ResponseOwner::acquire(admission)
        .context("RosterList diagnostic report was not admitted")?;
    funded(
        PreparedReply::Roster(FundedDiagnostic::new(joined.roster_list().await?, owner)),
        admission,
    )
    .context("RosterList response line was not admitted")
}

/// Export the verified Closed bootstrap record without exposing engine state.
pub(in crate::control) fn bootstrap_export(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
) -> Result<Answer> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let owner =
        ResponseOwner::acquire(admission).context("Closed bootstrap response was not admitted")?;
    let bootstrap = joined
        .export_bootstrap_record()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    funded(
        PreparedReply::Bootstrap(FundedDiagnostic::new(bootstrap, owner)),
        admission,
    )
    .context("Closed bootstrap response line was not admitted")
}

/// Export one receive-safe, provider-funded semantic fact page.  The core
/// facade owns cursor, context, signature, and frame-bound validation; this
/// boundary only binds the result to the authenticated joined network and the
/// response owner that keeps its page lease alive through serialization.
pub(in crate::control) fn semantic_fact_page_export(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    request: myownmesh_core::semantic::SemanticFactPageRequest,
) -> Result<Answer> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let owner = ResponseOwner::acquire(admission)
        .context("semantic fact page response was not admitted")?;
    let page = joined
        .export_semantic_fact_page(request)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    funded(
        PreparedReply::SemanticFactPage(FundedDiagnostic::new(page, owner)),
        admission,
    )
    .context("semantic fact page response line was not admitted")
}

/// Import one bounded semantic fact page through the canonical reducer.  A
/// deserialized page has no in-process lease, so the core import path
/// reacquires its exact provider claim before admitting any facts.
pub(in crate::control) async fn semantic_fact_page_import(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    page: myownmesh_core::semantic::SemanticFactPage,
) -> Result<Answer> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let owner = ResponseOwner::acquire(admission)
        .context("semantic fact page import response was not admitted")?;
    let identity = joined
        .import_semantic_fact_page(page)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    funded(
        PreparedReply::SemanticStateIdentity(FundedDiagnostic::new(identity, owner)),
        admission,
    )
    .context("semantic fact page import response line was not admitted")
}

/// Inspect one deterministic semantic state identity for a joined network.
pub(in crate::control) fn semantic_state_identity(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
) -> Result<Answer> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let owner = ResponseOwner::acquire(admission)
        .context("semantic state identity response was not admitted")?;
    let identity = joined
        .semantic_state_identity()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    funded(
        PreparedReply::SemanticStateIdentity(FundedDiagnostic::new(identity, owner)),
        admission,
    )
    .context("semantic state identity response line was not admitted")
}

/// Render one bounded, non-canonical diagnostic view from the live cache.
pub(in crate::control) fn semantic_recent_facts(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    request: myownmesh_core::semantic::SemanticRecentFactsRequest,
) -> Result<Answer> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let owner = ResponseOwner::acquire(admission)
        .context("semantic recent-facts response was not admitted")?;
    let facts = joined
        .recent_semantic_facts(request)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    funded(
        PreparedReply::SemanticRecentFacts(FundedDiagnostic::new(facts, owner)),
        admission,
    )
    .context("semantic recent-facts response line was not admitted")
}

/// Set the local topology directly.
pub(in crate::control) async fn topology_set(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    topology: String,
    hub: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match super::network::parse_topology(&topology, hub.as_deref()) {
        Err(error) => Err(error),
        Ok(mode) => match state.registry.get(&network) {
            None => Err(no_such_network(&network)),
            Some(net) => net
                .set_topology(mode)
                .await
                .map(|_| OperationReplyData::Topology(topology))
                .map_err(|error| error.to_string()),
        },
    };
    answered(result, owner, admission)
}

/// Propose granting a role to a device.
pub(in crate::control) async fn propose_role_grant(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    target: String,
    role: myownmesh_core::semantic::Role,
    mfa_code: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => match net.propose_role_grant(&target, role, mfa_code).await {
            Ok(id) => Ok(OperationReplyData::ProposalId(id.to_string())),
            Err(error) => Ok(governance_refusal(error)),
        },
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Propose revoking a device's role.
pub(in crate::control) async fn propose_role_revoke(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    target: String,
    mfa_code: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => match net.propose_role_revoke(&target, mfa_code).await {
            Ok(id) => Ok(OperationReplyData::ProposalId(id.to_string())),
            Err(error) => Ok(governance_refusal(error)),
        },
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Propose evicting a device from the network.
pub(in crate::control) async fn propose_evict(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    target: String,
    mfa_code: Option<String>,
) -> Result<Answer> {
    let owner = operation_owner(admission)?;
    let result = match state.registry.get(&network) {
        Some(net) => match net.propose_evict(&target, mfa_code).await {
            Ok(id) => Ok(OperationReplyData::ProposalId(id.to_string())),
            Err(error) => Ok(governance_refusal(error)),
        },
        None => Err(no_such_network(&network)),
    };
    answered(result, owner, admission)
}

/// Prepare this device's local MFA custody transaction for one network.
///
/// The lock is installed before this answers, so a success response names an
/// Enrollment that already exists is recovered by its exact transaction
/// identity, and a second client preparing the same network observes the same
/// durable material rather than creating a successor.
///
/// The secret and recovery codes are returned from the exact Prepared record.
/// That record remains queryable and redeliverable until the exact transaction
/// commit or abort command settles it; neither response delivery nor a socket
/// write is a durable custody decision. The durable transaction remains
/// Prepared until an explicit Commit or Abort command.
pub(in crate::control) fn mfa_prepare(
    admission: &FrameAdmission,
    network: String,
) -> Result<Answer> {
    let owner =
        ResponseOwner::acquire(admission).context("MFA enrollment operation was not admitted")?;
    let (result, transaction_id) =
        match myownmesh_core::custody::prepare_or_recover_provisional_enroll(&network, &network) {
            Ok(myownmesh_core::custody::EnrollmentPreparation::Fresh(installed)) => (
                Ok(installed.enrolled().clone()),
                Some(installed.transaction_id().to_owned()),
            ),
            Ok(myownmesh_core::custody::EnrollmentPreparation::Existing(prepared)) => (
                Ok(prepared.enrolled().clone()),
                Some(prepared.transaction_id().to_owned()),
            ),
            Err(error) => (Err(error), None),
        };
    funded(
        PreparedReply::Variable(FundedVariableReply::mfa_enrollment(
            result,
            transaction_id,
            owner,
        )),
        admission,
    )
    .context("MFA enrollment response line was not admitted")
}

/// Query one exact transaction. A prepared record is deliberately not
/// consumed here; only the explicit Commit or Abort command changes its
/// durable state.
pub(in crate::control) fn mfa_query(
    admission: &FrameAdmission,
    network: String,
    transaction_id: String,
) -> Result<Answer> {
    let owner =
        ResponseOwner::acquire(admission).context("MFA transaction query was not admitted")?;
    let (state, material) =
        match myownmesh_core::custody::enrollment_transaction(&network, &transaction_id) {
            Ok(myownmesh_core::custody::EnrollmentTransaction::Prepared(prepared)) => {
                ("prepared", Some(prepared.enrolled().clone()))
            }
            Ok(myownmesh_core::custody::EnrollmentTransaction::Committed) => ("committed", None),
            Ok(myownmesh_core::custody::EnrollmentTransaction::Absent) => ("absent", None),
            Err(error) => return answered(Ok(governance_refusal(error)), owner, admission),
        };
    funded(
        PreparedReply::Variable(FundedVariableReply::mfa_transaction(
            network,
            transaction_id,
            state,
            material,
            owner,
        )),
        admission,
    )
}

/// Re-deliver only the exact prepared transaction named by the request.
pub(in crate::control) fn mfa_redeliver(
    admission: &FrameAdmission,
    network: String,
    transaction_id: String,
) -> Result<Answer> {
    let owner =
        ResponseOwner::acquire(admission).context("MFA transaction redelivery was not admitted")?;
    let prepared = match myownmesh_core::custody::enrollment_transaction(&network, &transaction_id)
    {
        Ok(myownmesh_core::custody::EnrollmentTransaction::Prepared(prepared)) => prepared,
        Ok(myownmesh_core::custody::EnrollmentTransaction::Committed) => {
            return answered(
                Ok(governance_message(
                    "MFA transaction is already committed".into(),
                    "mfa_state",
                )),
                owner,
                admission,
            );
        }
        Ok(myownmesh_core::custody::EnrollmentTransaction::Absent) => {
            return answered(
                Ok(governance_message(
                    "MFA transaction is absent".into(),
                    "mfa_state",
                )),
                owner,
                admission,
            );
        }
        Err(error) => return answered(Ok(governance_refusal(error)), owner, admission),
    };
    let result = Ok(prepared.enrolled().clone());
    funded(
        PreparedReply::Variable(FundedVariableReply::mfa_enrollment(
            result,
            Some(transaction_id),
            owner,
        )),
        admission,
    )
}

/// Apply one exact idempotent terminal operation and report the resulting
/// durable state. A stale transaction ID never reaches a successor.
pub(in crate::control) fn mfa_commit_or_abort(
    admission: &FrameAdmission,
    network: String,
    transaction_id: String,
    commit: bool,
) -> Result<Answer> {
    let owner =
        ResponseOwner::acquire(admission).context("MFA transaction settlement was not admitted")?;
    let settlement =
        match myownmesh_core::custody::enrollment_transaction(&network, &transaction_id) {
            Ok(myownmesh_core::custody::EnrollmentTransaction::Prepared(prepared)) => prepared
                .settle(if commit {
                    myownmesh_core::custody::EnrollmentSettlementRequest::Commit
                } else {
                    myownmesh_core::custody::EnrollmentSettlementRequest::Abort
                })
                .map(|result| match result {
                    myownmesh_core::custody::EnrollmentSettlementResult::Committed => "committed",
                    myownmesh_core::custody::EnrollmentSettlementResult::Absent => "absent",
                }),
            Ok(myownmesh_core::custody::EnrollmentTransaction::Committed) => Ok("committed"),
            Ok(myownmesh_core::custody::EnrollmentTransaction::Absent) => Ok("absent"),
            Err(error) => Err(error),
        };
    let state = match settlement {
        Ok(state) => state,
        Err(error) => return answered(Ok(governance_refusal(error)), owner, admission),
    };
    funded(
        PreparedReply::Variable(FundedVariableReply::mfa_transaction(
            network,
            transaction_id,
            state,
            None,
            owner,
        )),
        admission,
    )
}

/// Whether this device holds MFA custody for one network.
pub(in crate::control) fn mfa_status(
    admission: &FrameAdmission,
    network: String,
) -> Result<Answer> {
    funded(
        PreparedReply::Bool {
            key: "enrolled",
            value: myownmesh_core::custody::is_enrolled(&network),
        },
        admission,
    )
}

/// Surrender MFA custody, which requires presenting a current code.
pub(in crate::control) fn mfa_disable(
    admission: &FrameAdmission,
    network: String,
    code: String,
) -> Result<Answer> {
    match myownmesh_core::custody::disable(&network, &code) {
        Ok(()) => funded(
            PreparedReply::Bool {
                key: "disabled",
                value: true,
            },
            admission,
        ),
        Err(error) => refused_governance(error, admission),
    }
}
