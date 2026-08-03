//! `myownmesh serve`: run the daemon in the foreground.
//!
//! A thin wrapper over [`myownmesh::embedded`]: load the config, start the
//! daemon on this runtime, and hold it until SIGINT/SIGTERM asks for the
//! graceful teardown. Everything the daemon owns, including the mesh instance, the
//! network registry, hosted services, the updater tick, the control-socket
//! listener, lives in the library, so an embedder (an iOS app, which can't
//! spawn processes) runs the identical daemon in-process.

use std::num::NonZeroUsize;

use anyhow::{anyhow, Context, Result};

pub async fn run() -> Result<()> {
    let cfg = myownmesh_core::MeshConfig::load().context("load config")?;
    let daemon = if cfg.services.node.enabled {
        let policy = connector_policy_from_lookup(|name| std::env::var(name).ok())?;
        myownmesh::embedded::start_connector_capable(cfg, policy).await?
    } else {
        myownmesh::embedded::start_infrastructure_only(cfg).await?
    };

    // Wait for SIGINT (Ctrl-C) or SIGTERM.
    wait_for_shutdown_signal().await;
    tracing::info!("shutdown requested");
    daemon.shutdown().await;
    Ok(())
}

fn connector_policy_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<myownmesh_core::ConnectorCapableResourcePolicy> {
    fn nonzero(
        lookup: &mut impl FnMut(&str) -> Option<String>,
        name: &'static str,
    ) -> Result<NonZeroUsize> {
        let raw = lookup(name).ok_or_else(|| {
            anyhow!("connector-capable serve requires owner-selected environment value {name}")
        })?;
        raw.parse::<usize>()
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| anyhow!("{name} must be a nonzero integer"))
    }

    let process_candidates = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_PROCESS_MAX_CANDIDATES")?;
    let mesh_candidates = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_MESH_MAX_CANDIDATES")?;
    let pending_candidate_items =
        nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_ITEMS")?;
    let pending_candidate_bytes =
        nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_BYTES")?;
    let control_capacity = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_CONTROL_CAPACITY")?;
    let endpoint_capacity = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_CAPACITY")?;
    let control_weight = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_CONTROL_WEIGHT")?;
    let endpoint_weight = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_WEIGHT")?;
    let realtime_mode = lookup("MYOWNMESH_CONNECTOR_REALTIME_POLICY").ok_or_else(|| {
        anyhow!(
            "connector-capable serve requires owner-selected environment value MYOWNMESH_CONNECTOR_REALTIME_POLICY"
        )
    })?;
    let (service_weights, realtime) = match realtime_mode.trim().to_ascii_lowercase().as_str() {
        "disabled" => (
            myownmesh_core::ConnectorCallbackServiceWeights::data_only(
                control_weight,
                endpoint_weight,
            ),
            myownmesh_core::RealtimeConnectorPolicy::Disabled,
        ),
        "enabled" => {
            let realtime_weight = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_REALTIME_WEIGHT")?;
            let max_realtime_unit_bytes =
                nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_MAX_REALTIME_UNIT_BYTES")?;
            let max_inbound_flows = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FLOWS",
            )?;
            let max_outbound_flows = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_OUTBOUND_FLOWS",
            )?;
            let queue_capacity_per_flow = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_REALTIME_QUEUE_CAPACITY_PER_FLOW",
            )?;
            let max_inbound_fragment_bytes = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENT_BYTES",
            )?;
            let max_inbound_fragments_per_unit = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENTS_PER_UNIT",
            )?;
            let max_in_progress_units_per_flow = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_IN_PROGRESS_UNITS_PER_FLOW",
            )?;
            let max_inbound_accounted_bytes = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_ACCOUNTED_BYTES",
            )?;
            let max_outbound_accounted_bytes = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_OUTBOUND_ACCOUNTED_BYTES",
            )?;
            let max_total_accounted_bytes = nonzero(
                &mut lookup,
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_TOTAL_ACCOUNTED_BYTES",
            )?;
            let flows = myownmesh_core::ConnectorRealtimeFlowPolicy::new(
                myownmesh_core::ConnectorRealtimeFlowCapacities::new(
                    max_inbound_flows,
                    max_outbound_flows,
                    queue_capacity_per_flow,
                ),
                myownmesh_core::ConnectorRealtimeInboundLimits::new(
                    max_inbound_fragment_bytes,
                    max_inbound_fragments_per_unit,
                    max_in_progress_units_per_flow,
                ),
                myownmesh_core::ConnectorRealtimeByteBudgets::new(
                    max_inbound_accounted_bytes,
                    max_outbound_accounted_bytes,
                    max_total_accounted_bytes,
                ),
                myownmesh_core::RealtimeQueueOverflowRule::DropNewest,
            );
            (
                myownmesh_core::ConnectorCallbackServiceWeights::new(
                    control_weight,
                    endpoint_weight,
                    realtime_weight,
                ),
                myownmesh_core::RealtimeConnectorPolicy::enabled(max_realtime_unit_bytes, flows)?,
            )
        }
        _ => {
            return Err(anyhow!(
                "MYOWNMESH_CONNECTOR_REALTIME_POLICY must be disabled or enabled"
            ))
        }
    };

    let callbacks = myownmesh_core::ConnectorCallbackPolicy::new(
        myownmesh_core::ConnectorCallbackMailboxCapacities::new(
            control_capacity,
            endpoint_capacity,
        ),
        service_weights,
        realtime,
    )?;
    let process = myownmesh_core::ConnectorResourcePolicy::new(
        process_candidates,
        callbacks,
        myownmesh_core::PendingRemoteCandidatePolicy::new(
            pending_candidate_items,
            pending_candidate_bytes,
        ),
    );
    Ok(myownmesh_core::ConnectorCapableResourcePolicy::new(
        process,
        myownmesh_core::MeshConnectorResourcePolicy::new(mesh_candidates),
    ))
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = sigint.recv().await;
                return;
            }
        };
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const BASE_POLICY_KEYS: [&str; 9] = [
        "MYOWNMESH_CONNECTOR_PROCESS_MAX_CANDIDATES",
        "MYOWNMESH_CONNECTOR_MESH_MAX_CANDIDATES",
        "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_ITEMS",
        "MYOWNMESH_CONNECTOR_PENDING_CANDIDATE_BYTES",
        "MYOWNMESH_CONNECTOR_CONTROL_CAPACITY",
        "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_CAPACITY",
        "MYOWNMESH_CONNECTOR_CONTROL_WEIGHT",
        "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_WEIGHT",
        "MYOWNMESH_CONNECTOR_REALTIME_POLICY",
    ];

    const ENABLED_REALTIME_KEYS: [&str; 11] = [
        "MYOWNMESH_CONNECTOR_REALTIME_WEIGHT",
        "MYOWNMESH_CONNECTOR_MAX_REALTIME_UNIT_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FLOWS",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_OUTBOUND_FLOWS",
        "MYOWNMESH_CONNECTOR_REALTIME_QUEUE_CAPACITY_PER_FLOW",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENT_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENTS_PER_UNIT",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_IN_PROGRESS_UNITS_PER_FLOW",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_ACCOUNTED_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_OUTBOUND_ACCOUNTED_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_TOTAL_ACCOUNTED_BYTES",
    ];

    fn fixture_values(realtime: &str) -> HashMap<&'static str, String> {
        let mut values: HashMap<_, _> = BASE_POLICY_KEYS
            .into_iter()
            .map(|key| (key, "1".to_string()))
            .collect();
        values.insert("MYOWNMESH_CONNECTOR_REALTIME_POLICY", realtime.to_string());
        if realtime == "enabled" {
            values.extend(
                ENABLED_REALTIME_KEYS
                    .into_iter()
                    .map(|key| (key, "1".to_string())),
            );
            values.insert(
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_ACCOUNTED_BYTES",
                "2".to_string(),
            );
            values.insert(
                "MYOWNMESH_CONNECTOR_REALTIME_MAX_TOTAL_ACCOUNTED_BYTES",
                "3".to_string(),
            );
        }
        values
    }

    #[test]
    fn connector_capable_serve_requires_every_owner_value() {
        let mut values = fixture_values("enabled");
        values.remove("MYOWNMESH_CONNECTOR_REALTIME_MAX_TOTAL_ACCOUNTED_BYTES");
        let error = connector_policy_from_lookup(|name| values.get(name).cloned())
            .expect_err("an omitted owner value is rejected");
        assert!(error
            .to_string()
            .contains("MYOWNMESH_CONNECTOR_REALTIME_MAX_TOTAL_ACCOUNTED_BYTES"));
    }

    #[test]
    fn connector_capable_serve_rejects_zero_instead_of_inventing_a_value() {
        let mut values = fixture_values("disabled");
        values.insert(
            "MYOWNMESH_CONNECTOR_PROCESS_MAX_CANDIDATES",
            "0".to_string(),
        );
        let error = connector_policy_from_lookup(|name| values.get(name).cloned())
            .expect_err("zero cannot become a connector limit");
        assert!(error.to_string().contains("must be a nonzero integer"));
    }

    #[test]
    fn connector_capable_serve_builds_only_from_the_complete_owner_vector() {
        let values = fixture_values("enabled");
        let policy = connector_policy_from_lookup(|name| values.get(name).cloned())
            .expect("the complete explicit test vector is accepted");
        assert_eq!(policy.process().max_active_candidates().get(), 1);
        assert_eq!(policy.mesh().max_active_candidates().get(), 1);
        assert!(matches!(
            policy.process().callbacks().realtime(),
            myownmesh_core::RealtimeConnectorPolicy::Enabled(_)
        ));
    }

    #[test]
    fn data_only_connector_policy_requires_no_realtime_values() {
        let values = fixture_values("disabled");
        let policy = connector_policy_from_lookup(|name| values.get(name).cloned())
            .expect("an explicit data-only policy needs no real-time limits");
        assert!(matches!(
            policy.process().callbacks().realtime(),
            myownmesh_core::RealtimeConnectorPolicy::Disabled
        ));
    }
}
