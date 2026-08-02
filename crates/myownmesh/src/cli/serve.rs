//! `myownmesh serve`: run the daemon in the foreground.
//!
//! A thin wrapper over [`myownmesh::embedded`]: load the config, start the
//! daemon on this runtime, and hold it until SIGINT/SIGTERM asks for the
//! graceful teardown. Everything the daemon owns, including the mesh instance, the
//! network registry, hosted services, the updater tick, the control-socket
//! listener, lives in the library, so an embedder (an iOS app, which can't
//! spawn processes) runs the identical daemon in-process.

use std::num::NonZeroUsize;
use std::time::Duration;

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

    fn duration_ms(
        lookup: &mut impl FnMut(&str) -> Option<String>,
        name: &'static str,
    ) -> Result<Duration> {
        let raw = lookup(name).ok_or_else(|| {
            anyhow!("connector-capable serve requires owner-selected environment value {name}")
        })?;
        let millis = raw
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or_else(|| anyhow!("{name} must be a nonzero integer number of milliseconds"))?;
        Ok(Duration::from_millis(millis))
    }

    let process_candidates = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_PROCESS_MAX_CANDIDATES")?;
    let mesh_candidates = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_MESH_MAX_CANDIDATES")?;
    let control_capacity = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_CONTROL_CAPACITY")?;
    let endpoint_capacity = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_CAPACITY")?;
    let control_weight = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_CONTROL_WEIGHT")?;
    let endpoint_weight = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_WEIGHT")?;
    let realtime_weight = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_REALTIME_WEIGHT")?;
    let max_realtime_unit_bytes =
        nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_MAX_REALTIME_UNIT_BYTES")?;
    let realtime_deadline = duration_ms(
        &mut lookup,
        "MYOWNMESH_CONNECTOR_REALTIME_USEFUL_LIFETIME_MS",
    )?;
    let max_active_flows = nonzero(&mut lookup, "MYOWNMESH_CONNECTOR_REALTIME_MAX_ACTIVE_FLOWS")?;
    let queue_capacity_per_flow = nonzero(
        &mut lookup,
        "MYOWNMESH_CONNECTOR_REALTIME_QUEUE_CAPACITY_PER_FLOW",
    )?;
    let max_inbound_fragment_bytes = nonzero(
        &mut lookup,
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENT_BYTES",
    )?;
    let max_in_progress_units = nonzero(
        &mut lookup,
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_IN_PROGRESS_UNITS",
    )?;
    let max_retained_bytes = nonzero(
        &mut lookup,
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_RETAINED_BYTES",
    )?;
    let close_timeout = duration_ms(&mut lookup, "MYOWNMESH_CONNECTOR_NATIVE_CLOSE_TIMEOUT_MS")?;

    let callbacks = myownmesh_core::ConnectorCallbackPolicy::new(
        myownmesh_core::ConnectorCallbackMailboxCapacities::new(
            control_capacity,
            endpoint_capacity,
        ),
        myownmesh_core::ConnectorCallbackServiceWeights::new(
            control_weight,
            endpoint_weight,
            realtime_weight,
        ),
        max_realtime_unit_bytes,
        realtime_deadline,
    )?
    .with_realtime_flow_policy(myownmesh_core::ConnectorRealtimeFlowPolicy::new(
        max_active_flows,
        queue_capacity_per_flow,
        max_inbound_fragment_bytes,
        max_in_progress_units,
        max_retained_bytes,
    ));
    let process =
        myownmesh_core::ConnectorResourcePolicy::new(process_candidates, callbacks, close_timeout)
            .ok_or_else(|| anyhow!("connector native close timeout must be nonzero"))?;
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

    const POLICY_KEYS: [&str; 15] = [
        "MYOWNMESH_CONNECTOR_PROCESS_MAX_CANDIDATES",
        "MYOWNMESH_CONNECTOR_MESH_MAX_CANDIDATES",
        "MYOWNMESH_CONNECTOR_CONTROL_CAPACITY",
        "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_CAPACITY",
        "MYOWNMESH_CONNECTOR_CONTROL_WEIGHT",
        "MYOWNMESH_CONNECTOR_ENDPOINT_DATA_WEIGHT",
        "MYOWNMESH_CONNECTOR_REALTIME_WEIGHT",
        "MYOWNMESH_CONNECTOR_MAX_REALTIME_UNIT_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_USEFUL_LIFETIME_MS",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_ACTIVE_FLOWS",
        "MYOWNMESH_CONNECTOR_REALTIME_QUEUE_CAPACITY_PER_FLOW",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_INBOUND_FRAGMENT_BYTES",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_IN_PROGRESS_UNITS",
        "MYOWNMESH_CONNECTOR_REALTIME_MAX_RETAINED_BYTES",
        "MYOWNMESH_CONNECTOR_NATIVE_CLOSE_TIMEOUT_MS",
    ];

    fn fixture_values() -> HashMap<&'static str, String> {
        POLICY_KEYS
            .into_iter()
            .map(|key| (key, "1".to_string()))
            .collect()
    }

    #[test]
    fn connector_capable_serve_requires_every_owner_value() {
        let mut values = fixture_values();
        values.remove("MYOWNMESH_CONNECTOR_REALTIME_MAX_RETAINED_BYTES");
        let error = connector_policy_from_lookup(|name| values.get(name).cloned())
            .expect_err("an omitted owner value is rejected");
        assert!(error
            .to_string()
            .contains("MYOWNMESH_CONNECTOR_REALTIME_MAX_RETAINED_BYTES"));
    }

    #[test]
    fn connector_capable_serve_rejects_zero_instead_of_inventing_a_value() {
        let mut values = fixture_values();
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
        let values = fixture_values();
        let policy = connector_policy_from_lookup(|name| values.get(name).cloned())
            .expect("the complete explicit test vector is accepted");
        assert_eq!(policy.process().max_active_candidates().get(), 1);
        assert_eq!(policy.mesh().max_active_candidates().get(), 1);
        assert!(policy
            .process()
            .callbacks()
            .realtime_flow_policy()
            .is_some());
    }
}
