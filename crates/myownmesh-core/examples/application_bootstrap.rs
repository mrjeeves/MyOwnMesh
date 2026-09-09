//! Production-facing embedding bootstrap.
//!
//! This example is intentionally default-feature compatible and does not
//! choose a capacity grant for the caller. An application supplies its own
//! reviewed [`WebRtcConnectorCapablePolicy`] and network configuration, then
//! retains the returned signaling drivers until shutdown.

use myownmesh_core::{
    engine::SignalingDrivers, ConnectorCallbackPolicy, Error, JoinedNetwork, Mesh, MeshConfig,
    MeshHandle, NetworkConfig, ResourceProviderPort, Result, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile, WebRtcConnectorProfileError, WebRtcRealtimeCodec,
    WebRtcRealtimeProfile, WebRtcRealtimeProfileError,
};

/// The live objects an embedding application must retain together.
pub struct RunningApplication {
    mesh: MeshHandle,
    network: JoinedNetwork,
    signaling: SignalingDrivers,
}

impl RunningApplication {
    /// Access the process-level mesh handle for identity, events, and reports.
    pub fn mesh(&self) -> &MeshHandle {
        &self.mesh
    }

    /// Access the joined network used by application channels and RPC.
    pub fn network(&self) -> &JoinedNetwork {
        &self.network
    }

    /// Stop signaling before the joined-network driver, then await both.
    pub async fn shutdown(self) -> Result<()> {
        self.signaling.shutdown().await;
        self.network.shutdown().await
    }
}

/// Open one production mesh runtime from caller-owned policy and configuration.
///
/// The policy must be funded by the embedding application's finite resource
/// provider; this function deliberately does not invent a grant or a codec
/// profile. `NetworkConfig::signaling` selects the configured carrier, while
/// `turn_servers` remains the endpoint ICE fallback rather than an application
/// relay. The returned signaling owner must stay alive until [`RunningApplication::shutdown`].
pub async fn start(
    mesh_config: MeshConfig,
    connector_policy: WebRtcConnectorCapablePolicy,
    network_config: NetworkConfig,
) -> Result<RunningApplication> {
    let mesh = Mesh::open_connector_capable(mesh_config, connector_policy).await?;
    let network = mesh.join(network_config).await?;
    let signaling = match network.attach_signaling() {
        Ok(Some(drivers)) => drivers,
        Ok(None) => {
            return Err(cleanup_after_attach_failure(
                network,
                Error::Network("configured signaling receiver was already attached".into()),
            )
            .await);
        }
        Err(error) => {
            return Err(cleanup_after_attach_failure(network, error).await);
        }
    };

    Ok(RunningApplication {
        mesh,
        network,
        signaling,
    })
}

async fn cleanup_after_attach_failure(network: JoinedNetwork, error: Error) -> Error {
    match network.shutdown().await {
        Ok(()) => error,
        Err(cleanup) => Error::Other(format!("{error}; network cleanup also failed: {cleanup}")),
    }
}

/// Build the real-time-enabled connector profile before opening any Mesh.
///
/// The codec profile is validated by the caller-facing `WebRtcRealtimeProfile`
/// constructor; this function only selects the elastic real-time callback
/// policy and attaches that caller-supplied profile. Capacity still comes from
/// the separately supplied provider port.
pub fn realtime_connector_policy(
    resources: ResourceProviderPort,
    profile: WebRtcRealtimeProfile,
) -> std::result::Result<WebRtcConnectorCapablePolicy, WebRtcConnectorProfileError> {
    let connector = WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_realtime())
        .with_realtime_profile(profile)?;
    Ok(WebRtcConnectorCapablePolicy::new(resources, connector))
}

/// Validate the caller's codec registrations before any peer connection is
/// created. No built-in codec list or capacity default is supplied.
pub fn validate_realtime_profile(
    codecs: Vec<WebRtcRealtimeCodec>,
) -> std::result::Result<WebRtcRealtimeProfile, WebRtcRealtimeProfileError> {
    WebRtcRealtimeProfile::new(codecs)
}

fn main() {
    println!("application_bootstrap exposes start(mesh_config, connector_policy, network_config);");
    println!(
        "the embedding application supplies the finite provider grant and runs the Tokio runtime"
    );
}
