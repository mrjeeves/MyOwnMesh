//! `myownmesh serve`: run the daemon in the foreground.
//!
//! A thin wrapper over [`myownmesh::embedded`]: load the config, start the
//! daemon on this runtime, and hold it until SIGINT/SIGTERM asks for the
//! graceful teardown. Everything the daemon owns, including the mesh instance, the
//! network registry, hosted services, the updater tick, the control-socket
//! listener, lives in the library, so an embedder (an iOS app, which can't
//! spawn processes) runs the identical daemon in-process.

use anyhow::{anyhow, Context, Result};

/// Run the daemon in the foreground.
///
/// There is one way to start, and that is the point: no CLI flag selects a
/// deployment variant, so there is no authority a flag can install and no
/// branch here to take by mistake. What the daemon can do is decided by the
/// owner's configuration and environment, which this reads once.
pub async fn run() -> Result<()> {
    let cfg = myownmesh_core::MeshConfig::load().context("load config")?;
    let daemon = if cfg.services.node.enabled {
        let ConnectorStartup { policy, realtime } =
            connector_policy_from_lookup(|name| std::env::var(name).ok())?;
        myownmesh::embedded::start_connector_capable(cfg, policy, realtime).await?
    } else {
        // Same parse, same variables, same refusals as the connector-capable
        // branch above — the mode selects what is installed on top of the
        // grant, never whether the owner had to choose one.
        let resources = owner_selected_resource_port(|name| std::env::var(name).ok())?;
        myownmesh::embedded::start_infrastructure_only(cfg, resources).await?
    };

    // Two ways this process stops serving, and neither is a duration. The host
    // signal is the operator's; the runtime request is the daemon's own, raised
    // by a reset that has already removed the state it was running on. Either
    // way the drain below is the same one — the same `shutdown` an embedder
    // calls, reached here through a select because this deployment also has a
    // signal to answer, and through `run_until_shutdown` where it does not.
    //
    // No subscription is taken first. The request is a latched state, so one
    // submitted while this process was still starting — the control socket is
    // accepting before `start_*` returns — resolves here rather than being a
    // wake nobody was listening for.
    tokio::select! {
        () = wait_for_shutdown_signal() => tracing::info!("shutdown requested"),
        () = daemon.supervisor().wait_requested() => {
            tracing::info!("daemon runtime requested shutdown — returning so the service supervisor can start a fresh instance");
        }
    }
    daemon
        .shutdown()
        .await
        .map_err(|error| anyhow!("daemon shutdown failed: {error}"))?;
    Ok(())
}

// The types below are the *configuration* shape — what the application writes
// in `MYOWNMESH_REALTIME_PROFILE`, with `deny_unknown_fields` so a misspelled
// key is a startup error rather than a silently missing codec. They are parsed
// here and converted straight into `myownmesh_core`'s registration types; the
// daemon holds no realtime profile of its own and interprets none of the
// values it carries.
//
// The split is not duplication for its own sake. Core's constructor refuses the
// same malformations, but it sees a `Vec<RealtimeCodec>` and can only describe
// the shape of the problem; parsing here is what lets the error name the
// configuration that caused it. Both refusals are kept for that reason.

/// One RTCP feedback message to register alongside a codec.
///
/// The two SDP fields, carried as plain strings. The daemon does not interpret
/// either; it passes them through to registration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealtimeRtcpFeedback {
    /// e.g. `nack`, `ccm`, `goog-remb`. Core calls this `mechanism`; the
    /// configuration key stays `kind` because that is the SDP spelling
    /// applications already write.
    pub kind: String,
    /// e.g. `pli`, `fir`, or empty.
    #[serde(default)]
    pub parameter: String,
}

/// The RTP media kind a codec registers under, as configured.
///
/// Supplied, never inferred from `mime`: which transceiver a codec occupies is
/// a connector decision, and deriving it by matching on `video/` would be the
/// same hardcoded branch the profile exists to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeKind {
    Audio,
    Video,
}

/// How the connector turns a codec's RTP into units, as configured.
///
/// Chosen by the application per codec, never selected by core from a MIME
/// name — picking this by codec name is the same hardcoded branch the profile
/// exists to remove, one layer down. A codec whose framing is not stated cannot
/// be registered, because there is no correct default: choosing wrong produces
/// a stream that negotiates and then decodes to nothing.
///
/// Stated per registration tuple, but it is the *encoding family* that has to
/// agree — a flow names a family and negotiation picks which of that family's
/// tuples is used, so a family whose tuples disagreed would have no determinate
/// answer at open time. Both [`realtime_profile_from_lookup`] and core's
/// constructor refuse such a profile.
///
/// These are two structurally different treatments, not two interchangeable
/// adapters. `AnnexB` reassembles RTP into an access unit and then splits it at
/// start codes; `Whole` does no reassembly at all, because one payload is
/// already one unit. Opus needs `Whole` specifically: reassembly completes a
/// unit on the RTP marker bit, and Opus sets the marker only on the first packet
/// of a talkspurt, so reassembling it would emit that packet and drop the rest
/// of the speech — silent as an error, obvious as broken audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeFraming {
    /// Reassemble, then split at start codes. What current H.264 video needs.
    AnnexB,
    /// One payload is one unit, carried as-is with no reassembly state. What
    /// Opus needs, and the right answer for any codec whose units already
    /// arrive one per packet.
    Whole,
}

impl RealtimeKind {
    fn to_core(self) -> myownmesh_core::WebRtcRtpKind {
        use myownmesh_core::WebRtcRtpKind;
        match self {
            Self::Audio => WebRtcRtpKind::Audio,
            Self::Video => WebRtcRtpKind::Video,
        }
    }
}

impl RealtimeFraming {
    fn to_core(self) -> myownmesh_core::WebRtcRealtimeFraming {
        match self {
            Self::AnnexB => myownmesh_core::WebRtcRealtimeFraming::AnnexB,
            Self::Whole => myownmesh_core::WebRtcRealtimeFraming::Whole,
        }
    }
}

/// One complete codec registration, exactly as the application supplies it.
///
/// Everything the connector needs to register a capability and to frame units
/// for it is stated here, so core registers and frames what it is given rather
/// than deriving values from a MIME name. That is the point: a profile that
/// carried only `mime` would force core to know that `video/H264` implies
/// 90 kHz, which fmtp lines are acceptable, and Annex-B framing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealtimeCodec {
    /// Which transceiver this codec occupies. See [`RealtimeKind`].
    pub kind: RealtimeKind,
    pub payload_type: u8,
    pub mime: String,
    pub clock_rate: u32,
    /// 0 for video; 2 for stereo Opus.
    #[serde(default)]
    pub channels: u16,
    /// The SDP `a=fmtp` parameter line, verbatim.
    #[serde(default)]
    pub fmtp: String,
    #[serde(default)]
    pub rtcp_feedback: Vec<RealtimeRtcpFeedback>,
    /// Required, with no default: see [`RealtimeFraming`].
    pub framing: RealtimeFraming,
}

/// The application-supplied realtime profile, read once at daemon start.
///
/// Registration happens before any `PeerConnection` exists, so this is read
/// and validated at startup rather than per flow. Every tuple listed here is
/// registered on the `MediaEngine`; a per-flow encoding then names an encoding
/// *family* among them, and SDP negotiation picks which tuple of that family is
/// actually used. Deployed H.264 is five payload/fmtp variants sharing one
/// mime, clock rate and channel count, so a flow that had to name one exact
/// tuple could not be opened against a peer that chose a different variant. A
/// flow never introduces a codec that was not registered here.
///
/// The profile says which encodings this application can carry, and nothing
/// about how many flows may exist at once: concurrency is the owner's resource
/// envelope to state and the connector's to enforce.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealtimeProfile {
    pub codecs: Vec<RealtimeCodec>,
}

/// Parse and validate the application-supplied realtime profile.
///
/// Refuses rather than defaulting: a daemon that guessed a codec set would
/// advertise capabilities the application cannot actually produce, and the
/// failure would surface as a negotiated-but-dead track rather than a startup
/// error.
fn realtime_profile_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<RealtimeProfile> {
    const VAR: &str = "MYOWNMESH_REALTIME_PROFILE";
    let raw = lookup(VAR).ok_or_else(|| {
        anyhow!("realtime media requires the application-supplied profile in {VAR}")
    })?;
    let profile: RealtimeProfile = serde_json::from_str(&raw)
        .map_err(|error| anyhow!("{VAR} is not a valid realtime profile: {error}"))?;

    if profile.codecs.is_empty() {
        return Err(anyhow!("{VAR} registers no codecs"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut families: std::collections::HashMap<(String, u32, u16), RealtimeFraming> =
        std::collections::HashMap::new();
    for codec in &profile.codecs {
        if codec.mime.trim().is_empty() {
            return Err(anyhow!("{VAR} has a codec with an empty mime"));
        }
        if codec.clock_rate == 0 {
            return Err(anyhow!(
                "{VAR} codec {} has a zero clock_rate; it is what makes a flow's \
                 timestamp interpretable",
                codec.mime
            ));
        }
        // A duplicate payload type is the one malformation that would not fail
        // loudly at registration: the second tuple silently replaces the first,
        // and the loss only shows up as a codec that negotiates and then
        // carries nothing.
        if !seen.insert(codec.payload_type) {
            return Err(anyhow!(
                "{VAR} reuses payload_type {} across codecs",
                codec.payload_type
            ));
        }
        // Several tuples per family is expected and correct — deployed H.264 is
        // five payload/fmtp variants — but a flow names the family and
        // negotiation picks the variant, so the family is what has to fix the
        // framer. Disagreement here has no answer at open time.
        let family = (
            codec.mime.trim().to_ascii_lowercase(),
            codec.clock_rate,
            codec.channels,
        );
        match families.insert(family, codec.framing) {
            Some(prior) if prior != codec.framing => {
                return Err(anyhow!(
                    "{VAR} gives codec family {} two framings; a flow selects the \
                     family, not one payload type, so its treatment would be \
                     undetermined",
                    codec.mime
                ));
            }
            _ => {}
        }
    }
    Ok(profile)
}

/// Convert the parsed configuration into core's registration profile.
///
/// Core's constructor validates again and is the only way to make one. Its
/// refusals should be unreachable from here — everything it checks, the parse
/// above has already checked against the configuration text — so a failure is
/// reported as what it is: a disagreement between the two, not a user error.
fn realtime_profile_into_core(
    profile: RealtimeProfile,
) -> Result<myownmesh_core::WebRtcRealtimeProfile> {
    let codecs = profile
        .codecs
        .into_iter()
        .map(|codec| myownmesh_core::WebRtcRealtimeCodec {
            kind: codec.kind.to_core(),
            payload_type: codec.payload_type,
            mime: codec.mime,
            clock_rate: codec.clock_rate,
            channels: codec.channels,
            fmtp: codec.fmtp,
            framing: codec.framing.to_core(),
            rtcp_feedback: codec
                .rtcp_feedback
                .into_iter()
                .map(|fb| myownmesh_core::WebRtcRealtimeRtcpFeedback {
                    mechanism: fb.kind,
                    parameter: fb.parameter,
                })
                .collect(),
        })
        .collect();
    myownmesh_core::WebRtcRealtimeProfile::new(codecs).map_err(|error| {
        anyhow!(
            "realtime profile was accepted by the daemon and refused by the \
             connector ({error}); the two validations have drifted apart"
        )
    })
}

/// The connector policy plus what the control socket publishes alongside it.
///
/// They travel together because they have one origin: `realtime` describes the
/// profile that was actually registered on `policy`. Rebuilding the advert from
/// configuration a second time somewhere else is exactly how the two would
/// drift into a daemon advertising encodings it never registered.
struct ConnectorStartup {
    policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    realtime: myownmesh::control::RealtimeAdvert,
}

/// The one owner-selected process resource grant, parsed identically for every
/// serve mode.
///
/// This is the process resource grant, not a local policy ceiling. It is the
/// envelope every byte, handle and task this daemon owns is funded from, so
/// there is deliberately no default and nothing derived from the machine: an
/// owner who has not selected one has not said how much of their system this
/// daemon may take, and starting anyway would answer that on their behalf.
///
/// Both serve modes call this. Infrastructure-only is not a lesser case that
/// may guess — it still admits IPC payloads, local application state and its
/// own tasks — so the two modes cannot drift into reading different variables,
/// or into accepting a value for one that the other would reject.
fn owner_selected_resource_port(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<myownmesh_core::ResourceProviderPort> {
    /// The configuration spelling of one dimension, paired with the dimension.
    ///
    /// Written out rather than derived from the `Debug` name: the wire spelling
    /// of an operator-facing key is a contract, and deriving it would let a
    /// rename inside core silently invalidate every deployment's configuration.
    const DIMENSIONS: [(&str, myownmesh_core::ResourceClass); 11] = [
        (
            "accounted_memory_bytes",
            myownmesh_core::ResourceClass::AccountedMemoryBytes,
        ),
        ("queued_bytes", myownmesh_core::ResourceClass::QueuedBytes),
        (
            "socket_or_handle",
            myownmesh_core::ResourceClass::SocketOrHandle,
        ),
        (
            "native_transport_object",
            myownmesh_core::ResourceClass::NativeTransportObject,
        ),
        (
            "worker_or_task",
            myownmesh_core::ResourceClass::WorkerOrTask,
        ),
        (
            "callback_or_scheduled_work",
            myownmesh_core::ResourceClass::CallbackOrScheduledWork,
        ),
        ("storage_bytes", myownmesh_core::ResourceClass::StorageBytes),
        (
            "storage_object",
            myownmesh_core::ResourceClass::StorageObject,
        ),
        (
            "relay_or_provider_allocation",
            myownmesh_core::ResourceClass::RelayOrProviderAllocation,
        ),
        (
            "parsing_or_cpu_work",
            myownmesh_core::ResourceClass::ParsingOrCpuWork,
        ),
        (
            "opaque_dependency_residual",
            myownmesh_core::ResourceClass::OpaqueDependencyResidual,
        ),
    ];

    const NAME: &str = "MYOWNMESH_RESOURCE_GRANT";

    let raw = lookup(NAME).ok_or_else(|| {
        anyhow!(
            "serve requires owner-selected environment value {NAME}, a comma-separated \
             list of `dimension=value` naming every one of the {} dimensions",
            DIMENSIONS.len()
        )
    })?;

    let mut amounts: [Option<u64>; 11] = [None; 11];
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(anyhow!("{NAME} contains an empty entry"));
        }
        let (name, value) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("{NAME} entry `{entry}` is not `dimension=value`"))?;
        let name = name.trim();
        let index = DIMENSIONS
            .iter()
            .position(|(spelling, _)| *spelling == name)
            .ok_or_else(|| anyhow!("{NAME} names unknown dimension `{name}`"))?;
        if amounts[index].is_some() {
            return Err(anyhow!("{NAME} names dimension `{name}` more than once"));
        }
        // Parsed as `u64` and nothing wider: an amount this type cannot hold is
        // refused here rather than saturating into a grant the owner did not
        // choose.
        let amount = value.trim().parse::<u64>().map_err(|_| {
            anyhow!("{NAME} dimension `{name}` must be a finite nonnegative integer")
        })?;
        amounts[index] = Some(amount);
    }

    // Every dimension, explicitly, including a deliberate zero. A grant that
    // omitted one would be this daemon deciding how much of that resource the
    // owner meant to give it, which is the decision this variable exists to
    // take away from us.
    let mut entries = [(myownmesh_core::ResourceClass::AccountedMemoryBytes, 0u64); 11];
    for (slot, ((name, dimension), amount)) in
        entries.iter_mut().zip(DIMENSIONS.into_iter().zip(amounts))
    {
        let amount = amount.ok_or_else(|| anyhow!("{NAME} does not name dimension `{name}`"))?;
        *slot = (dimension, amount);
    }

    let provider_grant = myownmesh_core::ResourceClaim::try_from_entries(entries)?;
    let resources = myownmesh_core::ResourceProviderPort::new(
        myownmesh_core::FiniteResourceProvider::new(provider_grant),
    )?;
    Ok(resources)
}

fn connector_policy_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<ConnectorStartup> {
    let resources = owner_selected_resource_port(&mut lookup)?;
    let realtime_mode = lookup("MYOWNMESH_CONNECTOR_REALTIME_POLICY").ok_or_else(|| {
        anyhow!(
            "connector-capable serve requires owner-selected environment value MYOWNMESH_CONNECTOR_REALTIME_POLICY"
        )
    })?;
    let realtime_enabled = match realtime_mode.trim().to_ascii_lowercase().as_str() {
        "disabled" => false,
        "enabled" => true,
        _ => {
            return Err(anyhow!(
                "MYOWNMESH_CONNECTOR_REALTIME_POLICY must be disabled or enabled"
            ))
        }
    };
    // One connector shape: elastic, funded by the owner-selected provider. What
    // bounds this daemon is that provider's finite grant, not a second set of
    // locally configured counts beside it. The daemon therefore publishes no
    // flow ceiling, because there is nothing it could publish that anything
    // would enforce.
    let callbacks = if realtime_enabled {
        myownmesh_core::ConnectorCallbackPolicy::elastic_realtime()
    } else {
        myownmesh_core::ConnectorCallbackPolicy::elastic_data_only()
    };
    // Codec registration happens here, before any `PeerConnection` exists, and
    // wherever the connector can carry flows at all — which is exactly where
    // realtime is enabled. The advert names the encodings.
    let realtime_registration = if realtime_enabled {
        let parsed = realtime_profile_from_lookup(&mut lookup)?;
        let advert = realtime_advert_for(&parsed);
        Some((realtime_profile_into_core(parsed)?, advert))
    } else {
        // Refused, not ignored. A profile supplied to a daemon that cannot
        // register it would otherwise be read as configured-and-working right
        // up until the first flow open, which is the expensive place to find
        // out no codec was ever registered.
        if lookup("MYOWNMESH_REALTIME_PROFILE").is_some() {
            return Err(anyhow!(
                "MYOWNMESH_REALTIME_PROFILE was supplied but this daemon cannot register \
                 it: realtime codec registration requires \
                 MYOWNMESH_CONNECTOR_REALTIME_POLICY=enabled"
            ));
        }
        None
    };

    let webrtc = myownmesh_core::WebRtcConnectorProfile::new(callbacks);
    let (webrtc, realtime) = match realtime_registration {
        Some((profile, advert)) => (webrtc.with_realtime_profile(profile)?, advert),
        // Honestly unsupported: no codecs registered, so no flow can be carried,
        // and the status says exactly that rather than naming an encoding or a
        // capacity a caller could plan against.
        None => (webrtc, myownmesh::control::RealtimeAdvert::unsupported()),
    };
    Ok(ConnectorStartup {
        policy: myownmesh_core::WebRtcConnectorCapablePolicy::new(resources, webrtc),
        realtime,
    })
}

/// Describe a parsed profile for clients: its encoding families, and the
/// ceiling the owner stated if the owner stated one.
///
/// Deduplicated on `(kind, mime, clock_rate, channels)` — the four fields that
/// identify a family — because that is what a flow open selects. Deployed
/// H.264 is several payload/fmtp variants sharing all four, and publishing them
/// separately would present one negotiation choice as several caller choices.
/// Case is folded on `mime` for the same reason the startup validation folds
/// it: `video/H264` and `video/h264` are one family, and listing both would
/// invite a client to treat them as two.
fn realtime_advert_for(profile: &RealtimeProfile) -> myownmesh::control::RealtimeAdvert {
    let mut seen = std::collections::HashSet::new();
    let encodings = profile
        .codecs
        .iter()
        .filter(|codec| {
            seen.insert((
                codec.kind,
                codec.mime.trim().to_ascii_lowercase(),
                codec.clock_rate,
                codec.channels,
            ))
        })
        .map(|codec| myownmesh::control::RealtimeEncoding {
            kind: match codec.kind {
                RealtimeKind::Audio => "audio".to_string(),
                RealtimeKind::Video => "video".to_string(),
            },
            mime: codec.mime.trim().to_string(),
            clock_rate: codec.clock_rate,
            channels: codec.channels,
        })
        .collect();
    myownmesh::control::RealtimeAdvert::registered(encodings)
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

    /// A complete grant naming every dimension, which is the only accepted
    /// shape. Written out rather than generated from `DIMENSIONS`, so a
    /// spelling change in the parser has to be made here too and cannot pass
    /// by agreeing with itself.
    const COMPLETE_GRANT: &str = "accounted_memory_bytes=1,queued_bytes=1,\
         socket_or_handle=1,native_transport_object=1,worker_or_task=1,\
         callback_or_scheduled_work=1,storage_bytes=1,storage_object=1,\
         relay_or_provider_allocation=1,parsing_or_cpu_work=1,\
         opaque_dependency_residual=1";

    /// The application-supplied profile half of the complete explicit vector.
    ///
    /// Two codecs with different framings, because that is the deployed shape
    /// and because a one-codec profile would not exercise the per-family
    /// framing check at all. It states no capacity: how many flows may exist at
    /// once is the owner's envelope to say, and this is the application's half
    /// of the vector.
    const REALTIME_PROFILE_FIXTURE: &str = r#"{
        "codecs": [
            {
                "kind": "video", "payload_type": 96, "mime": "video/H264",
                "clock_rate": 90000, "framing": "annex_b"
            },
            {
                "kind": "audio", "payload_type": 111, "mime": "audio/opus",
                "clock_rate": 48000, "channels": 2, "framing": "whole"
            }
        ]
    }"#;

    fn fixture_values(realtime: &str) -> HashMap<&'static str, String> {
        let mut values = HashMap::new();
        values.insert("MYOWNMESH_RESOURCE_GRANT", COMPLETE_GRANT.to_string());
        values.insert("MYOWNMESH_CONNECTOR_REALTIME_POLICY", realtime.to_string());
        // The profile is added under exactly the condition that makes it
        // required, which is the same condition `connector_policy_from_lookup`
        // uses to register it. Supplying it to a realtime-disabled daemon is a
        // startup error there, not a harmless extra, so a fixture that always
        // set it would make the other vectors invalid rather than complete.
        if realtime == "enabled" {
            values.insert(
                "MYOWNMESH_REALTIME_PROFILE",
                REALTIME_PROFILE_FIXTURE.to_string(),
            );
        }
        values
    }

    /// Every way a grant can be wrong is refused, and the message names the
    /// dimension at fault.
    ///
    /// One control rather than five, because they are one property: the grant
    /// is the owner's statement of how much of their system this daemon may
    /// take, and anything short of an exact statement has to be refused rather
    /// than completed on their behalf. The five cases are the five ways a
    /// string can fail to be that statement.
    #[test]
    fn connector_capable_serve_requires_every_provider_dimension() {
        // `.err().expect(..)` rather than `.expect_err(..)`: the latter formats
        // the Ok value on failure and so would require `Debug` on
        // `ConnectorStartup`, which carries the live connector policy. Deriving
        // it to satisfy a test would put the whole policy — resource grants,
        // capacities, the registered codec set — one `{:?}` away from any log
        // line, to improve a message that only prints when this test fails.
        let refused = |grant: &str| -> String {
            let mut values = fixture_values("disabled");
            values.insert("MYOWNMESH_RESOURCE_GRANT", grant.to_string());
            connector_policy_from_lookup(|name| values.get(name).cloned())
                .err()
                .expect("an incomplete or malformed grant is rejected")
                .to_string()
        };

        // Missing: the complete grant with one dimension dropped.
        let without_native = COMPLETE_GRANT.replace("native_transport_object=1,", "");
        assert!(
            without_native != COMPLETE_GRANT,
            "non-vacuity: the fixture grant really did name that dimension"
        );
        assert!(refused(&without_native).contains("native_transport_object"));

        // Unknown, duplicate, malformed, and unrepresentable.
        assert!(refused(&format!("{COMPLETE_GRANT},invented_dimension=1"))
            .contains("invented_dimension"));
        assert!(refused(&format!("{COMPLETE_GRANT},queued_bytes=2")).contains("queued_bytes"));
        assert!(refused(&format!("{COMPLETE_GRANT},worker_or_task")).contains("worker_or_task"));
        let overflowing = COMPLETE_GRANT.replace(
            "accounted_memory_bytes=1",
            "accounted_memory_bytes=18446744073709551616",
        );
        assert!(refused(&overflowing).contains("accounted_memory_bytes"));

        // Non-vacuity for all five: the unmodified grant is accepted.
        let values = fixture_values("disabled");
        assert!(
            connector_policy_from_lookup(|name| values.get(name).cloned()).is_ok(),
            "the complete grant this control mutates must itself be accepted"
        );
    }

    /// Several payload types in one family are advertised once.
    ///
    /// Deployed H.264 is five payload/fmtp variants sharing kind, mime, clock
    /// rate and channel count. A flow open names the family and negotiation
    /// picks the variant, so listing the variants separately would present one
    /// negotiation outcome as five caller choices — and a caller that picked
    /// one would be naming something it does not get to decide.
    #[test]
    fn one_encoding_family_is_advertised_once_however_many_payload_types_it_has() {
        let family = |payload_type: u8, fmtp: &str| RealtimeCodec {
            kind: RealtimeKind::Video,
            payload_type,
            // Case differs deliberately: the same family, spelled two ways.
            mime: if payload_type % 2 == 0 {
                "video/H264".to_string()
            } else {
                "video/h264".to_string()
            },
            clock_rate: 90000,
            channels: 0,
            fmtp: fmtp.to_string(),
            rtcp_feedback: Vec::new(),
            framing: RealtimeFraming::AnnexB,
        };
        let profile = RealtimeProfile {
            codecs: vec![
                family(96, "profile-level-id=42e01f"),
                family(97, "profile-level-id=42001f"),
                family(98, "profile-level-id=4d001f"),
            ],
        };

        let advert = realtime_advert_for(&profile);
        assert_eq!(
            advert.encodings.len(),
            1,
            "three payload types of one family are one advertised encoding: {:?}",
            advert.encodings
        );
        assert_eq!(advert.encodings[0].clock_rate, 90000);
    }

    /// The profile is required, and this vector's completeness is what carries
    /// the positive above.
    ///
    /// Without this control, the profile could quietly become optional while
    /// the positive elastic-realtime control kept passing. So the same vector
    /// is run with exactly one thing removed, and the error must name the
    /// variable an operator has to set.
    #[test]
    fn the_complete_vector_is_refused_without_its_application_profile() {
        let mut values = fixture_values("enabled");
        assert!(
            values.remove("MYOWNMESH_REALTIME_PROFILE").is_some(),
            "the positive fixture must actually supply the profile, or this \
             control proves nothing"
        );
        // `.err().expect(..)` avoids requiring `Debug` on `ConnectorStartup`,
        // whose successful value carries the live connector policy.
        let error = connector_policy_from_lookup(|name| values.get(name).cloned())
            .err()
            .expect("a connector that can carry flows must be told which codecs");
        assert!(
            error.to_string().contains("MYOWNMESH_REALTIME_PROFILE"),
            "the error must name the variable to set: {error}"
        );
    }

    #[test]
    fn elastic_data_only_connector_requires_no_cardinality_values() {
        let values = fixture_values("disabled");
        let ConnectorStartup { policy, .. } =
            connector_policy_from_lookup(|name| values.get(name).cloned())
                .expect("elastic data-only construction needs no cardinality limits");
        assert!(matches!(
            policy.webrtc().callbacks().realtime(),
            myownmesh_core::RealtimeConnectorPolicy::Disabled
        ));
    }

    /// The ordinary elastic deployment starts and registers its codecs.
    ///
    /// Two things have to hold together, and each fails differently: the
    /// connector is elastic, and the codecs really were registered.
    #[test]
    fn elastic_realtime_connector_registers_its_codecs() {
        let values = fixture_values("enabled");
        let ConnectorStartup { policy, realtime } =
            connector_policy_from_lookup(|name| values.get(name).cloned())
                .expect("elastic generic real-time construction needs no local count vector");
        assert!(matches!(
            policy.webrtc().callbacks().realtime(),
            myownmesh_core::RealtimeConnectorPolicy::Enabled
        ));
        assert!(realtime.supported);
        assert_eq!(realtime.encodings.len(), 2);
    }

    /// The retired lane variables configure nothing, and are not quietly
    /// tolerated either.
    ///
    /// A profile that still named per-kind lane counts, or its own flow
    /// capacity, would be a live configuration file describing a surface that no
    /// longer exists. Because the realtime profile is parsed with
    /// `deny_unknown_fields`, an operator who ports one across gets a startup
    /// error naming the offending key rather than a daemon that silently ignores
    /// half its configuration and then carries no media.
    ///
    /// `flow_capacity` is here for the same reason as the lane field and not as
    /// a lesser case: an accepted-and-ignored capacity key would leave the
    /// operator believing they had set a ceiling that nothing enforces.
    #[test]
    fn a_profile_naming_retired_lane_or_capacity_configuration_is_refused() {
        for (retired, key) in [
            (
                r#"{"codecs": [{"kind": "video", "payload_type": 96,
                    "mime": "video/H264", "clock_rate": 90000,
                    "framing": "annex_b"}], "max_lanes_per_kind": 2}"#,
                "max_lanes_per_kind",
            ),
            (
                r#"{"codecs": [{"kind": "video", "payload_type": 96,
                    "mime": "video/H264", "clock_rate": 90000,
                    "framing": "annex_b"}], "flow_capacity": 4}"#,
                "flow_capacity",
            ),
        ] {
            // `expect_err` here, unlike the `connector_policy_from_lookup`
            // controls above: this call's `Ok` is a `RealtimeProfile`, which
            // already derives `Debug`, so formatting it on failure costs
            // nothing and exposes nothing.
            let error = realtime_profile_from_lookup(|_| Some(retired.to_string()))
                .expect_err("a retired field is not a valid realtime profile");
            assert!(
                error.to_string().contains(key),
                "the error must name the offending key so it can be removed: {error}"
            );
        }
    }
}
