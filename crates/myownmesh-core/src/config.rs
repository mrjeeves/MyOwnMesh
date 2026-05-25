//! Config schema for `~/.myownmesh/config.json`. Reading & writing
//! lives here so any caller (binary, library embedder, tests) shares
//! the same parse / default behavior.
//!
//! Schema versioning: a single `version` field on the root. v1 is
//! current; additive changes (new optional fields, new networks)
//! don't bump the version. Field-shape-breaking changes will bump and
//! ship a migration in this module.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::DeviceId;

pub const CONFIG_VERSION: u32 = 1;

/// Topology selector for a single network. Wire-form matches the
/// JSON-tagged shape; embedders construct these directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TopologyMode {
    /// Default. Auto-healing ring with `n_preferred` neighbors (2
    /// immediate + (n-2) shortcuts). Missing/null `n_preferred`
    /// defaults to 3.
    Ring {
        #[serde(default)]
        n_preferred: Option<u32>,
    },
    /// All spokes route through a single, config-named hub. Hub holds
    /// all peers active; spokes shelve everyone but the hub.
    Star { hub: DeviceId },
    /// Full mesh — every peer keeps every other peer active. N² cost;
    /// only useful for small fixed-size deployments.
    FullMesh,
}

impl Default for TopologyMode {
    fn default() -> Self {
        TopologyMode::Ring { n_preferred: None }
    }
}

impl TopologyMode {
    /// The default `n_preferred` for ring topology (2 immediate +
    /// 1 shortcut). Used when a Ring config omits the field.
    pub const DEFAULT_RING_N_PREFERRED: u32 = 3;

    /// Resolve the effective `n_preferred` for a Ring topology,
    /// substituting the default when the field is None. Other
    /// topology modes return 0 — they don't use this value.
    pub fn effective_n_preferred(&self) -> u32 {
        match self {
            TopologyMode::Ring { n_preferred } => {
                n_preferred.unwrap_or(Self::DEFAULT_RING_N_PREFERRED)
            }
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StunServer {
    pub urls: Vec<String>,
}

/// Built-in STUN URLs applied when a deserialized `NetworkConfig`
/// omits `stun_servers`. Three vendors so any single provider's
/// outage still leaves NAT traversal working. Mirrors MyOwnLLM's
/// `DEFAULT_NETWORK_STUN`. Users can opt out by writing an explicit
/// empty array (`"stun_servers": []`) — `default_stun_servers` only
/// fires when the field is absent.
pub const DEFAULT_NETWORK_STUN: &[&str] = &[
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun.cloudflare.com:3478",
];

/// Build the default STUN server list. Exposed so embedders that
/// construct `NetworkConfig` programmatically can call
/// `default_stun_servers()` instead of repeating the URL list.
pub fn default_stun_servers() -> Vec<StunServer> {
    vec![StunServer {
        urls: DEFAULT_NETWORK_STUN
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    }]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TurnServer {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    /// TURN servers use the loose "credential" field name rather than
    /// "password" — keep parity with the RTC ICE config shape so
    /// users copy-pasting from Cloudflare/Metered.ca dashboards see
    /// the field name they expect.
    #[serde(default)]
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SignalingConfig {
    /// Which signaling strategy to use. Only `"nostr"` is supported in
    /// v1; sibling crates can add others (BitTorrent trackers, MQTT,
    /// IPFS, Firebase) and the engine picks via this field.
    pub strategy: String,
    /// Explicit relay URLs. Empty = use the built-in deterministic
    /// top-N defaults filtered by the denylist.
    pub servers: Vec<String>,
    /// How many relays to keep connected at once. Default 5 — five
    /// independent forwarders are enough that no single relay can
    /// censor or stall the room, while keeping the per-peer
    /// bandwidth tax tolerable.
    pub redundancy: u32,
    /// Hostnames we never connect to even if they'd be picked by the
    /// deterministic shuffle. Used to skip relays known to rate-limit
    /// us, drop our REQs, or otherwise misbehave. Hostname-only
    /// (no scheme); match is case-insensitive.
    pub denylist: Vec<String>,
}

impl Default for SignalingConfig {
    fn default() -> Self {
        Self {
            strategy: "nostr".to_string(),
            servers: Vec::new(),
            redundancy: DEFAULT_SIGNALING_REDUNDANCY,
            denylist: default_signaling_denylist(),
        }
    }
}

/// Default number of signaling relays to maintain concurrent
/// connections to. Five is the proven sweet spot from MyOwnLLM:
/// fewer means a single relay's outage can stall handshake; more
/// adds per-peer announce bandwidth without improving recovery time.
pub const DEFAULT_SIGNALING_REDUNDANCY: u32 = 5;

/// Hostnames excluded from the default relay shuffle. Known to
/// rate-limit or stall our REQs in field testing.
pub fn default_signaling_denylist() -> Vec<String> {
    vec!["relay.damus.io".to_string(), "chorus.pjv.me".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkConfig {
    /// Local config record id. User-chosen, unique within this
    /// device's config — distinguishes multiple saved entries for
    /// the same wire-level network (different STUN/TURN setups for
    /// the same fleet, etc.).
    pub id: String,
    /// Wire-level rendezvous handle. Normalised via
    /// [`crate::identity::normalize_network_id`] on load.
    pub network_id: String,
    /// Cosmetic display name. Empty falls back to `network_id`.
    #[serde(default)]
    pub label: String,
    /// Initial governance kind for this network. Open is the
    /// default and matches the engine's behaviour through every
    /// release before `network_state_v1` shipped. Closed sets up
    /// the per-network signed state log so the founder
    /// self-elects as `Owner` on first attach. Configs written by
    /// older builds parse via #[serde(default)] without an
    /// explicit field.
    ///
    /// At runtime, the *authoritative* kind is the one in the
    /// signed [`crate::NetworkState`] log; this field is only the
    /// initial value used to bootstrap the log on first attach.
    /// Subsequent kind changes happen via signed transitions, not
    /// by editing config.json.
    #[serde(default)]
    pub kind: crate::network_state::NetworkKind,
    #[serde(default)]
    pub topology: TopologyMode,
    #[serde(default)]
    pub signaling: SignalingConfig,
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<StunServer>,
    /// TURN servers are never bundled — user-supplied only. ICE
    /// works without TURN for most cases; the engine surfaces a
    /// dedicated `ice-failed-no-turn` diagnostic so the user knows
    /// when their topology needs one.
    #[serde(default)]
    pub turn_servers: Vec<TurnServer>,
    /// Override the on-disk roster path. Null = use the default
    /// (`~/.myownmesh/mesh/rosters/{network_id}.json`).
    #[serde(default)]
    pub roster_path: Option<PathBuf>,
    /// When true, every authenticating peer is added to the roster
    /// automatically without user approval. Useful for headless
    /// fleet members; off by default.
    #[serde(default)]
    pub auto_approve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AutoUpdateConfig {
    pub enabled: bool,
    /// `"stable"` or `"beta"`. Beta channel pulls pre-releases; stable
    /// only takes the latest released version.
    pub channel: String,
    /// `"patch"` | `"minor"` | `"all"` | `"none"`. Controls which
    /// version bumps the updater applies without confirmation.
    /// "patch" is the default; bigger jumps stage but wait for a
    /// user "apply" action.
    pub auto_apply: String,
    pub check_interval_hours: u32,
    /// Override the release feed URL. Null = use the build-time
    /// `MYOWNMESH_RELEASE_URL_STABLE` env-var default.
    pub stable_url: Option<String>,
    pub beta_url: Option<String>,
}

impl Default for AutoUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            channel: "stable".to_string(),
            auto_apply: "patch".to_string(),
            check_interval_hours: 6,
            stable_url: None,
            beta_url: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct AutoCleanupConfig {
    pub updates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DaemonConfig {
    pub enabled: bool,
    /// Unix-domain socket path for `myownmesh ctl …` to reach the
    /// running daemon. Null = derive default
    /// (`~/.myownmesh/daemon.sock` on Unix; named pipe on Windows).
    pub control_socket: Option<PathBuf>,
    pub log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            control_socket: None,
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MeshConfig {
    pub version: u32,
    /// Override the identity anchor file path. Null = use the default
    /// (`~/.myownmesh/.secrets/identity.json`).
    pub identity_path: Option<PathBuf>,
    pub auto_update: AutoUpdateConfig,
    pub auto_cleanup: AutoCleanupConfig,
    pub daemon: DaemonConfig,
    pub networks: Vec<NetworkConfig>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            identity_path: None,
            auto_update: AutoUpdateConfig::default(),
            auto_cleanup: AutoCleanupConfig::default(),
            daemon: DaemonConfig::default(),
            networks: Vec::new(),
        }
    }
}

impl MeshConfig {
    /// Load the config from the default location. Missing file
    /// returns [`MeshConfig::default`] — embedders should call
    /// `save()` afterward if they want the file to exist.
    pub fn load() -> Result<Self> {
        let path = crate::dirs::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        let cfg: MeshConfig = serde_json::from_str(&raw)
            .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))?;
        if cfg.version != CONFIG_VERSION {
            return Err(Error::Config(format!(
                "config version {} unsupported (this build expects v{})",
                cfg.version, CONFIG_VERSION
            )));
        }
        Ok(cfg)
    }

    /// Persist to the default location. Pretty-printed JSON for
    /// easy hand-editing; the file isn't on a hot path.
    pub fn save(&self) -> Result<()> {
        let path = crate::dirs::config_path()?;
        let parent = path.parent().ok_or_else(|| {
            Error::Config(format!("config path has no parent: {}", path.display()))
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Config(format!("create {}: {e}", parent.display())))?;
        let serialized = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, serialized)
            .map_err(|e| Error::Config(format!("write {}: {e}", path.display())))?;
        Ok(())
    }

    /// Find a network config by its local `id`.
    pub fn network(&self, id: &str) -> Option<&NetworkConfig> {
        self.networks.iter().find(|n| n.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_v1_with_defaults() {
        let cfg = MeshConfig::default();
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert!(cfg.auto_update.enabled);
        assert_eq!(cfg.auto_update.channel, "stable");
        assert_eq!(cfg.auto_update.auto_apply, "patch");
        assert_eq!(cfg.auto_update.check_interval_hours, 6);
        assert!(cfg.daemon.enabled);
        assert!(cfg.networks.is_empty());
    }

    #[test]
    fn topology_default_is_ring() {
        let t = TopologyMode::default();
        match t {
            TopologyMode::Ring { n_preferred } => assert!(n_preferred.is_none()),
            _ => panic!("default topology should be ring"),
        }
    }

    #[test]
    fn topology_effective_n_preferred_falls_back() {
        let r = TopologyMode::Ring { n_preferred: None };
        assert_eq!(r.effective_n_preferred(), 3);
        let r5 = TopologyMode::Ring {
            n_preferred: Some(5),
        };
        assert_eq!(r5.effective_n_preferred(), 5);
        // Non-Ring topologies don't have an n_preferred — return 0.
        assert_eq!(TopologyMode::FullMesh.effective_n_preferred(), 0);
    }

    #[test]
    fn topology_serde_tags_by_kind() {
        let ring = TopologyMode::Ring {
            n_preferred: Some(3),
        };
        let s = serde_json::to_string(&ring).unwrap();
        assert!(s.contains("\"kind\":\"ring\""), "got: {s}");
        assert!(s.contains("\"n_preferred\":3"));

        let star = TopologyMode::Star {
            hub: "abcdef".into(),
        };
        let s = serde_json::to_string(&star).unwrap();
        assert!(s.contains("\"kind\":\"star\""));
        assert!(s.contains("\"hub\":\"abcdef\""));

        let full = TopologyMode::FullMesh;
        let s = serde_json::to_string(&full).unwrap();
        assert!(s.contains("\"kind\":\"full_mesh\""));
    }

    #[test]
    fn signaling_defaults_carry_denylist() {
        let s = SignalingConfig::default();
        assert_eq!(s.strategy, "nostr");
        assert_eq!(s.redundancy, DEFAULT_SIGNALING_REDUNDANCY);
        assert!(s.denylist.iter().any(|h| h == "relay.damus.io"));
    }

    #[test]
    fn round_trip_empty_config() {
        let cfg = MeshConfig::default();
        let s = serde_json::to_string(&cfg).unwrap();
        let back: MeshConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn network_config_omits_stun_field_picks_up_defaults() {
        // A user writing a minimal network config without
        // mentioning stun_servers should get the built-in defaults
        // rather than launching with zero ICE servers.
        let json = r#"{
            "id": "n1",
            "network_id": "test-net"
        }"#;
        let cfg: NetworkConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.stun_servers, default_stun_servers());
        assert!(!cfg.stun_servers.is_empty());
        assert!(cfg.stun_servers[0]
            .urls
            .iter()
            .any(|u| u.contains("google")));
        assert!(cfg.stun_servers[0]
            .urls
            .iter()
            .any(|u| u.contains("cloudflare")));
    }

    #[test]
    fn network_config_empty_stun_array_opts_out() {
        // Writing an explicit empty list must remain empty — the
        // defaults only fire when the field is absent.
        let json = r#"{
            "id": "n1",
            "network_id": "test-net",
            "stun_servers": []
        }"#;
        let cfg: NetworkConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.stun_servers.is_empty());
    }
}
