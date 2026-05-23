//! Room-handle derivation. The wire identifier two peers exchange is
//! `SHA-256( app_id || ":" || network_id )` — opaque to the relay
//! network, deterministic across runtimes so JS Trystero and Rust
//! MyOwnMesh agree on the same handle for the same `(app_id,
//! network_id)` pair.
//!
//! Default `app_id` is [`myownmesh_core::TRYSTERO_APP_ID`]. Forks
//! that want isolation choose their own app-id and the derived
//! handles diverge automatically — no per-fork denylist needed.

use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

/// Derive the 64-char hex room-handle for a `(app_id, network_id)`
/// pair. Inputs are NUL-free strings; no normalization beyond the
/// caller's own (the engine calls
/// [`myownmesh_core::normalize_network_id`] first).
pub fn derive_room_handle(app_id: &str, network_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(app_id.as_bytes());
    hasher.update(b":");
    hasher.update(network_id.as_bytes());
    HEXLOWER.encode(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_is_deterministic() {
        let a = derive_room_handle("myownmesh-cloud-mesh-v1", "office-mesh");
        let b = derive_room_handle("myownmesh-cloud-mesh-v1", "office-mesh");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_app_ids_produce_different_handles() {
        let mesh = derive_room_handle("myownmesh-cloud-mesh-v1", "office-mesh");
        let llm = derive_room_handle("myownllm-cloud-mesh-v1", "office-mesh");
        assert_ne!(mesh, llm);
    }

    #[test]
    fn different_network_ids_produce_different_handles() {
        let a = derive_room_handle("app", "home");
        let b = derive_room_handle("app", "office");
        assert_ne!(a, b);
    }
}
