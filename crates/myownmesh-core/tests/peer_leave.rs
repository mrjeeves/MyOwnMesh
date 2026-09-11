//! Authenticated departure controls live in `engine::tests`.
//!
//! The departure receipt gate is a cfg(test)-only engine seam. Keeping its
//! controls in the crate's unit-test scope prevents the integration target
//! from requiring a feature-only release facade, while the production-shaped
//! real-link control remains available to the transport-lab unit suite.
#![cfg(all(feature = "transport-lab", target_os = "none"))]
