//! Checked per-network scheduler policy plumbing.
//!
//! Timing and bounded-work choices are persisted in
//! [`crate::config::SchedulerPolicyConfig`]. This module deliberately does
//! not retain process-wide production constants: every engine path must copy
//! the checked policy from its owning [`crate::config::NetworkConfig`] before
//! starting a timer, task, or bounded await.
