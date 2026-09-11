//! Target-owned runtime signaling namespace.
//!
//! The active typed ingress ports live at their authority-bearing engine
//! boundaries (`engine::semantic_ingress` and `engine::signaling_ingress`).
//! This namespace contains only the narrow terminal-task custody adapter; it
//! is not a queue, parser, or authority store for signaling data.

mod custodian;

#[cfg(test)]
pub(crate) use custodian::SIGNALING_TASK_SLOTS;
pub(crate) use custodian::{MdnsTaskCustodian, NostrTaskCustodians, SignalingTaskCustodian};
