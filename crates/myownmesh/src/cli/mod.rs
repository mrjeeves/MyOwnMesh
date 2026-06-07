//! Subcommand modules for the CLI. Kept in their own files so each
//! command's argv shape and behavior lives in one place rather than
//! threading through a giant `main.rs`.

pub mod config;
pub mod ctl;
pub mod gui;
pub mod identity;
pub mod serve;
pub mod service;
pub mod update;
