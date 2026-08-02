//! The MyOwnMesh **daemon**, as a library.
//!
//! The `myownmesh` binary (this package's bin target) is a thin CLI over the
//! modules here. They are exposed as a library for one reason: so a host
//! application that is **forbidden from spawning processes**, such as an iOS
//! app where the sandbox allows neither fork nor exec, can run the same daemon
//! inside its own process via [`embedded::start_with_connector_resource_policy`], instead of
//! re-implementing the daemon's behaviour piece by piece.
//!
//! Everything else about the daemon is unchanged: it still listens on the
//! control socket (a unix socket inside the app sandbox on iOS; sockets are
//! allowed; processes aren't), speaks the same wire protocol, and hosts the
//! same registry/services, so existing clients (`myownmesh ctl`, the GUIs,
//! `allmystuff-serve`) work against it identically whether it runs as a
//! process or embedded.

pub mod control;
pub mod embedded;
pub mod ipc;
pub mod registry;
pub mod services;
