// Run the actual vendored timer controls with the application's locked Tokio
// graph, without compiling the dependency's unrelated legacy library tests.
#[path = "../../../vendor/webrtc-sctp-0.12.0/tests/ack_timer_rearm.rs"]
mod ack_timer_rearm;
