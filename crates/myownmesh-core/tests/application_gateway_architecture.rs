//! Architecture controls for the Application Gateway dispatch boundary.
//!
//! These controls intentionally inspect the shipped source rather than
//! constructing a second transport fixture. The engine owns connector and
//! signaling admission; this test protects the smaller claim that public
//! application facades reach that owner only through the typed gateway ports.

const CHANNELS: &str = include_str!("../src/channels.rs");
const RPC: &str = include_str!("../src/rpc.rs");
const ERRORS: &str = include_str!("../src/error.rs");
const GATEWAY_CHANNELS: &str = include_str!("../src/application_gateway/channels.rs");
const GATEWAY_FRAME: &str = include_str!("../src/application_gateway/frame.rs");
const GATEWAY_RPC: &str = include_str!("../src/application_gateway/rpc.rs");
const GATEWAY_CAPABILITIES: &str = include_str!("../src/application_gateway/capabilities.rs");

fn require_all(source: &str, file: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            source.contains(needle),
            "{file} lost required typed gateway boundary fragment: {needle}"
        );
    }
}

#[test]
fn public_application_facades_have_no_engine_command_bypass() {
    for (file, source) in [
        ("channels.rs", CHANNELS),
        ("rpc.rs", RPC),
        ("error.rs", ERRORS),
    ] {
        assert!(
            !source.contains("NetworkCmd"),
            "{file} must not construct or name an engine command directly"
        );
        assert!(
            !source.contains("cmd_tx"),
            "{file} must not access the engine command queue directly"
        );
    }

    require_all(
        CHANNELS,
        "channels.rs",
        &[
            "application_gateway",
            ".send_channel_frame(",
            ".send_channel_reliable(",
            ".broadcast_channel_frame(",
            ".subscribe_channel(",
        ],
    );
    require_all(
        RPC,
        "rpc.rs",
        &[
            "application_gateway",
            ".register_rpc_request_prepared::<Unary>",
            ".register_rpc_request_prepared::<Streaming>",
            ".send_rpc_request(",
            ".replace_capabilities(",
            ".fanout_capabilities(",
        ],
    );
}

#[test]
fn gateway_ports_keep_session_funding_and_backpressure_typed() {
    require_all(
        GATEWAY_CHANNELS,
        "application_gateway/channels.rs",
        &[
            "pub(crate) async fn send_channel_frame(",
            "pub(crate) async fn send_channel_reliable(",
            "pub(crate) async fn broadcast_channel_frame(",
            "pub(crate) fn accept_channel(",
            "reserve_retained(",
            "GatewayRefusal::Pressure",
        ],
    );
    require_all(
        GATEWAY_RPC,
        "application_gateway/rpc.rs",
        &[
            "register_rpc_request_prepared<S:",
            "with_live_session_state(",
            "register_local_request_prepared::<S>",
            "pub(crate) async fn send_rpc_request(",
        ],
    );
    require_all(
        GATEWAY_FRAME,
        "application_gateway/frame.rs",
        &[
            "pub(crate) fn claim(",
            "pub(crate) fn admit(",
            "reserve_retained(claim)",
            "serde_json::from_slice(&self.encoded)",
        ],
    );
}

#[test]
fn frame_admission_funds_before_parse_and_gateway_owns_retention() {
    let reserve = GATEWAY_FRAME
        .find("reserve_retained(claim)")
        .expect("frame admission must reserve its measured claim");
    let parse = GATEWAY_FRAME
        .find("serde_json::from_slice(&self.encoded)")
        .expect("frame decoding must remain a separate step");
    assert!(
        reserve < parse,
        "measured session funding must precede sender-controlled parsing"
    );

    require_all(
        GATEWAY_CAPABILITIES,
        "application_gateway/capabilities.rs",
        &[
            "pub(crate) fn fanout_capabilities(",
            "pub(crate) fn replace_capabilities(",
            "self.closed",
        ],
    );
}
