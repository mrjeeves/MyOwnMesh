//! Standalone STUN server.
//!
//! Answers RFC 5389 Binding requests with the source transport address
//! XOR-mapped per spec. Pure reflexion: no authentication, no
//! allocations, no `CHANGE-REQUEST` handling — just the one job a STUN
//! server does in an ICE flow, which is to tell a client what address
//! the world sees it coming from.
//!
//! For relaying (symmetric NAT), run the [`crate::turn`] server instead
//! — a TURN server answers Binding requests too, so you rarely need
//! both on one host.

use std::net::SocketAddr;
use std::sync::Arc;

use stun::message::{Message, BINDING_REQUEST, BINDING_SUCCESS};
use stun::xoraddr::XorMappedAddress;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use myownmesh_core::config::StunServiceConfig;

use crate::{Error, Result};

/// A running STUN server. Constructed via [`StunServer::start`].
pub struct StunServer;

/// Handle to a running STUN server. Drop it (or call
/// [`StunServerHandle::stop`]) to shut the listener down.
pub struct StunServerHandle {
    task: JoinHandle<()>,
    local_addr: SocketAddr,
}

impl StunServerHandle {
    /// The address the server actually bound. Useful when the config
    /// requested port 0 (ephemeral) — common in tests.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop the server, aborting its listener task.
    pub fn stop(self) {
        self.task.abort();
    }
}

impl Drop for StunServerHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl StunServer {
    /// Bind a UDP socket and start serving Binding requests. Returns
    /// once the socket is bound; the request loop runs in a spawned
    /// task.
    pub async fn start(config: &StunServiceConfig) -> Result<StunServerHandle> {
        let addr = format!("{}:{}", config.bind, config.port);
        let socket = UdpSocket::bind(&addr)
            .await
            .map_err(|e| Error::Bind(addr.clone(), e))?;
        let local_addr = socket
            .local_addr()
            .map_err(|e| Error::Bind(addr.clone(), e))?;
        info!(%local_addr, "STUN server listening");
        let socket = Arc::new(socket);
        let task = tokio::spawn(serve(socket));
        Ok(StunServerHandle { task, local_addr })
    }
}

async fn serve(socket: Arc<UdpSocket>) {
    // STUN messages are tiny; an MTU-sized buffer is plenty and a stray
    // oversized datagram just gets truncated and fails to decode (which
    // we handle as a bad packet).
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("STUN recv error: {e}");
                continue;
            }
        };
        match binding_response(&buf[..n], src) {
            Ok(Some(resp)) => {
                if let Err(e) = socket.send_to(&resp, src).await {
                    trace!(%src, "STUN send error: {e}");
                } else {
                    trace!(%src, "STUN binding response sent");
                }
            }
            // Decoded fine but wasn't a Binding request — ignore
            // silently (could be a TURN client probing the wrong port).
            Ok(None) => {}
            Err(e) => trace!(%src, "STUN: dropping bad packet: {e}"),
        }
    }
}

/// Build a Binding success response for an incoming packet. Returns
/// `Ok(None)` when the packet decodes but isn't a Binding request, and
/// `Err` when it doesn't decode as STUN at all.
fn binding_response(packet: &[u8], src: SocketAddr) -> Result<Option<Vec<u8>>> {
    let mut req = Message::new();
    req.unmarshal_binary(packet)
        .map_err(|e| Error::Decode(e.to_string()))?;
    if req.typ != BINDING_REQUEST {
        return Ok(None);
    }
    debug!(%src, "STUN binding request");

    let mut resp = Message::new();
    let xor = XorMappedAddress {
        ip: src.ip(),
        port: src.port(),
    };
    // Order matters: the request setter copies its transaction id onto
    // the response, and XorMappedAddress XORs the address against that
    // transaction id, so it must run after the request setter.
    resp.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(req.clone()),
        Box::new(xor),
    ])
    .map_err(|e| Error::Encode(e.to_string()))?;
    Ok(Some(resp.raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stun::message::Getter;
    use stun::xoraddr::XorMappedAddress;

    #[tokio::test]
    async fn binding_request_gets_reflexive_address_back() {
        let cfg = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0, // ephemeral
        };
        let server = StunServer::start(&cfg).await.unwrap();
        let server_addr = server.local_addr();

        // A real client socket sends a real Binding request.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let mut req = Message::new();
        req.build(&[Box::new(BINDING_REQUEST)]).unwrap();
        client.send_to(&req.raw, server_addr).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("STUN response timed out")
        .unwrap();
        assert_eq!(from, server_addr);

        let mut resp = Message::new();
        resp.unmarshal_binary(&buf[..n]).unwrap();
        assert_eq!(resp.typ, BINDING_SUCCESS);
        assert_eq!(resp.transaction_id, req.transaction_id);

        // The server should report back the client's own address.
        let mut mapped = XorMappedAddress::default();
        mapped.get_from(&resp).unwrap();
        assert_eq!(mapped.ip, client_addr.ip());
        assert_eq!(mapped.port, client_addr.port());

        server.stop();
    }

    #[tokio::test]
    async fn non_binding_packet_is_ignored() {
        // Garbage that isn't STUN at all decodes-errors and is dropped;
        // a well-formed non-Binding message returns None. Either way
        // the helper must not panic.
        let src: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(binding_response(b"not a stun packet", src).is_err());
    }

    #[tokio::test]
    async fn double_bind_same_port_errors() {
        let cfg = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
        };
        let server = StunServer::start(&cfg).await.unwrap();
        let taken = server.local_addr();
        // Re-binding the now-occupied port must surface as Error::Bind.
        let cfg2 = StunServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: taken.port(),
        };
        let err = StunServer::start(&cfg2).await;
        assert!(matches!(err, Err(Error::Bind(_, _))));
        server.stop();
    }
}
