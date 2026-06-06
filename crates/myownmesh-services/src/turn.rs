//! Standalone TURN server (RFC 5766).
//!
//! Relays media / data for peers that can't establish a direct path
//! (symmetric NAT). A TURN server also answers STUN Binding requests, so
//! a single TURN listener covers both jobs in an ICE flow.
//!
//! This is a thin wrapper over the webrtc-rs `turn` crate's
//! [`Server`](turn::server::Server), wired to a single UDP listener and
//! a static long-term-credential auth handler driven by
//! [`TurnServiceConfig`]. Credentials are configured up front (mirror
//! them into each peer's `turn_servers` config); there's no dynamic
//! REST-style credential issuance.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::info;
use turn::auth::{generate_auth_key, AuthHandler};
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use turn::Error as TurnError;
use webrtc_util::vnet::net::Net;

use myownmesh_core::config::{TurnCredential, TurnServiceConfig};

use crate::{Error, Result};

/// Long-term credential auth handler backed by a static username → key
/// map. The key is the MD5 digest `generate_auth_key` computes from
/// `username:realm:password`, which is what the TURN message-integrity
/// check compares against — so we never store the plaintext password
/// past startup.
struct StaticAuthHandler {
    cred_map: HashMap<String, Vec<u8>>,
}

impl StaticAuthHandler {
    fn new(realm: &str, creds: &[TurnCredential]) -> Self {
        let mut cred_map = HashMap::new();
        for c in creds {
            cred_map.insert(
                c.username.clone(),
                generate_auth_key(&c.username, realm, &c.password),
            );
        }
        Self { cred_map }
    }
}

impl AuthHandler for StaticAuthHandler {
    fn auth_handle(
        &self,
        username: &str,
        _realm: &str,
        _src_addr: SocketAddr,
    ) -> std::result::Result<Vec<u8>, TurnError> {
        self.cred_map
            .get(username)
            .cloned()
            .ok_or(TurnError::ErrNoSuchUser)
    }
}

/// A running TURN server. Constructed via [`TurnServer::start`].
pub struct TurnServer;

/// Handle to a running TURN server. Call [`TurnServerHandle::stop`] to
/// shut it down cleanly (closing allocations and the listener); dropping
/// it also tears the listener task down, but `stop` is preferred so
/// in-flight allocations get a clean close.
pub struct TurnServerHandle {
    server: Server,
    local_addr: SocketAddr,
    relay_ip: IpAddr,
}

impl TurnServerHandle {
    /// The address the listener actually bound (resolves an ephemeral
    /// port to the real one — used in tests).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The public/relay IP the server hands out in allocations.
    pub fn relay_ip(&self) -> IpAddr {
        self.relay_ip
    }

    /// Stop the server, closing allocations and the listener.
    pub async fn stop(self) -> Result<()> {
        self.server
            .close()
            .await
            .map_err(|e| Error::Turn(e.to_string()))
    }
}

impl TurnServer {
    /// Bind a UDP listener and start the TURN server. Fails fast on
    /// misconfiguration (no credentials, or a wildcard bind with no
    /// public IP to advertise) since a TURN server that can't be
    /// reached or authenticated against is worse than none.
    pub async fn start(config: &TurnServiceConfig) -> Result<TurnServerHandle> {
        if config.credentials.is_empty() {
            return Err(Error::TurnConfig(
                "TURN requires at least one username/password credential".into(),
            ));
        }
        let relay_ip = resolve_relay_ip(config)?;

        let bind_addr = format!("{}:{}", config.bind, config.port);
        let conn = Arc::new(
            UdpSocket::bind(&bind_addr)
                .await
                .map_err(|e| Error::Bind(bind_addr.clone(), e))?,
        );
        let local_addr = conn
            .local_addr()
            .map_err(|e| Error::Bind(bind_addr.clone(), e))?;

        let auth_handler = Arc::new(StaticAuthHandler::new(&config.realm, &config.credentials));

        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: relay_ip,
                    // Interface the relay sockets bind on; the wildcard
                    // is fine here — relay_address is what clients are
                    // told to use.
                    address: "0.0.0.0".to_owned(),
                    net: Arc::new(Net::new(None)),
                }),
            }],
            realm: config.realm.clone(),
            auth_handler,
            // Zero = use the crate's DEFAULT_LIFETIME for channel binds.
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await
        .map_err(|e| Error::Turn(e.to_string()))?;

        info!(
            %local_addr,
            %relay_ip,
            realm = %config.realm,
            credentials = config.credentials.len(),
            "TURN server listening"
        );
        Ok(TurnServerHandle {
            server,
            local_addr,
            relay_ip,
        })
    }
}

/// Resolve the IP a TURN allocation should advertise. Prefers
/// `public_ip`; falls back to the bind address; rejects a wildcard
/// (clients can't connect to 0.0.0.0).
fn resolve_relay_ip(config: &TurnServiceConfig) -> Result<IpAddr> {
    let candidate = if config.public_ip.trim().is_empty() {
        config.bind.trim().to_string()
    } else {
        config.public_ip.trim().to_string()
    };
    let ip: IpAddr = candidate
        .parse()
        .map_err(|_| Error::TurnConfig(format!("relay address '{candidate}' is not a valid IP")))?;
    if ip.is_unspecified() {
        return Err(Error::TurnConfig(
            "TURN public_ip must be set to the server's routable address when bind is a wildcard \
             (0.0.0.0 / ::)"
                .into(),
        ));
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(u: &str, p: &str) -> TurnCredential {
        TurnCredential {
            username: u.into(),
            password: p.into(),
        }
    }

    fn loopback_config() -> TurnServiceConfig {
        TurnServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
            public_ip: "127.0.0.1".into(),
            realm: "myownmesh".into(),
            credentials: vec![cred("alice", "s3cret")],
        }
    }

    #[tokio::test]
    async fn rejects_missing_credentials() {
        let mut cfg = loopback_config();
        cfg.credentials.clear();
        assert!(matches!(
            TurnServer::start(&cfg).await,
            Err(Error::TurnConfig(_))
        ));
    }

    #[tokio::test]
    async fn rejects_wildcard_bind_without_public_ip() {
        let cfg = TurnServiceConfig {
            enabled: true,
            bind: "0.0.0.0".into(),
            port: 0,
            public_ip: "".into(),
            realm: "myownmesh".into(),
            credentials: vec![cred("alice", "pw")],
        };
        assert!(matches!(
            TurnServer::start(&cfg).await,
            Err(Error::TurnConfig(_))
        ));
    }

    #[tokio::test]
    async fn starts_and_stops_on_loopback() {
        let server = TurnServer::start(&loopback_config()).await.unwrap();
        assert_ne!(server.local_addr().port(), 0);
        assert_eq!(server.relay_ip().to_string(), "127.0.0.1");
        server.stop().await.unwrap();
    }

    #[test]
    fn auth_handler_keys_known_users_only() {
        let handler = StaticAuthHandler::new("myownmesh", &[cred("alice", "pw")]);
        let src: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let key = handler.auth_handle("alice", "myownmesh", src).unwrap();
        assert_eq!(key, generate_auth_key("alice", "myownmesh", "pw"));
        assert!(handler.auth_handle("mallory", "myownmesh", src).is_err());
    }

    // Proves the server actually serves on the wire: a real TURN client
    // sends a STUN Binding request through the TURN listener and gets a
    // reflexive address back. (A TURN server answers Binding requests as
    // part of being a TURN server.)
    #[tokio::test]
    async fn answers_binding_request_through_turn_listener() {
        use turn::client::{Client, ClientConfig};

        let server = TurnServer::start(&loopback_config()).await.unwrap();
        let server_port = server.local_addr().port();

        let conn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = Client::new(ClientConfig {
            stun_serv_addr: String::new(),
            turn_serv_addr: String::new(),
            username: String::new(),
            password: String::new(),
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 0,
            conn,
            vnet: None,
        })
        .await
        .unwrap();
        client.listen().await.unwrap();

        let mapped = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.send_binding_request_to(&format!("127.0.0.1:{server_port}")),
        )
        .await
        .expect("TURN binding request timed out")
        .expect("binding request failed");
        // The server saw us come from loopback.
        assert_eq!(mapped.ip().to_string(), "127.0.0.1");

        client.close().await.unwrap();
        server.stop().await.unwrap();
    }
}
