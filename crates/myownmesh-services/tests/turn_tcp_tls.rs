//! Real TCP/TLS TURN and trusted-loopback PROXYv2 backend controls. The TLS
//! terminator is test-owned; these are not external Caddy or native WebRTC ICE tests.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{TurnCredential, TurnServiceConfig};
use myownmesh_core::{
    FiniteResourceProvider, LocalApplicationResourceScope, ResourceClaim, ResourceClass,
    ResourceProviderPort,
};
use myownmesh_services::{ServiceCleanupOwner, ServiceCleanupPort, TurnServer};
use stun::agent::TransactionId;
use stun::attributes::{ATTR_NONCE, ATTR_REALM, ATTR_USERNAME};
use stun::error_code::{ErrorCodeAttribute, CODE_UNAUTHORIZED};
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::{
    Getter, Message, MessageType, Setter, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, METHOD_ALLOCATE,
    METHOD_BINDING, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION,
};
use stun::textattrs::{Nonce, Realm, Username};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use turn::proto::{
    channum::ChannelNumber, peeraddr::PeerAddress, relayaddr::RelayedAddress,
    reqtrans::RequestedTransport, PROTO_UDP,
};

const GUARD: Duration = Duration::from_secs(10);

fn config() -> TurnServiceConfig {
    TurnServiceConfig {
        enabled: true,
        bind: "127.0.0.1".into(),
        public_ip: "127.0.0.1".into(),
        port: 0,
        realm: "tcp-control".into(),
        credentials: vec![TurnCredential {
            username: "tcp-user".into(),
            password: "tcp-password".into(),
        }],
        tcp_enabled: true,
        tcp_max_connections: 4,
        tcp_max_connections_per_ip: 2,
        ..Default::default()
    }
}

fn fixture<F, Fut>(body: F)
where
    F: FnOnce(LocalApplicationResourceScope, ServiceCleanupPort, FiniteResourceProvider) -> Fut,
    Fut: Future<Output = ()>,
{
    fixture_outcome(0, body)
}

fn fixture_outcome<F, Fut>(task_failures: u64, body: F)
where
    F: FnOnce(LocalApplicationResourceScope, ServiceCleanupPort, FiniteResourceProvider) -> Fut,
    Fut: Future<Output = ()>,
{
    // Same existing same finite policy as service_restart_custody's scope:
    // this is a workload budget, not a claim of exact startup sizing.
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, 1_000_000)),
    )
    .unwrap();
    let provider = FiniteResourceProvider::new(grant);
    let port = ResourceProviderPort::new(provider.clone()).unwrap();
    let scope = LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap();
    let owner = ServiceCleanupOwner::new(scope.clone()).unwrap();
    let cleanup = owner.port();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::timeout(GUARD, body(scope.clone(), cleanup, provider.clone()))
                .await
                .expect("bounded TCP control completes");
        });
        drop(runtime);
    }));
    let report = owner.close_and_join().expect("outside cleanup owner joins");
    drop((scope, port));
    assert_eq!(
        provider.in_use(),
        ResourceClaim::ZERO,
        "all TCP/service/root storage released after joins"
    );
    assert_eq!(
        provider.retained_after_failed_cleanup(),
        ResourceClaim::ZERO
    );
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
    assert_eq!(report.task_failures, task_failures);
    assert_eq!(report.worker_failures, 0);
}

fn request(method: stun::message::Method, extra: Vec<Box<dyn Setter>>) -> Message {
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(TransactionId::new()),
        Box::new(MessageType::new(method, CLASS_REQUEST)),
    ];
    setters.extend(extra);
    let mut request = Message::new();
    request.build(&setters).unwrap();
    request
}

async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut first = [0; 4];
    stream.read_exact(&mut first).await.unwrap();
    let body = usize::from(u16::from_be_bytes([first[2], first[3]]));
    let channel = first[0] & 0xc0 == 0x40;
    let len = body + if channel { 4 } else { 20 };
    let padded = if channel { (len + 3) & !3 } else { len };
    assert!(padded <= 65_556);
    let mut frame = vec![0; padded];
    frame[..4].copy_from_slice(&first);
    stream.read_exact(&mut frame[4..]).await.unwrap();
    frame.truncate(len);
    frame
}

async fn response(stream: &mut (impl AsyncRead + Unpin), sent: &Message) -> Message {
    let frame = read_frame(stream).await;
    let mut response = Message::new();
    response.unmarshal_binary(&frame).unwrap();
    assert_eq!(response.transaction_id, sent.transaction_id);
    response
}

async fn exchange(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), sent: &Message) -> Message {
    stream.write_all(&sent.raw).await.unwrap();
    response(stream, sent).await
}

async fn binding(stream: &mut TcpStream) {
    let sent = request(METHOD_BINDING, vec![]);
    assert_eq!(
        exchange(stream, &sent).await.typ,
        MessageType::new(METHOD_BINDING, CLASS_SUCCESS_RESPONSE)
    );
}

fn proxy_header(source: Ipv4Addr) -> Vec<u8> {
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    header.extend_from_slice(&[0x21, 0x11, 0, 12]);
    header.extend_from_slice(&source.octets());
    header.extend_from_slice(&[127, 0, 0, 1, 0x23, 0x45, 0x0d, 0x96]);
    header
}

async fn closed(stream: &mut TcpStream) {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(n) => assert_eq!(n, 0),
        Err(error) => assert!(matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
        )),
    }
}

#[test]
fn tcp_binding_fragmentation_coalescing_stop_and_exact_restart() {
    fixture(|scope, cleanup, _| async move {
        let mut cfg = config();
        let server = TurnServer::start_with_resource_scope(&cfg, scope.clone(), cleanup.clone())
            .await
            .unwrap();
        let addr = server.tcp_local_addr().unwrap();
        assert_eq!(addr, server.local_addr());
        let mut client = TcpStream::connect(addr).await.unwrap();
        let first = request(METHOD_BINDING, vec![]);
        for part in first.raw.chunks(3) {
            client.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
        assert_eq!(
            response(&mut client, &first).await.typ,
            MessageType::new(METHOD_BINDING, CLASS_SUCCESS_RESPONSE)
        );
        let second = request(METHOD_BINDING, vec![]);
        let third = request(METHOD_BINDING, vec![]);
        client
            .write_all(&[second.raw.as_slice(), third.raw.as_slice()].concat())
            .await
            .unwrap();
        response(&mut client, &second).await;
        response(&mut client, &third).await;
        server.stop().await.unwrap(); // client held open across joined service stop
        closed(&mut client).await;
        cfg.port = addr.port();
        let replacement = TurnServer::start_with_resource_scope(&cfg, scope, cleanup)
            .await
            .unwrap();
        assert_eq!(replacement.tcp_local_addr(), Some(addr));
        replacement.stop().await.unwrap();
    });
}

#[test]
fn tcp_caps_refuse_and_joined_client_release_recovers_capacity() {
    fixture(|scope, cleanup, provider| async move {
        let mut cfg = config();
        cfg.tcp_max_connections = 2;
        cfg.tcp_max_connections_per_ip = 1;
        let server = TurnServer::start_with_resource_scope(&cfg, scope, cleanup)
            .await
            .unwrap();
        let addr = server.tcp_local_addr().unwrap();
        let baseline = provider.in_use();
        let mut first = TcpStream::connect(addr).await.unwrap();
        binding(&mut first).await;
        let mut refused = TcpStream::connect(addr).await.unwrap();
        closed(&mut refused).await;
        drop(first);
        while provider.in_use() != baseline {
            tokio::task::yield_now().await;
        }
        let mut recovered = TcpStream::connect(addr).await.unwrap();
        binding(&mut recovered).await;
        server.stop().await.unwrap();
        closed(&mut recovered).await;
    });
}

#[test]
fn proxy_original_ip_quota_and_listener_class_reservation() {
    fixture(|scope, cleanup, provider| async move {
        let temporary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = temporary.local_addr().unwrap().port();
        drop(temporary);
        let mut cfg = config();
        cfg.tls_proxy_enabled = true;
        cfg.tls_proxy_port = proxy_port;
        let server = TurnServer::start_with_resource_scope(&cfg, scope, cleanup)
            .await
            .unwrap();
        let mut direct = TcpStream::connect(server.tcp_local_addr().unwrap())
            .await
            .unwrap();
        binding(&mut direct).await;
        let second_socket = tokio::net::TcpSocket::new_v4().unwrap();
        second_socket
            .bind(SocketAddr::from(([127, 0, 0, 2], 0)))
            .unwrap();
        let mut second_direct = second_socket
            .connect(server.tcp_local_addr().unwrap())
            .await
            .unwrap();
        binding(&mut second_direct).await;
        let third_socket = tokio::net::TcpSocket::new_v4().unwrap();
        third_socket
            .bind(SocketAddr::from(([127, 0, 0, 3], 0)))
            .unwrap();
        let mut excess_direct = third_socket
            .connect(server.tcp_local_addr().unwrap())
            .await
            .unwrap();
        closed(&mut excess_direct).await; // distinct IP: direct GLOBAL class reservation exhausted
        let addr = server.tls_proxy_local_addr().unwrap();
        assert!(addr.ip().is_loopback());
        let mut one = TcpStream::connect(addr).await.unwrap();
        one.write_all(&proxy_header(Ipv4Addr::new(192, 0, 2, 1)))
            .await
            .unwrap();
        binding(&mut one).await;
        let admitted = provider.in_use();
        let mut duplicate_ip = TcpStream::connect(addr).await.unwrap();
        duplicate_ip
            .write_all(&proxy_header(Ipv4Addr::new(192, 0, 2, 1)))
            .await
            .unwrap();
        closed(&mut duplicate_ip).await;
        while provider.in_use() != admitted {
            tokio::task::yield_now().await;
        }
        let mut two = TcpStream::connect(addr).await.unwrap();
        two.write_all(&proxy_header(Ipv4Addr::new(192, 0, 2, 2)))
            .await
            .unwrap();
        binding(&mut two).await; // loopback socket peer did not collapse identities
        server.stop().await.unwrap();
        closed(&mut direct).await;
        closed(&mut second_direct).await;
        closed(&mut one).await;
        closed(&mut two).await;
    });
}

#[test]
fn direct_proxy_spoof_and_missing_backend_header_are_client_local_refusals() {
    fixture(|scope, cleanup, _| async move {
        let mut cfg = config();
        let temporary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        cfg.tls_proxy_port = temporary.local_addr().unwrap().port();
        drop(temporary);
        cfg.tls_proxy_enabled = true;
        let server = TurnServer::start_with_resource_scope(&cfg, scope, cleanup)
            .await
            .unwrap();
        let mut spoof = TcpStream::connect(server.tcp_local_addr().unwrap())
            .await
            .unwrap();
        spoof
            .write_all(&proxy_header(Ipv4Addr::new(192, 0, 2, 1)))
            .await
            .unwrap();
        closed(&mut spoof).await;
        let mut missing = TcpStream::connect(server.tls_proxy_local_addr().unwrap())
            .await
            .unwrap();
        missing
            .write_all(&request(METHOD_BINDING, vec![]).raw)
            .await
            .unwrap();
        closed(&mut missing).await;
        server.stop().await.unwrap(); // remote malformed data did not poison stop
    });
}

#[test]
fn tcp_bind_failure_rolls_back_already_started_udp() {
    fixture_outcome(1, |scope, cleanup, _| async move {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();
        let mut cfg = config();
        cfg.port = addr.port();
        assert!(TurnServer::start_with_resource_scope(&cfg, scope, cleanup)
            .await
            .is_err());
        let udp = UdpSocket::bind(addr)
            .await
            .expect("failed TCP startup already closed UDP listener");
        drop((udp, occupied));
    });
}

struct Auth {
    nonce: Nonce,
    realm: Realm,
    integrity: MessageIntegrity,
}

impl Auth {
    fn message(
        &self,
        method: stun::message::Method,
        mut attributes: Vec<Box<dyn Setter>>,
    ) -> Message {
        attributes.extend(vec![
            Box::new(Username::new(ATTR_USERNAME, "tcp-user".into())) as Box<dyn Setter>,
            Box::new(self.realm.clone()),
            Box::new(self.nonce.clone()),
            Box::new(self.integrity.clone()),
            Box::new(FINGERPRINT),
        ]);
        request(method, attributes)
    }
}

async fn authenticate(client: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> (Auth, SocketAddr) {
    let initial = request(
        METHOD_ALLOCATE,
        vec![Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    let challenge = exchange(client, &initial).await;
    let mut code = ErrorCodeAttribute::default();
    code.get_from(&challenge).unwrap();
    assert!(code.code == CODE_UNAUTHORIZED);
    let auth = Auth {
        nonce: Nonce::get_from_as(&challenge, ATTR_NONCE).unwrap(),
        realm: Realm::get_from_as(&challenge, ATTR_REALM).unwrap(),
        integrity: MessageIntegrity::new_long_term_integrity(
            "tcp-user".into(),
            "tcp-control".into(),
            "tcp-password".into(),
        ),
    };
    let allocate = auth.message(
        METHOD_ALLOCATE,
        vec![Box::new(RequestedTransport {
            protocol: PROTO_UDP,
        })],
    );
    let mut allocated = exchange(client, &allocate).await;
    assert_eq!(
        allocated.typ,
        MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE)
    );
    auth.integrity.check(&mut allocated).unwrap();
    let mut relay = RelayedAddress::default();
    relay.get_from(&allocated).unwrap();
    (auth, SocketAddr::new(relay.ip, relay.port))
}

fn tls_configs(
    trust: bool,
    expired: bool,
) -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let mut parameters = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    if expired {
        parameters.not_before = rcgen::date_time_ymd(2000, 1, 1);
        parameters.not_after = rcgen::date_time_ymd(2001, 1, 1);
    }
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = parameters.self_signed(&key_pair).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    if trust {
        roots.add(cert.der().clone()).unwrap();
    }
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
    )
    .unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

fn downstream_proxy_header(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
        panic!("TLS fixture uses IPv4 loopback endpoints");
    };
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    header.extend_from_slice(&[0x21, 0x11, 0, 12]); // v2 PROXY, IPv4 STREAM, exact address length
    header.extend_from_slice(&source.ip().octets());
    header.extend_from_slice(&destination.ip().octets());
    header.extend_from_slice(&source.port().to_be_bytes());
    header.extend_from_slice(&destination.port().to_be_bytes());
    header
}

// None means TLS rejected before connecting to the TURN backend. Both futures
// are joined by the caller; no detached proxy task or alternate plaintext path.
async fn terminate_tls_once(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    backend: SocketAddr,
) -> std::io::Result<Option<(u64, u64)>> {
    let (downstream, source) = listener.accept().await?;
    let destination = downstream.local_addr()?;
    let mut tls = match tokio_rustls::TlsAcceptor::from(config)
        .accept(downstream)
        .await
    {
        Ok(tls) => tls,
        Err(_) => return Ok(None),
    };
    let mut upstream = TcpStream::connect(backend).await?;
    upstream
        .write_all(&downstream_proxy_header(source, destination))
        .await?;
    tokio::io::copy_bidirectional(&mut tls, &mut upstream)
        .await
        .map(Some)
}

async fn tls_only_config() -> TurnServiceConfig {
    let mut cfg = config();
    cfg.tcp_enabled = false;
    cfg.tls_proxy_enabled = true;
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    cfg.tls_proxy_port = reservation.local_addr().unwrap().port();
    drop(reservation);
    cfg
}

#[test]
fn tls_authenticated_proxy_permission_channel_and_bidirectional_udp_relay() {
    fixture(|scope, cleanup, provider| async move {
        let baseline = provider.in_use();
        let server = TurnServer::start_with_resource_scope(
            &tls_only_config().await,
            scope.clone(),
            cleanup.clone(),
        )
        .await
        .unwrap();
        assert_eq!(server.tcp_local_addr(), None);
        let no_plaintext = TcpListener::bind(server.local_addr())
            .await
            .expect("public TURN port has no plaintext TCP listener");
        let backend = server.tls_proxy_local_addr().unwrap();
        assert!(backend.ip().is_loopback());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (server_tls, client_tls) = tls_configs(true, false);
        let proxy = terminate_tls_once(listener, server_tls, backend);
        let client = async {
            let downstream = TcpStream::connect(endpoint).await.unwrap();
            let mut client = tokio_rustls::TlsConnector::from(client_tls)
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    downstream,
                )
                .await
                .unwrap();
            let (auth, relay) = authenticate(&mut client).await;
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer_addr = peer.local_addr().unwrap();
            let permission = auth.message(
                METHOD_CREATE_PERMISSION,
                vec![Box::new(PeerAddress {
                    ip: peer_addr.ip(),
                    port: peer_addr.port(),
                })],
            );
            let mut permitted = exchange(&mut client, &permission).await;
            assert_eq!(
                permitted.typ,
                MessageType::new(METHOD_CREATE_PERMISSION, CLASS_SUCCESS_RESPONSE)
            );
            auth.integrity.check(&mut permitted).unwrap();
            let channel = auth.message(
                METHOD_CHANNEL_BIND,
                vec![
                    Box::new(ChannelNumber(0x4001)),
                    Box::new(PeerAddress {
                        ip: peer_addr.ip(),
                        port: peer_addr.port(),
                    }),
                ],
            );
            let mut bound = exchange(&mut client, &channel).await;
            assert_eq!(
                bound.typ,
                MessageType::new(METHOD_CHANNEL_BIND, CLASS_SUCCESS_RESPONSE)
            );
            auth.integrity.check(&mut bound).unwrap();
            client
                .write_all(&[0x40, 1, 0, 3, 9, 8, 7, 0])
                .await
                .unwrap();
            let mut packet = [0; 32];
            let (len, source) = peer.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..len], &[9, 8, 7]);
            assert_eq!(source, relay);
            peer.send_to(&[1, 2, 3], relay).await.unwrap();
            assert_eq!(read_frame(&mut client).await, vec![0x40, 1, 0, 3, 1, 2, 3]);
            client.shutdown().await.unwrap();
            let mut tail = Vec::new();
            client.read_to_end(&mut tail).await.unwrap();
            assert!(tail.is_empty());
        };
        let (proxy_result, ()) = tokio::join!(proxy, client);
        let (to_backend, from_backend) = proxy_result.unwrap().expect("TLS used proxy backend");
        assert!(to_backend > 0 && from_backend > 0);
        server.stop().await.unwrap();
        drop(no_plaintext);
        assert_eq!(provider.in_use(), baseline);
    });
}

fn rejected_tls_control(name: &'static str, trust: bool, expired: bool) {
    fixture(|scope, cleanup, provider| async move {
        let baseline = provider.in_use();
        let server = TurnServer::start_with_resource_scope(
            &tls_only_config().await,
            scope.clone(),
            cleanup.clone(),
        )
        .await
        .unwrap();
        assert_eq!(server.tcp_local_addr(), None);
        let no_plaintext = TcpListener::bind(server.local_addr())
            .await
            .expect("no plaintext TCP fallback listener");
        let ready = provider.in_use();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (server_tls, client_tls) = tls_configs(trust, expired);
        let proxy =
            terminate_tls_once(listener, server_tls, server.tls_proxy_local_addr().unwrap());
        let client = async {
            let downstream = TcpStream::connect(endpoint).await.unwrap();
            tokio_rustls::TlsConnector::from(client_tls)
                .connect(
                    rustls::pki_types::ServerName::try_from(name).unwrap(),
                    downstream,
                )
                .await
        };
        let (proxy_result, client_result) = tokio::join!(proxy, client);
        assert!(
            proxy_result.unwrap().is_none(),
            "TLS refusal never connected to backend"
        );
        let Err(error) = client_result else {
            panic!("certificate validation refuses handshake");
        };
        let tls_error = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<rustls::Error>());
        if expired {
            assert!(matches!(
                tls_error,
                Some(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired
                        | rustls::CertificateError::ExpiredContext { .. }
                ))
            ));
        } else if trust {
            assert!(matches!(
                tls_error,
                Some(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidForName
                        | rustls::CertificateError::NotValidForNameContext { .. }
                ))
            ));
        } else {
            assert!(matches!(
                tls_error,
                Some(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            ));
        }
        // No backend connection, challenge or allocation, and no alternate
        // plaintext attempt: the service's exact ready footprint is unchanged.
        assert_eq!(provider.in_use(), ready);
        server.stop().await.unwrap();
        drop(no_plaintext);
        assert_eq!(provider.in_use(), baseline);
    });
}

#[test]
fn tls_wrong_name_refuses_before_backend_without_plaintext_fallback() {
    rejected_tls_control("wrong.invalid", true, false);
}

#[test]
fn tls_untrusted_root_refuses_before_backend_without_plaintext_fallback() {
    rejected_tls_control("localhost", false, false);
}

#[test]
fn tls_expired_certificate_refuses_before_backend_without_plaintext_fallback() {
    rejected_tls_control("localhost", true, true);
}

#[test]
fn plaintext_stun_to_tls_listener_refuses_before_backend() {
    fixture(|scope, cleanup, provider| async move {
        let baseline = provider.in_use();
        let server = TurnServer::start_with_resource_scope(
            &tls_only_config().await,
            scope.clone(),
            cleanup.clone(),
        )
        .await
        .unwrap();
        assert_eq!(server.tcp_local_addr(), None);
        let no_plaintext = TcpListener::bind(server.local_addr())
            .await
            .expect("no plaintext TCP fallback listener");
        let ready = provider.in_use();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (server_tls, _) = tls_configs(true, false);
        let proxy =
            terminate_tls_once(listener, server_tls, server.tls_proxy_local_addr().unwrap());
        let client = async {
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            client
                .write_all(&request(METHOD_BINDING, vec![]).raw)
                .await
                .unwrap();
            let mut reply = Vec::new();
            let mut bytes = [0; 256];
            loop {
                match client.read(&mut bytes).await {
                    Ok(0) => break,
                    Ok(len) => {
                        reply.extend_from_slice(&bytes[..len]);
                        assert!(reply.len() <= 1024, "bounded TLS rejection response");
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        break
                    }
                    Err(error) => panic!("unexpected TLS rejection read: {error}"),
                }
            }
            // A TLS alert is permitted, a plaintext STUN response is not.
            if !reply.is_empty() {
                assert_eq!(reply[0], 21);
                assert!(Message::new().unmarshal_binary(&reply).is_err());
            }
        };
        let (proxy_result, ()) = tokio::join!(proxy, client);
        assert!(
            proxy_result.unwrap().is_none(),
            "plaintext never reached TURN backend"
        );
        assert_eq!(provider.in_use(), ready);
        server.stop().await.unwrap();
        drop(no_plaintext);
        assert_eq!(provider.in_use(), baseline);
    });
}

#[test]
fn tcp_authenticated_permission_channel_and_bidirectional_udp_relay() {
    fixture(|scope, cleanup, _| async move {
        let server = TurnServer::start_with_resource_scope(&config(), scope, cleanup)
            .await
            .unwrap();
        let mut client = TcpStream::connect(server.tcp_local_addr().unwrap())
            .await
            .unwrap();
        let (auth, relay) = authenticate(&mut client).await;
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let permission = auth.message(
            METHOD_CREATE_PERMISSION,
            vec![Box::new(PeerAddress {
                ip: peer_addr.ip(),
                port: peer_addr.port(),
            })],
        );
        assert_eq!(
            exchange(&mut client, &permission).await.typ,
            MessageType::new(METHOD_CREATE_PERMISSION, CLASS_SUCCESS_RESPONSE)
        );
        let channel = auth.message(
            METHOD_CHANNEL_BIND,
            vec![
                Box::new(ChannelNumber(0x4001)),
                Box::new(PeerAddress {
                    ip: peer_addr.ip(),
                    port: peer_addr.port(),
                }),
            ],
        );
        assert_eq!(
            exchange(&mut client, &channel).await.typ,
            MessageType::new(METHOD_CHANNEL_BIND, CLASS_SUCCESS_RESPONSE)
        );
        let wire = [0x40, 1, 0, 3, 9, 8, 7, 0];
        // Leave an inbound frame partial while the opposite direction moves.
        client.write_all(&wire[..2]).await.unwrap();
        peer.send_to(&[1, 2, 3], relay).await.unwrap();
        assert_eq!(read_frame(&mut client).await, vec![0x40, 1, 0, 3, 1, 2, 3]);
        client.write_all(&wire[2..]).await.unwrap();
        let mut packet = [0; 32];
        let (len, source) = peer.recv_from(&mut packet).await.unwrap();
        assert_eq!(&packet[..len], &[9, 8, 7]);
        assert_eq!(source, relay);
        server.stop().await.unwrap();
        closed(&mut client).await;
    });
}

#[test]
fn tcp_challenge_and_binding_trickle_do_not_renew_auth_deadline() {
    fixture(|scope, cleanup, _| async move {
        let mut cfg = config();
        cfg.tcp_auth_timeout_ms = 250;
        cfg.tcp_idle_timeout_ms = 5_000;
        let server = TurnServer::start_with_resource_scope(&cfg, scope, cleanup)
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        let mut client = TcpStream::connect(server.tcp_local_addr().unwrap())
            .await
            .unwrap();
        let allocate = request(
            METHOD_ALLOCATE,
            vec![Box::new(RequestedTransport {
                protocol: PROTO_UDP,
            })],
        );
        let challenge = exchange(&mut client, &allocate).await;
        let mut code = ErrorCodeAttribute::default();
        code.get_from(&challenge).unwrap();
        assert!(code.code == CODE_UNAUTHORIZED);
        let packet = request(METHOD_BINDING, vec![]).raw;
        let (mut reader, mut writer) = client.split();
        let trickle = async {
            loop {
                if writer.write_all(&packet).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let ended = async {
            let mut buffer = [0; 2048];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => return,
                    Err(error) => panic!("unexpected stream read: {error}"),
                }
            }
        };
        tokio::select! { () = trickle => {}, () = ended => {} }
        assert!(started.elapsed() >= Duration::from_millis(cfg.tcp_auth_timeout_ms));
        assert!(started.elapsed() < Duration::from_millis(cfg.tcp_idle_timeout_ms));
        server.stop().await.unwrap();
    });
}

#[test]
fn tcp_allocate_success_survives_auth_deadline_and_drop_joins_live_client() {
    fixture(|scope, cleanup, provider| async move {
        let baseline = provider.in_use();
        let mut cfg = config();
        cfg.tcp_auth_timeout_ms = 500;
        cfg.tcp_idle_timeout_ms = 5_000;
        let server = TurnServer::start_with_resource_scope(&cfg, scope, cleanup)
            .await
            .unwrap();
        let mut client = TcpStream::connect(server.tcp_local_addr().unwrap())
            .await
            .unwrap();
        authenticate(&mut client).await;
        tokio::time::sleep(Duration::from_millis(cfg.tcp_auth_timeout_ms + 20)).await;
        binding(&mut client).await; // same authenticated stream beyond its original deadline
        drop(server); // no explicit stop/retire await; outside owner still joins all clients
        closed(&mut client).await;
        while provider.in_use() != baseline {
            tokio::task::yield_now().await;
        }
    });
}

#[test]
fn tcp_provider_refusal_precedes_client_task_and_recovers_without_extra_grant() {
    fixture(|scope, cleanup, provider| async move {
        let server = TurnServer::start_with_resource_scope(&config(), scope.clone(), cleanup)
            .await
            .unwrap();
        let available_workers = 1_000_000 - provider.in_use().amount(ResourceClass::WorkerOrTask);
        let exhausted = scope
            .acquire(ResourceClaim::single(
                ResourceClass::WorkerOrTask,
                available_workers,
            ))
            .unwrap();
        let held = provider.in_use();
        let mut refused = TcpStream::connect(server.tcp_local_addr().unwrap())
            .await
            .unwrap();
        closed(&mut refused).await;
        assert_eq!(
            provider.in_use(),
            held,
            "refused client retained no task or reservation"
        );
        drop(exhausted);
        let mut admitted = TcpStream::connect(server.tcp_local_addr().unwrap())
            .await
            .unwrap();
        binding(&mut admitted).await;
        server.stop().await.unwrap();
        closed(&mut admitted).await;
    });
}

#[test]
fn proxy_only_has_no_public_plaintext_listener() {
    fixture(|scope, cleanup, _| async move {
        let mut cfg = config();
        cfg.tcp_enabled = false;
        cfg.tls_proxy_enabled = true;
        let temporary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        cfg.tls_proxy_port = temporary.local_addr().unwrap().port();
        drop(temporary);
        let server = TurnServer::start_with_resource_scope(&cfg, scope, cleanup)
            .await
            .unwrap();
        assert_eq!(server.tcp_local_addr(), None);
        let not_installed = tokio::net::TcpListener::bind(server.local_addr())
            .await
            .expect("UDP numeric port has no public TCP listener");
        let mut client = TcpStream::connect(server.tls_proxy_local_addr().unwrap())
            .await
            .unwrap();
        client
            .write_all(&proxy_header(Ipv4Addr::new(192, 0, 2, 1)))
            .await
            .unwrap();
        binding(&mut client).await;
        server.stop().await.unwrap();
        closed(&mut client).await;
        drop(not_installed);
    });
}

#[test]
fn tcp_last_handle_drop_after_origin_runtime_destruction_joins_private_children() {
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, 1_000_000)),
    )
    .unwrap();
    let provider = FiniteResourceProvider::new(grant);
    let port = ResourceProviderPort::new(provider.clone()).unwrap();
    let scope = LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap();
    let owner = ServiceCleanupOwner::new(scope.clone()).unwrap();
    let cleanup = owner.port();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (server, client) = runtime.block_on(async {
        tokio::time::timeout(GUARD, async {
            let server = TurnServer::start_with_resource_scope(&config(), scope.clone(), cleanup)
                .await
                .unwrap();
            let mut client = TcpStream::connect(server.tcp_local_addr().unwrap())
                .await
                .unwrap();
            binding(&mut client).await;
            (server, client)
        })
        .await
        .unwrap()
    });
    drop(runtime);
    drop(server); // no caller runtime, live client not closed first
    let report = owner
        .close_and_join()
        .expect("outside root joined the private worker and all TCP children");
    drop((client, scope, port));
    assert_eq!(report.completed, 1);
    assert_eq!(report.task_failures, 0);
    assert_eq!(report.worker_failures, 0);
    assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    assert_eq!(
        provider.retained_after_failed_cleanup(),
        ResourceClaim::ZERO
    );
}
