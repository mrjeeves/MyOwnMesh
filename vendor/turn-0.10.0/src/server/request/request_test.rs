use std::net::IpAddr;
use std::str::FromStr;

use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};
use util::vnet::net::*;

use super::*;
use crate::relay::relay_none::*;

const STATIC_KEY: &str = "ABC";

struct ChallengeAuth;

impl AuthHandler for ChallengeAuth {
    fn auth_handle(&self, username: &str, realm: &str, _: SocketAddr) -> Result<Vec<u8>> {
        if username == "user" && realm == "realm" {
            Ok(STATIC_KEY.as_bytes().to_vec())
        } else {
            Err(Error::ErrNoSuchUser)
        }
    }
}

fn nonce_budget() -> u64 {
    let charge = ResourceCharge::with_bytes(1, build_nonce().unwrap().capacity() as u64);
    charge.units + charge.retained_bytes.div_ceil(1024)
}

async fn challenge_fixture() -> Result<(
    Request,
    UdpSocket,
    Arc<crate::resource::BoundedTestAdmission>,
)> {
    let conn = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let allocation_manager = Arc::new(Manager::new(ManagerConfig {
        relay_addr_generator: Box::new(RelayAddressGeneratorNone {
            address: "127.0.0.1".to_owned(),
            net: Arc::new(Net::new(None)),
        }),
        alloc_close_notify: None,
        resource_admission: Arc::new(crate::resource::UnboundedTestAdmission),
        cleanup: crate::resource::CleanupStatus::new(&crate::resource::UnboundedTestAdmission)
            .expect("fixture manager cleanup"),
    }));
    let admission = Arc::new(crate::resource::BoundedTestAdmission::new(nonce_budget()));
    let mut request = Request::new(
        conn,
        client.local_addr()?,
        allocation_manager,
        Arc::new(ChallengeAuth),
    );
    request.resource_admission = Some(admission.clone());
    request.realm = "realm".to_owned();
    Ok((request, client, admission))
}

async fn receive_challenge(client: &UdpSocket, expected: ErrorCode) -> Result<String> {
    let mut bytes = [0; 1500];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut bytes))
        .await
        .expect("challenge response deadline")?;
    let mut message = Message {
        raw: bytes[..len].to_vec(),
        ..Default::default()
    };
    message.decode()?;
    let mut code = ErrorCodeAttribute::default();
    code.get_from(&message)?;
    assert!(code.code == expected, "unexpected challenge error code");
    let mut nonce = Nonce::new(ATTR_NONCE, String::new());
    nonce.get_from(&message)?;
    let mut realm = Realm::new(ATTR_REALM, String::new());
    realm.get_from(&message)?;
    assert_eq!(realm.text, "realm");
    Ok(nonce.text)
}

fn authenticated_challenge(nonce: String, key: &[u8]) -> Result<Message> {
    build_msg(
        Message::new().transaction_id,
        MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST),
        vec![
            Box::new(Username::new(ATTR_USERNAME, "user".to_owned())),
            Box::new(Realm::new(ATTR_REALM, "realm".to_owned())),
            Box::new(Nonce::new(ATTR_NONCE, nonce)),
            Box::new(MessageIntegrity(key.to_vec())),
        ],
    )
}

#[tokio::test]
async fn anonymous_challenges_reuse_one_budget_and_legitimate_authentication_survives() -> Result<()>
{
    let (mut request, client, admission) = challenge_fixture().await?;
    let anonymous = Message::new();
    let mut first = None;
    for _ in 0..64 {
        assert!(request
            .authenticate_request(&anonymous, METHOD_ALLOCATE)
            .await?
            .is_none());
        let nonce = receive_challenge(&client, CODE_UNAUTHORIZED).await?;
        if let Some((original, created)) = &first {
            assert!(original == &nonce, "challenge must be reused");
            assert!(request.nonces.lock().await.get(&nonce).unwrap().0 == *created);
        } else {
            let created = request.nonces.lock().await.get(&nonce).unwrap().0;
            first = Some((nonce, created));
        }
        assert_eq!(request.nonces.lock().await.len(), 1);
        assert_eq!(admission.remaining_for_test(), 0);
    }
    // A later legitimate client's fresh challenge still fits the same budget.
    assert!(request
        .authenticate_request(&anonymous, METHOD_ALLOCATE)
        .await?
        .is_none());
    let nonce = receive_challenge(&client, CODE_UNAUTHORIZED).await?;
    let valid = authenticated_challenge(nonce.clone(), STATIC_KEY.as_bytes())?;
    assert!(request
        .authenticate_request(&valid, METHOD_ALLOCATE)
        .await?
        .is_some());
    let invalid = authenticated_challenge(nonce, b"incorrect key")?;
    assert!(request
        .authenticate_request(&invalid, METHOD_ALLOCATE)
        .await
        .is_err());
    drop(request);
    assert_eq!(admission.remaining_for_test(), nonce_budget());
    Ok(())
}

#[tokio::test]
async fn expired_and_stale_challenges_release_before_replacement() -> Result<()> {
    let (mut request, client, admission) = challenge_fixture().await?;
    let old = request.current_nonce().await?;
    request.nonces.lock().await.get_mut(&old).unwrap().0 = Instant::now() - NONCE_LIFETIME;
    // Anonymous issuance must sweep an abandoned expired entry itself.
    assert!(request
        .authenticate_request(&Message::new(), METHOD_ALLOCATE)
        .await?
        .is_none());
    let current = receive_challenge(&client, CODE_UNAUTHORIZED).await?;
    assert!(current != old, "expired challenge must be replaced");
    assert!(!request.nonces.lock().await.contains_key(&old));
    assert_eq!(admission.remaining_for_test(), 0);
    // Presenting the old value must not consume another lease or authenticate.
    let stale = authenticated_challenge(old, STATIC_KEY.as_bytes())?;
    assert!(request
        .authenticate_request(&stale, METHOD_ALLOCATE)
        .await?
        .is_none());
    assert!(receive_challenge(&client, CODE_STALE_NONCE).await? == current);
    // Expiry on the authenticated path removes the presented entry as well.
    request.nonces.lock().await.get_mut(&current).unwrap().0 = Instant::now() - NONCE_LIFETIME;
    let stale = authenticated_challenge(current.clone(), STATIC_KEY.as_bytes())?;
    assert!(request
        .authenticate_request(&stale, METHOD_ALLOCATE)
        .await?
        .is_none());
    let replacement = receive_challenge(&client, CODE_STALE_NONCE).await?;
    assert!(
        replacement != current,
        "stale presented challenge must be replaced"
    );
    let valid = authenticated_challenge(replacement, STATIC_KEY.as_bytes())?;
    assert!(request
        .authenticate_request(&valid, METHOD_ALLOCATE)
        .await?
        .is_some());
    assert_eq!(request.nonces.lock().await.len(), 1);
    drop(request);
    assert_eq!(admission.remaining_for_test(), nonce_budget());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_challenge_issuance_funds_only_one_entry() -> Result<()> {
    let (request, _client, admission) = challenge_fixture().await?;
    let request = Arc::new(request);
    let barrier = Arc::new(tokio::sync::Barrier::new(17));
    let mut handles = Vec::new();
    for _ in 0..16 {
        let request = request.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            request.current_nonce().await
        }));
    }
    barrier.wait().await;
    let results = futures::future::join_all(handles).await;
    let expected = request.current_nonce().await?;
    for result in results {
        assert!(result.expect("issuer joined")? == expected);
    }
    assert_eq!(request.nonces.lock().await.len(), 1);
    assert_eq!(admission.remaining_for_test(), 0);
    drop(request);
    assert_eq!(admission.remaining_for_test(), nonce_budget());
    Ok(())
}

#[tokio::test]
async fn server_close_and_drop_release_shared_nonce_lease() -> Result<()> {
    use crate::resource::{BoundedTestAdmission, CleanupStatus};
    use crate::server::{
        config::{ConnConfig, ServerConfig},
        Server,
    };

    let cleanup_charge = CleanupStatus::charge().unwrap();
    let cleanup_slots = cleanup_charge.units + cleanup_charge.retained_bytes.div_ceil(1024);
    let limit = cleanup_slots + 2 + nonce_budget(); // read + command + one nonce
    for explicit_close in [true, false] {
        let admission = Arc::new(BoundedTestAdmission::new(limit));
        let conn = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let server_addr = conn.local_addr()?;
        let server = Server::new_with_resource_admission(
            ServerConfig {
                conn_configs: vec![ConnConfig {
                    conn,
                    relay_addr_generator: Box::new(RelayAddressGeneratorNone {
                        address: "127.0.0.1".to_owned(),
                        net: Arc::new(Net::new(None)),
                    }),
                }],
                realm: "realm".to_owned(),
                auth_handler: Arc::new(ChallengeAuth),
                channel_bind_timeout: Duration::ZERO,
                alloc_close_notify: None,
            },
            admission.clone(),
        )
        .await?;
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let anonymous = build_msg(
            Message::new().transaction_id,
            MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST),
            vec![],
        )?;
        client.send_to(&anonymous.raw, server_addr).await?;
        let _ = receive_challenge(&client, CODE_UNAUTHORIZED).await?;
        assert_eq!(admission.remaining_for_test(), 0);
        if explicit_close {
            server.close().await?;
            assert!(server.nonces.lock().await.is_empty());
            assert_eq!(admission.remaining_for_test(), limit - cleanup_slots);
            drop(server);
        } else {
            // Keep only join handles, not a server/map custodian. Dropping the
            // server closes its command sender; join its actual read tasks.
            let tasks = server.tasks.lock().await.take().unwrap();
            drop(server);
            let results = futures::future::join_all(tasks).await;
            for result in results {
                result.expect("dropped server read task joined")?;
            }
        }
        assert_eq!(admission.remaining_for_test(), limit);
    }
    Ok(())
}

#[tokio::test]
async fn test_allocation_lifetime_parsing() -> Result<()> {
    let lifetime = Lifetime(Duration::from_secs(5));

    let mut m = Message::new();
    let lifetime_duration = allocation_lifetime(&m);

    assert_eq!(
        lifetime_duration, DEFAULT_LIFETIME,
        "Allocation lifetime should be default time duration"
    );

    lifetime.add_to(&mut m)?;

    let lifetime_duration = allocation_lifetime(&m);
    assert_eq!(
        lifetime_duration, lifetime.0,
        "Expect lifetime_duration is {lifetime}, but {lifetime_duration:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_allocation_lifetime_overflow() -> Result<()> {
    let lifetime = Lifetime(MAXIMUM_ALLOCATION_LIFETIME * 2);

    let mut m2 = Message::new();
    lifetime.add_to(&mut m2)?;

    let lifetime_duration = allocation_lifetime(&m2);
    assert_eq!(
        lifetime_duration, DEFAULT_LIFETIME,
        "Expect lifetime_duration is {DEFAULT_LIFETIME:?}, but {lifetime_duration:?}"
    );

    Ok(())
}

struct TestAuthHandler;
impl AuthHandler for TestAuthHandler {
    fn auth_handle(&self, _username: &str, _realm: &str, _src_addr: SocketAddr) -> Result<Vec<u8>> {
        Ok(STATIC_KEY.as_bytes().to_vec())
    }
}

#[tokio::test]
async fn test_allocation_lifetime_deletion_zero_lifetime() -> Result<()> {
    //env_logger::init();

    let l = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    let allocation_manager = Arc::new(Manager::new(ManagerConfig {
        relay_addr_generator: Box::new(RelayAddressGeneratorNone {
            address: "0.0.0.0".to_owned(),
            net: Arc::new(Net::new(None)),
        }),
        alloc_close_notify: None,
        resource_admission: Arc::new(crate::resource::UnboundedTestAdmission),
        cleanup: crate::resource::CleanupStatus::new(&crate::resource::UnboundedTestAdmission)
            .expect("test cleanup admission"),
    }));

    let socket = SocketAddr::new(IpAddr::from_str("127.0.0.1")?, 5000);

    let mut r = Request::new(l, socket, allocation_manager, Arc::new(TestAuthHandler {}));

    {
        let mut nonces = r.nonces.lock().await;
        let nonce = STATIC_KEY.to_owned();
        let nonce_charge = ResourceCharge::with_bytes(
            1,
            u64::try_from(nonce.capacity()).map_err(|_| Error::ErrResourceAdmission)?,
        );
        let nonce_admission = crate::resource::BoundedTestAdmission::new(
            nonce_charge.units + nonce_charge.retained_bytes.div_ceil(1024),
        );
        let nonce_lease = nonce_admission
            .acquire(ResourceKind::Nonce, nonce_charge)
            .map_err(|_| Error::ErrResourceAdmission)?;
        nonces.insert(nonce, (Instant::now(), nonce_lease));
    }

    let five_tuple = FiveTuple {
        src_addr: r.src_addr,
        dst_addr: r.conn.local_addr()?,
        protocol: PROTO_UDP,
    };

    r.allocation_manager
        .create_allocation(
            five_tuple,
            Arc::clone(&r.conn),
            0,
            Duration::from_secs(3600),
            TextAttribute::new(ATTR_USERNAME, "user".into()),
            true,
        )
        .await?;
    assert!(r
        .allocation_manager
        .get_allocation(&five_tuple)
        .await
        .is_some());

    let mut m = Message::new();
    Lifetime::default().add_to(&mut m)?;
    MessageIntegrity(STATIC_KEY.as_bytes().to_vec()).add_to(&mut m)?;
    Nonce::new(ATTR_NONCE, STATIC_KEY.to_owned()).add_to(&mut m)?;
    Realm::new(ATTR_REALM, STATIC_KEY.to_owned()).add_to(&mut m)?;
    Username::new(ATTR_USERNAME, STATIC_KEY.to_owned()).add_to(&mut m)?;

    r.handle_refresh_request(&m).await?;
    assert!(r
        .allocation_manager
        .get_allocation(&five_tuple)
        .await
        .is_none());

    Ok(())
}
