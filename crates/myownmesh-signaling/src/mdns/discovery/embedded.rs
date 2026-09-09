//! One process-wide mDNS socket/cache owner. Networks retain independent
//! advertisements and subscriptions, but do not each parse and answer the
//! same multicast traffic in their own daemon thread.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Weak};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use super::{DiscoveryConfig, DiscoveryEvent};
use crate::Error;

pub struct Discovery {
    shared: Mutex<Option<Arc<Shared>>>,
    service_type: String,
    subscription: u64,
    service_info: ServiceInfo,
    fullname: String,
}

static DAEMON: LazyLock<Mutex<Weak<Shared>>> = LazyLock::new(|| Mutex::new(Weak::new()));
static NEXT_SUBSCRIPTION: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct Browser {
    subscribers: HashMap<u64, mpsc::UnboundedSender<DiscoveryEvent>>,
    cache: HashMap<String, DiscoveryEvent>,
}

impl Browser {
    fn subscribe(&mut self, id: u64, tx: mpsc::UnboundedSender<DiscoveryEvent>) {
        // Replay under the publication lock: no gap or old replay after a removal.
        for event in self.cache.values() {
            let _ = tx.send(event.clone());
        }
        self.subscribers.insert(id, tx);
    }

    fn publish(&mut self, event: DiscoveryEvent) {
        match &event {
            DiscoveryEvent::Resolved { key, .. } => {
                self.cache.insert(key.clone(), event.clone());
            }
            DiscoveryEvent::Removed { key } => {
                self.cache.remove(key);
            }
        }
        self.subscribers
            .retain(|_, tx| tx.send(event.clone()).is_ok());
    }
}

struct Shared {
    daemon: ServiceDaemon,
    browsers: Mutex<HashMap<String, Browser>>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}

impl Discovery {
    /// Bring the daemon up, start browsing, and hand back the event stream.
    /// Browse starts before the first [`register`](Self::register) so we never
    /// miss a burst of resolves racing our own announce.
    pub fn start(
        cfg: &DiscoveryConfig,
    ) -> crate::Result<(Self, mpsc::UnboundedReceiver<DiscoveryEvent>)> {
        let host_name = format!("{}.local.", cfg.instance);
        let props: std::collections::HashMap<String, String> = cfg.txt.iter().cloned().collect();
        let service_info = ServiceInfo::new(
            &cfg.service_type,
            &cfg.instance,
            &host_name,
            "",
            cfg.port,
            props,
        )
        .map_err(|e| Error::Other(format!("mdns service info: {e}")))?
        .enable_addr_auto();
        let fullname = service_info.get_fullname().to_string();

        let (tx, rx) = mpsc::unbounded_channel();
        let shared = {
            let mut singleton = DAEMON.lock();
            if let Some(shared) = singleton.upgrade() {
                shared
            } else {
                let daemon =
                    ServiceDaemon::new().map_err(|e| Error::Other(format!("mdns daemon: {e}")))?;
                let shared = Arc::new(Shared {
                    daemon,
                    browsers: Mutex::new(HashMap::new()),
                });
                *singleton = Arc::downgrade(&shared);
                shared
            }
        };
        let subscription = NEXT_SUBSCRIPTION.fetch_add(1, Ordering::Relaxed);
        {
            let mut browsers = shared.browsers.lock();
            if !browsers.contains_key(&cfg.service_type) {
                let browse_rx = shared
                    .daemon
                    .browse(&cfg.service_type)
                    .map_err(|e| Error::Other(format!("mdns browse: {e}")))?;
                browsers.insert(cfg.service_type.clone(), Browser::default());
                let weak = Arc::downgrade(&shared);
                let service_type = cfg.service_type.clone();
                tokio::spawn(async move {
                    pump(browse_rx, weak, service_type).await;
                    trace!("mdns embedded browse pump exiting");
                });
            }
            browsers
                .get_mut(&cfg.service_type)
                .unwrap()
                .subscribe(subscription, tx);
        }

        Ok((
            Discovery {
                shared: Mutex::new(Some(shared)),
                service_type: cfg.service_type.clone(),
                subscription,
                service_info,
                fullname,
            },
            rx,
        ))
    }

    /// Attempt (re-)registration — the announce. Repeats are cheap no-ops on
    /// the daemon. `false` = soft failure (e.g. no usable interface yet); the
    /// caller's re-announce tick retries.
    pub fn register(&self) -> bool {
        let shared = self.shared.lock();
        let Some(shared) = shared.as_ref() else {
            return false;
        };
        match shared.daemon.register(self.service_info.clone()) {
            Ok(()) => true,
            Err(e) => {
                debug!("mdns register failed (will retry): {e}");
                false
            }
        }
    }

    /// Withdraw the advertisement (the mDNS goodbye).
    pub fn unregister(&self) {
        if let Some(shared) = self.shared.lock().as_ref() {
            let _ = shared.daemon.unregister(&self.fullname);
        }
    }

    /// Detach this network. Only the last owner shuts down the daemon.
    pub fn shutdown(&self) {
        if let Some(shared) = self.shared.lock().take() {
            if let Some(browser) = shared.browsers.lock().get_mut(&self.service_type) {
                browser.subscribers.remove(&self.subscription);
            }
            let _ = shared.daemon.unregister(&self.fullname);
        }
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn pump(
    browse_rx: mdns_sd::Receiver<ServiceEvent>,
    shared: Weak<Shared>,
    service_type: String,
) {
    loop {
        let event = match browse_rx.recv_async().await {
            Ok(e) => e,
            // Channel closes when the daemon shuts down.
            Err(_) => return,
        };
        let out = match event {
            ServiceEvent::ServiceResolved(resolved) => {
                if !resolved.is_valid() {
                    continue;
                }
                let txt = resolved
                    .get_properties()
                    .iter()
                    .map(|p| (p.key().to_string(), p.val_str().to_string()))
                    .collect();
                DiscoveryEvent::Resolved {
                    key: resolved.get_fullname().to_string(),
                    addrs: resolved
                        .get_addresses_v4()
                        .into_iter()
                        .map(IpAddr::V4)
                        .collect(),
                    port: resolved.get_port(),
                    txt,
                }
            }
            ServiceEvent::ServiceRemoved(_ty, fullname) => {
                DiscoveryEvent::Removed { key: fullname }
            }
            _ => continue,
        };
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let mut browsers = shared.browsers.lock();
        if let Some(browser) = browsers.get_mut(&service_type) {
            browser.publish(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(key: &str) -> DiscoveryEvent {
        DiscoveryEvent::Resolved {
            key: key.into(),
            addrs: vec![],
            port: 42,
            txt: HashMap::new(),
        }
    }

    #[tokio::test]
    #[ignore = "requires permission to bind local mDNS sockets"]
    async fn networks_share_daemon_and_stopping_one_keeps_the_other_alive() {
        let cfg = DiscoveryConfig {
            service_type: "_momtest._tcp.local.".into(),
            instance: "shared-owner-one".into(),
            port: 41001,
            txt: vec![],
        };
        let (first, _) = Discovery::start(&cfg).unwrap();
        let (second, _) = Discovery::start(&DiscoveryConfig {
            instance: "shared-owner-two".into(),
            ..cfg
        })
        .unwrap();
        let owner = Arc::downgrade(first.shared.lock().as_ref().unwrap());
        assert!(Arc::ptr_eq(
            first.shared.lock().as_ref().unwrap(),
            second.shared.lock().as_ref().unwrap()
        ));
        first.shutdown();
        assert!(owner.upgrade().is_some());
        assert!(second.register());
        second.shutdown();
        // Let an in-flight pump release its short-lived owner before checking.
        tokio::task::yield_now().await;
        assert!(owner.upgrade().is_none());
    }

    #[test]
    fn shared_browse_replays_and_removes_without_losing_other_subscribers() {
        let mut browser = Browser::default();
        browser.publish(resolved("peer"));
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        browser.subscribe(1, tx1);
        browser.subscribe(2, tx2);
        assert!(matches!(
            rx1.try_recv().unwrap(),
            DiscoveryEvent::Resolved { .. }
        ));
        assert!(matches!(
            rx2.try_recv().unwrap(),
            DiscoveryEvent::Resolved { .. }
        ));
        browser.subscribers.remove(&1);
        browser.publish(DiscoveryEvent::Removed { key: "peer".into() });
        assert!(matches!(
            rx2.try_recv().unwrap(),
            DiscoveryEvent::Removed { .. }
        ));
        assert!(browser.cache.is_empty());
        let (tx3, mut rx3) = mpsc::unbounded_channel();
        browser.subscribe(3, tx3);
        assert!(rx3.try_recv().is_err());
    }
}
