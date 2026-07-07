//! The pure-Rust discovery backend: a per-driver `mdns-sd` [`ServiceDaemon`]
//! owning its own multicast socket set (SO_REUSEADDR/SO_REUSEPORT), which
//! also lets it coexist with a system avahi/Bonjour daemon. This is the
//! pre-seam behaviour, extracted verbatim.

use std::net::IpAddr;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::mpsc;
use tracing::{debug, trace};

use super::{DiscoveryConfig, DiscoveryEvent};
use crate::Error;

pub struct Discovery {
    daemon: ServiceDaemon,
    service_info: ServiceInfo,
    fullname: String,
}

impl Discovery {
    /// Bring the daemon up, start browsing, and hand back the event stream.
    /// Browse starts before the first [`register`](Self::register) so we never
    /// miss a burst of resolves racing our own announce.
    pub fn start(
        cfg: &DiscoveryConfig,
    ) -> crate::Result<(Self, mpsc::UnboundedReceiver<DiscoveryEvent>)> {
        let daemon = ServiceDaemon::new().map_err(|e| Error::Other(format!("mdns daemon: {e}")))?;

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

        let browse_rx = daemon
            .browse(&cfg.service_type)
            .map_err(|e| Error::Other(format!("mdns browse: {e}")))?;

        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            pump(browse_rx, tx).await;
            trace!("mdns embedded browse pump exiting");
        });

        Ok((
            Discovery {
                daemon,
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
        match self.daemon.register(self.service_info.clone()) {
            Ok(()) => true,
            Err(e) => {
                debug!("mdns register failed (will retry): {e}");
                false
            }
        }
    }

    /// Withdraw the advertisement (the mDNS goodbye).
    pub fn unregister(&self) {
        let _ = self.daemon.unregister(&self.fullname);
    }

    /// Stop the daemon: closes the browse stream and every socket.
    pub fn shutdown(&self) {
        let _ = self.daemon.shutdown();
    }
}

async fn pump(
    browse_rx: mdns_sd::Receiver<ServiceEvent>,
    tx: mpsc::UnboundedSender<DiscoveryEvent>,
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
        if tx.send(out).is_err() {
            return;
        }
    }
}
