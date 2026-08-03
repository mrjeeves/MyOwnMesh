//! Exact native WebRTC cleanup ownership and conservative claim retention.

use super::*;

#[derive(Clone, Debug)]
pub(super) enum ConnectorCloseStatus {
    Open,
    Closing,
    Closed,
    Failed(String),
    Unproven(String),
}

enum ConnectedClaimRetention {
    Empty,
    One(Box<crate::connector::ConnectedChannelCapability>),
    Multiple(Vec<crate::connector::ConnectedChannelCapability>),
}

impl ConnectedClaimRetention {
    fn retain_after_cleanup_failure(&mut self) {
        match self {
            Self::Empty => {}
            Self::One(capability) => capability.retain_after_cleanup_failure(),
            Self::Multiple(capabilities) => {
                for capability in capabilities {
                    capability.retain_after_cleanup_failure();
                }
            }
        }
    }
}

pub(super) type NativeCloseFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Owner-private close boundary for the native connector allocation.
/// Production wraps the existing webrtc-rs peer connection. Tests supply a
/// deterministic close result without allocating a socket-bearing peer.
pub(super) trait NativeConnectorClosePort: Send + Sync {
    fn close(&self) -> NativeCloseFuture<'_>;
}

pub(super) struct WebRtcNativeClosePort {
    pub(super) peer: Arc<RTCPeerConnection>,
}

impl NativeConnectorClosePort for WebRtcNativeClosePort {
    fn close(&self) -> NativeCloseFuture<'_> {
        Box::pin(async {
            self.peer
                .close()
                .await
                .map_err(|error| Error::Transport(format!("close: {error}")))
        })
    }
}

#[cfg(test)]
pub(super) struct WebRtcNativeCloseErrorPort {
    pub(super) peer: Arc<RTCPeerConnection>,
}

#[cfg(test)]
impl NativeConnectorClosePort for WebRtcNativeCloseErrorPort {
    fn close(&self) -> NativeCloseFuture<'_> {
        Box::pin(async {
            self.peer
                .close()
                .await
                .map_err(|error| Error::Transport(format!("close: {error}")))?;
            Err(Error::Transport(
                "injected native close failure after physical close".to_string(),
            ))
        })
    }
}

/// Single cleanup owner for one native peer connection.
pub(super) struct ConnectorCloseOwner {
    pub(super) ownership: ConnectorOwnership,
    resource_owner: MeshConnectorResourceScope,
    native: SyncMutex<Option<Arc<dyn NativeConnectorClosePort>>>,
    remote_candidates: SyncMutex<Option<Arc<SyncMutex<RemoteCandidateState>>>>,
    native_close_observation_limit: Duration,
    started: AtomicBool,
    cleanup_complete: AtomicBool,
    status: watch::Sender<ConnectorCloseStatus>,
    status_transition: SyncMutex<()>,
    connected_claims: SyncMutex<ConnectedClaimRetention>,
    #[cfg(test)]
    fail_background_start: AtomicBool,
}

impl ConnectorCloseOwner {
    pub(super) fn new(
        ownership: ConnectorOwnership,
        resource_owner: MeshConnectorResourceScope,
    ) -> Arc<Self> {
        let (status, _receiver) = watch::channel(ConnectorCloseStatus::Open);
        Arc::new(Self {
            ownership,
            resource_owner: resource_owner.clone(),
            native: SyncMutex::new(None),
            remote_candidates: SyncMutex::new(None),
            native_close_observation_limit: resource_owner.native_close_observation_limit(),
            started: AtomicBool::new(false),
            cleanup_complete: AtomicBool::new(false),
            status,
            status_transition: SyncMutex::new(()),
            connected_claims: SyncMutex::new(ConnectedClaimRetention::Empty),
            #[cfg(test)]
            fail_background_start: AtomicBool::new(false),
        })
    }

    pub(super) fn attach_native(&self, native: Arc<RTCPeerConnection>) -> bool {
        self.attach_native_port(Arc::new(WebRtcNativeClosePort { peer: native }))
    }

    pub(super) fn attach_native_port(&self, native: Arc<dyn NativeConnectorClosePort>) -> bool {
        let mut current = self.native.lock();
        if current.is_some() || self.started.load(Ordering::Acquire) {
            drop(current);
            self.resource_owner.poison_accounting();
            self.fail_cleanup("duplicate or late native peer installation".to_string());
            return false;
        }
        *current = Some(native);
        true
    }

    pub(super) fn attach_remote_candidates(
        &self,
        candidates: Arc<SyncMutex<RemoteCandidateState>>,
    ) -> bool {
        let mut current = self.remote_candidates.lock();
        if current.is_some() {
            drop(current);
            self.fail_cleanup("duplicate remote-candidate owner installation".to_string());
            return false;
        }
        *current = Some(candidates);
        true
    }

    pub(super) fn retire_local(&self) {
        self.ownership.retire();
        if let Some(candidates) = self.remote_candidates.lock().as_ref() {
            drain_remote_candidates(candidates);
        }
    }

    pub(super) fn retain_connected_claim(
        self: &Arc<Self>,
        mut capability: crate::connector::ConnectedChannelCapability,
    ) {
        let mut retained = self.connected_claims.lock();
        if self.cleanup_complete.load(Ordering::Acquire) {
            drop(capability);
            return;
        }
        if self.ownership.cleanup_failed.load(Ordering::Acquire) {
            capability.retain_after_cleanup_failure();
        }
        *retained = match std::mem::replace(&mut *retained, ConnectedClaimRetention::Empty) {
            ConnectedClaimRetention::Empty => ConnectedClaimRetention::One(Box::new(capability)),
            ConnectedClaimRetention::One(primary) => {
                trace!("native cleanup retains a duplicate connected claim");
                ConnectedClaimRetention::Multiple(vec![*primary, capability])
            }
            ConnectedClaimRetention::Multiple(mut claims) => {
                claims.push(capability);
                ConnectedClaimRetention::Multiple(claims)
            }
        };
        drop(retained);
        self.start();
    }

    pub(super) fn start(self: &Arc<Self>) {
        self.retire_local();
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        {
            let _transition = self.status_transition.lock();
            let current = self.status.borrow().clone();
            match current {
                ConnectorCloseStatus::Closed => return,
                ConnectorCloseStatus::Failed(_) | ConnectorCloseStatus::Unproven(_) => {}
                ConnectorCloseStatus::Open | ConnectorCloseStatus::Closing => {
                    self.status.send_replace(ConnectorCloseStatus::Closing);
                }
            }
        }
        let owner = Arc::clone(self);
        #[cfg(test)]
        if self.fail_background_start.load(Ordering::Acquire) {
            self.fail_cleanup("cleanup background task failed to start".to_string());
            return;
        }
        if let Err(error) = std::thread::Builder::new()
            .name("myownmesh-webrtc-close-owner".to_string())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(owner.run()),
                    Err(error) => owner.fail_cleanup(format!("build cleanup runtime: {error}")),
                }
            })
        {
            self.fail_cleanup(format!("start cleanup thread: {error}"));
        }
    }

    async fn run(self: Arc<Self>) {
        let native = self.native.lock().clone();
        let Some(native) = native else {
            self.finish_closed();
            return;
        };
        self.ownership.incarnation.retire();
        let result =
            tokio::time::timeout(self.native_close_observation_limit, native.close()).await;
        match result {
            Ok(Ok(())) => self.finish_closed(),
            Ok(Err(error)) => self.fail_cleanup(error.to_string()),
            Err(_) => self.mark_cleanup_unproven(format!(
                "native close did not complete within owner observation limit {:?}",
                self.native_close_observation_limit
            )),
        }
    }

    fn finish_closed(&self) {
        let _transition = self.status_transition.lock();
        if matches!(
            *self.status.borrow(),
            ConnectorCloseStatus::Failed(_) | ConnectorCloseStatus::Unproven(_)
        ) {
            return;
        }
        self.cleanup_complete.store(true, Ordering::Release);
        self.ownership.complete_cleanup();
        self.native.lock().take();
        self.remote_candidates.lock().take();
        *self.connected_claims.lock() = ConnectedClaimRetention::Empty;
        self.status.send_replace(ConnectorCloseStatus::Closed);
    }

    /// Retain this connector's exact cleanup claims after a known native
    /// close failure. The process aggregate remains exact, so unrelated
    /// connector slots remain admissible.
    pub(super) fn fail_cleanup(&self, reason: String) {
        let _transition = self.status_transition.lock();
        if matches!(
            *self.status.borrow(),
            ConnectorCloseStatus::Closed
                | ConnectorCloseStatus::Failed(_)
                | ConnectorCloseStatus::Unproven(_)
        ) {
            return;
        }
        self.ownership.cleanup_failed.store(true, Ordering::Release);
        self.retire_local();
        self.ownership.retain_after_cleanup_failure();
        self.connected_claims.lock().retain_after_cleanup_failure();
        self.status
            .send_replace(ConnectorCloseStatus::Failed(reason));
    }

    /// Elapsed time cannot prove that the dependency failed to close. Keep
    /// the exact connector claim consumed and report only that cleanup is no
    /// longer provable through this owner-selected observation window.
    fn mark_cleanup_unproven(&self, reason: String) {
        let _transition = self.status_transition.lock();
        if matches!(
            *self.status.borrow(),
            ConnectorCloseStatus::Closed
                | ConnectorCloseStatus::Failed(_)
                | ConnectorCloseStatus::Unproven(_)
        ) {
            return;
        }
        self.ownership.cleanup_failed.store(true, Ordering::Release);
        self.retire_local();
        self.ownership.retain_after_cleanup_failure();
        self.connected_claims.lock().retain_after_cleanup_failure();
        self.status
            .send_replace(ConnectorCloseStatus::Unproven(reason));
    }

    pub(super) async fn wait(self: &Arc<Self>) -> Result<()> {
        let mut status = self.status.subscribe();
        self.start();
        loop {
            match status.borrow().clone() {
                ConnectorCloseStatus::Closed => return Ok(()),
                ConnectorCloseStatus::Failed(error) => {
                    return Err(Error::Transport(format!(
                        "native peer cleanup failed and retained its exact claim: {error}"
                    )));
                }
                ConnectorCloseStatus::Unproven(reason) => {
                    return Err(Error::Transport(format!(
                        "native peer cleanup remains unproven and retained its exact claim: {reason}"
                    )));
                }
                ConnectorCloseStatus::Open | ConnectorCloseStatus::Closing => {}
            }
            if status.changed().await.is_err() {
                return Err(Error::Transport(
                    "native peer cleanup owner stopped".to_string(),
                ));
            }
        }
    }

    #[cfg(test)]
    pub(super) fn fail_background_start_for_test(&self) {
        self.fail_background_start.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn retained_connected_claims_for_test(&self) -> usize {
        match &*self.connected_claims.lock() {
            ConnectedClaimRetention::Empty => 0,
            ConnectedClaimRetention::One(_) => 1,
            ConnectedClaimRetention::Multiple(claims) => claims.len(),
        }
    }
}
