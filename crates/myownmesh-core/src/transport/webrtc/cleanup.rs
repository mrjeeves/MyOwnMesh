//! Exact native WebRTC cleanup ownership and conservative claim retention.

use super::*;

#[derive(Clone, Debug)]
pub(super) enum ConnectorCloseStatus {
    Open,
    Closing,
    Closed,
    Failed(String),
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
    realtime_flows: SyncMutex<Option<Arc<RealtimeFlowRegistry>>>,
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
            realtime_flows: SyncMutex::new(None),
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

    pub(super) fn pending_remote_candidate_policy(&self) -> PendingRemoteCandidatePolicy {
        self.resource_owner.pending_remote_candidates()
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

    pub(super) fn attach_realtime_flows(&self, flows: Arc<RealtimeFlowRegistry>) -> bool {
        let mut current = self.realtime_flows.lock();
        if current.is_some() {
            drop(current);
            self.fail_cleanup("duplicate real-time registry owner installation".to_string());
            return false;
        }
        *current = Some(flows);
        true
    }

    pub(super) fn retire_local(&self) {
        self.ownership.retire();
        if let Some(candidates) = self.remote_candidates.lock().as_ref() {
            drain_remote_candidates(candidates);
        }
        if let Some(flows) = self.realtime_flows.lock().as_ref() {
            flows.retire();
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
                ConnectorCloseStatus::Failed(_) => {}
                ConnectorCloseStatus::Open | ConnectorCloseStatus::Closing => {
                    self.status.send_replace(ConnectorCloseStatus::Closing);
                }
            }
        }
        #[cfg(test)]
        if self.fail_background_start.load(Ordering::Acquire) {
            self.fail_cleanup("cleanup background task failed to start".to_string());
            return;
        }
        let owner = Arc::clone(self);
        if self
            .resource_owner
            .submit_cleanup(Box::pin(async move { owner.run().await }))
            .is_err()
        {
            self.fail_cleanup("process cleanup executor refused the close owner".to_string());
        }
    }

    async fn run(self: Arc<Self>) {
        let native = self.native.lock().clone();
        let Some(native) = native else {
            self.finish_closed();
            return;
        };
        self.ownership.incarnation.retire();
        self.ownership.operation_fence.wait_for_operations().await;
        match native.close().await {
            Ok(()) => self.finish_closed(),
            Err(error) => self.fail_cleanup(error.to_string()),
        }
    }

    fn finish_closed(&self) {
        let _transition = self.status_transition.lock();
        if matches!(*self.status.borrow(), ConnectorCloseStatus::Failed(_)) {
            return;
        }
        self.cleanup_complete.store(true, Ordering::Release);
        self.ownership.complete_cleanup();
        self.native.lock().take();
        self.remote_candidates.lock().take();
        self.realtime_flows.lock().take();
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
            ConnectorCloseStatus::Closed | ConnectorCloseStatus::Failed(_)
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
