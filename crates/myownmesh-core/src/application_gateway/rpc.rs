//! The gateway's RPC seam: installing the one RPC owner, and the request and
//! capability operations that reach the engine through it.

use crate::resource::LocalApplicationResourceScope;

use super::{ApplicationGateway, GatewayRefusal};

impl ApplicationGateway {
    pub(crate) fn rpc_resource_scope_planning_charge() -> crate::resource::ResourceClaim {
        crate::resource::FiniteResourceProvider::scope_planning_charge()
    }

    pub(crate) fn rpc(&self) -> Option<crate::resource::FundedArc<crate::rpc::RpcInner>> {
        self.rpc.read().clone()
    }

    pub(crate) fn install_rpc(
        &self,
        candidate: crate::resource::FundedArc<crate::rpc::RpcInner>,
    ) -> Result<crate::resource::FundedArc<crate::rpc::RpcInner>, GatewayRefusal> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(GatewayRefusal::Revoked);
        }
        let mut installed = self.rpc.write();
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(GatewayRefusal::Revoked);
        }
        Ok(installed.get_or_insert(candidate).clone())
    }

    pub(crate) fn rpc_resource_scope(
        &self,
    ) -> Result<LocalApplicationResourceScope, GatewayRefusal> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(GatewayRefusal::Revoked);
        }
        self.resources.child().map_err(GatewayRefusal::Pressure)
    }

    /// File one locally-originated operation against `peer`'s exact current
    /// session, building its effect only once that session has funded it.
    ///
    /// The shape `S` supplies both the class the filing is funded under and the
    /// entry it stores, so the two cannot name different operations; the effect
    /// is built inside the session fence and past every refusal, so a caller
    /// that is refused has allocated nothing. See [`crate::rpc::PendingShape`].
    /// What comes back is the filing and the caller's own half of what was
    /// built.
    pub(crate) fn register_rpc_request_prepared<S: crate::rpc::PendingShape>(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
    ) -> Result<(crate::rpc::LocalRequest, S::Caller), crate::rpc::RpcRegistrationRefusal> {
        let owner = state
            .peers
            .owner(peer)
            .ok_or(crate::rpc::RpcRegistrationRefusal::SessionNotCurrent)?;
        state
            .peers
            .with_live_session_state(
                &owner,
                state.session_broker.as_ref(),
                &state.mesh_context_id().to_string(),
                |session, app| {
                    app.rpc_mut()
                        .register_local_request_prepared::<S>(peer, session)
                },
            )
            .ok_or(crate::rpc::RpcRegistrationRefusal::SessionNotCurrent)?
    }

    /// [`Self::register_rpc_request_prepared`] for a control that already holds
    /// its effect. Test-only, for the reason given there.
    #[cfg(test)]
    pub(crate) fn register_rpc_request(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        effect: crate::rpc::PendingEntry,
    ) -> Result<crate::rpc::LocalRequest, crate::rpc::RpcRegistrationRefusal> {
        let owner = state
            .peers
            .owner(peer)
            .ok_or(crate::rpc::RpcRegistrationRefusal::SessionNotCurrent)?;
        state
            .peers
            .with_live_session_state(
                &owner,
                state.session_broker.as_ref(),
                &state.mesh_context_id().to_string(),
                |session, app| app.rpc_mut().register_local_request(peer, session, effect),
            )
            .ok_or(crate::rpc::RpcRegistrationRefusal::SessionNotCurrent)?
    }

    pub(crate) fn abandon_rpc_request(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        filed: &crate::rpc::LocalRequest,
    ) {
        let Some(owner) = state.peers.owner(peer) else {
            return;
        };
        let _ = state.peers.with_live_session_state(
            &owner,
            state.session_broker.as_ref(),
            &state.mesh_context_id().to_string(),
            |_session, app| app.rpc_mut().abandon_local_request(filed),
        );
    }

    pub(crate) async fn send_rpc_request(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        request: crate::protocol::rpc::RpcRequestMessage,
    ) -> crate::error::Result<()> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        state
            .cmd_tx
            .send(crate::engine::state::NetworkCmd::SendRpcRequest {
                peer: peer.to_string(),
                request,
                reply,
            })
            .map_err(|error| error.into_admission_error())?;
        rx.await
            .map_err(|_| crate::error::Error::Network("engine dropped reply".into()))?
    }
}
