//! Binary codec-opaque application-flow pipe primitives.
//!
//! The control connection acknowledges the binding in JSON, then switches to
//! outbound `[u32 little-endian body length][raw body]` frames.  Inbound frames
//! are `[u32 little-endian payload length][u8 label length][raw label][raw
//! body]`; the label is copied verbatim and is never interpreted.  This module
//! deliberately has no parser for the body and no alternate flow table.
//! Outbound admission is synchronous queue admission, so the existing synchronous
//! `ClientHandle::with_realtime_flow` closure can lend the exact move-only
//! handle without holding an IPC guard across an await.

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

use myownmesh_core::realtime as core_realtime;

use super::{FrameAdmission, RealtimePipeDirection};

pub(super) enum OpaquePipeBinding {
    Outbound {
        network: String,
        flow_capability: String,
    },
    Inbound {
        network: String,
        peer: String,
    },
}

pub(super) enum OpaquePipeBindingPlan<'a> {
    Outbound {
        network: &'a str,
        flow_capability: &'a str,
    },
    Inbound {
        network: &'a str,
        peer: &'a str,
    },
}

impl OpaquePipeBindingPlan<'_> {
    pub(super) fn retained_lengths(&self) -> [usize; 2] {
        match self {
            Self::Outbound {
                network,
                flow_capability,
            } => [network.len(), flow_capability.len()],
            Self::Inbound { network, peer } => [network.len(), peer.len()],
        }
    }

    pub(super) fn build(self) -> OpaquePipeBinding {
        match self {
            Self::Outbound {
                network,
                flow_capability,
            } => OpaquePipeBinding::Outbound {
                network: network.to_owned(),
                flow_capability: flow_capability.to_owned(),
            },
            Self::Inbound { network, peer } => OpaquePipeBinding::Inbound {
                network: network.to_owned(),
                peer: peer.to_owned(),
            },
        }
    }
}

impl OpaquePipeBinding {
    pub(super) fn network(&self) -> &str {
        match self {
            Self::Outbound { network, .. } | Self::Inbound { network, .. } => network,
        }
    }
}

/// Validate the fields that bind an opaque pipe to either one exact flow or
/// one exact inbound session.  The plan retains only the coordinates needed by
/// the selected direction; peer selectors are never accepted on outbound.
pub(super) fn opaque_pipe_binding_plan<'a>(
    direction: RealtimePipeDirection,
    network: &'a str,
    peer: Option<&'a str>,
    flow_capability: Option<&'a str>,
) -> std::result::Result<OpaquePipeBindingPlan<'a>, &'static str> {
    if network.trim().is_empty() {
        return Err("opaque_pipe requires a network");
    }
    match direction {
        RealtimePipeDirection::Outbound => {
            if peer.is_some() {
                return Err(
                    "opaque_pipe outbound takes no peer: its flow_capability is the exact handle binding",
                );
            }
            let Some(flow_capability) = flow_capability else {
                return Err(
                    "opaque_pipe outbound requires flow_capability issued by opaque_flow_open",
                );
            };
            Ok(OpaquePipeBindingPlan::Outbound {
                network,
                flow_capability,
            })
        }
        RealtimePipeDirection::Inbound => {
            if flow_capability.is_some() {
                return Err(
                    "opaque_pipe inbound takes no flow_capability: it claims one session stream",
                );
            }
            let Some(peer) = peer.filter(|peer| !peer.trim().is_empty()) else {
                return Err("opaque_pipe inbound requires a peer session selector");
            };
            Ok(OpaquePipeBindingPlan::Inbound { network, peer })
        }
    }
}

const OPAQUE_FRAME_ALLOCATIONS: u64 = 1;

enum OpaqueEnqueueResult {
    Accepted,
    CapabilityGone,
    Refused(core_realtime::RealtimeRefusal),
}

fn body_len(len: u32) -> Option<usize> {
    let len = usize::try_from(len).ok()?;
    (len <= core_realtime::MAX_APPLICATION_FLOW_BODY_BYTES).then_some(len)
}

/// Read raw length-prefixed application bodies and admit each to the exact
/// flow capability held by the authenticated client.  The body is never
/// decoded or converted to text; synchronous core admission keeps the client
/// flow-table borrow entirely outside an await.
pub(super) async fn run_opaque_outbound_pipe<R>(
    net: &myownmesh_core::JoinedNetwork,
    owner: &crate::ipc::ClientHandle,
    flow_capability: &str,
    network: &str,
    reader: R,
    admission: &FrameAdmission,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    run_opaque_outbound_frames(reader, admission, |body| {
        match owner.with_realtime_flow(flow_capability, network, |flow| {
            net.send_opaque_flow(flow, body)
        }) {
            None => OpaqueEnqueueResult::CapabilityGone,
            Some(Ok(())) => OpaqueEnqueueResult::Accepted,
            Some(Err(refusal)) => OpaqueEnqueueResult::Refused(refusal),
        }
    })
    .await
}

async fn run_opaque_outbound_frames<R, F>(
    mut reader: R,
    admission: &FrameAdmission,
    mut enqueue: F,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    F: FnMut(bytes::Bytes) -> OpaqueEnqueueResult,
{
    loop {
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).await.is_err() {
            return Ok(());
        }
        let Some(len) = body_len(u32::from_le_bytes(len_buf)) else {
            warn!("opaque frame length exceeds the protocol body ceiling; dropping pipe");
            return Ok(());
        };
        let _bytes = match admission.admit(len) {
            Ok(lease) => lease,
            Err(refusal) => {
                warn!(%refusal, "opaque frame body was not admitted; dropping pipe");
                return Ok(());
            }
        };
        let _allocation = match admission.admit_allocator_residual(OPAQUE_FRAME_ALLOCATIONS) {
            Ok(lease) => lease,
            Err(refusal) => {
                warn!(%refusal, "opaque frame allocation was not admitted; dropping pipe");
                return Ok(());
            }
        };
        let mut body = vec![0u8; len];
        if reader.read_exact(&mut body).await.is_err() {
            return Ok(());
        }
        let body = bytes::Bytes::from(body);
        match enqueue(body) {
            OpaqueEnqueueResult::Accepted => {}
            OpaqueEnqueueResult::CapabilityGone => {
                debug!("opaque pipe flow capability is no longer held; dropping pipe");
                return Ok(());
            }
            OpaqueEnqueueResult::Refused(refusal) => {
                warn!(
                    code = refusal.code(),
                    "opaque body refused by core; closing pipe"
                );
                return Err(anyhow::anyhow!(
                    "opaque body refused by core: {}",
                    refusal.code()
                ));
            }
        }
    }
}

fn opaque_inbound_payload_len(label_len: usize, body_len: usize) -> Result<usize> {
    if label_len == 0 || label_len > core_realtime::MAX_REALTIME_FLOW_LABEL_BYTES {
        return Err(anyhow::anyhow!("opaque input label length is invalid"));
    }
    if body_len > core_realtime::MAX_APPLICATION_FLOW_BODY_BYTES {
        return Err(anyhow::anyhow!(
            "opaque input body length exceeds its ceiling"
        ));
    }
    1usize
        .checked_add(label_len)
        .and_then(|prefix| prefix.checked_add(body_len))
        .ok_or_else(|| anyhow::anyhow!("opaque output payload length overflow"))
}

fn append_opaque_inbound_frame(
    frame: &mut Vec<u8>,
    payload_len: usize,
    label: &[u8],
    body: &[u8],
) -> Result<()> {
    let expected = opaque_inbound_payload_len(label.len(), body.len())?;
    if payload_len != expected {
        return Err(anyhow::anyhow!("opaque output payload length changed"));
    }
    frame.extend_from_slice(
        &u32::try_from(payload_len)
            .map_err(|_| anyhow::anyhow!("opaque output payload length is not representable"))?
            .to_le_bytes(),
    );
    frame.push(
        u8::try_from(label.len())
            .map_err(|_| anyhow::anyhow!("opaque output label length is not representable"))?,
    );
    frame.extend_from_slice(label);
    frame.extend_from_slice(body);
    Ok(())
}

async fn write_opaque_inbound_frame<W>(
    writer: &mut W,
    frame: Vec<u8>,
    _frame_lease: myownmesh_core::ResourceLease,
    _allocation_lease: myownmesh_core::ResourceLease,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

/// Write raw opaque arrivals from one already-claimed exact session stream.
/// The output frame and its allocator residual are admitted before the copy is
/// built. Provider-owned arrival custody remains inside the guarded core arrival
/// value; this facade's local frame leases cover only the daemon copy and write.
pub(super) async fn run_opaque_inbound_pipe<W>(
    net: &myownmesh_core::JoinedNetwork,
    inbound: &core_realtime::RealtimeInboundStream,
    mut writer: W,
    admission: &FrameAdmission,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    loop {
        let arrival = match net.recv_opaque_flow(inbound).await {
            Ok(Some(arrival)) => arrival,
            Ok(None) => return Ok(()),
            Err(refusal) => {
                warn!(
                    code = refusal.code(),
                    "opaque inbound head is not opaque; closing pipe"
                );
                return Err(anyhow::anyhow!(
                    "opaque inbound receive refused by core: {}",
                    refusal.code()
                ));
            }
        };
        let len = arrival.bytes.len();
        if len > core_realtime::MAX_APPLICATION_FLOW_BODY_BYTES {
            warn!(
                len,
                "provider delivered an over-ceiling opaque body; dropping pipe"
            );
            return Ok(());
        }
        let payload_len = match opaque_inbound_payload_len(arrival.label.len(), len) {
            Ok(payload_len) => payload_len,
            Err(error) => {
                warn!(
                    label_len = arrival.label.len(),
                    body_len = len,
                    error = %error,
                    "provider delivered an invalid opaque flow arrival; dropping pipe"
                );
                return Ok(());
            }
        };
        let frame_len = 4usize
            .checked_add(payload_len)
            .ok_or_else(|| anyhow::anyhow!("opaque output frame length overflow"))?;
        let _bytes = match admission.admit(frame_len) {
            Ok(lease) => lease,
            Err(refusal) => {
                warn!(%refusal, "opaque output frame was not admitted; dropping pipe");
                return Ok(());
            }
        };
        let _allocation = match admission.admit_allocator_residual(OPAQUE_FRAME_ALLOCATIONS) {
            Ok(lease) => lease,
            Err(refusal) => {
                warn!(%refusal, "opaque output allocation was not admitted; dropping pipe");
                return Ok(());
            }
        };
        let mut frame = Vec::with_capacity(frame_len);
        append_opaque_inbound_frame(&mut frame, payload_len, &arrival.label, &arrival.bytes)?;
        write_opaque_inbound_frame(&mut writer, frame, _bytes, _allocation).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use tokio::io::{duplex, AsyncWriteExt};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn test_admission() -> (FrameAdmission, myownmesh_core::FiniteResourceProvider) {
        let grant = myownmesh_core::ResourceClaim::try_from_entries([
            (myownmesh_core::ResourceClass::AccountedMemoryBytes, 70_000),
            (myownmesh_core::ResourceClass::OpaqueDependencyResidual, 64),
            (myownmesh_core::ResourceClass::ParsingOrCpuWork, 1 << 20),
        ])
        .expect("opaque pipe test grant is representable");
        FrameAdmission::over_grant_probed(grant, None)
    }

    fn decode_inbound_frames(mut wire: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut decoded = Vec::new();
        while !wire.is_empty() {
            assert!(wire.len() >= 4, "truncated payload length");
            let payload_len = u32::from_le_bytes(wire[..4].try_into().unwrap()) as usize;
            wire = &wire[4..];
            assert!(wire.len() >= payload_len, "truncated payload");
            let payload = &wire[..payload_len];
            wire = &wire[payload_len..];
            assert!(!payload.is_empty(), "payload has a label length");
            let label_len = payload[0] as usize;
            assert!(label_len > 0);
            assert!(payload_len > label_len);
            let label = payload[1..1 + label_len].to_vec();
            let body = payload[1 + label_len..].to_vec();
            decoded.push((label, body));
        }
        decoded
    }

    #[test]
    fn inbound_frames_preserve_interleaved_non_utf8_labels_and_equal_bodies() {
        let body = [0, 0xff, 0x80, 1, 2];
        let labels = [vec![0, 0xff, b'A'], vec![b'B', 0x80, 0]];
        let mut wire = Vec::new();
        for label in &labels {
            let payload_len = opaque_inbound_payload_len(label.len(), body.len()).unwrap();
            let mut frame = Vec::with_capacity(4 + payload_len);
            append_opaque_inbound_frame(&mut frame, payload_len, label, &body).unwrap();
            wire.extend_from_slice(&frame);
        }

        let decoded = decode_inbound_frames(&wire[..]);
        assert_eq!(
            decoded,
            vec![
                (labels[0].clone(), body.to_vec()),
                (labels[1].clone(), body.to_vec())
            ]
        );
    }

    #[test]
    fn inbound_frame_bounds_include_zero_body_and_reject_invalid_lengths() {
        let max_label = vec![0xabu8; core_realtime::MAX_REALTIME_FLOW_LABEL_BYTES];
        let payload_len = opaque_inbound_payload_len(
            max_label.len(),
            core_realtime::MAX_APPLICATION_FLOW_BODY_BYTES,
        )
        .unwrap();
        let mut frame = Vec::with_capacity(4 + payload_len);
        let max_body = vec![0x5au8; core_realtime::MAX_APPLICATION_FLOW_BODY_BYTES];
        append_opaque_inbound_frame(&mut frame, payload_len, &max_label, &max_body).unwrap();
        assert_eq!(frame.len(), 4 + payload_len);
        assert!(
            append_opaque_inbound_frame(&mut Vec::new(), payload_len, &max_label, &[]).is_err()
        );
        assert_eq!(opaque_inbound_payload_len(1, 0).unwrap(), 2);
        assert!(opaque_inbound_payload_len(0, 0).is_err());
        assert!(
            opaque_inbound_payload_len(core_realtime::MAX_REALTIME_FLOW_LABEL_BYTES + 1, 0)
                .is_err()
        );
        assert!(
            opaque_inbound_payload_len(1, core_realtime::MAX_APPLICATION_FLOW_BODY_BYTES + 1)
                .is_err()
        );
    }

    #[tokio::test]
    async fn outbound_zero_and_max_units_are_admitted_without_body_rewrite() {
        let (mut tx, rx) = duplex(70_100);
        let max = vec![0x5au8; core_realtime::MAX_APPLICATION_FLOW_BODY_BYTES];
        tx.write_all(&0u32.to_le_bytes()).await.unwrap();
        tx.write_all(&(max.len() as u32).to_le_bytes())
            .await
            .unwrap();
        tx.write_all(&max).await.unwrap();
        tx.shutdown().await.unwrap();

        let (admission, provider) = test_admission();
        let baseline = provider.in_use();
        let mut bodies = Vec::new();
        run_opaque_outbound_frames(rx, &admission, |body| {
            bodies.push(body.to_vec());
            OpaqueEnqueueResult::Accepted
        })
        .await
        .unwrap();
        assert_eq!(bodies, vec![Vec::new(), max]);
        assert_eq!(
            provider.in_use(),
            baseline,
            "unit leases return after queue admission"
        );
    }

    #[tokio::test]
    async fn outbound_truncation_and_refusal_are_terminal_without_retry_or_leak() {
        let (mut tx, rx) = duplex(64);
        tx.write_all(&1u32.to_le_bytes()).await.unwrap();
        tx.write_all(&[7]).await.unwrap();
        tx.write_all(&1u32.to_le_bytes()).await.unwrap();
        tx.write_all(&[8]).await.unwrap();
        tx.shutdown().await.unwrap();
        let (admission, provider) = test_admission();
        let baseline = provider.in_use();
        let mut attempts = 0;
        let error = run_opaque_outbound_frames(rx, &admission, |_body| {
            attempts += 1;
            OpaqueEnqueueResult::Refused(core_realtime::RealtimeRefusal::FlowRefused)
        })
        .await
        .expect_err("the first refusal closes the pipe");
        assert!(format!("{error:#}").contains("flow_refused"));
        assert_eq!(
            attempts, 1,
            "a refused unit is never retried or followed by N+1"
        );
        assert_eq!(provider.in_use(), baseline, "refusal releases frame leases");

        let (mut tx, rx) = duplex(64);
        tx.write_all(&1u32.to_le_bytes()).await.unwrap();
        tx.write_all(&[9]).await.unwrap();
        tx.write_all(&1u32.to_le_bytes()).await.unwrap();
        tx.write_all(&[10]).await.unwrap();
        tx.shutdown().await.unwrap();
        let (admission, provider) = test_admission();
        let baseline = provider.in_use();
        let mut attempts = 0;
        run_opaque_outbound_frames(rx, &admission, |_body| {
            attempts += 1;
            OpaqueEnqueueResult::CapabilityGone
        })
        .await
        .unwrap();
        assert_eq!(attempts, 1, "a closed capability ends the pipe without N+1");
        assert_eq!(
            provider.in_use(),
            baseline,
            "capability loss releases frame leases"
        );

        let (mut tx, rx) = duplex(64);
        tx.write_all(&3u32.to_le_bytes()).await.unwrap();
        tx.write_all(&[1, 2]).await.unwrap();
        tx.shutdown().await.unwrap();
        let (admission, provider) = test_admission();
        let baseline = provider.in_use();
        let mut attempts = 0;
        run_opaque_outbound_frames(rx, &admission, |_body| {
            attempts += 1;
            OpaqueEnqueueResult::Accepted
        })
        .await
        .unwrap();
        assert_eq!(attempts, 0, "truncated body never reaches enqueue");
        assert_eq!(
            provider.in_use(),
            baseline,
            "truncated frame releases leases"
        );
    }

    #[tokio::test]
    async fn outbound_pending_body_cancellation_releases_admitted_frame() {
        let (mut tx, rx) = duplex(16);
        tx.write_all(&8u32.to_le_bytes()).await.unwrap();
        let (admission, provider) = test_admission();
        let baseline = provider.in_use();
        let task_admission = admission.clone();
        let mut future = Box::pin(async move {
            run_opaque_outbound_frames(rx, &task_admission, |_body| OpaqueEnqueueResult::Accepted)
                .await
        });
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let poll = future.as_mut().poll(&mut context);
        let held = provider
            .in_use()
            .amount(myownmesh_core::ResourceClass::AccountedMemoryBytes)
            > baseline.amount(myownmesh_core::ResourceClass::AccountedMemoryBytes);
        drop(future);
        assert!(matches!(poll, Poll::Pending));
        assert!(held, "pump reached its suspended, admitted body read");
        assert_eq!(
            provider.in_use(),
            baseline,
            "cancellation drops both frame leases"
        );
    }

    #[tokio::test]
    async fn inbound_pending_write_cancellation_releases_frame_leases() {
        let label = [0u8, 0xff, b'A'];
        let body = [0x80u8, 1, 2, 3];
        let payload_len = opaque_inbound_payload_len(label.len(), body.len()).unwrap();
        let frame_len = 4 + payload_len;
        let (admission, provider) = test_admission();
        let baseline = provider.in_use();
        let frame_lease = admission.admit(frame_len).unwrap();
        let allocation_lease = admission
            .admit_allocator_residual(OPAQUE_FRAME_ALLOCATIONS)
            .unwrap();
        let mut frame = Vec::with_capacity(frame_len);
        append_opaque_inbound_frame(&mut frame, payload_len, &label, &body).unwrap();
        let (mut writer, _reader) = duplex(1);
        let mut future = Box::pin(async move {
            write_opaque_inbound_frame(&mut writer, frame, frame_lease, allocation_lease).await
        });
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let poll = future.as_mut().poll(&mut context);
        let held = provider
            .in_use()
            .amount(myownmesh_core::ResourceClass::AccountedMemoryBytes)
            > baseline.amount(myownmesh_core::ResourceClass::AccountedMemoryBytes);
        drop(future);
        assert!(matches!(poll, Poll::Pending));
        assert!(held, "write boundary is pending with its admitted frame");
        assert_eq!(
            provider.in_use(),
            baseline,
            "cancelled write releases local frame leases"
        );
    }

    #[tokio::test]
    async fn outbound_over_ceiling_is_refused_before_enqueue() {
        let (mut tx, rx) = duplex(16);
        tx.write_all(
            &u32::try_from(core_realtime::MAX_APPLICATION_FLOW_BODY_BYTES + 1)
                .unwrap()
                .to_le_bytes(),
        )
        .await
        .unwrap();
        tx.shutdown().await.unwrap();
        let (admission, provider) = test_admission();
        let baseline = provider.in_use();
        let mut attempts = 0;
        run_opaque_outbound_frames(rx, &admission, |_body| {
            attempts += 1;
            OpaqueEnqueueResult::Accepted
        })
        .await
        .unwrap();
        assert_eq!(
            attempts, 0,
            "+1 length is rejected before body allocation/enqueue"
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "oversize refusal retains no lease"
        );
    }
}
