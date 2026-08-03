//! Capability boundary for one bounded connection attempt.
//!
//! The attempt owner admits connector candidates before allocation, retires
//! losing work, and transfers an exact child claim when a candidate connects.

use std::collections::HashMap;
use std::future::Future;
use std::num::{NonZeroU64, NonZeroUsize};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

use crate::resource::{PreAuthResourceFamily, ResourceUse, PRE_AUTH_RESOURCE_FAMILY_COUNT};

use super::RuntimeIncarnation;

mod admission;
mod lifetime;
pub(crate) use admission::admit_single_connector_candidate;
use admission::ConnectorCandidateReservation;
pub use admission::{ConnectorCandidateCapability, PreAuthAttemptPermit};
use lifetime::AttemptOwnership;
pub(crate) use lifetime::{AttemptLifetime, AttemptLiveness};

mod policy;
mod resource_owner;
pub use policy::*;
pub use resource_owner::*;

/// One componentwise resource vector indexed by the closed pre-authentication
/// family set.
///
/// A resource quantity in one family cannot cover another family. This value
/// is local, non-serializable accounting state. It does not select or imply any
/// production capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreAuthResourceClaim {
    by_family: [ResourceUse; PRE_AUTH_RESOURCE_FAMILY_COUNT],
}

impl PreAuthResourceClaim {
    const ZERO: Self = Self {
        by_family: [ResourceUse::ZERO; PRE_AUTH_RESOURCE_FAMILY_COUNT],
    };

    #[allow(
        dead_code,
        reason = "Arc 03 production claims wait for owner-approved measurements"
    )]
    fn single(family: PreAuthResourceFamily, use_: ResourceUse) -> Self {
        let mut claim = Self::ZERO;
        claim.by_family[family.index()] = use_;
        claim
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        let mut combined = Self::ZERO;
        for family in PreAuthResourceFamily::ALL {
            let index = family.index();
            combined.by_family[index] =
                self.by_family[index].checked_add(other.by_family[index])?;
        }
        Some(combined)
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        let mut remainder = Self::ZERO;
        for family in PreAuthResourceFamily::ALL {
            let index = family.index();
            remainder.by_family[index] =
                self.by_family[index].checked_sub(other.by_family[index])?;
        }
        Some(remainder)
    }

    #[cfg(test)]
    fn componentwise_max(self, other: Self) -> Self {
        let mut maximum = Self::ZERO;
        for family in PreAuthResourceFamily::ALL {
            let index = family.index();
            let left = self.by_family[index];
            let right = other.by_family[index];
            maximum.by_family[index] = ResourceUse::observed(
                left.items().max(right.items()),
                left.logical_bytes().max(right.logical_bytes()),
                left.retained_bytes().max(right.retained_bytes()),
                left.tasks().max(right.tasks()),
            );
        }
        maximum
    }

    #[cfg(test)]
    fn for_family(self, family: PreAuthResourceFamily) -> ResourceUse {
        self.by_family[family.index()]
    }
}

/// Resource claim for exactly one connector candidate.
///
/// This type establishes only the cardinality that is independent of owner
/// policy: one connector candidate owns one transport object. It does not
/// decide the remaining per-family quantities or any production capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnectorCandidateResourceClaim {
    opening: PreAuthResourceClaim,
    connected: PreAuthResourceClaim,
}

impl ConnectorCandidateResourceClaim {
    #[allow(
        dead_code,
        reason = "production construction waits for owner-approved per-family measurements"
    )]
    fn checked(opening: PreAuthResourceClaim, connected: PreAuthResourceClaim) -> Option<Self> {
        let opening_transport = opening.by_family[PreAuthResourceFamily::TransportObject.index()];
        let connected_transport =
            connected.by_family[PreAuthResourceFamily::TransportObject.index()];
        (opening_transport.items() == 1 && connected_transport.items() == 1)
            .then_some(Self { opening, connected })
    }

    /// The mechanically fixed Arc 03 claim. It describes the one native peer
    /// connection and one connector-construction operation whose ownership
    /// this arc can prove. It is not a complete WebRTC allocation budget and
    /// does not select a process-wide admission limit.
    pub(crate) fn exact_connector_floor() -> Self {
        let transport = PreAuthResourceClaim::single(
            PreAuthResourceFamily::TransportObject,
            ResourceUse::observed(1, 0, 0, 0),
        );
        let mut opening = transport;
        opening.by_family[PreAuthResourceFamily::ConnectorSpecificWork.index()] =
            ResourceUse::observed(1, 0, 0, 0);
        opening.by_family[PreAuthResourceFamily::Task.index()] = ResourceUse::observed(1, 0, 0, 1);
        let mut connected = transport;
        connected.by_family[PreAuthResourceFamily::Task.index()] =
            ResourceUse::observed(1, 0, 0, 1);
        Self { opening, connected }
    }

    #[cfg(test)]
    fn aggregate_capacity(self) -> PreAuthResourceClaim {
        self.opening.componentwise_max(self.connected)
    }
}

/// One live child claim against an attempt's aggregate reservation.
///
/// Dropping the child returns its claim. This guard is created before the
/// allocation closure runs, so a candidate cannot consume resources first and
/// ask for accounting afterward.
#[cfg(test)]
fn candidate_capacity(items: u64) -> PreAuthResourceClaim {
    PreAuthResourceClaim::single(
        PreAuthResourceFamily::TransportObject,
        ResourceUse::observed(items, 0, 0, 0),
    )
}

#[cfg(test)]
fn candidate_claim() -> ConnectorCandidateResourceClaim {
    ConnectorCandidateResourceClaim::checked(candidate_capacity(1), candidate_capacity(1))
        .expect("one transport object is one connector candidate")
}

#[cfg(test)]
pub(crate) fn connector_candidate_for_test(
    runtime: RuntimeIncarnation,
) -> (ConnectorCandidateCapability, AttemptLifetime) {
    let claim = candidate_claim();
    let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, claim.aggregate_capacity());
    let capability = permit
        .allocate_connector_candidate(claim, || ())
        .map(|(capability, ())| capability)
        .expect("the fixture aggregate admits its exact fixture claim");
    (capability, lifetime)
}

#[cfg(test)]
pub(crate) fn two_connector_candidates_for_test(
    runtime: RuntimeIncarnation,
) -> (
    ConnectorCandidateCapability,
    ConnectorCandidateCapability,
    AttemptLifetime,
) {
    let claim = candidate_claim();
    let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, candidate_capacity(2));
    let first = permit
        .allocate_connector_candidate(claim, || ())
        .map(|(capability, ())| capability)
        .expect("the fixture aggregate admits its first candidate");
    let second = permit
        .allocate_connector_candidate(claim, || ())
        .map(|(capability, ())| capability)
        .expect("the fixture aggregate admits its second candidate");
    (first, second, lifetime)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explicit_test_policy(max_active_candidates: usize) -> ConnectorResourcePolicy {
        let one = NonZeroUsize::new(1).expect("fixture value is nonzero");
        let callbacks = ConnectorCallbackPolicy::new(
            ConnectorCallbackMailboxCapacities::new(one, one),
            ConnectorCallbackServiceWeights::data_only(one, one),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect("fixture data-only callback policy is valid");
        ConnectorResourcePolicy::new(
            NonZeroUsize::new(max_active_candidates).expect("fixture connector bound is nonzero"),
            callbacks,
            PendingRemoteCandidatePolicy::new(one, one),
        )
    }

    fn explicit_realtime_test_policy(max_outbound_flows: usize) -> ConnectorResourcePolicy {
        let one = NonZeroUsize::new(1).expect("fixture value is nonzero");
        let two = NonZeroUsize::new(2).expect("fixture value is nonzero");
        let three = NonZeroUsize::new(3).expect("fixture value is nonzero");
        let flows = ConnectorRealtimeFlowPolicy::new(
            ConnectorRealtimeFlowCapacities::new(
                one,
                NonZeroUsize::new(max_outbound_flows)
                    .expect("fixture outbound flow ceiling is nonzero"),
                one,
            ),
            ConnectorRealtimeInboundLimits::new(one, one, one),
            ConnectorRealtimeByteBudgets::new(two, one, three),
            RealtimeQueueOverflowRule::DropNewest,
        );
        let realtime = RealtimeConnectorPolicy::enabled(one, flows)
            .expect("fixture real-time policy is structurally valid");
        let callbacks = ConnectorCallbackPolicy::new(
            ConnectorCallbackMailboxCapacities::new(one, one),
            ConnectorCallbackServiceWeights::new(one, one, one),
            realtime,
        )
        .expect("fixture callback policy is valid");
        ConnectorResourcePolicy::new(one, callbacks, PendingRemoteCandidatePolicy::new(one, one))
    }

    #[test]
    fn v4_arc03g_generic_realtime_policy_does_not_request_media_tracks() {
        assert_eq!(explicit_realtime_test_policy(1).legacy_media(), None);
    }

    #[test]
    fn v4_arc03g_legacy_video_and_audio_require_two_preprovisioned_flows() {
        let one = NonZeroUsize::new(1).expect("fixture value is nonzero");
        let profile = LegacyWebRtcMediaProfile::h264_opus(one, 1, 1, Duration::ZERO)
            .expect("one lane per compatibility kind is representable");
        assert_eq!(
            explicit_realtime_test_policy(1)
                .with_legacy_webrtc_media(profile)
                .expect_err("one outbound flow cannot pre-provision both compatibility kinds"),
            ConnectorCallbackPolicyError::LegacyMediaExceedsOutboundFlowCeiling {
                required_flows: 2,
                available_flows: 1,
            }
        );
    }

    #[test]
    fn v4_arc03d_process_root_shares_one_connector_limit_across_mesh_runtimes() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        let policy = explicit_test_policy(1);
        root.install_connector_policy(policy)
            .expect("first Mesh runtime installs the policy");
        let mesh_policy = MeshConnectorResourcePolicy::new(
            NonZeroUsize::new(1).expect("fixture Mesh ceiling is nonzero"),
        );
        let first_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("process owner issues the first Mesh scope");
        let second_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("process owner issues the second Mesh scope");
        let claim = candidate_claim();
        let (first_attempt, _first_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), first_scope);
        let first = first_attempt
            .reserve_connector_candidate(claim)
            .expect("first Mesh runtime consumes the process slot");
        let (second_attempt, _second_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), second_scope);
        assert!(second_attempt.reserve_connector_candidate(claim).is_none());
        drop(first);
        assert!(second_attempt.reserve_connector_candidate(claim).is_some());
    }

    #[test]
    fn v4_arc03e_mesh_scope_requires_the_single_installed_process_owner() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        let error = match root.issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(
            NonZeroUsize::new(1).expect("fixture Mesh ceiling is nonzero"),
        )) {
            Ok(_) => panic!("an ownerless process cannot issue a Mesh connector scope"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            MeshConnectorResourceScopeIssueError::ProcessPolicyMissing
        );
    }

    #[test]
    fn v4_arc03e_mesh_ceiling_isolates_children_inside_the_process_cap() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_connector_policy(explicit_test_policy(3))
            .expect("fixture installs the process policy");
        let first_scope = root
            .issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(
                NonZeroUsize::new(1).expect("fixture first Mesh ceiling is nonzero"),
            ))
            .expect("process owner issues the first Mesh scope");
        let second_scope = root
            .issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(
                NonZeroUsize::new(3).expect("fixture second Mesh ceiling is nonzero"),
            ))
            .expect("process owner issues the second Mesh scope");
        let (first_attempt, _first_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), first_scope.clone());
        let (second_attempt, _second_lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            second_scope.clone(),
        );
        let claim = candidate_claim();

        let first = first_attempt
            .reserve_connector_candidate(claim)
            .expect("first Mesh uses its one explicit slot");
        assert!(
            first_attempt.reserve_connector_candidate(claim).is_none(),
            "the first Mesh cannot consume free process capacity above its child ceiling"
        );
        let second_a = second_attempt
            .reserve_connector_candidate(claim)
            .expect("second Mesh uses the second process slot");
        let second_b = second_attempt
            .reserve_connector_candidate(claim)
            .expect("second Mesh uses the third process slot");
        assert!(
            second_attempt.reserve_connector_candidate(claim).is_none(),
            "combined children cannot exceed the process cap"
        );

        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            3
        );
        assert_eq!(first_scope.report().active_candidates, 1);
        assert_eq!(second_scope.report().active_candidates, 2);

        drop(first);
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            2
        );
        assert_eq!(first_scope.report().active_candidates, 0);
        assert!(second_attempt.reserve_connector_candidate(claim).is_some());
        drop(second_a);
        drop(second_b);
    }

    #[test]
    fn v4_arc03e_failed_cleanup_retains_the_exact_process_and_mesh_claim() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_connector_policy(explicit_test_policy(2))
            .expect("fixture installs the process policy");
        let first_scope = root
            .issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(
                NonZeroUsize::new(1).expect("fixture first Mesh ceiling is nonzero"),
            ))
            .expect("process owner issues the first Mesh scope");
        let second_scope = root
            .issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(
                NonZeroUsize::new(2).expect("fixture second Mesh ceiling is nonzero"),
            ))
            .expect("process owner issues the second Mesh scope");
        let (first_attempt, _first_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), first_scope.clone());
        let (second_attempt, _second_lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            second_scope.clone(),
        );
        let claim = candidate_claim();

        let mut failed = first_attempt
            .reserve_connector_candidate(claim)
            .expect("first Mesh reserves its exact candidate");
        failed.retain_after_cleanup_failure();
        drop(failed);

        let process_report = root.connector_resource_owner().unwrap().report();
        let first_report = first_scope.report();
        assert_eq!(process_report.active_candidates, 1);
        assert_eq!(process_report.failed_cleanup_candidates, 1);
        assert_eq!(first_report.active_candidates, 1);
        assert_eq!(first_report.failed_cleanup_candidates, 1);
        assert!(!process_report.accounting_poisoned);
        assert!(!first_report.accounting_poisoned);
        assert!(first_attempt.reserve_connector_candidate(claim).is_none());

        let other = second_attempt
            .reserve_connector_candidate(claim)
            .expect("unrelated Mesh can use the remaining process slot");
        assert!(second_attempt.reserve_connector_candidate(claim).is_none());
        drop(other);
        assert_eq!(second_scope.report().active_candidates, 0);
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            1
        );
    }

    #[test]
    fn v4_arc03e_final_failed_cleanup_scope_drop_keeps_unrelated_capacity_usable() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_connector_policy(explicit_test_policy(2))
            .expect("fixture installs the process policy");
        let mesh_policy = MeshConnectorResourcePolicy::new(
            NonZeroUsize::new(1).expect("fixture Mesh ceiling is nonzero"),
        );
        let retained_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("process owner issues the retained Mesh scope");
        let (retained_attempt, retained_lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            retained_scope.clone(),
        );
        let mut failed = retained_attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("retained Mesh reserves its exact candidate");
        failed.retain_after_cleanup_failure();
        drop(failed);
        drop(retained_attempt);
        drop(retained_lifetime);
        drop(retained_scope);

        let retained_report = root.connector_resource_owner().unwrap().report();
        assert_eq!(retained_report.active_candidates, 1);
        assert_eq!(retained_report.failed_cleanup_candidates, 1);
        assert!(!retained_report.accounting_poisoned);

        let unrelated_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("retained cleanup does not poison scope issuance");
        let (unrelated_attempt, _unrelated_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), unrelated_scope);
        let unrelated = unrelated_attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("unrelated Mesh uses the remaining process slot");
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            2
        );
        drop(unrelated);
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            1
        );
        assert!(
            !root
                .connector_resource_owner()
                .unwrap()
                .report()
                .accounting_poisoned
        );
    }

    #[test]
    fn v4_arc03e_concurrent_children_never_oversubscribe_either_ceiling() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_connector_policy(explicit_test_policy(3))
            .expect("fixture installs the process policy");
        let mesh_policy = MeshConnectorResourcePolicy::new(
            NonZeroUsize::new(2).expect("fixture Mesh ceiling is nonzero"),
        );
        let first_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("process owner issues the first Mesh scope");
        let second_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("process owner issues the second Mesh scope");
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut workers = Vec::new();
        for index in 0..8 {
            let scope = if index % 2 == 0 {
                first_scope.clone()
            } else {
                second_scope.clone()
            };
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                scope.reserve(candidate_claim().opening)
            }));
        }
        barrier.wait();
        let reservations: Vec<_> = workers
            .into_iter()
            .filter_map(|worker| worker.join().expect("admission worker joins"))
            .collect();

        assert_eq!(reservations.len(), 3);
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            3
        );
        assert!(first_scope.report().active_candidates <= 2);
        assert!(second_scope.report().active_candidates <= 2);
        drop(reservations);
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            0
        );
        assert_eq!(first_scope.report().active_candidates, 0);
        assert_eq!(second_scope.report().active_candidates, 0);
    }

    #[test]
    #[ignore = "owner-run observation; requires only multi-Mesh workload-shape inputs"]
    fn v4_arc03f_measure_multi_mesh_connector_scopes_without_selecting_a_budget() {
        fn workload_nonzero(name: &str) -> NonZeroUsize {
            std::env::var(name)
                .unwrap_or_else(|_| panic!("observation scenario supplies {name}"))
                .parse::<usize>()
                .ok()
                .and_then(NonZeroUsize::new)
                .unwrap_or_else(|| panic!("{name} must be a nonzero integer"))
        }

        let mesh_count = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_MESHES");
        let candidates_per_mesh = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_CANDIDATES_PER_MESH");
        let process_candidates = mesh_count
            .get()
            .checked_mul(candidates_per_mesh.get())
            .and_then(NonZeroUsize::new)
            .expect("finite observation workload fits usize");
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_connector_policy(explicit_test_policy(process_candidates.get()))
            .expect("observation installs its derived finite process envelope");

        let mut scopes = Vec::with_capacity(mesh_count.get());
        let mut reservations = Vec::with_capacity(process_candidates.get());
        let mut lifetimes = Vec::with_capacity(mesh_count.get());
        for mesh_index in 0..mesh_count.get() {
            let scope = root
                .issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(candidates_per_mesh))
                .expect("observation issues one exact Mesh child scope");
            let (attempt, lifetime) =
                PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scope.clone());
            for candidate_index in 0..candidates_per_mesh.get() {
                reservations.push(
                    attempt
                        .reserve_connector_candidate(candidate_claim())
                        .expect("derived observation envelope admits requested candidate"),
                );
                println!(
                    "arc03_multi_mesh_raw mesh_index={mesh_index} candidate_index={candidate_index} mesh_active={} process_active={}",
                    scope.report().active_candidates,
                    root.connector_resource_owner()
                        .expect("process owner remains installed")
                        .report()
                        .active_candidates,
                );
            }
            scopes.push(scope);
            lifetimes.push(lifetime);
        }

        assert_eq!(
            root.connector_resource_owner()
                .expect("process owner remains installed")
                .report()
                .active_candidates,
            process_candidates.get()
        );
        drop(reservations);
        assert_eq!(
            root.connector_resource_owner()
                .expect("process owner remains installed")
                .report()
                .active_candidates,
            0
        );
        assert!(scopes
            .iter()
            .all(|scope| scope.report().active_candidates == 0));
        drop(lifetimes);
    }

    #[test]
    fn v4_arc03d_process_root_rejects_a_conflicting_policy() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        let installed = explicit_test_policy(1);
        let requested = explicit_test_policy(2);
        root.install_connector_policy(installed)
            .expect("fixture installs its first policy");
        let error = match root.install_connector_policy(requested) {
            Ok(_) => panic!("a live process root cannot split its connector limit"),
            Err(error) => error,
        };
        assert_eq!(error.installed, installed);
        assert_eq!(error.requested, requested);
    }

    #[test]
    fn v4_arc03d_concurrent_process_policy_installation_has_one_winner() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        let first_policy = explicit_test_policy(1);
        let second_policy = explicit_test_policy(2);
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let first_root = root.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            first_root.install_connector_policy(first_policy)
        });
        let second_root = root.clone();
        let second_barrier = Arc::clone(&barrier);
        let second = std::thread::spawn(move || {
            second_barrier.wait();
            second_root.install_connector_policy(second_policy)
        });

        barrier.wait();
        let first_result = first.join().expect("first installer joins");
        let second_result = second.join().expect("second installer joins");
        assert_ne!(first_result.is_ok(), second_result.is_ok());

        let installed = root
            .connector_resource_owner()
            .expect("one concurrent installer owns the root")
            .policy();
        for result in [first_result, second_result] {
            match result {
                Ok(owner) => assert_eq!(owner.policy(), installed),
                Err(conflict) => {
                    assert_eq!(conflict.installed, installed);
                    assert_ne!(conflict.requested, installed);
                }
            }
        }
    }

    #[test]
    fn v4_arc03d_callback_policy_rejects_runtime_panicking_capacity() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let unsupported = NonZeroUsize::new(
            tokio::sync::Semaphore::MAX_PERMITS
                .checked_add(1)
                .expect("Tokio's maximum is below usize::MAX"),
        )
        .expect("the unsupported fixture is nonzero");

        let error = ConnectorCallbackPolicy::new(
            ConnectorCallbackMailboxCapacities::new(unsupported, one),
            ConnectorCallbackServiceWeights::data_only(one, one),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect_err("policy construction rejects a capacity that mpsc::channel would panic on");

        assert!(matches!(
            error,
            ConnectorCallbackPolicyError::MailboxCapacityExceedsRuntimeLimit {
                class: "control",
                requested,
                maximum,
            } if requested == tokio::sync::Semaphore::MAX_PERMITS + 1
                && maximum == tokio::sync::Semaphore::MAX_PERMITS
        ));
    }

    #[test]
    fn v4_arc03f_realtime_policy_rejects_vectors_that_cannot_hold_one_assembly() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let four = NonZeroUsize::new(4).expect("four is nonzero");
        let seven = NonZeroUsize::new(7).expect("seven is nonzero");
        let flows = ConnectorRealtimeFlowPolicy::new(
            ConnectorRealtimeFlowCapacities::new(one, one, one),
            ConnectorRealtimeInboundLimits::new(four, one, one),
            ConnectorRealtimeByteBudgets::new(seven, four, NonZeroUsize::new(11).unwrap()),
            RealtimeQueueOverflowRule::DropNewest,
        );
        assert!(matches!(
            RealtimeConnectorPolicy::enabled(four, flows),
            Err(
                ConnectorCallbackPolicyError::AccountedBytesCannotHoldOneAssembly {
                    required_bytes: 8,
                    available_bytes: 7,
                }
            )
        ));
    }

    #[test]
    fn v4_arc03f_realtime_policy_rejects_fragment_limit_above_unit_limit() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let four = NonZeroUsize::new(4).expect("four is nonzero");
        let five = NonZeroUsize::new(5).expect("five is nonzero");
        let eight = NonZeroUsize::new(8).expect("eight is nonzero");
        let flows = ConnectorRealtimeFlowPolicy::new(
            ConnectorRealtimeFlowCapacities::new(one, one, one),
            ConnectorRealtimeInboundLimits::new(five, one, one),
            ConnectorRealtimeByteBudgets::new(
                eight,
                four,
                NonZeroUsize::new(12).expect("twelve is nonzero"),
            ),
            RealtimeQueueOverflowRule::DropNewest,
        );
        assert!(matches!(
            RealtimeConnectorPolicy::enabled(four, flows),
            Err(ConnectorCallbackPolicyError::InboundFragmentExceedsUnit {
                fragment_bytes: 5,
                unit_bytes: 4,
            })
        ));
    }

    #[test]
    fn v4_arc02_attempt_issues_multiple_candidate_children_from_one_aggregate() {
        let runtime = crate::runtime::runtime_for_test();
        let one = candidate_claim();
        let two = candidate_capacity(2);
        let (permit, _lifetime) = PreAuthAttemptPermit::admitted(runtime.clone(), two);
        let (first, first_value) = permit
            .allocate_connector_candidate(one, || "first")
            .expect("first child fits");
        let (second, second_value) = permit
            .allocate_connector_candidate(one, || "second")
            .expect("second child fits");

        assert_eq!(first_value, "first");
        assert_eq!(second_value, "second");
        assert!(first.runtime().is_same(&runtime));
        assert!(first.is_live());
        assert!(first.belongs_to(&permit));
        assert!(second.belongs_to(&permit));
        assert_eq!(permit.aggregate.active(), two);
        assert!(permit
            .allocate_connector_candidate(one, || "third")
            .is_none());

        fn accepts_candidate(_: ConnectorCandidateCapability) {}
        accepts_candidate(first);
        assert_eq!(permit.aggregate.active(), one.opening);
        accepts_candidate(second);
        assert_eq!(permit.aggregate.active(), PreAuthResourceClaim::ZERO);
    }

    #[test]
    fn v4_arc02_candidate_allocation_runs_only_after_child_reservation() {
        let one = candidate_claim();
        let (permit, _lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            one.aggregate_capacity(),
        );
        let (first, saw_active) = permit
            .allocate_connector_candidate(one, || permit.aggregate.active())
            .expect("fixture child fits");
        assert_eq!(saw_active, one.opening);

        let allocation_called = std::cell::Cell::new(false);
        let refused = permit.allocate_connector_candidate(one, || allocation_called.set(true));
        assert!(refused.is_none());
        assert!(!allocation_called.get());
        drop(first);
    }

    #[test]
    fn v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed() {
        let child_claim = candidate_claim();
        let aggregate_capacity = candidate_capacity(2);
        let corrupted_active = PreAuthResourceClaim::ZERO;
        let (permit, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), aggregate_capacity);
        let (first, ()) = permit
            .allocate_connector_candidate(child_claim, || ())
            .expect("first child fits");
        let (second, ()) = permit
            .allocate_connector_candidate(child_claim, || ())
            .expect("second child fits");
        assert_eq!(permit.aggregate.active(), aggregate_capacity);

        permit.aggregate.corrupt_active_for_test(corrupted_active);
        drop(first);

        assert!(permit.aggregate.is_poisoned());
        assert_eq!(permit.aggregate.active(), corrupted_active);
        assert!(permit.resource_scope.report().accounting_poisoned);
        let allocation_called = std::cell::Cell::new(false);
        assert!(permit
            .allocate_connector_candidate(child_claim, || allocation_called.set(true))
            .is_none());
        assert!(!allocation_called.get());

        drop(second);
        assert!(permit.aggregate.is_poisoned());
        assert_eq!(permit.aggregate.active(), corrupted_active);
    }

    #[test]
    fn v4_arc03_attempt_retirement_invalidates_every_connector_candidate() {
        let runtime = crate::runtime::runtime_for_test();
        let one = candidate_claim();
        let two = candidate_capacity(2);
        let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, two);
        let (first, ()) = permit
            .allocate_connector_candidate(one, || ())
            .expect("first connector candidate fits");
        let (second, ()) = permit
            .allocate_connector_candidate(one, || ())
            .expect("second connector candidate fits");

        assert!(first.is_live());
        assert!(second.is_live());
        lifetime.retire();
        assert!(!first.is_live());
        assert!(!second.is_live());
    }

    #[test]
    fn v4_arc03_retired_attempt_refuses_later_candidate_allocation() {
        let one = candidate_claim();
        let (permit, lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            one.aggregate_capacity(),
        );
        lifetime.retire();
        let allocation_called = std::cell::Cell::new(false);

        assert!(permit
            .allocate_connector_candidate(one, || allocation_called.set(true))
            .is_none());
        assert!(!allocation_called.get());
        assert_eq!(permit.aggregate.active(), PreAuthResourceClaim::ZERO);
    }

    #[test]
    fn v4_arc03_attempt_retirement_signal_replays_to_late_subscriber() {
        let (candidate, lifetime) =
            connector_candidate_for_test(crate::runtime::runtime_for_test());
        let liveness = candidate.liveness();
        lifetime.retire();

        assert!(!liveness.is_active());
        assert!(*liveness.subscribe_retirement().borrow());
    }

    #[test]
    fn v4_arc03_promotion_and_retirement_have_one_linearized_order() {
        let (candidate, lifetime) =
            connector_candidate_for_test(crate::runtime::runtime_for_test());
        let lifetime = Arc::new(lifetime);
        let (promotion_entered_tx, promotion_entered_rx) = std::sync::mpsc::channel();
        let (release_promotion_tx, release_promotion_rx) = std::sync::mpsc::channel();
        let promotion = std::thread::spawn(move || {
            candidate.promote_if_live(|candidate| {
                promotion_entered_tx
                    .send(())
                    .expect("test observes promotion inside transition");
                release_promotion_rx
                    .recv()
                    .expect("test releases promotion");
                candidate
            })
        });
        promotion_entered_rx
            .recv()
            .expect("promotion acquires the transition first");

        let retire_lifetime = Arc::clone(&lifetime);
        let (retirement_contended_tx, retirement_contended_rx) = std::sync::mpsc::channel();
        let (retired_tx, retired_rx) = std::sync::mpsc::channel();
        let retirement = std::thread::spawn(move || {
            let contended = matches!(
                retire_lifetime.attempt.transition.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            );
            retirement_contended_tx
                .send(contended)
                .expect("test observes retirement waiting on promotion");
            if contended {
                retire_lifetime.retire();
                retired_tx.send(()).expect("retirement reports completion");
            }
        });
        let retirement_contended = retirement_contended_rx
            .recv()
            .expect("retirement shares the promotion transition");
        assert!(
            retired_rx.try_recv().is_err(),
            "retirement cannot pass an in-progress promotion"
        );

        release_promotion_tx
            .send(())
            .expect("release the promotion transition");
        assert!(
            promotion.join().expect("promotion thread joins").is_some(),
            "promotion linearized before retirement"
        );
        retirement.join().expect("retirement thread joins");
        assert!(
            retirement_contended,
            "retirement must contend on the same transition as promotion"
        );
        retired_rx
            .recv()
            .expect("retirement completes after promotion");
        assert!(!lifetime.is_active());
    }

    #[test]
    fn v4_arc03_reservation_precedes_allocation_and_retirement_fences_result() {
        let claim = candidate_claim();
        let (permit, lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            claim.aggregate_capacity(),
        );
        let lifetime = Arc::new(lifetime);
        let (allocation_entered_tx, allocation_entered_rx) = std::sync::mpsc::channel();
        let (release_allocation_tx, release_allocation_rx) = std::sync::mpsc::channel();
        let allocation = std::thread::spawn(move || {
            permit.allocate_connector_candidate(claim, || {
                allocation_entered_tx
                    .send(())
                    .expect("test observes allocation inside transition");
                release_allocation_rx
                    .recv()
                    .expect("test releases allocation");
            })
        });
        allocation_entered_rx
            .recv()
            .expect("allocation acquires the transition first");

        lifetime.retire();
        assert!(!lifetime.is_active());
        release_allocation_tx
            .send(())
            .expect("release allocation transition");
        let (candidate, ()) = allocation
            .join()
            .expect("allocation thread joins")
            .expect("reservation completed before allocation began");
        assert!(!candidate.is_live());
    }

    #[test]
    fn v4_arc03_resource_families_cannot_substitute_for_each_other() {
        let one_candidate = candidate_claim();
        let one_task = PreAuthResourceClaim::single(
            PreAuthResourceFamily::Task,
            ResourceUse::observed(1, 0, 0, 0),
        );
        let capacity = one_candidate
            .opening
            .checked_add(one_task)
            .expect("fixture sum");
        let (permit, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), capacity);
        let (candidate, ()) = permit
            .allocate_connector_candidate(one_candidate, || ())
            .expect("candidate family has one item of capacity");

        assert!(
            permit
                .allocate_connector_candidate(one_candidate, || ())
                .is_none(),
            "unused task capacity must not authorize another candidate object"
        );
        assert_eq!(
            permit
                .aggregate
                .active()
                .for_family(PreAuthResourceFamily::Task),
            ResourceUse::ZERO
        );
        drop(candidate);
    }

    #[test]
    fn v4_arc03_connector_candidate_claim_rejects_zero_and_mislabeled_resources() {
        assert!(ConnectorCandidateResourceClaim::checked(
            PreAuthResourceClaim::ZERO,
            candidate_capacity(1)
        )
        .is_none());
        assert!(ConnectorCandidateResourceClaim::checked(
            PreAuthResourceClaim::single(
                PreAuthResourceFamily::Task,
                ResourceUse::observed(1, 0, 0, 0),
            ),
            candidate_capacity(1)
        )
        .is_none());
        assert!(ConnectorCandidateResourceClaim::checked(
            candidate_capacity(2),
            candidate_capacity(1)
        )
        .is_none());
        assert!(ConnectorCandidateResourceClaim::checked(
            candidate_capacity(1),
            candidate_capacity(1)
        )
        .is_some());
    }

    #[test]
    fn v4_arc03_promotion_atomically_releases_candidate_only_claims() {
        let claim = ConnectorCandidateResourceClaim::exact_connector_floor();
        let (permit, _lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            claim.aggregate_capacity(),
        );
        let candidate = permit
            .reserve_connector_candidate(claim)
            .expect("opening claim fits");
        assert_eq!(permit.aggregate.active(), claim.opening);
        assert_eq!(permit.resource_scope.active(), Some(claim.opening));

        let connected = candidate
            .promote_if_live(|candidate| candidate)
            .expect("live candidate promotes");
        assert_eq!(permit.aggregate.active(), claim.connected);
        assert_eq!(permit.resource_scope.active(), Some(claim.connected));
        assert_eq!(
            permit
                .aggregate
                .active()
                .for_family(PreAuthResourceFamily::ConnectorSpecificWork),
            ResourceUse::ZERO
        );
        drop(connected);
        assert_eq!(permit.aggregate.active(), PreAuthResourceClaim::ZERO);
        assert_eq!(
            permit.resource_scope.active(),
            Some(PreAuthResourceClaim::ZERO)
        );
    }
}
