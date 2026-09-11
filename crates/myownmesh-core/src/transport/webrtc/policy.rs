//! WebRTC-specific connector policy.
//!
//! The process resource owner remains connector-neutral. ICE candidate work and
//! the application's registered real-time codecs are transport-edge choices
//! owned by this profile.

use crate::runtime::attempt::ConnectorCallbackPolicy;
use crate::transport::ice::{rank_candidate_paths, IceCandidatePath};
use std::num::NonZeroUsize;

/// Why a bounded candidate-path planner refused an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WebRtcCandidatePathPolicyError {
    #[error("candidate path set is empty")]
    EmptyPathSet,
    #[error("candidate path set exceeds its caller-provided admission bound")]
    AdmissionCapacityExceeded,
    #[error("candidate path IDs must be unique")]
    DuplicatePathId,
    #[error("candidate path is not currently in flight")]
    PathNotInFlight,
    #[error("candidate path planner is already terminal")]
    Terminal,
}

/// The result of observing one transport-only candidate path attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebRtcCandidatePathDecision {
    /// The failed path was retired; the caller may ask for another bounded
    /// batch through [`WebRtcCandidatePathPlanner::start_parallel_paths`].
    Continue,
    /// A path was selected.  This is only an opaque transport path ID; it is
    /// not an application data-plane grant.
    Selected(u64),
    /// Every admitted path failed and no fallback remains.
    Exhausted,
}

/// Deterministic, bounded candidate-path admission and failover state.
///
/// The caller supplies both the total admission bound and the parallelism
/// bound.  There is no hidden candidate count, timer, or payload allowance in
/// this planner.  A successful result exposes only an opaque path ID; the
/// application channel still requires the existing authenticated promotion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebRtcCandidatePathPlanner {
    paths: Vec<IceCandidatePath>,
    next_path: usize,
    active: Vec<u64>,
    failed: Vec<u64>,
    winner: Option<u64>,
    max_parallel_paths: NonZeroUsize,
}

impl WebRtcCandidatePathPlanner {
    pub fn new(
        mut paths: Vec<IceCandidatePath>,
        max_admitted_paths: NonZeroUsize,
        max_parallel_paths: NonZeroUsize,
    ) -> Result<Self, WebRtcCandidatePathPolicyError> {
        if paths.is_empty() {
            return Err(WebRtcCandidatePathPolicyError::EmptyPathSet);
        }
        if paths.len() > max_admitted_paths.get() {
            return Err(WebRtcCandidatePathPolicyError::AdmissionCapacityExceeded);
        }
        let mut ids = std::collections::HashSet::with_capacity(paths.len());
        if paths.iter().any(|path| !ids.insert(path.id)) {
            return Err(WebRtcCandidatePathPolicyError::DuplicatePathId);
        }
        rank_candidate_paths(&mut paths);
        Ok(Self {
            paths,
            next_path: 0,
            active: Vec::new(),
            failed: Vec::new(),
            winner: None,
            max_parallel_paths,
        })
    }

    /// Admit the next deterministic batch, up to the caller's parallelism
    /// bound. Repeated calls do not duplicate an in-flight path.
    pub fn start_parallel_paths(&mut self) -> Vec<u64> {
        if self.winner.is_some() {
            return Vec::new();
        }
        let capacity = self
            .max_parallel_paths
            .get()
            .saturating_sub(self.active.len());
        let mut started = Vec::with_capacity(capacity.min(self.paths.len()));
        while started.len() < capacity && self.next_path < self.paths.len() {
            let id = self.paths[self.next_path].id;
            self.next_path += 1;
            self.active.push(id);
            started.push(id);
        }
        started
    }

    /// Record one path's terminal transport result. Failed paths are retired
    /// before the next fallback is admitted; a selected path closes the
    /// planner and prevents later paths from being started.
    pub fn observe(
        &mut self,
        path_id: u64,
        succeeded: bool,
    ) -> Result<WebRtcCandidatePathDecision, WebRtcCandidatePathPolicyError> {
        if self.winner.is_some() {
            return Err(WebRtcCandidatePathPolicyError::Terminal);
        }
        let Some(active_index) = self.active.iter().position(|id| *id == path_id) else {
            return Err(WebRtcCandidatePathPolicyError::PathNotInFlight);
        };
        // Preserve ranked order in the live set as well as at admission.
        // The set is caller-bounded, so the linear shift is deliberate: a
        // diagnostic snapshot never depends on which sibling failed first.
        self.active.remove(active_index);
        if succeeded {
            self.winner = Some(path_id);
            self.active.clear();
            return Ok(WebRtcCandidatePathDecision::Selected(path_id));
        }

        self.failed.push(path_id);
        if self.active.is_empty() && self.next_path == self.paths.len() {
            Ok(WebRtcCandidatePathDecision::Exhausted)
        } else {
            Ok(WebRtcCandidatePathDecision::Continue)
        }
    }

    #[cfg(test)]
    pub fn active_path_ids(&self) -> &[u64] {
        &self.active
    }

    #[cfg(test)]
    pub fn failed_path_ids(&self) -> &[u64] {
        &self.failed
    }

    #[cfg(test)]
    pub const fn selected_path_id(&self) -> Option<u64> {
        self.winner
    }
}

// The owner-selected ICE candidate envelope used to live here: four cumulative
// ceilings — unique items, content bytes, duplicate submissions and native
// application work — that a deployment could state per attempt. It is gone, and
// nothing replaces it. Every one of those quantities is admitted against the
// process provider at its actual size, so a second ceiling in front of that
// could only refuse work the owner's real grant would have funded, in units the
// owner never chose. What remains bounding a candidate is what always really
// bounded it: an exact `ResourceClaim` per submission.

/// Why a connector profile was refused.
///
/// One variant, and the two that stood beside it are gone rather than
/// deprecated. `RealtimeProfileRequiresLocalCeiling` refused the elastic
/// deployment this release exists to support, and
/// `RealtimeProfileExceedsFlowCeiling` compared a number the profile no longer
/// carries against a ceiling that is now enforced where it is held. Neither can
/// be reached any more, so neither is described any more.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WebRtcConnectorProfileError {
    #[error("a real-time codec profile requires the connector's real-time policy to be enabled")]
    RealtimeProfileRequiresRealtime,
}

/// WebRTC-specific construction and work policy for one Mesh runtime.
///
/// The process resource owner never inspects this profile. It owns only the
/// connector-neutral resource ownership. WebRTC callback, ICE candidate,
/// and temporary compatibility-provider choices stay at the transport edge.
/// No longer `Copy`: the real-time profile it now carries owns its codec
/// registrations, and interning them to keep a marker copyable would buy
/// nothing but a lifetime to get wrong. The getters take `&self` instead, so
/// every existing `profile.callbacks()` call still reads the same.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebRtcConnectorProfile {
    callbacks: ConnectorCallbackPolicy,
    realtime: Option<super::RealtimeProfile>,
}

impl WebRtcConnectorProfile {
    pub const fn new(callbacks: ConnectorCallbackPolicy) -> Self {
        Self {
            callbacks,
            realtime: None,
        }
    }

    /// Supply the application's real-time codec profile.
    ///
    /// The only public way a real-time profile reaches the connector, and it
    /// takes an already-validated [`super::RealtimeProfile`] — so the shape
    /// refusals happen once, at parse time, where the application can still
    /// say which line of its configuration was wrong.
    ///
    /// It must be set before the peer connection exists, because codec
    /// registration is a property of the media engine a connection is built
    /// from. There is no later point at which core could accept one, and
    /// therefore no point at which core could fall back to a built-in list.
    ///
    /// It refuses exactly one thing: a profile on a connector whose realtime
    /// policy is `Disabled`. That is a contradiction the owner can only have
    /// stated by mistake — codecs registered on a connector that will admit no
    /// flow at all.
    ///
    /// **`Enabled(None)` is accepted, and that is the elastic case, not a
    /// missing one.** A profile states *which encodings the application can
    /// carry* and nothing else. How many concurrent flows may exist is the
    /// owner's to say through its envelope, or the owner's to leave open — so a
    /// profile carries no capacity of its own and is checked against none. A
    /// second number here would describe the same thing the envelope already
    /// describes, and requiring one would make "I have codecs and no fixed
    /// ceiling" — the ordinary elastic deployment — unstateable.
    ///
    /// Nothing is counted here, and nothing needs to be. The registry remains
    /// the sole enforcer of concurrency, and it enforces the owner's real
    /// ceilings when there are ceilings and the provider's real leases when
    /// there are not. There is no shadow ceiling in this file and no second
    /// counter to drift from the first.
    pub fn with_realtime_profile(
        mut self,
        profile: super::RealtimeProfile,
    ) -> std::result::Result<Self, WebRtcConnectorProfileError> {
        match self.callbacks.realtime() {
            crate::runtime::attempt::RealtimeConnectorPolicy::Disabled => {
                return Err(WebRtcConnectorProfileError::RealtimeProfileRequiresRealtime)
            }
            crate::runtime::attempt::RealtimeConnectorPolicy::Enabled => {}
        }
        self.realtime = Some(profile);
        Ok(self)
    }

    pub const fn callbacks(&self) -> ConnectorCallbackPolicy {
        self.callbacks
    }

    /// The application's registered real-time codecs, if it supplied any.
    ///
    /// Borrowed, and crate-internal: the daemon supplies this profile and
    /// core reads it. Handing a copy back out would invite a caller to treat
    /// its own edit as configuration.
    pub(crate) fn realtime(&self) -> Option<&super::RealtimeProfile> {
        self.realtime.as_ref()
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;
    use crate::transport::diag::IceCandidateKind;

    fn path(id: u64, priority: u32) -> IceCandidatePath {
        IceCandidatePath::new(id, IceCandidateKind::Host, IceCandidateKind::Host, priority)
    }

    #[test]
    fn admission_bound_refuses_n_plus_one_before_planning() {
        let result = WebRtcCandidatePathPlanner::new(
            vec![path(1, 1), path(2, 2)],
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        );

        assert_eq!(
            result,
            Err(WebRtcCandidatePathPolicyError::AdmissionCapacityExceeded)
        );
    }

    #[test]
    fn parallel_start_is_bounded_and_failed_paths_fail_over_once() {
        let mut planner = WebRtcCandidatePathPlanner::new(
            vec![path(7, 10), path(3, 30), path(5, 20)],
            NonZeroUsize::new(3).unwrap(),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();

        assert_eq!(planner.start_parallel_paths(), vec![3, 5]);
        assert!(planner.start_parallel_paths().is_empty());
        assert_eq!(planner.active_path_ids(), &[3, 5]);

        assert_eq!(
            planner.observe(3, false),
            Ok(WebRtcCandidatePathDecision::Continue)
        );
        assert_eq!(planner.start_parallel_paths(), vec![7]);
        assert_eq!(planner.active_path_ids(), &[5, 7]);

        assert_eq!(
            planner.observe(5, false),
            Ok(WebRtcCandidatePathDecision::Continue)
        );
        assert_eq!(
            planner.observe(7, true),
            Ok(WebRtcCandidatePathDecision::Selected(7))
        );
        assert!(planner.start_parallel_paths().is_empty());
        assert!(planner.active_path_ids().is_empty());
        assert_eq!(planner.selected_path_id(), Some(7));
        assert_eq!(planner.failed_path_ids(), &[3, 5]);
        assert_eq!(
            planner.observe(3, false),
            Err(WebRtcCandidatePathPolicyError::Terminal)
        );
    }

    #[test]
    fn duplicate_path_ids_are_refused_before_any_path_is_started() {
        let result = WebRtcCandidatePathPlanner::new(
            vec![path(1, 1), path(1, 2)],
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(2).unwrap(),
        );

        assert_eq!(result, Err(WebRtcCandidatePathPolicyError::DuplicatePathId));
    }
}

// A guessed Annex-B fragment stop used to live here: one constant, 2048,
// chosen against an estimate of a large keyframe. It is gone, and nothing
// replaces it in this file. Retention on an inbound path is bounded where the
// bound can be exact — `RealtimeAssemblyReservation::retain_ordered_fragment`,
// which admits each fragment against the owner's selected ceilings and against
// a real provider claim. A second bound in front of that could only be a guess,
// and a guess that fires first is the one that decides: it would cap a stream
// the owner had deliberately provisioned for, and would do it in units the
// owner never chose.
