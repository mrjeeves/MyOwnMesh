//! Pure RFC 6206 Trickle state for bounded, idempotent advertisements.
//!
//! This module deliberately owns no task, transport, wire, or serialization
//! state.  The engine adapter decides whether an authenticated advertisement
//! is consistent or inconsistent and feeds that decision into this timer.  In
//! particular, this is not Trickle ICE: candidates, end-of-candidates, and
//! session control must not be passed through this suppression state.

use std::num::NonZeroU32;

use rand_core::RngCore;

/// Checked local policy for one Trickle advertisement stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TricklePolicy {
    pub(super) imin_ms: u64,
    pub(super) imax_ms: u64,
    pub(super) redundancy: NonZeroU32,
    pub(super) reset_window_ms: u64,
    pub(super) max_resets_per_window: NonZeroU32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TricklePolicyError {
    ZeroMinimum,
    MinimumBelowResolution,
    MaximumBelowMinimum,
    ZeroResetWindow,
}

impl TricklePolicy {
    pub(super) fn checked(
        imin_ms: u64,
        imax_ms: u64,
        redundancy: NonZeroU32,
        reset_window_ms: u64,
        max_resets_per_window: NonZeroU32,
    ) -> Result<Self, TricklePolicyError> {
        if imin_ms == 0 {
            return Err(TricklePolicyError::ZeroMinimum);
        }
        if imin_ms < 2 {
            return Err(TricklePolicyError::MinimumBelowResolution);
        }
        if imax_ms < imin_ms {
            return Err(TricklePolicyError::MaximumBelowMinimum);
        }
        if reset_window_ms == 0 {
            return Err(TricklePolicyError::ZeroResetWindow);
        }
        Ok(Self {
            imin_ms,
            imax_ms,
            redundancy,
            reset_window_ms,
            max_resets_per_window,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TrickleError {
    ClockWentBackwards,
    ClockOverflow,
    GenerationOverflow,
    Retired,
}

/// The two distinct timer boundaries are observable so an adapter cannot
/// confuse a transmission wake with the interval-end wake that advances I.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TrickleDeadline {
    Transmission(u64),
    IntervalEnd(u64),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TrickleReset {
    Accepted,
    AlreadyAtMinimum,
    RateLimited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TricklePoll {
    SleepUntil(TrickleDeadline),
    Transmit { generation: u64 },
    Suppress { generation: u64 },
    Retired,
}

/// Allocation-free RFC 6206 state machine.
///
/// `now_ms` is a caller-supplied monotonic millisecond value.  Production
/// code must derive it from a monotonic clock; it must never use a wall-clock
/// timestamp received from the mesh as timer or authority input.  The random
/// source is also caller supplied so tests can reproduce every deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TrickleTimer {
    policy: TricklePolicy,
    interval_start_ms: u64,
    interval_end_ms: u64,
    transmit_at_ms: u64,
    interval_ms: u64,
    consistent_count: u32,
    transmission_decided: bool,
    transmitted: bool,
    suppressed: bool,
    reset_window_start_ms: u64,
    resets_in_window: u32,
    repair_needed: bool,
    last_now_ms: u64,
    generation: u64,
    retired: bool,
}

impl TrickleTimer {
    /// Start at Imin, with the transmission point sampled uniformly from
    /// `[I/2, I)`.  `RngCore` is used only through the rejection-sampling
    /// helper below, so the caller supplies an unbiased source rather than a
    /// pre-biased modulo sample.
    pub(super) fn start(
        policy: TricklePolicy,
        now_ms: u64,
        rng: &mut impl RngCore,
    ) -> Result<Self, TrickleError> {
        let mut timer = Self {
            policy,
            interval_start_ms: now_ms,
            interval_end_ms: 0,
            transmit_at_ms: 0,
            interval_ms: policy.imin_ms,
            consistent_count: 0,
            transmission_decided: false,
            transmitted: false,
            suppressed: false,
            reset_window_start_ms: now_ms,
            resets_in_window: 0,
            repair_needed: false,
            last_now_ms: now_ms,
            generation: 0,
            retired: false,
        };
        timer.begin_interval(now_ms, policy.imin_ms, rng)?;
        Ok(timer)
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub(super) fn interval_start_ms(&self) -> u64 {
        self.interval_start_ms
    }

    #[cfg(test)]
    pub(super) fn interval_end_ms(&self) -> u64 {
        self.interval_end_ms
    }

    #[cfg(test)]
    pub(super) fn transmit_at_ms(&self) -> u64 {
        self.transmit_at_ms
    }

    #[cfg(test)]
    pub(super) fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    #[cfg(test)]
    pub(super) fn was_transmitted(&self) -> bool {
        self.transmitted
    }

    #[cfg(test)]
    pub(super) fn was_suppressed(&self) -> bool {
        self.suppressed
    }

    #[cfg(test)]
    pub(super) fn repair_needed(&self) -> bool {
        self.repair_needed
    }

    #[cfg(test)]
    pub(super) fn resets_in_window(&self) -> u32 {
        self.resets_in_window
    }

    #[cfg(test)]
    pub(super) fn next_deadline(&self) -> Option<TrickleDeadline> {
        if self.retired {
            return None;
        }
        if self.transmission_decided {
            Some(TrickleDeadline::IntervalEnd(self.interval_end_ms))
        } else {
            Some(TrickleDeadline::Transmission(self.transmit_at_ms))
        }
    }

    /// Return false for a wake belonging to a retired or superseded timer
    /// generation.  Adapters can use this as a stale-wake fence.
    #[cfg(test)]
    pub(super) fn accepts_generation(&self, generation: u64) -> bool {
        !self.retired && self.generation == generation
    }

    /// Count one authenticated, protocol-defined consistent observation.
    /// The adapter is responsible for authentication and digest comparison;
    /// this method never ingests a packet or makes an authority decision.
    #[cfg(test)]
    pub(super) fn observe_consistent(&mut self) -> Result<(), TrickleError> {
        if self.retired {
            return Err(TrickleError::Retired);
        }
        self.consistent_count = self.consistent_count.saturating_add(1);
        Ok(())
    }

    /// Process one authenticated inconsistent observation.  At Imin the RFC
    /// rule leaves the interval in place.  A reset-budget refusal also leaves
    /// the schedule in place but retains `repair_needed` for the adapter.
    #[cfg(test)]
    pub(super) fn observe_inconsistent(
        &mut self,
        now_ms: u64,
        rng: &mut impl RngCore,
    ) -> Result<TrickleReset, TrickleError> {
        if self.retired {
            return Err(TrickleError::Retired);
        }
        self.check_now(now_ms)?;
        if self.interval_ms == self.policy.imin_ms {
            self.repair_needed = true;
            return Ok(TrickleReset::AlreadyAtMinimum);
        }
        now_ms
            .checked_add(self.policy.imin_ms)
            .ok_or(TrickleError::ClockOverflow)?;
        self.generation
            .checked_add(1)
            .ok_or(TrickleError::GenerationOverflow)?;
        if !self.consume_reset_budget(now_ms) {
            self.repair_needed = true;
            return Ok(TrickleReset::RateLimited);
        }
        self.repair_needed = true;
        self.begin_interval(now_ms, self.policy.imin_ms, rng)?;
        Ok(TrickleReset::Accepted)
    }

    /// A local advertised-state change is an external RFC event, not a packet
    /// observation, so it is not charged against the adversarial reset bucket.
    pub(super) fn local_change(
        &mut self,
        now_ms: u64,
        rng: &mut impl RngCore,
    ) -> Result<(), TrickleError> {
        if self.retired {
            return Err(TrickleError::Retired);
        }
        self.check_now(now_ms)?;
        now_ms
            .checked_add(self.policy.imin_ms)
            .ok_or(TrickleError::ClockOverflow)?;
        self.generation
            .checked_add(1)
            .ok_or(TrickleError::GenerationOverflow)?;
        self.repair_needed = true;
        self.begin_interval(now_ms, self.policy.imin_ms, rng)
    }

    /// Admit local change resets against the existing fixed-window budget.
    /// Work on a value copy so overflow/refusal cannot partly reset a timer.
    /// A budget refusal retains the repair obligation without postponing t.
    pub(super) fn bounded_local_change(
        &mut self,
        now_ms: u64,
        rng: &mut impl RngCore,
    ) -> Result<bool, TrickleError> {
        if self.retired {
            return Err(TrickleError::Retired);
        }
        let mut next = *self;
        next.check_now(now_ms)?;
        if !next.consume_reset_budget(now_ms) {
            next.repair_needed = true;
            *self = next;
            return Ok(false);
        }
        next.local_change(now_ms, rng)?;
        *self = next;
        Ok(true)
    }

    /// Clear the repair marker after the caller records a successful local
    /// advertisement handoff. This is not remote receipt or recipient coverage;
    /// a timer decision alone is not a successful handoff either.
    pub(super) fn acknowledge_repair(&mut self) -> Result<(), TrickleError> {
        if self.retired {
            return Err(TrickleError::Retired);
        }
        self.repair_needed = false;
        Ok(())
    }

    /// Advance the timer using a monotonic clock.  A delayed wake skips all
    /// missed intervals in at most 64 doublings; once Imax is reached it
    /// jumps arithmetically across missed Imax intervals, never spinning or
    /// replaying a burst of stale transmissions.
    pub(super) fn poll(
        &mut self,
        now_ms: u64,
        rng: &mut impl RngCore,
    ) -> Result<TricklePoll, TrickleError> {
        if self.retired {
            return Ok(TricklePoll::Retired);
        }
        self.check_now(now_ms)?;
        if !self.transmission_decided {
            if now_ms < self.transmit_at_ms {
                return Ok(TricklePoll::SleepUntil(TrickleDeadline::Transmission(
                    self.transmit_at_ms,
                )));
            }
            if now_ms < self.interval_end_ms {
                self.transmission_decided = true;
                if self.consistent_count < self.policy.redundancy.get() {
                    self.transmitted = true;
                    return Ok(TricklePoll::Transmit {
                        generation: self.generation,
                    });
                }
                self.suppressed = true;
                return Ok(TricklePoll::Suppress {
                    generation: self.generation,
                });
            }
        }

        if now_ms < self.interval_end_ms {
            return Ok(TricklePoll::SleepUntil(TrickleDeadline::IntervalEnd(
                self.interval_end_ms,
            )));
        }

        self.skip_missed_intervals(now_ms, rng)?;
        if now_ms < self.transmit_at_ms {
            return Ok(TricklePoll::SleepUntil(TrickleDeadline::Transmission(
                self.transmit_at_ms,
            )));
        }
        debug_assert!(now_ms < self.interval_end_ms);
        self.transmission_decided = true;
        if self.consistent_count < self.policy.redundancy.get() {
            self.transmitted = true;
            Ok(TricklePoll::Transmit {
                generation: self.generation,
            })
        } else {
            self.suppressed = true;
            Ok(TricklePoll::Suppress {
                generation: self.generation,
            })
        }
    }

    /// Retire this generation.  No later poll or observation can mutate it.
    #[cfg(test)]
    pub(super) fn retire(&mut self) -> Result<u64, TrickleError> {
        if self.retired {
            return Ok(self.generation);
        }
        let next = match self.generation.checked_add(1) {
            Some(next) => next,
            None => {
                self.retired = true;
                return Err(TrickleError::GenerationOverflow);
            }
        };
        self.generation = next;
        self.retired = true;
        Ok(next)
    }

    fn check_now(&mut self, now_ms: u64) -> Result<(), TrickleError> {
        if now_ms < self.last_now_ms {
            return Err(TrickleError::ClockWentBackwards);
        }
        self.last_now_ms = now_ms;
        Ok(())
    }

    fn consume_reset_budget(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.reset_window_start_ms);
        if elapsed >= self.policy.reset_window_ms {
            self.reset_window_start_ms = now_ms;
            self.resets_in_window = 0;
        }
        if self.resets_in_window >= self.policy.max_resets_per_window.get() {
            return false;
        }
        self.resets_in_window += 1;
        true
    }

    fn next_interval_ms(&self) -> u64 {
        if self.interval_ms >= self.policy.imax_ms {
            return self.policy.imax_ms;
        }
        if self.interval_ms > self.policy.imax_ms / 2 {
            self.policy.imax_ms
        } else {
            self.interval_ms * 2
        }
    }

    fn begin_interval(
        &mut self,
        start_ms: u64,
        interval_ms: u64,
        rng: &mut impl RngCore,
    ) -> Result<(), TrickleError> {
        let end_ms = start_ms
            .checked_add(interval_ms)
            .ok_or(TrickleError::ClockOverflow)?;
        // RFC 6206's [I/2, I) interval is represented in integer
        // milliseconds with a ceiling midpoint, so odd intervals never admit
        // a sample below the mathematical half.
        let half = interval_ms / 2 + interval_ms % 2;
        let span = interval_ms - half;
        let offset = half
            .checked_add(uniform_below(rng, span))
            .ok_or(TrickleError::ClockOverflow)?;
        let transmit_at_ms = start_ms
            .checked_add(offset)
            .ok_or(TrickleError::ClockOverflow)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(TrickleError::GenerationOverflow)?;
        self.interval_start_ms = start_ms;
        self.interval_end_ms = end_ms;
        self.transmit_at_ms = transmit_at_ms;
        self.interval_ms = interval_ms;
        self.consistent_count = 0;
        self.transmission_decided = false;
        self.transmitted = false;
        self.suppressed = false;
        self.generation = generation;
        Ok(())
    }

    fn skip_missed_intervals(
        &mut self,
        now_ms: u64,
        rng: &mut impl RngCore,
    ) -> Result<(), TrickleError> {
        let mut start_ms = self.interval_end_ms;
        let mut interval_ms = self.next_interval_ms();
        let mut doublings = 0_u8;

        while interval_ms < self.policy.imax_ms {
            let next_end = start_ms
                .checked_add(interval_ms)
                .ok_or(TrickleError::ClockOverflow)?;
            if next_end > now_ms {
                break;
            }
            start_ms = next_end;
            interval_ms = if interval_ms > self.policy.imax_ms / 2 {
                self.policy.imax_ms
            } else {
                interval_ms * 2
            };
            doublings = doublings.saturating_add(1);
            if doublings == 64 {
                break;
            }
        }

        if interval_ms == self.policy.imax_ms {
            let next_end = start_ms
                .checked_add(interval_ms)
                .ok_or(TrickleError::ClockOverflow)?;
            if next_end <= now_ms {
                let elapsed = now_ms - start_ms;
                let missed = elapsed / interval_ms;
                let advance = missed
                    .checked_mul(interval_ms)
                    .ok_or(TrickleError::ClockOverflow)?;
                start_ms = start_ms
                    .checked_add(advance)
                    .ok_or(TrickleError::ClockOverflow)?;
            }
        }

        self.begin_interval(start_ms, interval_ms, rng)
    }
}

/// Uniformly sample an integer in `[0, upper_exclusive)` without modulo bias.
fn uniform_below(rng: &mut impl RngCore, upper_exclusive: u64) -> u64 {
    debug_assert!(upper_exclusive != 0);
    let threshold = upper_exclusive.wrapping_neg() % upper_exclusive;
    loop {
        let sample = rng.next_u64();
        if sample >= threshold {
            return sample % upper_exclusive;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct SequenceRng {
        next: u64,
    }

    impl RngCore for SequenceRng {
        fn next_u32(&mut self) -> u32 {
            self.next as u32
        }

        fn next_u64(&mut self) -> u64 {
            let sample = self.next;
            self.next = if sample == 0 { u64::MAX } else { 0 };
            sample
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next.to_le_bytes();
                let len = chunk.len();
                chunk.copy_from_slice(&bytes[..len]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    struct RejectThenAcceptRng {
        samples: [u64; 2],
        index: usize,
        calls: u8,
    }

    impl RngCore for RejectThenAcceptRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.calls = self.calls.saturating_add(1);
            let sample = self.samples.get(self.index).copied().unwrap_or(u64::MAX);
            self.index = self.index.saturating_add(1);
            sample
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                let len = chunk.len();
                chunk.copy_from_slice(&bytes[..len]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn policy(k: u32) -> TricklePolicy {
        TricklePolicy::checked(
            10,
            40,
            NonZeroU32::new(k).unwrap(),
            100,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn policy_rejects_unbounded_or_zero_dimensions() {
        let k = NonZeroU32::new(1).unwrap();
        assert_eq!(
            TricklePolicy::checked(0, 1, k, 1, k),
            Err(TricklePolicyError::ZeroMinimum)
        );
        assert_eq!(
            TricklePolicy::checked(2, 1, k, 1, k),
            Err(TricklePolicyError::MaximumBelowMinimum)
        );
        assert_eq!(
            TricklePolicy::checked(2, 2, k, 0, k),
            Err(TricklePolicyError::ZeroResetWindow)
        );
        assert_eq!(
            TricklePolicy::checked(1, 1, k, 1, k),
            Err(TricklePolicyError::MinimumBelowResolution)
        );
    }

    #[test]
    fn rejection_sampling_progresses_after_one_bounded_rejection() {
        let mut rng = RejectThenAcceptRng {
            samples: [0, u64::MAX],
            index: 0,
            calls: 0,
        };
        assert_eq!(uniform_below(&mut rng, 5), 0);
        assert_eq!(rng.calls, 2);
    }

    #[test]
    fn start_samples_half_open_range_and_separate_deadlines() {
        let mut rng = SequenceRng { next: 4 };
        let timer = TrickleTimer::start(policy(1), 100, &mut rng).unwrap();
        assert!(timer.transmit_at_ms() >= 105);
        assert!(timer.transmit_at_ms() < 110);
        assert_eq!(
            timer.next_deadline(),
            Some(TrickleDeadline::Transmission(109))
        );
        assert_eq!(timer.interval_end_ms(), 110);

        let odd_policy = TricklePolicy::checked(
            3,
            3,
            NonZeroU32::new(1).unwrap(),
            1,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();
        let mut odd_rng = SequenceRng { next: 0 };
        let odd = TrickleTimer::start(odd_policy, 0, &mut odd_rng).unwrap();
        assert_eq!(odd.transmit_at_ms(), 2);
        assert!(odd.transmit_at_ms() < odd.interval_end_ms());
    }

    #[test]
    fn k_controls_transmit_and_suppress_once() {
        let mut rng = SequenceRng { next: 0 };
        let mut transmit = TrickleTimer::start(policy(2), 0, &mut rng).unwrap();
        assert_eq!(
            transmit.poll(9, &mut rng).unwrap(),
            TricklePoll::Transmit { generation: 1 }
        );
        assert!(transmit.was_transmitted());
        assert_eq!(
            transmit.poll(9, &mut rng).unwrap(),
            TricklePoll::SleepUntil(TrickleDeadline::IntervalEnd(10))
        );

        let mut suppress = TrickleTimer::start(policy(2), 0, &mut rng).unwrap();
        suppress.observe_consistent().unwrap();
        suppress.observe_consistent().unwrap();
        assert_eq!(
            suppress.poll(9, &mut rng).unwrap(),
            TricklePoll::Suppress { generation: 1 }
        );
        assert!(suppress.was_suppressed());
    }

    #[test]
    fn interval_doubles_and_caps_without_deadline_spin() {
        let mut rng = SequenceRng { next: 0 };
        let mut timer = TrickleTimer::start(policy(1), 0, &mut rng).unwrap();
        assert!(matches!(
            timer.poll(10, &mut rng).unwrap(),
            TricklePoll::SleepUntil(_)
        ));
        assert_eq!(timer.interval_ms(), 20);
        assert_eq!(timer.interval_start_ms(), 10);
        assert_eq!(timer.interval_end_ms(), 30);
        assert_eq!(
            timer.poll(11, &mut rng).unwrap(),
            TricklePoll::SleepUntil(TrickleDeadline::Transmission(25))
        );
        let due = timer.poll(25, &mut rng).unwrap();
        assert_eq!(due, TricklePoll::Transmit { generation: 2 });
        assert!(timer.interval_start_ms() <= 25);
        assert!(25 < timer.interval_end_ms());
        assert_eq!(timer.interval_ms(), 20);
        assert_eq!(
            timer.poll(25, &mut rng).unwrap(),
            TricklePoll::SleepUntil(TrickleDeadline::IntervalEnd(30))
        );

        let mut timer = TrickleTimer::start(policy(1), 0, &mut rng).unwrap();
        timer.poll(10, &mut rng).unwrap();
        assert!(matches!(
            timer.poll(30, &mut rng).unwrap(),
            TricklePoll::SleepUntil(_)
        ));
        assert_eq!(timer.interval_ms(), 40);
        assert_eq!(timer.interval_end_ms(), 70);
        let delayed = timer.poll(1_000_000, &mut rng).unwrap();
        assert!(matches!(
            delayed,
            TricklePoll::SleepUntil(TrickleDeadline::Transmission(_))
        ));
        assert!(timer.interval_start_ms() <= 1_000_000);
        assert!(1_000_000 < timer.interval_end_ms());
        assert!(timer.transmit_at_ms() > 1_000_000);
        assert_eq!(timer.interval_ms(), 40);
    }

    #[test]
    fn clock_overflow_is_rejected_before_start() {
        let mut rng = SequenceRng { next: 0 };
        assert_eq!(
            TrickleTimer::start(policy(1), u64::MAX, &mut rng),
            Err(TrickleError::ClockOverflow)
        );
    }

    #[test]
    fn reset_budget_and_minimum_preserve_repair_need() {
        let mut rng = SequenceRng { next: 0 };
        let mut timer = TrickleTimer::start(policy(1), 0, &mut rng).unwrap();
        timer.poll(10, &mut rng).unwrap();
        assert_eq!(
            timer.observe_inconsistent(11, &mut rng).unwrap(),
            TrickleReset::Accepted
        );
        timer.poll(21, &mut rng).unwrap();
        assert_eq!(
            timer.observe_inconsistent(22, &mut rng).unwrap(),
            TrickleReset::RateLimited
        );
        assert!(timer.repair_needed());
        assert_eq!(timer.resets_in_window(), 1);
    }

    #[test]
    fn backwards_clock_and_retirement_fence_mutation() {
        let mut rng = SequenceRng { next: 0 };
        let mut timer = TrickleTimer::start(policy(1), 10, &mut rng).unwrap();
        assert_eq!(
            timer.poll(9, &mut rng),
            Err(TrickleError::ClockWentBackwards)
        );
        let generation = timer.generation();
        assert_eq!(timer.retire().unwrap(), generation + 1);
        assert!(!timer.accepts_generation(generation));
        assert_eq!(timer.poll(10, &mut rng).unwrap(), TricklePoll::Retired);
        assert_eq!(timer.observe_consistent(), Err(TrickleError::Retired));
    }

    #[test]
    fn local_change_resets_even_at_imin_without_using_attack_budget() {
        let mut rng = SequenceRng { next: 0 };
        let mut timer = TrickleTimer::start(policy(1), 0, &mut rng).unwrap();
        let before = timer.generation();
        timer.local_change(2, &mut rng).unwrap();
        assert!(timer.generation() > before);
        assert_eq!(timer.interval_ms(), 10);
        assert_eq!(timer.resets_in_window(), 0);
        assert!(timer.repair_needed());
        timer.acknowledge_repair().unwrap();
        assert!(!timer.repair_needed());
    }

    #[test]
    fn bounded_local_change_refuses_invalid_time_and_overflow_without_partial_reset() {
        let mut rng = SequenceRng { next: 0 };
        let mut timer = TrickleTimer::start(policy(1), 10, &mut rng).unwrap();
        let before = timer;
        assert_eq!(
            timer.bounded_local_change(9, &mut rng),
            Err(TrickleError::ClockWentBackwards)
        );
        assert_eq!(timer, before);
        assert_eq!(
            timer.bounded_local_change(u64::MAX, &mut rng),
            Err(TrickleError::ClockOverflow)
        );
        assert_eq!(timer, before);
        timer.generation = u64::MAX;
        let before = timer;
        assert_eq!(
            timer.bounded_local_change(11, &mut rng),
            Err(TrickleError::GenerationOverflow)
        );
        assert_eq!(timer, before);
        timer.generation = 1;
        timer.retire().unwrap();
        let before = timer;
        assert_eq!(
            timer.bounded_local_change(11, &mut rng),
            Err(TrickleError::Retired)
        );
        assert_eq!(timer, before);
    }
}
