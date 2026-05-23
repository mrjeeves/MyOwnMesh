//! Apply-policy gate. Decides whether a candidate version bump is
//! permitted to apply automatically, requires user confirmation, or
//! is disabled entirely.
//!
//! Versions are compared semver-style: `MAJOR.MINOR.PATCH`. Non-
//! numeric pre-release suffixes (`-alpha`, `-rc1`) are accepted in
//! the input but compared by lexicographic fallback — refine when
//! the release pipeline starts producing them.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyPolicy {
    /// Apply patch-level bumps automatically (`0.1.5 → 0.1.6`).
    /// Minor / major stage but wait.
    Patch,
    /// Apply patch + minor bumps automatically (`0.1.5 → 0.2.0`).
    /// Major waits.
    Minor,
    /// Apply any version bump automatically.
    All,
    /// Disable auto-apply entirely. Staging still happens; user
    /// must trigger apply manually.
    None,
}

impl ApplyPolicy {
    /// Parse the string values used in `config.json`. Unknown
    /// strings return `None`; the caller decides whether to fall
    /// back to a default or error.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "patch" => Some(Self::Patch),
            "minor" => Some(Self::Minor),
            "all" => Some(Self::All),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Compare two semver-like versions. Returns:
///
///   - `Less` when `a < b`
///   - `Equal` when same
///   - `Greater` when `a > b`
///
/// Pre-release suffixes are stripped before numeric comparison and
/// then compared lexicographically as a tiebreaker — refine when
/// the release pipeline begins using them.
pub fn compare_semver(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (a_core, a_pre) = split_prerelease(a);
    let (b_core, b_pre) = split_prerelease(b);
    let a_parts = parse_core(a_core);
    let b_parts = parse_core(b_core);
    match a_parts.cmp(&b_parts) {
        Ordering::Equal => {
            // A version with no pre-release outranks one with a
            // pre-release suffix (e.g. `1.2.3` > `1.2.3-rc1`).
            match (a_pre.is_empty(), b_pre.is_empty()) {
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                _ => a_pre.cmp(b_pre),
            }
        }
        other => other,
    }
}

fn split_prerelease(v: &str) -> (&str, &str) {
    match v.split_once('-') {
        Some((core, pre)) => (core, pre),
        None => (v, ""),
    }
}

fn parse_core(core: &str) -> [u32; 3] {
    let mut parts = [0u32; 3];
    for (i, p) in core.split('.').take(3).enumerate() {
        parts[i] = p.parse().unwrap_or(0);
    }
    parts
}

/// True when `candidate` is reachable from `current` under the
/// chosen policy. Same version returns `false` (nothing to do);
/// older candidates return `false` (downgrade not permitted).
pub fn policy_allows(policy: ApplyPolicy, current: &str, candidate: &str) -> bool {
    use std::cmp::Ordering;
    if compare_semver(candidate, current) != Ordering::Greater {
        return false;
    }
    let [cur_maj, cur_min, _] = parse_core(split_prerelease(current).0);
    let [cand_maj, cand_min, _] = parse_core(split_prerelease(candidate).0);
    match policy {
        ApplyPolicy::None => false,
        ApplyPolicy::Patch => cur_maj == cand_maj && cur_min == cand_min,
        ApplyPolicy::Minor => cur_maj == cand_maj,
        ApplyPolicy::All => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn compare_basic() {
        assert_eq!(compare_semver("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(compare_semver("1.2.3", "1.2.4"), Ordering::Less);
        assert_eq!(compare_semver("1.2.4", "1.2.3"), Ordering::Greater);
        assert_eq!(compare_semver("1.10.0", "1.2.0"), Ordering::Greater);
        assert_eq!(compare_semver("2.0.0", "1.99.99"), Ordering::Greater);
    }

    #[test]
    fn compare_prerelease() {
        assert_eq!(compare_semver("1.2.3", "1.2.3-rc1"), Ordering::Greater);
        assert_eq!(compare_semver("1.2.3-rc1", "1.2.3-rc2"), Ordering::Less);
    }

    #[test]
    fn policy_patch_allows_patch_only() {
        assert!(policy_allows(ApplyPolicy::Patch, "0.1.5", "0.1.6"));
        assert!(!policy_allows(ApplyPolicy::Patch, "0.1.5", "0.2.0"));
        assert!(!policy_allows(ApplyPolicy::Patch, "0.1.5", "1.0.0"));
        // Downgrade never allowed.
        assert!(!policy_allows(ApplyPolicy::Patch, "0.1.5", "0.1.4"));
        // Same version is not an "update".
        assert!(!policy_allows(ApplyPolicy::Patch, "0.1.5", "0.1.5"));
    }

    #[test]
    fn policy_minor_allows_patch_and_minor() {
        assert!(policy_allows(ApplyPolicy::Minor, "0.1.5", "0.1.6"));
        assert!(policy_allows(ApplyPolicy::Minor, "0.1.5", "0.2.0"));
        assert!(!policy_allows(ApplyPolicy::Minor, "0.1.5", "1.0.0"));
    }

    #[test]
    fn policy_all_allows_any_upgrade() {
        assert!(policy_allows(ApplyPolicy::All, "0.1.5", "1.0.0"));
        assert!(policy_allows(ApplyPolicy::All, "0.1.5", "5.0.0"));
        assert!(!policy_allows(ApplyPolicy::All, "0.1.5", "0.1.5"));
    }

    #[test]
    fn policy_none_blocks_everything() {
        assert!(!policy_allows(ApplyPolicy::None, "0.1.5", "0.1.6"));
    }
}
