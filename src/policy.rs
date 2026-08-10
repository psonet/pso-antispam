//! Admission policy constants.
//!
//! These are shared, not node-local: a wallet reads them to size its own work
//! and to decide whether a solution it already has is still usable. They were
//! never VDF-specific — they describe the *lane's* policy — which is why they
//! survive the scheme swap untouched.

use crate::Difficulty;

/// Baseline work parameter, before any retargeting.
///
/// Under hashcash this is a target divisor: a solution must hash below
/// `2^256 / T`, so this is roughly `T` expected hash attempts. That is
/// sub-millisecond, unlike the retired VDF where the same number meant that
/// many *sequential* modexps and cost an honest wallet over a second.
pub const T_BASE: Difficulty = 100_000;

/// Maximum per-epoch difficulty change, as a percentage.
///
/// The retarget controller moves `T` by at most ±25% per epoch. This is why the
/// scheme uses a 256-bit target rather than leading-zero bits: bits quantise
/// difficulty to powers of two, and a controller that can only double or halve
/// cannot express a 25% step.
pub const MAX_DIFFICULTY_ADJUSTMENT_PCT: u64 = 25;

/// Blocks per retarget epoch.
pub const EPOCH_LENGTH_BLOCKS: u64 = 128;

/// How many blocks back a solution stays valid.
///
/// Bounds stockpiling: work is bound to a `submitted_block`, so a solver cannot
/// build a reserve of admissions in advance and release them in a burst. See
/// [`crate::params::is_block_valid`].
pub const PROOF_VALIDITY_WINDOW: u64 = 32;

/// A solution must not outlive the retarget that was supposed to reprice it, or
/// a difficulty increase could be waited out instead of paid. Enforced at
/// COMPILE time: a future edit that inverts these two constants fails the
/// build rather than a test someone might not run.
const _: () = assert!(PROOF_VALIDITY_WINDOW < EPOCH_LENGTH_BLOCKS);

#[cfg(test)]
mod tests {
    use super::*;

    /// These four are consensus of a sort: a node and a wallet that disagree
    /// admit different transactions, and the failure is silent. Changing one is
    /// a coordinated release, so they are pinned by value here rather than
    /// merely being read from the source.
    #[test]
    fn the_policy_constants_are_pinned() {
        assert_eq!(T_BASE, 100_000);
        assert_eq!(MAX_DIFFICULTY_ADJUSTMENT_PCT, 25);
        assert_eq!(EPOCH_LENGTH_BLOCKS, 128);
        assert_eq!(PROOF_VALIDITY_WINDOW, 32);
    }
}
