//! Hashcash over SHA-256, with a 256-bit target.
//!
//! **Internal.** Everything here takes the EFFECTIVE difficulty — already
//! scaled by [`crate::PowScheme::work_multiplier`]. Callers go through
//! [`crate::PowScheme`], which applies that scaling on both the solve and the
//! verify side so the two cannot disagree.
//!
//! A solution is a 64-bit nonce such that
//! `SHA-256(input ‖ nonce)`, read big-endian, is at most `2^256 / T`.
//!
//! # Why a target, not leading zero bits
//!
//! Leading-zero-bit difficulty quantises work to powers of two: the only moves
//! are doubling and halving. The retarget controller adjusts `T` by up to ±25%
//! per epoch ([`crate::policy::MAX_DIFFICULTY_ADJUSTMENT_PCT`]), which a
//! bit-count simply cannot express. A 256-bit target makes difficulty
//! continuous, so the controller that already exists keeps working unchanged.

use sha2::{Digest, Sha256};

use crate::Difficulty;

/// Width of a hashcash solution: a 64-bit nonce.
///
/// Exported so [`crate::PowScheme::solution_len`] can be tied to it at compile
/// time instead of the two drifting apart.
pub const NONCE_LEN: usize = 8;

/// Does `nonce` solve `input` at `difficulty`?
///
/// One hash and one 256-bit comparison — on the order of 100 ns, against the
/// 0.2–0.7 ms the retired MinRoot verify cost. That gap is not incidental: the
/// old cost was itself a denial-of-service surface, because admission ran it on
/// a globally serialised validation path.
pub fn verify(input: &[u8; 32], nonce: &[u8], difficulty: Difficulty) -> bool {
    if difficulty == 0 {
        return false;
    }
    let mut h = Sha256::new();
    h.update(input);
    h.update(nonce);
    let digest: [u8; 32] = h.finalize().into();
    leq_target(&digest, difficulty)
}

/// Find a nonce for `input` at `difficulty`.
///
/// This is the client/tooling side — a node only ever verifies. Expected cost
/// is about `difficulty` hashes, so callers on an interactive thread should
/// treat a large `T` accordingly.
///
/// # Panics
///
/// If `difficulty` is 0, which no solution can satisfy.
pub fn solve(input: &[u8; 32], difficulty: Difficulty) -> [u8; NONCE_LEN] {
    assert!(difficulty > 0, "difficulty 0 is unsatisfiable");
    for n in 0u64.. {
        let nonce = n.to_be_bytes();
        if verify(input, &nonce, difficulty) {
            return nonce;
        }
    }
    unreachable!("a solution exists for any difficulty >= 1")
}

/// Is the 256-bit big-endian `digest` at most `floor(2^256 / t)`?
///
/// Computed without a bigint: for `t >= 1`, `digest <= 2^256/t` exactly when
/// `digest * t < 2^256`. So the question becomes "does the 256×64 multiply
/// overflow 256 bits?" — anything left in the carry is that overflow, i.e. the
/// digest was too large and not enough work was done.
fn leq_target(digest: &[u8; 32], t: u64) -> bool {
    debug_assert!(t >= 1);
    let mut carry: u128 = 0;
    // Little-endian limb walk over a big-endian digest: least-significant limb
    // first, so the carry propagates upward.
    for i in (0..4).rev() {
        let limb = u64::from_be_bytes(
            digest[i * 8..i * 8 + 8]
                .try_into()
                .expect("8 bytes of a 32-byte digest"),
        );
        let prod = u128::from(limb) * u128::from(t) + carry;
        carry = prod >> 64;
    }
    carry == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT: [u8; 32] = [0x11; 32];

    /// A solved nonce verifies at the difficulty it was solved for.
    #[test]
    fn a_solved_nonce_verifies() {
        let t = 4_096;
        let nonce = solve(&INPUT, t);
        assert!(verify(&INPUT, &nonce, t));
    }

    /// Work is bound to the input, so a solution cannot be lifted onto another
    /// transaction. The input carries signer/nonce/block/chain, so this is what
    /// actually stops cross-submission replay.
    #[test]
    fn a_solution_does_not_transfer_to_another_input() {
        let t = 4_096;
        let nonce = solve(&INPUT, t);
        assert!(!verify(&[0x22; 32], &nonce, t));
    }

    /// Harder difficulty is strictly stronger: anything accepted at `t` must
    /// also be accepted at every easier `t' < t`. Without monotonicity a
    /// retarget upward could act as an accidental loosening.
    #[test]
    fn difficulty_is_monotonic() {
        let hard = 8_192;
        let nonce = solve(&INPUT, hard);
        for easier in [1u64, 2, 64, 1_024, hard] {
            assert!(
                verify(&INPUT, &nonce, easier),
                "a solution for t={hard} must satisfy the easier t={easier}"
            );
        }
    }

    /// The target arithmetic at its boundaries — where an off-by-one would
    /// either accept everything or nothing.
    #[test]
    fn the_target_boundaries_hold() {
        assert!(leq_target(&[0xFF; 32], 1), "t=1 accepts any digest");
        assert!(!leq_target(&[0xFF; 32], 2), "a maximal digest fails t=2");
        assert!(
            leq_target(&[0u8; 32], u64::MAX),
            "zero passes any difficulty"
        );
        // Top bit clear is exactly the t=2 threshold.
        let mut half = [0xFFu8; 32];
        half[0] = 0x7F;
        assert!(leq_target(&half, 2));
    }

    /// Difficulty 0 is rejected rather than treated as "no target".
    #[test]
    fn zero_difficulty_never_verifies() {
        assert!(!verify(&INPUT, &[0u8; 8], 0));
    }

    /// Expected work scales with `T`, which is the property the retarget
    /// controller relies on. Sampled over many inputs rather than asserted on
    /// one, since any single solve is geometrically distributed.
    #[test]
    fn expected_work_scales_with_difficulty() {
        fn mean_attempts(t: Difficulty, samples: u32) -> f64 {
            let mut total = 0u64;
            for s in 0..samples {
                let mut input = [0u8; 32];
                input[..4].copy_from_slice(&s.to_be_bytes());
                let nonce = solve(&input, t);
                total += u64::from_be_bytes(nonce) + 1;
            }
            f64::from(u32::try_from(total).expect("small sample totals")) / f64::from(samples)
        }
        let easy = mean_attempts(64, 64);
        let hard = mean_attempts(1_024, 64);
        assert!(
            hard > easy * 4.0,
            "16x the difficulty should cost far more work: easy={easy}, hard={hard}"
        );
    }
}
