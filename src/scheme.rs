//! Which anti-spam construction an envelope carries.

use crate::{hashcash, Difficulty};

/// The scheme a solution was produced under.
///
/// The tag travels on the wire so a node can verify a solution it did not
/// choose the scheme for, and so two schemes can be accepted simultaneously
/// during a rollout.
///
/// This is safe to change without a fork because these fields are POOL-ONLY
/// metadata, stripped before a transaction enters a block. A node running a
/// different scheme admits more or less spam; it cannot disagree about state.
/// That is what makes a rolling upgrade possible, and what leaves room for a
/// memory-hard scheme (Equihash, Cuckoo Cycle) later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PowScheme {
    /// Tag 0 — MinRoot/Wesolowski over BLS12-381 `Fq`. **FORGEABLE IN O(1)**
    /// (SR-43); retained only so a legacy envelope still decodes and can be
    /// given a truthful rejection. [`PowScheme::verify`] always answers `false`
    /// for it.
    MinRoot,
    /// Tag 1 — hashcash over SHA-256, with a 256-bit target. See
    /// [`crate::hashcash`].
    Hashcash,
}

impl PowScheme {
    /// Wire tag.
    pub const fn tag(self) -> u8 {
        match self {
            Self::MinRoot => 0,
            Self::Hashcash => 1,
        }
    }

    /// Decode a wire tag. Unknown tags do not decode, rather than defaulting.
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::MinRoot),
            1 => Some(Self::Hashcash),
            _ => None,
        }
    }

    /// Exact solution width in bytes, pinned per scheme.
    ///
    /// Exact, not a maximum. A variable width would let a caller append bytes
    /// the verifier ignores, giving the same logical solution more than one
    /// encoding — malleability on a hash-addressed transaction.
    pub const fn solution_len(self) -> usize {
        match self {
            // 48-byte compressed Fq output ‖ 48-byte proof.
            Self::MinRoot => 96,
            // A 64-bit nonce. The digest is recomputed, never transmitted.
            Self::Hashcash => 8,
        }
    }

    /// Is `solution` well-formed for `input` at `difficulty`?
    ///
    /// Shape is checked before anything expensive. `MinRoot` always answers
    /// `false`: this crate refuses to be the thing that validates a forgeable
    /// proof. A caller that wants to explain the refusal to a client should
    /// check the tag itself and say the scheme is retired — silence here would
    /// be indistinguishable from "your work was wrong".
    pub fn verify(self, input: &[u8; 32], solution: &[u8], difficulty: Difficulty) -> bool {
        if solution.len() != self.solution_len() || difficulty == 0 {
            return false;
        }
        match self {
            Self::MinRoot => false,
            Self::Hashcash => hashcash::verify(input, solution, difficulty),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT: [u8; 32] = [0x11; 32];

    /// Tags are wire values: changing one silently reinterprets every envelope
    /// already in flight, so they are pinned rather than derived from ordering.
    #[test]
    fn tags_round_trip_and_are_pinned() {
        assert_eq!(PowScheme::MinRoot.tag(), 0);
        assert_eq!(PowScheme::Hashcash.tag(), 1);
        for s in [PowScheme::MinRoot, PowScheme::Hashcash] {
            assert_eq!(PowScheme::from_tag(s.tag()), Some(s));
        }
        assert_eq!(PowScheme::from_tag(2), None, "unknown tags must not decode");
    }

    /// Width is exact, not a minimum: a longer nonce sharing a prefix must not
    /// verify, or one logical solution would have many encodings.
    #[test]
    fn the_solution_width_is_exact() {
        let t = 1_024;
        let nonce = hashcash::solve(&INPUT, t);
        let mut padded = [0u8; 9];
        padded[..8].copy_from_slice(&nonce);
        assert!(!PowScheme::Hashcash.verify(&INPUT, &padded, t));
        assert!(!PowScheme::Hashcash.verify(&INPUT, &nonce[..7], t));
    }

    /// SR-43. MinRoot decodes so a legacy envelope can be refused truthfully,
    /// but it is never VERIFIABLE here — its proof is forgeable in O(1), so a
    /// module that answered `true` would reopen the hole this crate closes.
    #[test]
    fn minroot_never_verifies_even_with_a_well_formed_solution() {
        let solution = [0x33u8; 96];
        assert_eq!(solution.len(), PowScheme::MinRoot.solution_len());
        assert!(!PowScheme::MinRoot.verify(&INPUT, &solution, 10_000));
        // Including the degenerate all-zero pair that started SR-01.
        assert!(!PowScheme::MinRoot.verify(&INPUT, &[0u8; 96], 10_000));
    }

    /// Difficulty 0 is never satisfiable — a target divisor of zero would
    /// otherwise mean "accept anything".
    #[test]
    fn zero_difficulty_never_verifies() {
        assert!(!PowScheme::Hashcash.verify(&INPUT, &[0u8; 8], 0));
    }
}
