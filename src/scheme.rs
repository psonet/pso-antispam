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

    /// Solve for this scheme, writing the solution into `out`.
    ///
    /// Returns `false` without touching `out` if the scheme cannot be solved
    /// (retired) or `out` is not exactly [`solution_len`](Self::solution_len)
    /// bytes.
    ///
    /// This exists so a client can solve for *whatever scheme the node asks
    /// for*. Without it, [`verify`](Self::verify) is scheme-generic but solving
    /// is not — every wallet has to name a concrete scheme and call its
    /// module directly, which re-creates exactly the hard-coding this crate was
    /// extracted to remove. A second scheme would then need a change in every
    /// client rather than only here.
    ///
    /// Alloc-free by design: the caller owns the buffer, so this works
    /// unchanged in a `no_std` wallet. Size it with `solution_len()`.
    ///
    /// Expected cost is about `difficulty` hashes, so treat it as blocking
    /// work rather than something to run on an interactive thread.
    ///
    /// ```
    /// use pso_antispam::PowScheme;
    /// let scheme = PowScheme::Hashcash;
    /// let input = [0x11u8; 32];
    /// let mut solution = [0u8; 8];
    /// assert_eq!(solution.len(), scheme.solution_len());
    /// assert!(scheme.solve_into(&input, 1_024, &mut solution));
    /// assert!(scheme.verify(&input, &solution, 1_024));
    /// ```
    pub fn solve_into(self, input: &[u8; 32], difficulty: Difficulty, out: &mut [u8]) -> bool {
        if out.len() != self.solution_len() || difficulty == 0 {
            return false;
        }
        match self {
            // Retired, and deliberately unsolvable here: handing a caller a
            // forgeable proof would defeat the point of retiring it.
            Self::MinRoot => false,
            Self::Hashcash => {
                out.copy_from_slice(&hashcash::solve(input, difficulty));
                true
            }
        }
    }
}

/// The solver writes a fixed-width nonce, and `solution_len` is what every
/// caller sizes its buffer with. If those two ever disagree, `solve_into`
/// would either panic on the copy or silently produce a solution the wire
/// format rejects — so tie them together at COMPILE time rather than hoping a
/// test covers it.
const _: () = assert!(PowScheme::Hashcash.solution_len() == hashcash::NONCE_LEN);

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

    /// Solve-then-verify round-trips through the generic entry points, with no
    /// mention of a concrete scheme — which is the property that lets a client
    /// follow whatever scheme the node asks for.
    #[test]
    fn solve_into_round_trips_through_verify() {
        let scheme = PowScheme::Hashcash;
        let t = 2_048;
        let mut out = [0u8; 8];
        assert_eq!(out.len(), scheme.solution_len());
        assert!(scheme.solve_into(&INPUT, t, &mut out));
        assert!(scheme.verify(&INPUT, &out, t));
    }

    /// A retired scheme cannot be solved. Handing a caller a forgeable proof
    /// would defeat retiring it, so this must stay false even though the
    /// buffer is correctly sized.
    #[test]
    fn a_retired_scheme_cannot_be_solved() {
        let mut out = [0u8; 96];
        assert_eq!(out.len(), PowScheme::MinRoot.solution_len());
        assert!(!PowScheme::MinRoot.solve_into(&INPUT, 10_000, &mut out));
        assert_eq!(
            out, [0u8; 96],
            "a refused solve must not write to the buffer"
        );
    }

    /// A wrongly sized buffer is refused rather than partially filled — a
    /// short write would leave the caller holding a solution that cannot
    /// verify, with nothing to say why.
    #[test]
    fn solve_into_refuses_a_wrongly_sized_buffer() {
        let scheme = PowScheme::Hashcash;
        let mut short = [0u8; 7];
        let mut long = [0u8; 9];
        assert!(!scheme.solve_into(&INPUT, 64, &mut short));
        assert!(!scheme.solve_into(&INPUT, 64, &mut long));
        assert_eq!(short, [0u8; 7]);
        assert_eq!(long, [0u8; 9]);
        // Difficulty 0 is unsolvable, and must not panic the way the bare
        // hashcash::solve does — the generic entry point answers instead.
        let mut ok = [0u8; 8];
        assert!(!scheme.solve_into(&INPUT, 0, &mut ok));
    }

    /// Difficulty 0 is never satisfiable — a target divisor of zero would
    /// otherwise mean "accept anything".
    #[test]
    fn zero_difficulty_never_verifies() {
        assert!(!PowScheme::Hashcash.verify(&INPUT, &[0u8; 8], 0));
    }
}
