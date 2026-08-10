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

    /// How many units of raw scheme work one unit of `difficulty` buys.
    ///
    /// The lane carries ONE difficulty for every scheme, and the retarget
    /// controller moves that single number. Without normalisation the same `T`
    /// means wildly different work per scheme: at `T = 10_000` MinRoot cost a
    /// client ~1.4 s of sequential modexps, while raw hashcash costs ~1.4 ms —
    /// a thousandfold gap under one number, which would silently gut the
    /// anti-spam budget the controller was calibrated against the moment a
    /// client switched schemes.
    ///
    /// 128 is a deliberate step BELOW strict parity with MinRoot, which
    /// measured ~1029. Parity was the first choice, and measuring it properly
    /// killed it: at ×1024 one unit of `T` costs ~0.13 ms, so the configured
    /// floor (`T = 10_000`) is ~1.3 s and `T_BASE` ~13.5 s of client work — on
    /// a desktop core, with a geometric tail putting the unlucky case near 40 s.
    /// A phone is no faster. That is not a transaction a wallet can ship.
    ///
    /// ×128 puts the floor at ~0.17 s and `T_BASE` at ~1.7 s, which a wallet
    /// can absorb. The lane is 8× cheaper to spam than MinRoot nominally was —
    /// but MinRoot's cost was FORGEABLE, so its real price was zero. 128 hashes
    /// per unit that an attacker must actually pay beats 1029 they could skip.
    ///
    /// Verification is unaffected: it is a single hash and a 256-bit compare,
    /// ~0.1 µs at ANY difficulty. Raising the multiplier costs the node
    /// nothing, which is the asymmetry proof-of-work is supposed to provide
    /// and the retired scheme did not (its verify was 0.2–0.7 ms, itself a
    /// denial-of-service surface).
    pub const fn work_multiplier(self) -> u64 {
        match self {
            // Its own native unit: one iteration of the sequential map.
            Self::MinRoot => 1,
            Self::Hashcash => 128,
        }
    }

    /// The raw scheme work one lane-level `difficulty` buys, saturating rather
    /// than wrapping — a wrap would turn a difficulty INCREASE into a
    /// catastrophic decrease.
    pub const fn effective_difficulty(self, difficulty: Difficulty) -> Difficulty {
        difficulty.saturating_mul(self.work_multiplier())
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
            Self::Hashcash => {
                hashcash::verify(input, solution, self.effective_difficulty(difficulty))
            }
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
    /// // Small T on purpose: effective work is T x work_multiplier().
    /// assert!(scheme.solve_into(&input, 4, &mut solution));
    /// assert!(scheme.verify(&input, &solution, 4));
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
                out.copy_from_slice(&hashcash::solve(
                    input,
                    self.effective_difficulty(difficulty),
                ));
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
        // Raw solve: this asserts WIDTH, so it deliberately skips the
        // multiplier and stays cheap.
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
        let t = 4;
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
        assert!(!scheme.solve_into(&INPUT, 4, &mut short));
        assert!(!scheme.solve_into(&INPUT, 4, &mut long));
        assert_eq!(short, [0u8; 7]);
        assert_eq!(long, [0u8; 9]);
        // Difficulty 0 is unsolvable, and must not panic the way the bare
        // hashcash::solve does — the generic entry point answers instead.
        let mut ok = [0u8; 8];
        assert!(!scheme.solve_into(&INPUT, 0, &mut ok));
    }

    /// The multiplier must be applied by BOTH sides or not at all. If solve
    /// and verify disagreed, the solution would be well-formed and simply
    /// never admitted — the silent failure this crate exists to prevent. This
    /// pins that they agree by construction: a solution produced at `t`
    /// verifies at `t`, and one produced at RAW `t` (multiplier skipped, as a
    /// stale client would) does not.
    #[test]
    fn the_multiplier_is_applied_on_both_sides() {
        let scheme = PowScheme::Hashcash;
        let t = 4;
        let mut out = [0u8; 8];
        assert!(scheme.solve_into(&INPUT, t, &mut out));
        assert!(scheme.verify(&INPUT, &out, t));

        // A raw solve at the same nominal t is 128x too easy, so it must not
        // pass the scheme-level check. (Probabilistic: a raw solution clears
        // the harder target only with chance 1/128, so pick one that doesn't.)
        let mut raw_rejected = false;
        for seed in 0u8..8 {
            let mut input = INPUT;
            input[0] = seed;
            let raw = hashcash::solve(&input, t);
            if !scheme.verify(&input, &raw, t) {
                raw_rejected = true;
                break;
            }
        }
        assert!(
            raw_rejected,
            "a solution that skipped the multiplier must not verify"
        );
    }

    /// The multiplier is a wire-affecting constant: changing it invalidates
    /// every solution in flight and silently reprices the whole lane, so it is
    /// pinned by value rather than merely being read from the source.
    #[test]
    fn the_multipliers_are_pinned() {
        assert_eq!(PowScheme::MinRoot.work_multiplier(), 1);
        assert_eq!(PowScheme::Hashcash.work_multiplier(), 128);
        assert_eq!(PowScheme::Hashcash.effective_difficulty(10_000), 1_280_000);
    }

    /// Saturating, not wrapping. A wrap would turn a difficulty INCREASE into
    /// a catastrophic decrease — the retarget controller raising T would make
    /// the lane easier, which is the worst possible direction to fail.
    #[test]
    fn effective_difficulty_saturates() {
        assert_eq!(PowScheme::Hashcash.effective_difficulty(u64::MAX), u64::MAX);
        assert_eq!(PowScheme::MinRoot.effective_difficulty(u64::MAX), u64::MAX);
    }

    /// Difficulty 0 is never satisfiable — a target divisor of zero would
    /// otherwise mean "accept anything".
    #[test]
    fn zero_difficulty_never_verifies() {
        assert!(!PowScheme::Hashcash.verify(&INPUT, &[0u8; 8], 0));
    }
}
