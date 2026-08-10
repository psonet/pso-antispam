//! The anonymous-lane admission contract: everything a node and a wallet must
//! agree on, byte for byte, for an anti-spam-protected transaction to be
//! admitted.
//!
//! # Why this crate exists
//!
//! These rules were spread across `pso-vdf` (input binding, policy constants)
//! and the node's own mempool crate (the scheme itself). That split was
//! dangerous in one specific way: **a client and a node that disagree here fail
//! silently.** The transaction is simply never admitted, and nothing in either
//! log says why. So the contract lives in one place, depends on nothing but a
//! hash, and is consumed unmodified by every party:
//!
//! ```text
//! node (mempool)  ─┐
//! mobile wallet   ─┼─→ pso-antispam
//! test suite      ─┘
//! ```
//!
//! # Why not in `pso-vdf`
//!
//! `pso-vdf` names a primitive that is being retired. Its MinRoot construction
//! operates in a group of PUBLIC order, so both the delay and the Wesolowski
//! proof are forgeable in O(1) (SR-43) — it is not a VDF in the sense that
//! matters. Only its MinRoot/prime/bigint modules are actually VDF code; the
//! input binding and the policy constants never were, and they survive the
//! retirement unchanged. Keeping the replacement inside the crate named after
//! the thing it replaces would mean `pso-vdf` can never be deleted, and would
//! repeat the naming mistake that made SR-43 confusing in the first place.
//!
//! This crate therefore does **not** depend on `pso-vdf`. What is left there is
//! the retired primitive, still needed by the consensus-critical `0x0200`
//! precompile until that is forked out.
//!
//! # What anti-spam actually needs
//!
//! Not sequentiality. A VDF's defining property is that one evaluation cannot
//! be parallelised, and that buys anti-spam nothing — an attacker never
//! parallelises a single proof, it runs a thousand independent proofs for a
//! thousand transactions. What bounds a flood is COST PER SUBMISSION, which is
//! proof-of-work.
//!
//! Freshness — the other property worth having — never came from the primitive
//! at all. It comes from [`params::derive_input_from`] binding the work to
//! `(signer, nonce, submitted_block, chain_id)`, plus the block window in
//! [`params::is_block_valid`]. Both are unchanged by the scheme swap, which is
//! precisely why they belong here rather than beside any one algorithm.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

// Crate-private ON PURPOSE. Its `solve`/`verify` take the EFFECTIVE difficulty
// (already multiplied); a caller handing them a lane-level `T` would produce a
// solution 1024x too easy that `PowScheme::verify` rejects — and rejects
// silently, since an unadmitted transaction reports nothing. Routing every
// caller through `PowScheme` makes that mistake unrepresentable rather than
// merely documented.
pub(crate) mod hashcash;
pub mod params;
pub mod policy;
pub mod scheme;

pub use params::{derive_input_from, is_block_valid};
pub use policy::{
    EPOCH_LENGTH_BLOCKS, MAX_DIFFICULTY_ADJUSTMENT_PCT, PROOF_VALIDITY_WINDOW, T_BASE,
};
pub use scheme::PowScheme;

/// The work parameter `T`.
///
/// Read as a TARGET DIVISOR, not an iteration count: a solution must hash below
/// `2^256 / T`, so expected work is proportional to `T`. The retired VDF used
/// the same type as a count of sequential steps — same number, different
/// meaning — so anything that treated difficulty as elapsed time is wrong now.
pub type Difficulty = u64;

/// The canonical 32-byte value a solution is computed against.
///
/// Never transmitted on the `0x77` wire: both sides derive it from transaction
/// context via [`derive_input_from`], which is what binds a solution to one
/// submission and makes replay onto another impossible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input(pub [u8; 32]);

impl Input {
    /// Borrow the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Input {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
