//! The binding contract: what a solution is computed against, and how long it
//! stays valid.
//!
//! This is the part that must never fork. The scheme can be swapped — it is
//! mempool policy, not consensus — but if a wallet and a node derive different
//! inputs, every transaction that wallet sends is rejected with no way to tell
//! why from either side. The byte layout below is therefore frozen and pinned
//! by known-answer tests.

use sha2::{Digest, Sha256};

use crate::Input;

/// Derive the canonical input a solution must be computed against:
///
/// ```text
/// input = SHA-256(signer_20 ‖ nonce_le_8 ‖ submitted_block_le_8 ‖ chain_id_le_8)
/// ```
///
/// **The byte order is frozen** — it is what deployed wallets already sign
/// against, carried over unchanged from `pso-vdf`'s `VdfParams::derive_input_from`.
/// Note the mixed endianness (raw address bytes, then little-endian integers):
/// it is not what one would choose today, but changing it would invalidate
/// every client at once, so it is preserved deliberately. See
/// [`the_binding_layout_is_frozen`](self#tests).
///
/// Why these four fields, and no others:
///
/// * `signer` — ties the work to one account, so a solution cannot be lifted
///   from another wallet's transaction.
/// * `nonce` — ties it to one transaction slot for that account, so it cannot
///   be reused across that account's own transactions.
/// * `submitted_block` — ties it to a block window, so work cannot be
///   stockpiled and released in a burst (with [`is_block_valid`]).
/// * `chain_id` — so work for one chain is not replayable on another.
///
/// `tx_hash` is deliberately absent: it would be circular, since the hash
/// covers the envelope that carries the solution. `(signer, nonce)` already
/// identifies a transaction slot uniquely before signing.
///
/// Since the `0x77` envelope does not transmit this value, both sides compute
/// it independently — which is what makes the binding unforgeable rather than
/// merely asserted.
pub fn derive_input_from(
    signer: [u8; 20],
    nonce: u64,
    submitted_block: u64,
    chain_id: u64,
) -> Input {
    let mut hasher = Sha256::new();
    hasher.update(signer);
    hasher.update(nonce.to_le_bytes());
    hasher.update(submitted_block.to_le_bytes());
    hasher.update(chain_id.to_le_bytes());
    let out: [u8; 32] = hasher.finalize().into();
    Input(out)
}

/// Is a solution bound to `submitted_block` still acceptable at `current_block`?
///
/// Accepts iff `submitted_block <= current_block` and the gap is at most
/// `window` (see [`crate::policy::PROOF_VALIDITY_WINDOW`]).
///
/// The forward check matters as much as the backward one: without it a client
/// could bind work to a block that does not exist yet and keep the solution
/// valid indefinitely as the chain caught up.
pub const fn is_block_valid(submitted_block: u64, current_block: u64, window: u64) -> bool {
    submitted_block <= current_block && current_block - submitted_block <= window
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Known-answer vectors.** These digests are what `pso-vdf 0.2.x` produced
    /// and what deployed wallets are already computing. If this test fails, the
    /// binding has silently forked and every existing client is locked out —
    /// which presents as "the chain stopped accepting my transactions" with no
    /// error explaining it. Do not re-bless these values; fix the code.
    #[test]
    fn the_binding_layout_is_frozen() {
        let a = derive_input_from([0xab; 20], 7, 100, 19_280_501);
        assert_eq!(
            &hex(a.as_bytes()),
            b"c1a74a596d9bd6c3849dcc890e4019587aa648ba7c4cfffbec1d0a3a47f5aec4"
        );

        let mut signer = [0u8; 20];
        for (i, b) in signer.iter_mut().enumerate() {
            *b = i as u8;
        }
        let b = derive_input_from(signer, 0, 0, 9_900_501);
        assert_eq!(
            &hex(b.as_bytes()),
            b"11c9d34c2c3540d1787b8138f2118624b6216b2ed0e0457de7d183071a36ba28"
        );
    }

    /// Each bound field must actually change the input — otherwise the field is
    /// decorative and the replay it was meant to stop is possible.
    #[test]
    fn every_bound_field_changes_the_input() {
        let base = derive_input_from([0xab; 20], 7, 100, 19_280_501);
        assert_ne!(
            base,
            derive_input_from([0xac; 20], 7, 100, 19_280_501),
            "signer"
        );
        assert_ne!(
            base,
            derive_input_from([0xab; 20], 8, 100, 19_280_501),
            "nonce"
        );
        assert_ne!(
            base,
            derive_input_from([0xab; 20], 7, 101, 19_280_501),
            "block"
        );
        assert_ne!(
            base,
            derive_input_from([0xab; 20], 7, 100, 19_280_502),
            "chain"
        );
    }

    /// The window is backward-looking and inclusive at both ends, and a
    /// future-dated block is never valid.
    #[test]
    fn the_block_window_bounds_both_directions() {
        assert!(is_block_valid(100, 100, 32), "same block is in window");
        assert!(is_block_valid(100, 132, 32), "the far edge is inclusive");
        assert!(!is_block_valid(100, 133, 32), "past the window");
        assert!(
            !is_block_valid(101, 100, 32),
            "a future block is never valid"
        );
    }

    /// Alloc-free hex, so the tests run in the same `no_std` configuration the
    /// crate ships in rather than only under `--features std`.
    fn hex(bytes: &[u8; 32]) -> [u8; 64] {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 64];
        for (i, b) in bytes.iter().enumerate() {
            out[i * 2] = DIGITS[(b >> 4) as usize];
            out[i * 2 + 1] = DIGITS[(b & 0x0f) as usize];
        }
        out
    }
}
