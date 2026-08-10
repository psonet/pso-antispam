# pso-antispam

The anonymous-lane admission contract: everything a node and a wallet must agree
on, byte for byte, for an anti-spam-protected transaction to be admitted.

`no_std`, alloc-free, one dependency (`sha2`).

## Why this crate exists

These rules used to be split between `pso-vdf` (input binding, policy constants)
and the node's own mempool crate (the scheme itself). That split fails in one
particularly nasty way: **a client and a node that disagree here fail silently.**
The transaction is never admitted, and neither side logs anything that explains
it — to a user it looks like the chain is down.

So the contract lives in one place and is consumed unmodified by everyone:

```text
node (mempool)  ─┐
mobile wallet   ─┼─→ pso-antispam
test suite      ─┘
```

## What is in it

| Module | Contents |
|---|---|
| `scheme` | `PowScheme` — wire tag, exact solution width, `verify` |
| `hashcash` | SHA-256 hashcash with a 256-bit target (internal — reached via `PowScheme`) |
| `params` | `derive_input_from` (the binding), `is_block_valid` (the window) |
| `policy` | `T_BASE`, `MAX_DIFFICULTY_ADJUSTMENT_PCT`, `EPOCH_LENGTH_BLOCKS`, `PROOF_VALIDITY_WINDOW` |

## Why not in `pso-vdf`

`pso-vdf` is named after a primitive that is being retired. Its MinRoot
construction operates in a group of **public** order, so both the delay and the
Wesolowski proof are forgeable in O(1) (SR-43) — it is not a VDF in the sense
that matters. Only its `minroot`/`prime`/`bigint` modules were ever VDF code;
the input binding and the policy constants never were, and they survive the
retirement unchanged.

Keeping the replacement inside the crate named after the thing it replaces would
mean `pso-vdf` can never be deleted, and would repeat the naming mistake that
made SR-43 confusing in the first place. This crate therefore does **not** depend
on `pso-vdf`. What remains there is the retired primitive, still needed by the
consensus-critical `0x0200` precompile until that is forked out.

## What anti-spam actually needs

Not sequentiality. A VDF's defining property is that one evaluation cannot be
parallelised — and that buys anti-spam nothing, because an attacker never
parallelises a single proof, it runs a thousand independent proofs for a thousand
transactions. What bounds a flood is **cost per submission**, which is
proof-of-work.

Freshness — the other property worth having — never came from the primitive at
all. It comes from the input binding plus the block window, both unchanged by the
scheme swap. That is exactly why they belong here rather than beside any one
algorithm.

## One difficulty, comparable work

The lane carries a single `T` and the retarget controller moves that one
number — but raw schemes cost wildly different amounts per unit. At
`T = 10 000` MinRoot cost a client ~1.4 s of sequential modexps while raw
hashcash costs ~1.4 ms, a thousandfold gap under one number.

`PowScheme::work_multiplier()` normalises that (hashcash ×128). It is applied
**inside** `verify` and `solve_into`, so the two sides cannot drift — which is
why `hashcash` is not public: handing its raw API a lane-level `T` would produce
a solution that is silently never admitted.

×128 is a deliberate step below strict MinRoot parity (~1029). Parity measured
at ~1.3 s per transaction at the configured floor and ~13.5 s at `T_BASE`, with
a geometric tail near 40 s — unshippable in a wallet. ×128 puts those at ~0.17 s
and ~1.7 s. The lane is nominally 8× cheaper to spam than MinRoot, but MinRoot's
cost was FORGEABLE and therefore actually zero: 128 hashes an attacker must pay
beats 1029 they can skip.

Verification is unaffected at ~0.1 µs for any difficulty, so the multiplier
costs the node nothing either way.

## Difficulty is a target divisor

`T` means "a solution must hash below `2^256 / T`", so expected work is
proportional to `T`. The retired VDF used the same type as a count of sequential
steps.

**Same number, different meaning** — anything that treated difficulty as elapsed
time is now wrong.

Cost is quoted in EFFECTIVE work, i.e. after the multiplier above. At the
configured floor `T = 10 000`, hashcash does ~1.28M hashes — roughly 0.17 s on a
desktop core. Raw hashcash at that `T` would be ~1.4 ms, which is why the
multiplier exists.

A 256-bit target rather than leading-zero bits is deliberate. Bits quantise
difficulty to powers of two, and the retarget controller moves `T` by up to ±25%
per epoch — a step a bit-count cannot express.

## Compatibility

`params::derive_input_from` is **frozen**: it reproduces `pso-vdf 0.2.x`
byte for byte, including its mixed endianness (raw address bytes, then
little-endian integers). That is not what one would choose today, but changing it
would lock out every deployed wallet at once. Known-answer tests pin it, and they
have been cross-checked against the real `pso-vdf` implementation rather than a
re-derivation of its documentation.

## Adding a scheme

`PowScheme` is `#[non_exhaustive]`. A new scheme needs a tag, an exact
`solution_len`, and a `verify` arm. It does **not** need a fork: these fields are
pool-only metadata, stripped before a transaction enters a block, so a node
running a different scheme admits more or less spam but cannot disagree about
state.

Note that exact-width solutions are load-bearing. A variable width would let a
caller append bytes the verifier ignores, giving one logical solution several
encodings — malleability on a hash-addressed transaction.
