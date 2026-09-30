# ethrex-side `pre_verify` Validation-Prefix Recognition — Design Spec

## Context and Goal

EIP-8141's validation prefix currently recognizes four canonical shapes:
`SelfVerify`, `DeploySelfVerify`, `OnlyVerifyPay`, `DeployOnlyVerifyPay`. An
in-progress ERC (ethereum/ERCs#2028, "Frame Transaction Alternative
Mempools") adds a fifth frame role, `pre_verify`: a `DEFAULT`-mode
(write-capable) frame that may immediately precede an approving
(`VERIFY`-mode) frame in the prefix, whose resolved target must equal that
approving frame's resolved target (ERC-2028 PREFIX-110). This lets, e.g., a
paymaster's `pay` frame be preceded by a `pre_verify` frame that pulls an
ERC-20 payment into the paymaster's balance before the `pay` frame runs —
a state-writing step inside the validation prefix that today's structural
rules reject outright.

Skandha (the TypeScript bundler sidecar) already recognizes and displays
`pre_verify` shapes end-to-end — this was scoped narrowly to shape
recognition only (not the ERC's staking/reputation/propagation machinery),
and is complete and merged. This spec covers the matching gap on ethrex,
the execution client Skandha talks to: **ethrex's mempool/RPC layer
doesn't recognize `pre_verify` shapes at all today**, so a `pre_verify`
demo transaction can't be admitted or simulated, blocking the paymaster
demo end-to-end.

**Scope, confirmed with the user (revised from an earlier draft of this
spec — see below):** shape recognition, plus decoupling
`ethrex_simulateFrameTransaction`'s canonical-mempool-policy verdict from
whether it actually runs and reports execution. Explicitly **out of
scope**: the canonical-paymaster exemption pattern and EIP-8312
vault-sender/self-funded-UTXO interplay. Also out of scope: the real
mempool's own admission path (`blockchain.rs`'s transaction-pool
admission, backing `eth_sendRawTransaction`) — this spec touches only the
read-only `ethrex_simulateFrameTransaction` RPC's own handler.

**Known incidental behavior change (found during final review, accepted as-is
— not a deliberate code change, just documented):** EIP-8369 Profile 2
(FOCIL AA-VOPS) inclusion-list eligibility (`crates/blockchain/focil_eligibility.rs`,
`crates/blockchain/focil_profile2.rs`) calls the same shared
`validation_prefix()` this spec extends. Before this change, a `pre_verify`
transaction was always `UnrecognizedPrefix` and therefore never a Profile 2
candidate; after this change, a transaction with a recognized `pre_verify`
shape CAN become a Profile 2 candidate (its prefix gas is counted toward
`verify_budget_prefix_cost`, and a pre_verify frame that stays inside the
AA-VOPS storage surface can pass Profile 2 replay) — purely as a side effect
of sharing the recognizer, with no `pre_verify`-specific FOCIL logic added.
This was NOT gated off: the user reviewed this finding and chose to accept
the behavior change rather than add a `pre_verify_indices.is_empty()` guard
to preserve the old exclusion. If FOCIL/Profile 2 eligibility for
`pre_verify` transactions ever needs to be revisited, start here.

**Revision note:** an earlier draft of this spec's Part 2 proposed
widening `ValidationObserver`'s write-permission gate (a
`deploy_frame_index: Option<usize>` → `write_allowed_frames: Vec<usize>`
rename) so `pre_verify` frames could `SSTORE` like deploy frames do. That
turned out to solve the wrong layer: `SSTORE`'s observer check restricts
writes to the *sender's own* storage (`address == sender`, where `address`
is the executing call frame's own address per normal EVM `SSTORE`
semantics) — so even with that widening, a `pre_verify` frame calling out
to an ERC-20 contract to pull a payment would still trip the check on the
token contract's own balance-update `SSTORE`, which never touches sender's
storage. The actual fix, below, is to stop gating execution on
canonical-mempool-policy verdicts at all for this RPC, which sidesteps the
problem entirely rather than trying to widen what the write-gate permits.

**Confirmed non-consensus:** `validation_prefix()` /
`validate_prefix_structure()` and `ValidationObserver` are exclusively
mempool/RPC/FOCIL-eligibility policy — never a consensus rule. Block
execution and block building always run with `ValidationObserver::disabled()`
and never call `validation_prefix()`. This change touches none of that
consensus path.

## Two-Part Change

### Part 1 — Shape recognition (`crates/common/types/transaction.rs`)

`validation_prefix()` and `validate_prefix_structure()` are restructured to
recognize an optional `pre_verify` frame immediately before *any* approving
(`VERIFY`-mode) frame in the prefix — not just a fixed leading position —
while keeping the existing `deploy`-frame recognition and disambiguating
between the two the same way Skandha's already-shipped algorithm does.

`PrefixShape`'s four variants are unchanged — they still describe the
approving-frame skeleton. `ValidationPrefix` gains one new field:

```rust
pub struct ValidationPrefix {
    pub shape: PrefixShape,
    pub frame_indices: Vec<usize>,          // unchanged: every frame in the
                                             // prefix, in order, now
                                             // including any pre_verify frames
    pub deploy_index: Option<usize>,        // unchanged
    pub pay_index: Option<usize>,           // unchanged
    /// (pre_verify frame index, the approving frame index it precedes and
    /// target-matches), one pair per recognized pre_verify frame. Empty
    /// when no pre_verify frame is present.
    pub pre_verify_indices: Vec<(usize, usize)>,
}
```

Carrying both indices per pair (rather than a flat `Vec<usize>`) lets
`validate_prefix_structure` re-derive and re-check the PREFIX-110
target-match without recomputing which approving frame each pre_verify
frame belongs to.

**Matching algorithm.** Reusing `validation_prefix()`'s existing
`non_expiry`/`frame`/`is_default`/`is_verify`/`scope_of` closures, add:

```rust
// Deliberately NOT `.unwrap_or(self.sender)`: a DEFAULT-mode frame's
// target of `None` means CREATE-at-self-address semantics for a real
// deploy (see `deploy_frame()`'s test fixture, which always uses `None`)
// — resolving it to `sender` here would make an ordinary deploy frame
// indistinguishable from a pre_verify frame targeting sender, breaking
// existing shape recognition (verified against
// `prefix_shape_deploy_self_verify` in
// `test/tests/common/frame_tx_validation_tests.rs`, whose `deploy_frame()`
// has `target: None` immediately followed by `self_verify_frame()`
// targeting sender — with `.unwrap_or(sender)` this pair would wrongly
// match as `SelfVerify` + pre_verify instead of `DeploySelfVerify`).
// pre_verify candidacy therefore requires an EXPLICIT target.
let target_at = |pos: usize| -> Option<Address> { frame(pos).and_then(|f| f.target) };

// Matches an approving VERIFY frame with `expected_scope` at `pos`,
// optionally preceded by a pre_verify frame (a DEFAULT-mode frame with an
// explicit target equal to the approving frame's). Returns the approving
// frame's position, the pre_verify frame's position (if any), and the
// next unconsumed position — or None if `pos` doesn't yield a match.
let match_approving = |pos: usize, expected_scope: u8| -> Option<(usize, Option<usize>, usize)> {
    if is_verify(pos) && scope_of(pos) == expected_scope {
        return Some((pos, None, pos + 1));
    }
    if is_default(pos)
        && target_at(pos).is_some()
        && is_verify(pos + 1)
        && scope_of(pos + 1) == expected_scope
        && target_at(pos) == target_at(pos + 1)
    {
        return Some((pos + 1, Some(pos), pos + 2));
    }
    None
};
```

Control flow is organized by approving-frame count first, deploy-vs-not
second — the two counts are mutually exclusive by construction (a 2-frame
skeleton requires `scope_of` values a 1-frame skeleton can't produce), so
trying them in either order is equally correct; the deploy-vs-not choice
within each is where the new ambiguity lives:

1. Try the 2-approving-frame skeleton (`exec` then `pay`) starting at
   position 0, **without** consuming position 0 as deploy — i.e. call
   `match_approving(0, APPROVE_EXECUTION)` then `match_approving(next,
   APPROVE_PAYMENT)`. Success → `OnlyVerifyPay` (with whatever
   `pre_verify_indices` the calls found).
2. Only if step 1 failed, retry the same skeleton starting at position 1
   with `deploy_index: Some(non_expiry[0])`, requiring `is_default(0)`.
   Success → `DeployOnlyVerifyPay`.
3. Only if steps 1-2 failed, try the 1-approving-frame skeleton
   (`match_approving(0, APPROVE_EXECUTION_AND_PAYMENT)`) without deploy.
   Success → `SelfVerify`.
4. Only if step 3 failed, retry from position 1 with `deploy_index:
   Some(non_expiry[0])`. Success → `DeploySelfVerify`.
5. All four failed → `UnrecognizedPrefix`.

Trying the no-deploy interpretation before the deploy interpretation at
each step is what resolves the deploy/pre_verify ambiguity at position 0:
if frame 0's target matches frame 1's target, `match_approving` consumes
it as `pre_verify` in step 1 (or 3) and the function returns before step 2
(or 4) — the deploy branch — ever runs. This is structurally equivalent to
(and simpler than) the explicit target-mismatch guard Skandha needed,
because here the two interpretations are tried in explicit priority order
rather than reasoned about after the fact.

Example (`DeployOnlyVerifyPay` arm, no-deploy attempt shown; the full
function repeats this shape for both the with- and without-deploy cases,
and equivalently for the other three shapes):

```rust
if let Some((exec_pos, pv1, next)) = match_approving(0, APPROVE_EXECUTION) {
    if let Some((pay_pos, pv2, _)) = match_approving(next, APPROVE_PAYMENT) {
        let mut frame_indices = Vec::new();
        let mut pre_verify_indices = Vec::new();
        if let Some(p) = pv1 {
            frame_indices.push(non_expiry[p]);
            pre_verify_indices.push((non_expiry[p], non_expiry[exec_pos]));
        }
        frame_indices.push(non_expiry[exec_pos]);
        if let Some(p) = pv2 {
            frame_indices.push(non_expiry[p]);
            pre_verify_indices.push((non_expiry[p], non_expiry[pay_pos]));
        }
        frame_indices.push(non_expiry[pay_pos]);
        return Ok(ValidationPrefix {
            shape: PrefixShape::OnlyVerifyPay,
            frame_indices,
            deploy_index: None,
            pay_index: Some(non_expiry[pay_pos]),
            pre_verify_indices,
        });
    }
}
```

(The plan will spell out all eight arms — with/without deploy × the two
non-deploy shapes' approving-frame counts — in full; this spec fixes the
algorithm and data shape, not every line.)

**`validate_prefix_structure` changes.** The existing per-frame `match
prefix.deploy_index { Some(idx) if idx == frame_idx => ..., _ => ... }`
gains a third arm for pre_verify frames (checked before the deploy/VERIFY
match, since pre_verify frames are DEFAULT-mode like deploy but must not
fall into the deploy branch):

```rust
if let Some(&(_, approving_idx)) = prefix.pre_verify_indices.iter().find(|(pv, _)| *pv == idx) {
    if frame.mode != FrameMode::Default as u8 {
        return Err(FrameValidationError::PreVerifyNotDefaultMode { frame_index: idx });
    }
    // Explicit `Some` only — see `target_at`'s note in the matching
    // algorithm above for why `None` (deploy's CREATE-at-self semantics)
    // must never be treated as "matches the approving frame's target".
    let approving_target = self.frames[approving_idx].target.unwrap_or(self.sender);
    match frame.target {
        Some(addr) if addr == approving_target => {}
        _ => return Err(FrameValidationError::PreVerifyTargetMismatch { frame_index: idx }),
    }
} else {
    match prefix.deploy_index {
        // ... existing deploy / VERIFY-frame arms, unchanged ...
    }
}
```

Two new `FrameValidationError` variants:

```rust
#[error("frame {frame_index}: pre_verify frame must use DEFAULT execution mode")]
PreVerifyNotDefaultMode { frame_index: usize },
#[error("frame {frame_index}: pre_verify frame target does not match the approving frame it precedes")]
PreVerifyTargetMismatch { frame_index: usize },
```

All other existing checks (atomic-batch ban, expiry-frame-first,
no-VERIFY-after-prefix, gas budget) already iterate `prefix.frame_indices`
generically and need no change — pre_verify frames are covered
automatically since they're included in `frame_indices`.

### Part 2 — Decouple canonical-policy verdict from execution (`crates/networking/rpc/ethrex.rs`)

This part has no Skandha-side equivalent and, after the revision above, no
`ValidationObserver`/`vm.rs` changes at all — it is scoped entirely to
`SimulateFrameTransactionRequest::handle` (`ethrex_simulateFrameTransaction`'s
handler).

**The principle (the user's framing, adopted as-is):**
`ethrex_simulateFrameTransaction`'s primary job is to answer "what happens
if this transaction is included in a block" — that's what `execute_for_gas`
(plain execution, `ValidationObserver` always `disabled()`, confirmed by
reading `VM::new`'s default at `crates/vm/levm/src/vm.rs:1137` and that
`execute_tx` never touches `validation_observer`) and the optional
`erc7562_trace` pass already compute, and it is genuinely unrestricted —
real consensus-equivalent execution, no ERC-7562/EIP-8141 mempool-policy
opcode or storage restriction applies to it at all. Separately, "would
`eth_sendRawTransaction`'s mempool accept this" is a DIFFERENT question,
answered today by `validation_prefix()`/`validate_prefix_structure()` and
the `ValidationObserver`-gated `simulate_prefix()` pass. Today the RPC
handler treats a `false` answer to the second question as a reason to
never answer the first — an early `return` at each canonical-policy check
skips `execute_for_gas`/the trace pass entirely. That coupling is the
actual root cause blocking the `pre_verify` demo: even after Part 1 makes
`validation_prefix()` recognize `pre_verify`, the *separate*
`ValidationObserver`-gated `simulate_prefix()` pass would still flag a
policy violation for a `pre_verify` frame's ERC-20-pulling nested call
(its target contract's own `SSTORE`, which the sender-only write-gate
was never designed to permit — see the Revision Note above), and that
`false` would still suppress the execution result. The fix is to make the
canonical-policy verdict purely informational everywhere it is currently a
gate, so a policy rejection is *reported*, never *hidden*.

**What stays a hard precondition (unchanged, still gates the response
before any of the below runs):**
- `frame_tx.validate_static_constraints(...)` — wire-level well-formedness
  (frame mode bytes, EIP-8250 nonce-key shape, EIP-8312 fork gating). Not a
  policy opinion; a malformed frame transaction cannot be meaningfully
  executed at all.
- `frame_tx.signature_verification_cost() > max_verify_gas` — unrelated to
  `pre_verify`; left untouched to keep this change minimal and reviewable.
- `ethrex_vm::validate_frame_signatures(...)` — `sender` is an
  unauthenticated wire field until this passes; simulating "what an
  unauthenticated claimed sender's transaction does" would attribute state
  changes to a sender who never actually signed anything, which is a
  different and less meaningful question than the one this RPC answers.
- The per-transaction gas-limit DoS guard (`total_gas_limit > max_allowed`)
  — protects the RPC server's own resources, not a policy opinion about
  the transaction; unrelated to `pre_verify`, left untouched.

**What becomes informational instead of gating:**
- `frame_tx.validation_prefix()` / `validate_prefix_structure()` failing
  (today: `return structurally_invalid(...)` at the call site around
  `ethrex.rs:276-282`).
- `context.blockchain.check_utxo_admission(...)` /
  `check_recent_root_references(...)` failing (today: same early-return
  pattern, `ethrex.rs:290-304`). **Scope note:** neither of these is
  actually required to unblock the `pre_verify` demo — only
  `validation_prefix()`/`simulate_prefix()` are. I'm including them because
  the user's stated principle ("simulate what happens; report acceptance
  separately") applies to them identically — both are "would the mempool
  accept this" questions, not "what happens" ones, and `check_utxo_admission`/
  `check_recent_root_references` take `frame_tx` directly (not `prefix`),
  so they have no data dependency on prefix recognition succeeding and can
  run/report independently either way. If you'd rather keep this change
  minimal and leave UTXO/recent-root as hard gates (untouched), say so
  when reviewing this spec and I'll narrow it back to just the two bullets
  below.
- `simulate_prefix()`'s returned `FrameValidationOutcome.passed == false`
  (today: `return` at `ethrex.rs:340-358`, which is the specific gate that
  blocks the `pre_verify` demo). This pass only runs at all when
  `frame_tx.validation_prefix()` succeeded (it needs a `&ValidationPrefix`
  to run `simulate_frame_validation_prefix` against) — when recognition
  itself failed, there is nothing to run here, `payer` stays `null`, and
  the accumulated violation is whatever `validation_prefix()` reported.

None of these functions themselves change — `validation_prefix()` still
returns exactly what Part 1 defines, `ValidationObserver` still enforces
exactly what it enforces today, `check_utxo_admission`/
`check_recent_root_references` are untouched. Only this ONE handler's
control flow changes: instead of returning early on any of the three
above, it records the first failure's message into a single accumulated
`canonical_mempool_violation: Option<String>` (first-failure-wins, same
"never under-reject" ordering the existing code already documents) and
continues — through `execute_for_gas` and, if requested, the trace pass —
regardless.

**`payer` availability.** `payer` is derived from
`FrameValidationOutcome.accessed_paymaster`, which `simulate_prefix()`
populates whenever `frame_tx.validation_prefix()` succeeded (a
`ValidationPrefix` exists to run `simulate_frame_validation_prefix`
against) — independent of whether that same pass's structural check or
`ValidationObserver` subsequently found a violation. Confirmed by reading
`crates/vm/backends/levm/mod.rs`'s existing admission-path equivalent: it
computes `accessed_paymaster` from `sim.payer_address` BEFORE checking
`vm.validation_observer.violation`, and `ValidationObserver::record_violation`
(`validation_observer.rs`) only sets a flag — it does not abort execution,
so a frame that both APPROVEs (establishing payer) and later trips a
violation still ends up with `payer_address` set. So: `payer` is available
whenever `validation_prefix()` recognized a shape, `null` only when it did
not (no `ValidationPrefix` to simulate against at all).

**Response schema.** `SimulateFrameTransactionResult`'s `valid`/`violation`
fields are renamed to make the new semantics unambiguous — the old names'
implicit "and nothing else is populated" reading would now be actively
wrong:
- `valid` → `canonical_mempool_valid` (unchanged type, `bool`).
- `violation` → `canonical_mempool_violation` (unchanged type,
  `Option<String>`).
- `prefix_shape`, `payer`, `max_cost`: unchanged.
- `gas_used`, `frames`, `execution_status`, `execution_error`,
  `erc7562_trace`, `erc7562_trace_error`: unchanged types, but now
  populated whenever `execute_for_gas`/`execute_for_trace` actually ran —
  which, after this change, is unconditional (modulo the still-hard
  preconditions above and, for the trace fields, the existing `{"trace":
  true}` opt-in), independent of `canonical_mempool_valid`.

This is a rename, not an additive/back-compat change — this is a fork
under active development (`eip8141-tracer` branch), not a stable external
API, and the existing fields' meaning is changing regardless of name, so a
stale name would be actively misleading to a future reader.

**Explicitly out of scope for this change:** the real mempool admission
path (`crates/blockchain/blockchain.rs`'s pool-admission code backing
`eth_sendRawTransaction`) keeps gating on all of the same checks exactly as
it does today — an actual submitted transaction that fails
`validate_prefix_structure` or trips `ValidationObserver` is still
rejected from the pool. This spec changes only the read-only,
introspection-oriented `ethrex_simulateFrameTransaction` RPC.

## Testing

**Part 1 — shape recognition.** Tests live in
`test/tests/common/frame_tx_validation_tests.rs` (the migrated home of
`validation_prefix()`/`validate_prefix_structure()`'s existing tests —
confirmed by reading that file's own header comment and its
`prefix_shape_*` tests; `crates/common/types/transaction.rs`'s own
`#[cfg(test)] mod tests` is a separate module for unrelated tests, e.g.
blob-gas accounting). Reuse its existing helper builders (`self_verify_frame`,
`only_verify_frame`, `pay_frame`, `deploy_frame`, `base_frame_tx_with_frames`,
`sender_addr`), adding one new one (`pre_verify_frame(target)`):
- Each of the 4 canonical shapes, unchanged (regression — already covered
  by existing tests, no new test needed).
- Each of the 8 pre_verify-augmented shapes (pre_verify before the sole
  approving frame in `SelfVerify`/`DeploySelfVerify`; before `exec` only,
  `pay` only, and both, in `OnlyVerifyPay`/`DeployOnlyVerifyPay`), each
  asserting `prefix.shape`, `frame_indices`, `deploy_index`, `pay_index`,
  AND `pre_verify_indices`, plus a passing `validate_prefix_structure`
  call — mirroring `prefix_shape_self_verify`'s existing assertion style.
  The `SelfVerify`+pre_verify and `DeploySelfVerify`+pre_verify cases
  together are the deploy/pre_verify disambiguation regression coverage
  (asserting `deploy_index` comes out `None` vs. `Some(0)` correctly).
- `PreVerifyNotDefaultMode`/`PreVerifyTargetMismatch`: NOT given dedicated
  tests, matching this file's own established convention — confirmed by
  checking that the structurally-analogous, already-existing
  `DeployNotDefaultMode`/`MultipleDeploys` errors have no dedicated tests
  either, since (like those) they are unreachable via
  `validation_prefix()`'s own construction and only defend against a
  hand-built, bypassing `ValidationPrefix`.

**Part 2 — decoupled canonical verdict.** Tests live in
`test/tests/rpc/simulate_frame_transaction_tests.rs` (confirmed present;
full read deferred to the implementation plan). New coverage needed:
- A transaction whose prefix is a recognized `pre_verify` shape and whose
  execution would trip a canonical-mempool-policy violation (the
  ERC-20-pull scenario, or any other existing violation-producing fixture
  already in this test file, reused for minimal new setup) still returns
  populated `gas_used`/`frames`/`execution_status` (and `erc7562_trace`
  when `{"trace": true}` is passed), with `canonical_mempool_valid: false`
  and `canonical_mempool_violation: Some(...)`.
- `payer` is still populated in that same case (proving payer detection
  survived the decoupling).
- A transaction whose `validation_prefix()` fails outright (genuinely
  unrecognized, not a `pre_verify` case) still returns populated
  `gas_used`/`frames` with `payer: null` and `prefix_shape: null`.
- Regression: an ordinary valid, canonical-policy-passing transaction
  (existing test fixtures) still reports `canonical_mempool_valid: true`,
  `canonical_mempool_violation: null`, matching prior `valid`/`violation`
  behavior under the renamed fields.

No new fixtures/genesis/devnet changes are needed for either part —
existing frame-construction test helpers already build synthetic
`FrameTransaction`s frame-by-frame, and Part 2's RPC tests run against the
existing test-node/throwaway-state harness already used by that file's
other tests.

## Build/CI note

Per established practice, compiled artifacts (binaries, Docker images) for
running this against a live devnet build through GitHub Actions CI, not
local `cargo build`/`docker build` on this machine. Local `cargo
check`/`cargo test` for the unit tests above is fine to run locally.
