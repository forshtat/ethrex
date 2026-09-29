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

**Scope, confirmed with the user:** shape recognition + the write-gate
that makes `pre_verify`'s state writes actually simulatable. Explicitly
**out of scope**: EIP-8369 Profile 2 (FOCIL AA-VOPS) inclusion-list
eligibility awareness of `pre_verify`, the canonical-paymaster exemption
pattern, and EIP-8312 vault-sender/self-funded-UTXO interplay — none of
these need to know about `pre_verify` for the mempool/RPC-simulate demo to
work, and adding it there is deferred until a concrete need shows up.

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
let target_at = |pos: usize| -> Address {
    frame(pos).and_then(|f| f.target).unwrap_or(self.sender)
};

// Matches an approving VERIFY frame with `expected_scope` at `pos`,
// optionally preceded by a pre_verify frame. Returns the approving
// frame's position, the pre_verify frame's position (if any), and the
// next unconsumed position — or None if `pos` doesn't yield a match.
let match_approving = |pos: usize, expected_scope: u8| -> Option<(usize, Option<usize>, usize)> {
    if is_verify(pos) && scope_of(pos) == expected_scope {
        return Some((pos, None, pos + 1));
    }
    if is_default(pos)
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
    let approving_target = self.frames[approving_idx].target.unwrap_or(self.sender);
    let pre_verify_target = frame.target.unwrap_or(self.sender);
    if pre_verify_target != approving_target {
        return Err(FrameValidationError::PreVerifyTargetMismatch { frame_index: idx });
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

### Part 2 — The write gate (`crates/vm/levm/src/validation_observer.rs` + `crates/vm/levm/src/vm.rs`)

This part has no Skandha-side equivalent — Skandha never executes or
simulates writes itself.

`ValidationObserver.deploy_frame_index: Option<usize>` is today the sole
frame index where `SSTORE`/`CREATE`/`CREATE2` are permitted during mempool
simulation; everything else raises `FrameSimViolation::StateWriteOutsideDeploy`.
Per the confirmed naming decision, this widens and renames:

```rust
pub struct ValidationObserver {
    pub active: bool,
    pub sender: Address,
    /// Frame indices where SSTORE/CREATE/CREATE2 are permitted: the deploy
    /// frame (if any) plus any recognized pre_verify frames.
    pub write_allowed_frames: Vec<usize>,
    pub current_frame_index: usize,
    // ... unchanged fields ...
}

impl ValidationObserver {
    pub fn new(sender: Address, write_allowed_frames: Vec<usize>, expiry_verifier: Address) -> Self { /* ... */ }
    pub fn in_write_allowed_frame(&self) -> bool {
        self.write_allowed_frames.contains(&self.current_frame_index)
    }
    // in_canonical_pay_frame, within_vops_surface, charge_code_body,
    // record_violation: unchanged
}

pub enum FrameSimViolation {
    BannedOpcode(u8),
    StateWriteOutsideAllowedFrame,  // renamed from StateWriteOutsideDeploy
    // ... other variants unchanged ...
}
```

A `Vec<usize>` (not `HashSet`) because the prefix holds at most a handful
of frames — linear `contains` is simpler and just as fast at this size.

**Threading `pre_verify_indices` through to the observer.** Confirmed by
reading the call chain: `crates/vm/backends/levm/mod.rs:3216` calls
`vm.run_frame_validation_prefix(&prefix.frame_indices, prefix.deploy_index,
canonical_pay_frame, profile_2)`, which passes `deploy_index` straight
into `ValidationObserver::new(sender, deploy_index, expiry_verifier)` at
`crates/vm/levm/src/vm.rs:3548`. The fix threads the same path: `mod.rs`
builds `write_allowed_frames` from `prefix.deploy_index.into_iter().chain(
prefix.pre_verify_indices.iter().map(|(pv, _)| *pv)).collect()` and passes
that `Vec<usize>` in place of the bare `deploy_index` parameter;
`run_frame_validation_prefix`'s signature changes from `deploy_index:
Option<usize>` to `write_allowed_frames: Vec<usize>` accordingly.

**Confirmed unaffected (deploy-specific, stays keyed on `deploy_index`
alone, not touched by this change):**
- `crates/vm/backends/levm/mod.rs:3298` — `DeployInstalledNoCode` check
  ("a deploy frame must leave non-empty code at the sender"). A
  `pre_verify` frame does an arbitrary state write, not a code
  installation, so this assertion must not fire for it.
- `crates/blockchain/blockchain.rs:4425` — EIP-8250 keyed-nonce-domain
  concurrency eligibility (`keyed_concurrency_verdict`'s "no deploy frame,
  which would install code mid-flight" condition). A pre_verify frame
  doesn't install code either, so this check is correctly indifferent to
  it and stays keyed on `deploy_index.is_some()` alone.

## Testing

Rust unit tests in `crates/common/types/transaction.rs`'s existing test
module (mirroring its current shape-matching test style) covering:
- Each of the 4 canonical shapes, unchanged (regression).
- Each of the 8 pre_verify-augmented shapes (pre_verify before the sole
  approving frame in `SelfVerify`/`DeploySelfVerify`; before `exec` only,
  `pay` only, and both, in `OnlyVerifyPay`/`DeployOnlyVerifyPay`).
- The deploy/pre_verify disambiguation: a leading DEFAULT frame that
  target-matches the next approving frame is recognized as pre_verify,
  never deploy (regression-equivalent of Skandha's two Important-#2 fix
  tests).
- `validate_prefix_structure` rejecting a pre_verify frame in VERIFY mode
  (`PreVerifyNotDefaultMode`) and a pre_verify frame whose target doesn't
  match its approving frame (`PreVerifyTargetMismatch`).
- `ValidationObserver`/write-gate: an `SSTORE` inside a recognized
  pre_verify frame is permitted; an `SSTORE` in any other non-deploy frame
  is still rejected (`StateWriteOutsideAllowedFrame`) — this needs an
  integration-level test through `run_frame_validation_prefix` (or
  whatever the plan finds is the narrowest existing test seam), not just
  a `ValidationObserver` unit test, since the interesting behavior is the
  opcode-dispatch-time check, not the struct's own methods.

No new fixtures/genesis/devnet changes are needed for these — existing
frame-construction test helpers in `transaction.rs`'s test module already
build synthetic `FrameTransaction`s frame-by-frame.

## Build/CI note

Per established practice, compiled artifacts (binaries, Docker images) for
running this against a live devnet build through GitHub Actions CI, not
local `cargo build`/`docker build` on this machine. Local `cargo
check`/`cargo test` for the unit tests above is fine to run locally.
