# `pre_verify` Validation-Prefix Recognition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let ethrex recognize ERC-2028's `pre_verify` validation-prefix frame role and report full execution results for it through `ethrex_simulateFrameTransaction`, unblocking Skandha's paymaster demo.

**Architecture:** Two independent tasks. Task 1 teaches `FrameTransaction::validation_prefix()`/`validate_prefix_structure()` (`crates/common/types/transaction.rs`) to recognize an optional `pre_verify` frame immediately before any approving frame, mirroring Skandha's already-shipped TypeScript algorithm. Task 2 changes `ethrex_simulateFrameTransaction`'s RPC handler (`crates/networking/rpc/ethrex.rs`) so that a canonical-mempool-policy rejection (prefix recognition, UTXO/recent-root checks, or the `ValidationObserver`-gated prefix simulation) is reported as data instead of suppressing execution results — no `ValidationObserver`/`vm.rs` changes are needed once policy verdicts stop gating execution.

**Tech Stack:** Rust, the `ethrex-test` integration-test crate (`test/tests/...`), `cargo test`.

**Spec:** `docs/superpowers/specs/2026-09-29-pre-verify-frame-recognition-design.md`

## Global Constraints

- Only `ethrex_simulateFrameTransaction`'s own handler changes in Task 2 — the real mempool admission path (`crates/blockchain/blockchain.rs`, backing `eth_sendRawTransaction`) is untouched and keeps gating on every check exactly as today.
- No changes to `crates/vm/levm/src/validation_observer.rs` or `crates/vm/levm/src/vm.rs` — the write-gate/`ValidationObserver` enforcement is unchanged; only whether its verdict gates the RPC response changes.
- These hard preconditions in the RPC handler stay early-return gates, unchanged: `validate_static_constraints`, the signature-verification-cost budget check, `validate_frame_signatures`, and the per-transaction gas-limit DoS guard.
- EIP-8369 Profile 2 (FOCIL), the canonical-paymaster exemption pattern, and EIP-8312 vault-sender/UTXO interplay are untouched and need no `pre_verify` awareness.
- Compiled binaries/Docker images for running this against a live devnet build through GitHub Actions CI, not locally. Local `cargo check`/`cargo test` for the tests below is fine to run locally.
- `PrefixShape`'s four variants (`SelfVerify`, `DeploySelfVerify`, `OnlyVerifyPay`, `DeployOnlyVerifyPay`) are unchanged — `pre_verify` is recorded via a new `pre_verify_indices` field on `ValidationPrefix`, not a new shape variant.

## Review Focus

- A transaction whose prefix is recognized (`validation_prefix()` succeeds) but fails `validate_prefix_structure()` (a structural error, e.g. wrong scope restriction) — does `payer` still populate the same way it does for an `outcome.passed == false` (observer) violation? Task 2's design says yes (the `prefix` stays `Some` either way, so `simulate_prefix` still runs), but neither of Task 2's two new tests exercises this specific sub-case (they cover the observer-violation and the outright-unrecognized cases) — the final review should specifically check this path by reading the implementation, or a reviewer may want an added test.
- `erc7562_trace_error` must still only ever be set when tracing was requested AND `execute_for_gas` succeeded AND the separate trace pass itself failed — confirm the rewrite doesn't request a trace pass when `execute_for_gas` itself errored (today's code doesn't; the rewrite must preserve that, since decoupling policy-gating from execution must not also decouple the trace pass from `execute_for_gas` having actually produced a result).
- The camelCase field rename (`valid`→`canonicalMempoolValid`, `violation`→`canonicalMempoolViolation`) is a breaking wire-format change for any existing consumer of this RPC (e.g. Skandha's own `GethTracer` TypeScript wrapper, if it reads these two specific fields anywhere outside `payer`/`gasUsed`/`frames`). Out of scope for this plan to fix the consumer side, but the final review/plan handoff should flag it explicitly so nothing downstream silently breaks.
- The gas-limit DoS guard (`total_gas_limit > max_allowed`) still runs BEFORE the now-informational checks and still hard-rejects (unchanged). A `pre_verify`-shaped demo transaction must stay under `max_allowed` (`get_max_allowed_gas_limit(header.gas_limit, fork)`) or it will still see `gasUsed: null` despite this whole change — worth a one-line callout when reporting this plan's completion, not a new test (it's an unchanged, pre-existing gate).
- Task 1's 8 new tests hand-verify `pre_verify_indices`/`frame_indices`/`deploy_index`/`pay_index` per shape; the one input class they do NOT cover is a `pre_verify` frame with an EXPLICIT (non-`None`) target that does NOT match its following approving frame's target — this should fall through to `UnrecognizedPrefix` (or, if a leading position, get reconsidered as a `deploy` candidate) rather than silently matching. Not required by the spec's own test list, but worth a mental check during the final review since it's adjacent to the exact bug the `target_at` fix (Task 1, Step 3) exists to prevent.

---

### Task 1: `pre_verify` shape recognition

**Files:**
- Modify: `crates/common/types/transaction.rs:3053-3135` (`validation_prefix`), `crates/common/types/transaction.rs:3158-3290` (`validate_prefix_structure`), `crates/common/types/transaction.rs:3306-3350` (`ValidationPrefix` struct, `FrameValidationError` enum)
- Test: `test/tests/common/frame_tx_validation_tests.rs`

**Interfaces:**
- Consumes: nothing from another task (self-contained).
- Produces: `ValidationPrefix.pre_verify_indices: Vec<(usize, usize)>` (pre_verify frame index, the approving frame index it precedes and target-matches) — Task 2 does not consume this field directly (it only needs `ValidationPrefix` to exist and `validation_prefix()` to succeed for `pre_verify` shapes), but any later ethrex work building on this plan will read it the same way `deploy_index`/`pay_index` are read today.

- [ ] **Step 1: Write the 8 failing shape-recognition tests**

Add these helpers and tests to `test/tests/common/frame_tx_validation_tests.rs`, right after the existing `deploy_frame()` helper (around line 192) and after the existing `prefix_shape_deploy_only_verify_pay` test (around line 262):

```rust
fn payer_addr() -> Address {
    Address::from_low_u64_be(0xFACE)
}

/// A `pre_verify` candidate: DEFAULT mode, an explicit target (never `None`
/// — see `target_at`'s doc in `validation_prefix()` for why), small gas so
/// the heaviest 5-frame test fixture below stays under
/// `FRAME_TX_MAX_VERIFY_GAS` (100_000).
fn pre_verify_frame(target: Address) -> Frame {
    Frame {
        mode: FrameMode::Default as u8,
        flags: 0x00,
        target: Some(target),
        gas_limit: 5_000,
        state_limit: 0,
        value: U256::zero(),
        data: Bytes::from_static(b"pull_payment"),
    }
}

/// `pay_frame()` with an explicit non-sender target (a sponsor), per
/// structural rule 4.
fn pay_frame_to(target: Address) -> Frame {
    let mut frame = pay_frame();
    frame.target = Some(target);
    frame
}

// --- pre_verify shape tests ---

#[test]
fn prefix_shape_self_verify_with_pre_verify() {
    let tx = base_frame_tx_with_frames(vec![pre_verify_frame(sender_addr()), self_verify_frame()]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize SelfVerify with a leading pre_verify frame");
    assert_eq!(prefix.shape, PrefixShape::SelfVerify);
    assert_eq!(prefix.frame_indices, vec![0, 1]);
    assert_eq!(prefix.deploy_index, None);
    assert_eq!(prefix.pay_index, Some(1));
    assert_eq!(prefix.pre_verify_indices, vec![(0, 1)]);
    tx.validate_prefix_structure(&prefix, FRAME_TX_MAX_VERIFY_GAS)
        .expect("SelfVerify with pre_verify should be structurally valid");
}

#[test]
fn prefix_shape_deploy_self_verify_with_pre_verify() {
    let tx = base_frame_tx_with_frames(vec![
        deploy_frame(),
        pre_verify_frame(sender_addr()),
        self_verify_frame(),
    ]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize DeploySelfVerify with a pre_verify frame");
    assert_eq!(prefix.shape, PrefixShape::DeploySelfVerify);
    assert_eq!(prefix.frame_indices, vec![0, 1, 2]);
    assert_eq!(prefix.deploy_index, Some(0));
    assert_eq!(prefix.pay_index, Some(2));
    assert_eq!(prefix.pre_verify_indices, vec![(1, 2)]);
    tx.validate_prefix_structure(&prefix, FRAME_TX_MAX_VERIFY_GAS)
        .expect("DeploySelfVerify with pre_verify should be structurally valid");
}

#[test]
fn prefix_shape_only_verify_pay_with_pre_verify_before_exec() {
    let tx = base_frame_tx_with_frames(vec![
        pre_verify_frame(sender_addr()),
        only_verify_frame(),
        pay_frame(),
    ]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize OnlyVerifyPay with pre_verify before exec");
    assert_eq!(prefix.shape, PrefixShape::OnlyVerifyPay);
    assert_eq!(prefix.frame_indices, vec![0, 1, 2]);
    assert_eq!(prefix.deploy_index, None);
    assert_eq!(prefix.pay_index, Some(2));
    assert_eq!(prefix.pre_verify_indices, vec![(0, 1)]);
    tx.validate_prefix_structure(&prefix, FRAME_TX_MAX_VERIFY_GAS)
        .expect("OnlyVerifyPay with pre_verify before exec should be structurally valid");
}

#[test]
fn prefix_shape_only_verify_pay_with_pre_verify_before_pay() {
    let tx = base_frame_tx_with_frames(vec![
        only_verify_frame(),
        pre_verify_frame(payer_addr()),
        pay_frame_to(payer_addr()),
    ]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize OnlyVerifyPay with pre_verify before pay");
    assert_eq!(prefix.shape, PrefixShape::OnlyVerifyPay);
    assert_eq!(prefix.frame_indices, vec![0, 1, 2]);
    assert_eq!(prefix.deploy_index, None);
    assert_eq!(prefix.pay_index, Some(2));
    assert_eq!(prefix.pre_verify_indices, vec![(1, 2)]);
    tx.validate_prefix_structure(&prefix, FRAME_TX_MAX_VERIFY_GAS)
        .expect("OnlyVerifyPay with pre_verify before pay should be structurally valid");
}

#[test]
fn prefix_shape_only_verify_pay_with_pre_verify_before_both() {
    let tx = base_frame_tx_with_frames(vec![
        pre_verify_frame(sender_addr()),
        only_verify_frame(),
        pre_verify_frame(payer_addr()),
        pay_frame_to(payer_addr()),
    ]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize OnlyVerifyPay with pre_verify before both exec and pay");
    assert_eq!(prefix.shape, PrefixShape::OnlyVerifyPay);
    assert_eq!(prefix.frame_indices, vec![0, 1, 2, 3]);
    assert_eq!(prefix.deploy_index, None);
    assert_eq!(prefix.pay_index, Some(3));
    assert_eq!(prefix.pre_verify_indices, vec![(0, 1), (2, 3)]);
    tx.validate_prefix_structure(&prefix, FRAME_TX_MAX_VERIFY_GAS)
        .expect("OnlyVerifyPay with pre_verify before both should be structurally valid");
}

#[test]
fn prefix_shape_deploy_only_verify_pay_with_pre_verify_before_exec() {
    let tx = base_frame_tx_with_frames(vec![
        deploy_frame(),
        pre_verify_frame(sender_addr()),
        only_verify_frame(),
        pay_frame(),
    ]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize DeployOnlyVerifyPay with pre_verify before exec");
    assert_eq!(prefix.shape, PrefixShape::DeployOnlyVerifyPay);
    assert_eq!(prefix.frame_indices, vec![0, 1, 2, 3]);
    assert_eq!(prefix.deploy_index, Some(0));
    assert_eq!(prefix.pay_index, Some(3));
    assert_eq!(prefix.pre_verify_indices, vec![(1, 2)]);
    tx.validate_prefix_structure(&prefix, FRAME_TX_MAX_VERIFY_GAS)
        .expect("DeployOnlyVerifyPay with pre_verify before exec should be structurally valid");
}

#[test]
fn prefix_shape_deploy_only_verify_pay_with_pre_verify_before_pay() {
    let tx = base_frame_tx_with_frames(vec![
        deploy_frame(),
        only_verify_frame(),
        pre_verify_frame(payer_addr()),
        pay_frame_to(payer_addr()),
    ]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize DeployOnlyVerifyPay with pre_verify before pay");
    assert_eq!(prefix.shape, PrefixShape::DeployOnlyVerifyPay);
    assert_eq!(prefix.frame_indices, vec![0, 1, 2, 3]);
    assert_eq!(prefix.deploy_index, Some(0));
    assert_eq!(prefix.pay_index, Some(3));
    assert_eq!(prefix.pre_verify_indices, vec![(2, 3)]);
    tx.validate_prefix_structure(&prefix, FRAME_TX_MAX_VERIFY_GAS)
        .expect("DeployOnlyVerifyPay with pre_verify before pay should be structurally valid");
}

#[test]
fn prefix_shape_deploy_only_verify_pay_with_pre_verify_before_both() {
    let tx = base_frame_tx_with_frames(vec![
        deploy_frame(),
        pre_verify_frame(sender_addr()),
        only_verify_frame(),
        pre_verify_frame(payer_addr()),
        pay_frame_to(payer_addr()),
    ]);
    let prefix = tx
        .validation_prefix()
        .expect("should recognize DeployOnlyVerifyPay with pre_verify before both exec and pay");
    assert_eq!(prefix.shape, PrefixShape::DeployOnlyVerifyPay);
    assert_eq!(prefix.frame_indices, vec![0, 1, 2, 3, 4]);
    assert_eq!(prefix.deploy_index, Some(0));
    assert_eq!(prefix.pay_index, Some(4));
    assert_eq!(prefix.pre_verify_indices, vec![(1, 2), (3, 4)]);
    tx.validate_prefix_structure(&prefix, FRAME_TX_MAX_VERIFY_GAS)
        .expect("DeployOnlyVerifyPay with pre_verify before both should be structurally valid");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd test && cargo test --test integration_test -- common::frame_tx_validation_tests::prefix_shape 2>&1 | tail -40`

(If the test binary name differs, run `cargo test -p ethrex-test prefix_shape_self_verify_with_pre_verify 2>&1 | tail -40` instead — either way, the goal is to run only the new tests.)

Expected: a COMPILE ERROR — `ValidationPrefix` has no field `pre_verify_indices` (the 8 new tests reference it in their assertions). This is the correct "feature missing" failure for a struct-field addition; there is no way to get a clean runtime failure before the type exists.

- [ ] **Step 3: Implement `pre_verify` recognition**

In `crates/common/types/transaction.rs`, add the new field to `ValidationPrefix` (around line 3306-3318):

```rust
/// Identified validation prefix of an EIP-8141 frame transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationPrefix {
    /// Recognized shape of this prefix.
    pub shape: PrefixShape,
    /// Frame indices (into `FrameTransaction.frames`) that form the prefix,
    /// in order. Does not include expiry-verifier frames. Includes any
    /// pre_verify frames (see `pre_verify_indices`).
    pub frame_indices: Vec<usize>,
    /// Index of the deploy frame within `frames`, if this shape has one.
    pub deploy_index: Option<usize>,
    /// Index of the pay (or self_verify) frame within `frames`.
    pub pay_index: Option<usize>,
    /// (pre_verify frame index, the approving frame index it precedes and
    /// target-matches), one pair per recognized pre_verify frame. Empty
    /// when no pre_verify frame is present. ERC-2028 PREFIX-110: a
    /// DEFAULT-mode frame immediately preceding an approving frame,
    /// with an explicit (never `None`) target equal to that approving
    /// frame's resolved target.
    pub pre_verify_indices: Vec<(usize, usize)>,
}
```

Replace `validation_prefix()` (currently lines 3053-3135) in full:

```rust
    pub fn validation_prefix(&self) -> Result<ValidationPrefix, FrameValidationError> {
        // Collect non-expiry frame indices in order.
        let non_expiry: Vec<usize> = self
            .frames
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.is_expiry_verifier())
            .map(|(i, _)| i)
            .collect();

        // Helper to get a frame by its position in non_expiry.
        let frame = |pos: usize| -> Option<&Frame> {
            non_expiry.get(pos).and_then(|&idx| self.frames.get(idx))
        };

        let is_default = |pos: usize| -> bool {
            // DEFAULT/VERIFY wire bytes are era-independent, and the four
            // recognized prefix shapes are DEFAULT/VERIFY-only by definition —
            // a UTXO frame in prefix position simply fails to match, which is
            // the intended "unrecognized prefix" outcome.
            frame(pos).is_some_and(|f| f.mode == FrameMode::Default as u8)
        };
        let is_verify =
            |pos: usize| -> bool { frame(pos).is_some_and(|f| f.mode == FrameMode::Verify as u8) };
        let scope_of = |pos: usize| -> u8 { frame(pos).map_or(0, |f| f.scope_restriction()) };
        // Deliberately NOT `.unwrap_or(self.sender)`: a DEFAULT-mode frame's
        // `target: None` means CREATE-at-self-address semantics for a real
        // deploy (the `deploy_frame()` test helper always uses `None`), so
        // resolving it to `sender` here would make an ordinary deploy frame
        // indistinguishable from a pre_verify frame targeting sender. A
        // pre_verify candidate therefore requires an EXPLICIT target.
        let target_at = |pos: usize| -> Option<Address> { frame(pos).and_then(|f| f.target) };

        // Matches an approving VERIFY frame with `expected_scope` at `pos`,
        // optionally preceded by a pre_verify frame (a DEFAULT-mode frame
        // with an explicit target equal to the approving frame's). Returns
        // the approving frame's position, the pre_verify frame's position
        // (if any), and the next unconsumed position.
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

        if non_expiry.is_empty() {
            return Err(FrameValidationError::UnrecognizedPrefix);
        }

        // Assembles a ValidationPrefix from a deploy position (if any) and
        // the approving-frame matches `match_approving` found, in order.
        let build = |shape: PrefixShape,
                     deploy_pos: Option<usize>,
                     matches: &[(usize, Option<usize>)]|
         -> ValidationPrefix {
            let mut frame_indices = Vec::new();
            let mut pre_verify_indices = Vec::new();
            if let Some(d) = deploy_pos {
                frame_indices.push(non_expiry[d]);
            }
            for &(approving_pos, pre_verify_pos) in matches {
                if let Some(p) = pre_verify_pos {
                    frame_indices.push(non_expiry[p]);
                    pre_verify_indices.push((non_expiry[p], non_expiry[approving_pos]));
                }
                frame_indices.push(non_expiry[approving_pos]);
            }
            let pay_index = matches.last().map(|&(pos, _)| non_expiry[pos]);
            ValidationPrefix {
                shape,
                frame_indices,
                deploy_index: deploy_pos.map(|d| non_expiry[d]),
                pay_index,
                pre_verify_indices,
            }
        };

        // Control flow is organized by approving-frame count first,
        // deploy-vs-not second: the two counts are mutually exclusive by
        // construction (a 2-frame skeleton requires `scope_of` values a
        // 1-frame skeleton can't produce), so trying them in either order
        // is equally correct. Trying the no-deploy interpretation before
        // the deploy interpretation at each step is what resolves the
        // deploy/pre_verify ambiguity at position 0: if frame 0's target
        // matches frame 1's, `match_approving` consumes it as pre_verify
        // here and the function returns before the deploy branch below
        // ever runs.

        // Shape: OnlyVerifyPay — VERIFY(exec) + VERIFY(pay), no deploy.
        if let Some((exec_pos, exec_pv, next)) = match_approving(0, APPROVE_EXECUTION) {
            if let Some((pay_pos, pay_pv, _)) = match_approving(next, APPROVE_PAYMENT) {
                return Ok(build(
                    PrefixShape::OnlyVerifyPay,
                    None,
                    &[(exec_pos, exec_pv), (pay_pos, pay_pv)],
                ));
            }
        }
        // Shape: DeployOnlyVerifyPay — DEFAULT + VERIFY(exec) + VERIFY(pay).
        if is_default(0) {
            if let Some((exec_pos, exec_pv, next)) = match_approving(1, APPROVE_EXECUTION) {
                if let Some((pay_pos, pay_pv, _)) = match_approving(next, APPROVE_PAYMENT) {
                    return Ok(build(
                        PrefixShape::DeployOnlyVerifyPay,
                        Some(0),
                        &[(exec_pos, exec_pv), (pay_pos, pay_pv)],
                    ));
                }
            }
        }
        // Shape: SelfVerify — VERIFY(exec+pay), no deploy.
        if let Some((sv_pos, sv_pv, _)) = match_approving(0, APPROVE_EXECUTION_AND_PAYMENT) {
            return Ok(build(PrefixShape::SelfVerify, None, &[(sv_pos, sv_pv)]));
        }
        // Shape: DeploySelfVerify — DEFAULT + VERIFY(exec+pay).
        if is_default(0) {
            if let Some((sv_pos, sv_pv, _)) = match_approving(1, APPROVE_EXECUTION_AND_PAYMENT) {
                return Ok(build(
                    PrefixShape::DeploySelfVerify,
                    Some(0),
                    &[(sv_pos, sv_pv)],
                ));
            }
        }

        Err(FrameValidationError::UnrecognizedPrefix)
    }
```

Replace `validate_prefix_structure` (currently lines 3158-3290) in full — every branch outside the new `if let Some(&(_, approving_idx)) = ...` block below is verbatim-unchanged from today, just now nested one level deeper inside the trailing `else`:

```rust
    pub fn validate_prefix_structure(
        &self,
        prefix: &ValidationPrefix,
        max_verify_gas: u64,
    ) -> Result<(), FrameValidationError> {
        let mut deploy_count = 0usize;

        for &idx in &prefix.frame_indices {
            let frame = &self.frames[idx];

            if frame.is_atomic_batch() {
                return Err(FrameValidationError::AtomicBatchInPrefix { frame_index: idx });
            }

            if let Some(&(_, approving_idx)) =
                prefix.pre_verify_indices.iter().find(|&&(pv, _)| pv == idx)
            {
                if frame.mode != FrameMode::Default as u8 {
                    return Err(FrameValidationError::PreVerifyNotDefaultMode { frame_index: idx });
                }
                // Explicit `Some` only — `None` (deploy's CREATE-at-self
                // semantics) must never be treated as "matches the
                // approving frame's target"; see `target_at`'s note in
                // `validation_prefix()`.
                let approving_target = self.frames[approving_idx].target.unwrap_or(self.sender);
                match frame.target {
                    Some(addr) if addr == approving_target => {}
                    _ => {
                        return Err(FrameValidationError::PreVerifyTargetMismatch { frame_index: idx });
                    }
                }
            } else {
                match prefix.deploy_index {
                    Some(deploy_idx) if deploy_idx == idx => {
                        // This is the deploy frame.
                        deploy_count += 1;
                        if deploy_count > 1 {
                            return Err(FrameValidationError::MultipleDeploys { frame_index: idx });
                        }
                        // The deploy must be first among prefix frames. `validation_prefix`
                        // structurally guarantees this, but the raw frame index can be
                        // non-zero when expiry-verifier frames precede the deploy — check
                        // against the first element of `frame_indices`, not the raw index.
                        if prefix.frame_indices.first() != Some(&idx) {
                            return Err(FrameValidationError::DeployNotFirst { frame_index: idx });
                        }
                        if frame.mode != FrameMode::Default as u8 {
                            return Err(FrameValidationError::DeployNotDefaultMode {
                                frame_index: idx,
                            });
                        }
                    }
                    _ => {
                        // VERIFY frame (self_verify, only_verify, or pay).
                        if frame.mode != FrameMode::Verify as u8 {
                            return Err(FrameValidationError::VerifyFrameNotVerifyMode {
                                frame_index: idx,
                            });
                        }

                        // EIP-8141 structural rule 3 restricts the target to
                        // tx.sender (None means sender) only for self_verify /
                        // only_verify frames. Rule 4 places no target requirement
                        // on the pay frame: it may target a non-sender sponsor,
                        // which approves payment via APPROVE(APPROVE_PAYMENT)
                        // when the frame executes.
                        let is_pay_frame = matches!(
                            prefix.shape,
                            PrefixShape::OnlyVerifyPay | PrefixShape::DeployOnlyVerifyPay
                        ) && prefix.pay_index == Some(idx);
                        let target_ok = match frame.target {
                            None => true,
                            Some(addr) => addr == self.sender || is_pay_frame,
                        };
                        if !target_ok {
                            return Err(FrameValidationError::VerifyTargetNotSender {
                                frame_index: idx,
                            });
                        }

                        // Scope restriction must match role.
                        let expected_scope = match prefix.shape {
                            PrefixShape::SelfVerify | PrefixShape::DeploySelfVerify => {
                                APPROVE_EXECUTION_AND_PAYMENT
                            }
                            PrefixShape::OnlyVerifyPay | PrefixShape::DeployOnlyVerifyPay => {
                                // The only_verify frame comes before the pay frame.
                                if prefix.pay_index == Some(idx) {
                                    APPROVE_PAYMENT
                                } else {
                                    APPROVE_EXECUTION
                                }
                            }
                        };
                        if frame.scope_restriction() != expected_scope {
                            return Err(FrameValidationError::WrongScopeRestriction {
                                frame_index: idx,
                                expected: expected_scope,
                                actual: frame.scope_restriction(),
                            });
                        }
                    }
                }
            }
        }

        // EIP-8141 §Expiry Verifier Frame: an expiry verifier frame may appear
        // only as the first frame of the frame list. Expiry frames are otherwise
        // transparent to prefix matching, so a misplaced one would silently pin
        // the transaction's validity to a deadline outside the recognized shapes.
        if let Some((frame_index, _)) = self
            .frames
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, frame)| frame.is_expiry_verifier())
        {
            return Err(FrameValidationError::ExpiryFrameNotFirst { frame_index });
        }

        // EIP-8141 §Structural Rules rule 8: no VERIFY frame may follow the
        // validation prefix. A reverting VERIFY frame invalidates the whole
        // transaction wherever it sits, so one placed after the prefix would make
        // validity depend on state that prefix simulation never inspects — the
        // unbounded-invalidation case the public mempool rules exist to prevent.
        if let Some(&prefix_end) = prefix.frame_indices.last()
            && let Some((frame_index, _)) = self
                .frames
                .iter()
                .enumerate()
                .skip(prefix_end.saturating_add(1))
                .find(|(_, frame)| frame.execution_mode() == Some(FrameMode::Verify))
        {
            return Err(FrameValidationError::VerifyFrameAfterPrefix { frame_index });
        }

        // Gas budget: prefix frame gas limits + signature cost ≤ MAX_VERIFY_GAS.
        let prefix_gas: u64 = prefix
            .frame_indices
            .iter()
            .map(|&i| self.frames[i].gas_limit)
            .fold(0u64, |acc, g| acc.saturating_add(g));
        let total_verify_gas = prefix_gas.saturating_add(self.signature_verification_cost());
        if total_verify_gas > max_verify_gas {
            return Err(FrameValidationError::VerifyGasBudgetExceeded {
                actual: total_verify_gas,
                limit: max_verify_gas,
            });
        }

        Ok(())
    }
```

Add two new variants to `FrameValidationError` (currently lines 3323-3350), after the existing `VerifyGasBudgetExceeded` variant:

```rust
    #[error("frame {frame_index}: pre_verify frame must use DEFAULT execution mode")]
    PreVerifyNotDefaultMode { frame_index: usize },
    #[error("frame {frame_index}: pre_verify frame target does not match the approving frame it precedes")]
    PreVerifyTargetMismatch { frame_index: usize },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd test && cargo test -p ethrex-test frame_tx_validation_tests 2>&1 | tail -60`

Expected: every test in `frame_tx_validation_tests.rs` passes — the 8 new `prefix_shape_*_with_pre_verify*` tests, AND every pre-existing test in that file (the 4 canonical shapes, the expiry-verifier-interleaved variants, the rejection tests, the blob-gas tests) unaffected.

- [ ] **Step 5: Commit**

```bash
git add crates/common/types/transaction.rs test/tests/common/frame_tx_validation_tests.rs
git commit -m "$(cat <<'EOF'
feat(transaction): recognize ERC-2028 pre_verify validation-prefix frames

Extends validation_prefix()/validate_prefix_structure() to recognize an
optional pre_verify frame (a DEFAULT-mode write-capable frame with an
explicit target matching the approving frame it precedes) before any
approving frame in the prefix, mirroring Skandha's already-shipped
recognition algorithm. PrefixShape's four variants are unchanged;
ValidationPrefix gains pre_verify_indices: Vec<(usize, usize)>.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Decouple `ethrex_simulateFrameTransaction`'s canonical verdict from execution

**Files:**
- Modify: `crates/networking/rpc/ethrex.rs` (whole file's `SimulateFrameTransactionRequest`/`SimulateFrameTransactionResult`/`structurally_invalid` — lines 1-534)
- Test: `test/tests/rpc/simulate_frame_transaction_tests.rs`

**Interfaces:**
- Consumes: nothing from Task 1 directly (this task's own tests don't require `pre_verify` recognition — they exercise the decoupling mechanism using ordinary, already-recognized shapes, per the spec's Testing section). Task 1 landing first only means a `pre_verify`-shaped transaction would ALSO now benefit from this decoupling once both tasks are done; Task 2 has no code dependency on Task 1's new field.
- Produces: nothing consumed by another task in this plan.

- [ ] **Step 1: Update existing tests' field names and add 2 new tests**

In `test/tests/rpc/simulate_frame_transaction_tests.rs`, rename every `result["valid"]`/`result["violation"]` reference to `result["canonicalMempoolValid"]`/`result["canonicalMempoolViolation"]` in the 4 existing tests that use them:

- `simulate_rejects_nonce_keys_that_are_not_strictly_increasing` (line 148-149): `result["valid"]` → `result["canonicalMempoolValid"]`, `result["violation"]` → `result["canonicalMempoolViolation"]`.
- `simulate_rejects_an_unauthenticated_sender` (line 162-163): same two renames.
- `simulate_with_trace_true_returns_a_non_empty_erc7562_trace` (line 300-303): `result["valid"]` → `result["canonicalMempoolValid"]`.
- `simulate_without_trace_reports_null_and_matches_trace_false` (line 336-339): `omitted["valid"]` → `omitted["canonicalMempoolValid"]`.
- `simulate_reports_max_cost_even_when_a_gate_rejects` (line 383): `result["valid"]` → `result["canonicalMempoolValid"]`.

(`simulate_trace_true_changes_nothing_but_erc7562_trace` does not reference `valid`/`violation` directly — no change needed there.)

Then add these 2 new tests after `simulate_reports_max_cost_even_when_a_gate_rejects` (end of file):

```rust
/// `PUSH1 0x42 (TIMESTAMP)... ` — actually: TIMESTAMP, POP (a banned opcode
/// outside the expiry verifier), then the same APPROVE sequence
/// `approve_execution_and_payment_code` uses. The frame is recognized as a
/// valid `SelfVerify` shape and DOES establish a payer (APPROVE still runs —
/// `ValidationObserver::record_violation` only sets a flag, it does not
/// abort execution), but trips a canonical-mempool-policy violation
/// (`BannedOpcode`) along the way.
fn approve_with_banned_timestamp_code() -> Bytes {
    Bytes::from(vec![
        0x42, 0x50, // TIMESTAMP, POP
        0x60,
        APPROVE_EXECUTION_AND_PAYMENT,
        0x60,
        0x00,
        0x60,
        0x00,
        0xAA, // APPROVE
        0x00, // STOP
    ])
}

#[tokio::test]
async fn simulate_reports_execution_even_when_canonical_mempool_policy_rejects() {
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 0,
            shanghai_time: Some(0),
            amsterdam_time: Some(0),
            hegota_time: Some(0),
            ..Default::default()
        },
        gas_limit: 100_000_000,
        alloc: [(
            HEGOTA_SENDER,
            GenesisAccount {
                code: approve_with_banned_timestamp_code(),
                storage: BTreeMap::new(),
                balance: U256::zero(),
                nonce: 0,
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let mut store = Store::new(
        "simulate-frame-tx-policy-violation-test",
        EngineType::InMemory,
    )
    .expect("build store");
    store
        .add_initial_state(genesis)
        .await
        .expect("genesis state");
    let context = default_context_with_storage(store).await;

    let result = simulate_in(context, valid_self_verify_frame_tx(), None).await;

    assert_eq!(
        result["canonicalMempoolValid"],
        json!(false),
        "TIMESTAMP outside the expiry verifier must be a canonical-policy violation: {result}"
    );
    let violation = result["canonicalMempoolViolation"]
        .as_str()
        .expect("canonicalMempoolViolation must be present");
    assert!(
        violation.contains("BannedOpcode") || violation.contains("0x42"),
        "expected a banned-opcode violation, got: {violation}"
    );
    assert_eq!(
        result["prefixShape"],
        json!("SelfVerify"),
        "the shape is still recognized despite the policy violation: {result}"
    );
    assert_eq!(
        result["payer"],
        json!(format!("{HEGOTA_SENDER:#x}")),
        "APPROVE still runs before the violation is checked, so payer is still established: {result}"
    );
    assert!(
        result["gasUsed"].is_string(),
        "execution must still be reported despite the policy violation: {result}"
    );
    assert!(
        result["frames"].is_array(),
        "per-frame results must still be reported despite the policy violation: {result}"
    );
    assert!(
        result["executionStatus"].is_string(),
        "execution status must still be reported despite the policy violation: {result}"
    );
}

#[tokio::test]
async fn simulate_reports_execution_even_when_prefix_is_unrecognized() {
    // flags: 0 matches no shape's scope requirement at position 0, so
    // validation_prefix() returns UnrecognizedPrefix outright — no
    // ValidationPrefix exists at all, so payer/prefixShape stay null, but
    // execution still runs and is still reported.
    let mut tx = valid_self_verify_frame_tx();
    tx.frames[0].flags = 0;

    let result = simulate_in(hegota_context().await, tx, None).await;

    assert_eq!(
        result["canonicalMempoolValid"],
        json!(false),
        "flags: 0 matches no recognized shape: {result}"
    );
    assert_eq!(
        result["prefixShape"],
        Value::Null,
        "an unrecognized prefix has no shape to report: {result}"
    );
    assert_eq!(
        result["payer"],
        Value::Null,
        "an unrecognized prefix has no ValidationPrefix to establish a payer from: {result}"
    );
    assert!(
        result["gasUsed"].is_string(),
        "execution must still be reported for an unrecognized prefix: {result}"
    );
    assert!(
        result["executionStatus"].is_string(),
        "execution status must still be reported for an unrecognized prefix: {result}"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd test && cargo test -p ethrex-test simulate_frame_transaction_tests 2>&1 | tail -80`

Expected: the 5 renamed-field tests FAIL (the JSON object has no `canonicalMempoolValid`/`canonicalMempoolViolation` key yet, so those index expressions evaluate to `Value::Null` and the `assert_eq!`/`.expect(...)` calls fail — e.g. `assert_eq!(result["canonicalMempoolValid"], json!(false))` fails because the actual value is `Value::Null`). The 2 new tests FAIL because `result["gasUsed"]`/`result["frames"]`/`result["executionStatus"]` are `Value::Null` today (the early-return gates suppress them) rather than being present.

- [ ] **Step 3: Implement the decoupling**

In `crates/networking/rpc/ethrex.rs`, rename the two fields on `SimulateFrameTransactionResult` (currently lines 61-125) and update their doc comments:

```rust
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SimulateFrameTransactionResult {
    /// Whether every canonical-mempool admission gate passed: EIP-8141
    /// static constraints and signature authentication, EIP-8250 nonce-key
    /// rules, EIP-8272 recent-root references, EIP-8312 UTXO openings, and
    /// the validation-prefix recognition/structural/trace checks — the same
    /// checks the mempool runs, in the same order. Purely informational: a
    /// `false` here does NOT prevent `gas_used`/`frames`/`erc7562_trace`
    /// from being populated below (see those fields' docs) — this field
    /// answers "would `eth_sendRawTransaction`'s mempool accept this", a
    /// DIFFERENT question from "what happens if it executes", which this
    /// RPC always answers once the transaction is decodable and its
    /// signature authenticates (see the hard-precondition gates in
    /// `handle`).
    canonical_mempool_valid: bool,
    /// Recognized validation-prefix shape, or `null` if the prefix is
    /// structurally unrecognized (`validation_prefix()` itself failed —
    /// note this is a STRICTER condition than `canonical_mempool_valid ==
    /// false`: a recognized-but-structurally-invalid or
    /// recognized-but-policy-violating prefix still reports its shape
    /// here).
    prefix_shape: Option<String>,
    /// The payer (paymaster or self-funded sender) established by the
    /// prefix, or `null` if the prefix was never recognized at all (no
    /// `ValidationPrefix` to simulate against) or no payer was
    /// established. Available even when `canonical_mempool_valid` is
    /// `false` for any OTHER reason (a structural or observer-trace
    /// violation) — payer tracking and policy enforcement are independent
    /// within the same simulation pass.
    payer: Option<Address>,
    /// The transaction's max cost (TXPARAM `0x06`), as a `0x`-hex wei value.
    /// Always present — it is a pure function of the transaction fields.
    max_cost: String,
    /// Why `canonical_mempool_valid` is `false` — the first canonical-policy
    /// check that failed, in the same order the mempool applies them
    /// (never under-reports a passing check as failing). `null` when
    /// `canonical_mempool_valid` is `true`.
    canonical_mempool_violation: Option<String>,
    /// Accurate total gas used across all frames, as `0x`-hex. Populated
    /// whenever `execute_for_gas` ran and produced a result — which,
    /// unlike `canonical_mempool_valid`, happens unconditionally once the
    /// hard preconditions in `handle` pass (decodable tx, authenticated
    /// signature, signature-cost and total-gas-limit budgets) —
    /// independent of the canonical-mempool verdict above. `null` only when
    /// one of those hard preconditions failed, or `execute_for_gas` itself
    /// errored (see `execution_error`).
    gas_used: Option<String>,
    /// Per-frame gas used and success. Same availability as `gas_used`.
    frames: Option<Vec<FrameExecResult>>,
    /// Top-level execution summary: `"success"` (every frame succeeded) or
    /// `"reverted"` (at least one frame did not — see per-frame `frames`).
    /// Same availability as `gas_used`.
    execution_status: Option<String>,
    /// Error string if `execute_for_gas` itself could not run or complete.
    /// `null` when it succeeded (see `gas_used`) or was never attempted (a
    /// hard precondition failed first).
    execution_error: Option<String>,
    /// Full `Erc7562FrameTracer` trace (opcode counts, accessed storage/transient
    /// slots, EXTCODE access, contract sizes, Keccak preimages), one [`FrameEntry`]
    /// per frame in the transaction. Populated only when the caller opted in with
    /// the third param `{"trace": true}` AND `execute_for_gas` actually ran and
    /// succeeded (`gas_used.is_some()`); `null` otherwise. Omitting `trace` (or
    /// passing `{"trace": false}`) never constructs the tracer or runs the extra
    /// pass this field requires, so untraced callers pay nothing for this field's
    /// existence.
    erc7562_trace: Option<Vec<FrameEntry>>,
    /// Stringified error from the trace pass, distinguishing "tracing was
    /// requested but the trace pass itself failed" from every other reason
    /// `erc7562_trace` can be `null` (tracing not requested, `execute_for_gas`
    /// did not run or did not succeed, or the separate trace pass in
    /// [`SimulateFrameTransactionRequest::execute_for_trace`] itself failed).
    /// Populated only when `self.trace == true` AND `gas_used.is_some()` AND
    /// the trace pass failed — `null` in every other case, including when
    /// `erc7562_trace` is present (a successful trace pass).
    erc7562_trace_error: Option<String>,
}
```

Add a small helper function near `structurally_invalid`/`to_hex_u256` (end of the file, after `to_hex_u256`):

```rust
/// Records `message` as the canonical-mempool violation only if none has
/// been recorded yet (first-failure-wins, matching the mempool's own
/// check ordering: the FIRST check that fails is the one reported).
fn note_violation(valid: &mut bool, violation: &mut Option<String>, message: String) {
    if *valid {
        *valid = false;
        *violation = Some(message);
    }
}
```

Update `structurally_invalid` (currently lines 513-530) to use the new field names:

```rust
fn structurally_invalid(violation: String, max_cost: String) -> Result<Value, RpcErr> {
    to_value(SimulateFrameTransactionResult {
        canonical_mempool_valid: false,
        prefix_shape: None,
        payer: None,
        max_cost,
        canonical_mempool_violation: Some(violation),
        gas_used: None,
        frames: None,
        execution_status: None,
        execution_error: None,
        erc7562_trace: None,
        erc7562_trace_error: None,
    })
}
```

Replace `handle` (currently lines 198-399) in full:

```rust
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let block = self
            .block
            .clone()
            .unwrap_or(BlockIdentifierOrHash::Identifier(BlockIdentifier::default()));
        let header = match block.resolve_block_header(&context.storage).await? {
            Some(header) => header,
            _ => return Ok(Value::Null),
        };

        let Transaction::FrameTransaction(frame_tx) = &self.transaction else {
            // Guaranteed by `parse`; kept as a defensive guard.
            return Err(RpcErr::BadParams(
                "rawTx is not a type-0x06 frame transaction".to_owned(),
            ));
        };

        // `max_cost` is a pure function of the tx fields and the block's blob base
        // fee (no EVM pass), so it is reported on every path, including structural
        // rejection.
        let blob_schedule = context
            .storage
            .get_chain_config()
            .get_fork_blob_schedule(header.timestamp)
            .unwrap_or_default();
        let blob_base_fee = calculate_base_fee_per_blob_gas(
            header.excess_blob_gas.unwrap_or_default(),
            blob_schedule.base_fee_update_fraction,
        );
        let max_cost = to_hex_u256(frame_tx.max_cost(blob_base_fee));

        // Hard preconditions (unchanged): a transaction that fails these
        // cannot be meaningfully executed at all -- not canonical-mempool
        // policy opinions, but preconditions for the simulation being
        // meaningful. See this file's design spec for why each stays a gate.
        let config = context.storage.get_chain_config();
        let utxo_frames_active = config.is_utxo_frames_activated(header.timestamp);
        if let Err(error) = frame_tx.validate_static_constraints(utxo_frames_active) {
            return structurally_invalid(error, max_cost);
        }

        let max_verify_gas = context.blockchain.options.max_verify_gas;
        if frame_tx.signature_verification_cost() > max_verify_gas {
            return structurally_invalid(
                format!(
                    "signature verification cost {} exceeds MAX_VERIFY_GAS {max_verify_gas}",
                    frame_tx.signature_verification_cost()
                ),
                max_cost,
            );
        }

        let fork = config.fork(header.timestamp);
        if !ethrex_vm::validate_frame_signatures(
            &frame_tx.signatures,
            frame_tx.compute_sig_hash(),
            frame_tx.sender,
            fork,
            &NativeCrypto,
        ) {
            return structurally_invalid(
                "frame signature list does not authenticate the sender".to_owned(),
                max_cost,
            );
        }

        // DoS guard, applied BEFORE any EVM work -- still a hard gate: it
        // protects the RPC server's own resources, not a policy opinion
        // about the transaction.
        let max_allowed = get_max_allowed_gas_limit(header.gas_limit, fork);
        let total_gas_limit = frame_tx.total_gas_limit();
        if total_gas_limit > max_allowed {
            return to_value(SimulateFrameTransactionResult {
                canonical_mempool_valid: false,
                prefix_shape: None,
                payer: None,
                max_cost,
                canonical_mempool_violation: Some(format!(
                    "total gas limit {total_gas_limit} exceeds the per-transaction gas cap {max_allowed} (EIP-7825); not simulated"
                )),
                gas_used: None,
                frames: None,
                execution_status: None,
                execution_error: None,
                erc7562_trace: None,
                erc7562_trace_error: None,
            });
        }

        // Canonical-mempool policy checks, in the same order the mempool
        // applies them -- now purely informational: `canonical_mempool_valid`/
        // `canonical_mempool_violation` accumulate the FIRST failure (never
        // under-reporting a passing check as failing, same as before), but
        // no failure here skips `execute_for_gas`/the trace pass any more.
        let mut canonical_mempool_valid = true;
        let mut canonical_mempool_violation: Option<String> = None;

        let prefix = match frame_tx.validation_prefix() {
            Ok(prefix) => match frame_tx.validate_prefix_structure(&prefix, max_verify_gas) {
                Ok(()) => Some(prefix),
                Err(error) => {
                    note_violation(
                        &mut canonical_mempool_valid,
                        &mut canonical_mempool_violation,
                        error.to_string(),
                    );
                    Some(prefix)
                }
            },
            Err(error) => {
                note_violation(
                    &mut canonical_mempool_valid,
                    &mut canonical_mempool_violation,
                    error.to_string(),
                );
                None
            }
        };
        let prefix_shape = prefix
            .as_ref()
            .map(|prefix| prefix_shape_name(&prefix.shape).to_owned());

        if utxo_frames_active
            && let Err(error) =
                context
                    .blockchain
                    .check_utxo_admission(frame_tx, header.number, header.number + 1)
        {
            note_violation(
                &mut canonical_mempool_valid,
                &mut canonical_mempool_violation,
                error.to_string(),
            );
        }
        if let Err(error) =
            context
                .blockchain
                .check_recent_root_references(frame_tx, &header, header.number)
        {
            note_violation(
                &mut canonical_mempool_valid,
                &mut canonical_mempool_violation,
                error.to_string(),
            );
        }

        // `payer` is only derivable when the prefix was at least recognized
        // -- `simulate_prefix` needs a `&ValidationPrefix` to run against.
        // A structural-validation failure still runs it (payer tracking and
        // structural/observer policy are independent), but an outright
        // recognition failure (`prefix` is `None`) has nothing to run.
        let payer = match &prefix {
            Some(prefix) => {
                let outcome = self.simulate_prefix(&context, &header, prefix)?;
                if !outcome.passed {
                    note_violation(
                        &mut canonical_mempool_valid,
                        &mut canonical_mempool_violation,
                        outcome
                            .violation
                            .clone()
                            .unwrap_or_else(|| "validation prefix did not pass".to_owned()),
                    );
                }
                outcome.accessed_paymaster.map(|(payer, _)| payer)
            }
            None => None,
        };

        // Always run the full execution: this is the RPC's primary job --
        // "what happens if this transaction is included" -- independent of
        // the canonical-mempool verdict above.
        let (gas_used, frames, execution_status, execution_error) =
            self.execute_for_gas(&context, &header, frame_tx.sender);

        // Opt-in only, and only after `execute_for_gas` has shown the
        // transaction executes -- unchanged from before this change.
        let (erc7562_trace, erc7562_trace_error) = if self.trace && gas_used.is_some() {
            match self.execute_for_trace(&context, &header) {
                Ok(trace) => (Some(trace), None),
                Err(error) => (None, Some(error)),
            }
        } else {
            (None, None)
        };

        to_value(SimulateFrameTransactionResult {
            canonical_mempool_valid,
            prefix_shape,
            payer,
            max_cost,
            canonical_mempool_violation,
            gas_used,
            frames,
            execution_status,
            execution_error,
            erc7562_trace,
            erc7562_trace_error,
        })
    }
```

Also update the module-level doc comment on `SimulateFrameTransactionRequest` (currently lines 29-33):

```rust
/// `ethrex_simulateFrameTransaction` — run a full multi-frame execution of
/// the given EIP-8141 frame transaction against `block` (default `latest`),
/// WITHOUT submitting it, reporting what actually happens (gas used,
/// per-frame outcome, and optionally a full opcode trace). Separately
/// reports whether the transaction would be accepted by this node's
/// canonical mempool policy (`canonicalMempoolValid`/
/// `canonicalMempoolViolation`) — a DIFFERENT question that does not gate
/// the execution results above: a transaction the mempool would reject
/// still gets a full, accurate execution report here.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd test && cargo test -p ethrex-test simulate_frame_transaction_tests 2>&1 | tail -80`

Expected: all tests in `simulate_frame_transaction_tests.rs` pass — the 5 renamed-field tests (same values as before, just under the new field names), the 2 new decoupling tests, and every `parse_*` test (unaffected, they don't touch `handle` at all).

Then run the full workspace test suite once to confirm nothing else broke:

Run: `cargo test --workspace 2>&1 | tail -100`

Expected: no new failures relative to a baseline run on this branch before this plan's changes (the branch may have pre-existing unrelated failures — compare against a `git stash`-based baseline if anything is red, rather than assuming this plan caused it).

- [ ] **Step 5: Commit**

```bash
git add crates/networking/rpc/ethrex.rs test/tests/rpc/simulate_frame_transaction_tests.rs
git commit -m "$(cat <<'EOF'
feat(rpc): decouple ethrex_simulateFrameTransaction from canonical policy

The RPC's canonical-mempool-policy verdict (prefix recognition/structure,
UTXO admission, recent-root references, the ValidationObserver-gated
prefix simulation) no longer gates whether execute_for_gas/the trace pass
run. Execution results are now always reported once the hard preconditions
(decodable tx, authenticated signature, budget/DoS guards) pass; the
policy verdict is reported separately via renamed canonicalMempoolValid/
canonicalMempoolViolation fields. This unblocks any transaction whose
prefix the mempool's own trace rules would flag (e.g. a pre_verify frame's
nested ERC-20 pull tripping the sender-only write-gate) from still
getting a real execution report, which Skandha's own alt-mempool
validator needs regardless of what this node's canonical policy says.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```
