//! ethrex-specific JSON-RPC methods (`ethrex_*` namespace).
//!
//! These are non-standard extensions that ethrex exposes outside the
//! standardized `eth_`/`debug_` namespaces. They live in a dedicated namespace
//! so operators can enable them on a public endpoint (`--http.api ethrex`)
//! without also exposing the whole `debug_` surface.

use ethrex_blockchain::mempool::FRAME_CANONICAL_PAYMASTER_CODE_HASH;
use ethrex_blockchain::vm::StoreVmDatabase;
use ethrex_common::{
    Address, U256,
    types::{
        BlockHeader, FRAME_RECEIPT_STATUS_SUCCESS, PrefixShape, Transaction, ValidationPrefix,
        calculate_base_fee_per_blob_gas,
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_vm::backends::{
    ApproveRejection, ExceptionalHalt, FrameValidationOutcome, PrefixFailureReason, PrefixFrameFailure,
    levm::get_max_allowed_gas_limit,
};
use ethrex_vm::tracing::FrameEntry;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    rpc::{RpcApiContext, RpcHandler},
    types::block_identifier::{BlockIdentifier, BlockIdentifierOrHash},
    utils::RpcErr,
};

/// `ethrex_simulateFrameTransaction` — run a full multi-frame execution of
/// the given EIP-8141 frame transaction against `block` (default `latest`),
/// WITHOUT submitting it, reporting what actually happens (gas used,
/// per-frame outcome, and optionally a full opcode trace). Separately
/// reports whether the transaction would be accepted by this node's
/// canonical mempool policy (`canonicalMempoolValid`/
/// `canonicalMempoolViolation`) — a DIFFERENT question that does not gate
/// the execution results above: a transaction the mempool would reject
/// still gets a full, accurate execution report here.
#[derive(Debug)]
pub struct SimulateFrameTransactionRequest {
    /// Decoded type-`0x06` frame transaction (validated in `parse`).
    pub transaction: Transaction,
    /// Block the simulation runs against. Defaults to `latest`.
    pub block: Option<BlockIdentifierOrHash>,
    /// Opt-in flag (third param, `{"trace": true}`): when set, additionally run the
    /// full `Erc7562FrameTracer` trace and populate
    /// [`SimulateFrameTransactionResult::erc7562_trace`]. `false` (the default when the
    /// third param is absent or `null`) is byte-for-byte the pre-existing behavior --
    /// no tracer is constructed and no extra execution pass runs.
    pub trace: bool,
}

/// Optional third param of `ethrex_simulateFrameTransaction`. Absent, `null`, or
/// `{"trace": false}` all mean "do not trace" -- the same, unchanged behavior every
/// caller got before this option existed.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SimulateFrameTransactionOptions {
    #[serde(default)]
    trace: bool,
}

/// Result of `ethrex_simulateFrameTransaction`.
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
    /// Which validation-prefix frame failed and why, present only when the prefix
    /// failed inside a frame (a revert or an exceptional halt). Its fields are
    /// flattened into this object and are absent otherwise. `canonical_mempool_violation`
    /// still carries the coarse text (`"validation prefix frame reverted"`), unchanged.
    #[serde(flatten)]
    failure: Option<PrefixFailureDetail>,
}

/// Machine-readable detail of a validation-prefix frame failure, flattened into
/// [`SimulateFrameTransactionResult`]. `canonical_mempool_violation` says a prefix
/// frame failed; this says which frame and why, so a client can tell "the payer
/// has no funds" from "the verification ran out of gas" from "it reverted".
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrefixFailureDetail {
    /// Index (into the transaction's `frames`) of the frame that failed.
    failed_frame_index: usize,
    /// Machine-readable cause. One of `out_of_gas`, `revert`, `insufficient_funds`,
    /// `value_exceeds_balance`, `payment_before_execution_approval`,
    /// `approve_target_is_not_sender`, `approve_in_atomic_batch`, `invalid_opcode`,
    /// `stack_error`, `invalid_jump`, `static_violation`, `halt` (any other
    /// exceptional halt), `default_code_failed` or `vm_error`.
    halt_reason: &'static str,
    /// Human-readable description of the cause.
    halt_detail: String,
    /// `REVERT` return data as `0x`-hex, for `revert` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    revert_data: Option<String>,
    /// The account whose funds fell short, for `insufficient_funds` and
    /// `value_exceeds_balance`.
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<Address>,
    /// That account's balance in wei as `0x`-hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    /// The amount it needed in wei as `0x`-hex: the transaction's maximum cost for
    /// `insufficient_funds`, the frame's `value` for `value_exceeds_balance`.
    #[serde(skip_serializing_if = "Option::is_none")]
    required: Option<String>,
}

impl PrefixFailureDetail {
    fn new(
        failed_frame_index: usize,
        halt_reason: &'static str,
        halt_detail: impl Into<String>,
    ) -> Self {
        Self {
            failed_frame_index,
            halt_reason,
            halt_detail: halt_detail.into(),
            revert_data: None,
            account: None,
            balance: None,
            required: None,
        }
    }

    fn from_failure(failure: &PrefixFrameFailure, sender: Address) -> Self {
        let index = failure.frame_index;
        match &failure.reason {
            PrefixFailureReason::EntryGasTooLow { limit, needed } => Self::new(
                index,
                "out_of_gas",
                format!(
                    "the frame's gas limit {limit} cannot cover its entry charge of {needed} gas"
                ),
            ),
            PrefixFailureReason::ValueExceedsBalance { balance, value } => Self {
                account: Some(sender),
                balance: Some(to_hex_u256(*balance)),
                required: Some(to_hex_u256(*value)),
                ..Self::new(
                    index,
                    "value_exceeds_balance",
                    "the frame's value exceeds the sender's balance",
                )
            },
            PrefixFailureReason::InsufficientFunds {
                payer,
                balance,
                required,
            } => Self {
                account: Some(*payer),
                balance: Some(to_hex_u256(*balance)),
                required: Some(to_hex_u256(*required)),
                ..Self::new(
                    index,
                    "insufficient_funds",
                    "the paying account cannot cover the transaction's maximum cost",
                )
            },
            PrefixFailureReason::ApproveRejected(rejection) => {
                let (reason, detail) = match rejection {
                    ApproveRejection::PaymentBeforeExecution => (
                        "payment_before_execution_approval",
                        "APPROVE(payment) ran before the sender approved execution",
                    ),
                    ApproveRejection::TargetIsNotSender => (
                        "approve_target_is_not_sender",
                        "APPROVE(execution and payment) ran in a frame that does not target the sender",
                    ),
                    ApproveRejection::InAtomicBatch => (
                        "approve_in_atomic_batch",
                        "APPROVE(payment) is not allowed inside an atomic batch",
                    ),
                    // Reported as `InsufficientFunds` above; kept exhaustive.
                    ApproveRejection::InsufficientFunds { .. } => (
                        "insufficient_funds",
                        "the paying account cannot cover the transaction's maximum cost",
                    ),
                };
                Self::new(index, reason, detail)
            }
            PrefixFailureReason::Revert { data } => Self {
                revert_data: Some(format!("0x{}", hex::encode(data))),
                ..Self::new(index, "revert", "the frame reverted")
            },
            PrefixFailureReason::Halt(halt) => {
                let reason = match halt {
                    ExceptionalHalt::OutOfGas => "out_of_gas",
                    ExceptionalHalt::InvalidOpcode => "invalid_opcode",
                    ExceptionalHalt::StackUnderflow | ExceptionalHalt::StackOverflow => {
                        "stack_error"
                    }
                    ExceptionalHalt::InvalidJump => "invalid_jump",
                    ExceptionalHalt::OpcodeNotAllowedInStaticContext => "static_violation",
                    _ => "halt",
                };
                Self::new(index, reason, halt.to_string())
            }
            PrefixFailureReason::DefaultCodeFailed => Self::new(
                index,
                "default_code_failed",
                "the frame's default code reported failure",
            ),
            PrefixFailureReason::Error(error) => Self::new(index, "vm_error", error.clone()),
        }
    }
}

/// Per-frame execution outcome for the full-execution step.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrameExecResult {
    /// Gas used by this frame, as `0x`-hex.
    gas_used: String,
    /// Whether this frame completed successfully (did not revert/halt/skip).
    succeeded: bool,
}

/// Stable wire name for a validation-prefix shape (decoupled from the Rust
/// `Debug` representation, which must not leak into the public API).
fn prefix_shape_name(shape: &PrefixShape) -> &'static str {
    match shape {
        PrefixShape::SelfVerify => "SelfVerify",
        PrefixShape::DeploySelfVerify => "DeploySelfVerify",
        PrefixShape::OnlyVerifyPay => "OnlyVerifyPay",
        PrefixShape::DeployOnlyVerifyPay => "DeployOnlyVerifyPay",
    }
}

impl RpcHandler for SimulateFrameTransactionRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.is_empty() || params.len() > 3 {
            return Err(RpcErr::BadParams(format!(
                "Expected one to three params and {} were provided",
                params.len()
            )));
        }

        let raw: String = serde_json::from_value(params[0].clone())
            .map_err(|error| RpcErr::BadParams(error.to_string()))?;
        let raw = raw
            .strip_prefix("0x")
            .ok_or_else(|| RpcErr::BadParams("rawTx is not 0x-prefixed".to_owned()))?;
        let bytes = hex::decode(raw).map_err(|error| RpcErr::BadParams(error.to_string()))?;

        let transaction = Transaction::decode_canonical(&bytes)
            .map_err(|error| RpcErr::BadParams(error.to_string()))?;
        if !matches!(transaction, Transaction::FrameTransaction(_)) {
            return Err(RpcErr::BadParams(
                "rawTx is not a type-0x06 frame transaction".to_owned(),
            ));
        }

        let block = match params.get(1) {
            Some(value) => Some(BlockIdentifierOrHash::parse(value.clone(), 1)?),
            None => None,
        };

        let trace = match params.get(2) {
            Some(value) if !value.is_null() => {
                let options: SimulateFrameTransactionOptions = serde_json::from_value(
                    value.clone(),
                )
                .map_err(|error| RpcErr::BadParams(error.to_string()))?;
                options.trace
            }
            _ => false,
        };

        Ok(SimulateFrameTransactionRequest {
            transaction,
            block,
            trace,
        })
    }

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
                failure: None,
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

        // EIP-8312 UTXO admission and EIP-8272 recent-root references. Both read
        // head state natively rather than through the EVM.
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
        //
        // `failure` (which validation-prefix frame failed and why, if any)
        // is captured here too, alongside `payer` -- both come from the same
        // `outcome`, which only lives for the duration of this match arm.
        let mut failure: Option<PrefixFailureDetail> = None;
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
                    failure = outcome
                        .failure
                        .as_ref()
                        .map(|failure| PrefixFailureDetail::from_failure(failure, frame_tx.sender));
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
        //
        // `execute_for_trace` distinguishes "not requested" from "requested but
        // failed" via `Result` rather than swallowing every failure into `None`,
        // so a caller who explicitly asked for a trace and hit a genuine failure
        // sees `erc7562TraceError` populated instead of an indistinguishable
        // `erc7562Trace: null`.
        let (erc7562_trace, erc7562_trace_error) = if self.trace && frames.is_some() {
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
            failure,
        })
    }
}

impl SimulateFrameTransactionRequest {
    /// Runs the EIP-8141 validation-prefix simulation over a fresh throwaway
    /// state at `header`.
    fn simulate_prefix(
        &self,
        context: &RpcApiContext,
        header: &BlockHeader,
        prefix: &ValidationPrefix,
    ) -> Result<FrameValidationOutcome, RpcErr> {
        let vm_db = StoreVmDatabase::new(context.storage.clone(), header.clone())?;
        let mut vm = context.blockchain.new_evm(vm_db)?;
        // EvmError maps to RpcErr::Vm (-32015) via From, matching eth_call/estimateGas.
        vm.simulate_frame_validation_prefix(
            &self.transaction,
            header,
            prefix,
            Some(FRAME_CANONICAL_PAYMASTER_CODE_HASH),
            context.blockchain.options.max_verify_gas,
            None,
        )
        .map_err(RpcErr::from)
    }

    /// Executes the full transaction on a fresh throwaway state to measure
    /// total and per-frame gas. Returns `(gas_used, frames, status, error)`;
    /// on execution failure returns `(None, None, None, Some(error))` so the
    /// caller can still report the (valid) prefix outcome.
    fn execute_for_gas(
        &self,
        context: &RpcApiContext,
        header: &BlockHeader,
        sender: Address,
    ) -> (
        Option<String>,
        Option<Vec<FrameExecResult>>,
        Option<String>,
        Option<String>,
    ) {
        let vm_db = match StoreVmDatabase::new(context.storage.clone(), header.clone()) {
            Ok(db) => db,
            Err(error) => return (None, None, None, Some(error.to_string())),
        };
        let mut vm = match context.blockchain.new_evm(vm_db) {
            Ok(vm) => vm,
            Err(error) => return (None, None, None, Some(error.to_string())),
        };
        let mut cumulative_gas = 0u64;
        match vm.execute_tx(&self.transaction, header, &mut cumulative_gas, sender) {
            Ok((receipt, report)) => {
                let frames = receipt.frame_receipts.map(|frames| {
                    frames
                        .into_iter()
                        .map(|frame| FrameExecResult {
                            gas_used: format!("0x{:x}", frame.gas_used),
                            succeeded: frame.status == FRAME_RECEIPT_STATUS_SUCCESS,
                        })
                        .collect()
                });
                // For a frame tx the top-level result is Success iff every frame
                // succeeded, else a placeholder Revert (see execute_frame_tx);
                // per-frame detail is in `frames`.
                let status = if report.is_success() {
                    "success"
                } else {
                    "reverted"
                };
                (
                    Some(format!("0x{:x}", report.gas_used)),
                    frames,
                    Some(status.to_owned()),
                    None,
                )
            }
            Err(error) => (None, None, None, Some(error.to_string())),
        }
    }

    /// Runs the same transaction on ANOTHER fresh throwaway state, this time with
    /// `Erc7562FrameTracer` active, to produce `erc7562_trace`. Only ever called
    /// when the caller opted in with `{"trace": true}` -- so an untraced caller never
    /// constructs the tracer or pays for this pass -- and only after
    /// `execute_for_gas` has already shown the transaction executes.
    ///
    /// A separate pass rather than threading the tracer through `execute_for_gas`'s
    /// call to `Evm::execute_tx`: that method is the single most-used execution entry
    /// point in the codebase (block execution, mempool, L2 batching), so adding an
    /// opt-in tracer parameter there would touch far more surface than reusing the
    /// pattern this function already establishes -- `execute_for_gas` itself runs on
    /// its own fresh state, separate from the prefix simulation before it, for the
    /// identical reason: a throwaway state cannot be replayed once a pass has
    /// mutated it. Returns `Err` (stringified) on any setup or execution error rather
    /// than swallowing it -- the caller distinguishes "not requested" (this method
    /// never called) from "requested but failed" (`Err` here) by populating
    /// `SimulateFrameTransactionResult::erc7562_trace_error` in the latter case, so a
    /// genuine trace-pass failure is never indistinguishable from an opt-out.
    fn execute_for_trace(
        &self,
        context: &RpcApiContext,
        header: &BlockHeader,
    ) -> Result<Vec<FrameEntry>, String> {
        let vm_db = StoreVmDatabase::new(context.storage.clone(), header.clone())
            .map_err(|error| error.to_string())?;
        let mut vm = context
            .blockchain
            .new_evm(vm_db)
            .map_err(|error| error.to_string())?;
        vm.trace_tx_erc7562_standalone(&self.transaction, header)
            .map_err(|error| error.to_string())
    }
}

/// Builds the `{canonicalMempoolValid: false, ...}` response for a
/// transaction that fails one of `handle`'s hard preconditions (not
/// decodable/executable at all, so no EVM pass was run and
/// payer/prefixShape/gas are unknown; `maxCost` is a pure function of the
/// tx fields and is still reported).
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
        failure: None,
    })
}

/// Records `message` as the canonical-mempool violation only if none has
/// been recorded yet (first-failure-wins, matching the mempool's own
/// check ordering: the FIRST check that fails is the one reported).
fn note_violation(valid: &mut bool, violation: &mut Option<String>, message: String) {
    if *valid {
        *valid = false;
        *violation = Some(message);
    }
}

fn to_hex_u256(value: U256) -> String {
    format!("0x{value:x}")
}

fn to_value(result: SimulateFrameTransactionResult) -> Result<Value, RpcErr> {
    serde_json::to_value(result).map_err(|error| RpcErr::Internal(error.to_string()))
}

/// `ethrex_submitPrivilegedFrameTransaction` — a demo-grade, fully
/// unauthenticated fast path for a trusted, localhost-only caller (an
/// EIP-8141 frame-transaction sidecar that has already run its own full
/// ERC-7562-derived admission checks) to force a frame transaction into the
/// very next payload build, bypassing the mempool's `validate_transaction`
/// admission pipeline entirely.
///
/// This is NOT a substitute for `eth_sendRawTransaction`/the normal
/// mempool: there is no fee-competitiveness check, no paymaster-reservation
/// accounting, no expiry-deadline check, and no spam protection of any
/// kind. There is also no retry across blocks: a transaction not caught by
/// the very next payload build is simply dropped — see
/// `Blockchain::push_privileged_transaction`'s own doc comment for why that
/// is the entire mechanism behind "current block only", not a bug to fix
/// later. MUST NOT be exposed on anything but a trusted deployment where
/// the caller is known to have already validated the transaction itself.
#[derive(Debug)]
pub struct SubmitPrivilegedFrameTransactionRequest {
    /// Decoded type-`0x06` frame transaction (validated in `parse`).
    pub transaction: Transaction,
}

impl RpcHandler for SubmitPrivilegedFrameTransactionRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 1 {
            return Err(RpcErr::BadParams(format!(
                "Expected one param and {} were provided",
                params.len()
            )));
        }

        let raw: String = serde_json::from_value(params[0].clone())
            .map_err(|error| RpcErr::BadParams(error.to_string()))?;
        let raw = raw
            .strip_prefix("0x")
            .ok_or_else(|| RpcErr::BadParams("rawTx is not 0x-prefixed".to_owned()))?;
        let bytes = hex::decode(raw).map_err(|error| RpcErr::BadParams(error.to_string()))?;

        let transaction = Transaction::decode_canonical(&bytes)
            .map_err(|error| RpcErr::BadParams(error.to_string()))?;
        if !matches!(transaction, Transaction::FrameTransaction(_)) {
            return Err(RpcErr::BadParams(
                "rawTx is not a type-0x06 frame transaction".to_owned(),
            ));
        }

        Ok(SubmitPrivilegedFrameTransactionRequest { transaction })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        // No validation of any kind is performed here, deliberately - see this
        // struct's own doc comment. The hash is computed the same way
        // `eth_sendRawTransaction` computes it, so a caller correlating
        // hashes across both methods sees the same value regardless of
        // which one it used.
        let hash = self.transaction.hash(&NativeCrypto);
        context
            .blockchain
            .push_privileged_transaction(self.transaction.clone());
        serde_json::to_value(format!("{hash:#x}"))
            .map_err(|error| RpcErr::Internal(error.to_string()))
    }
}
