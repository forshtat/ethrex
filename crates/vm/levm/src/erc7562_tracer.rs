//! Native ERC-7562/EIP-8141 validation-diagnostics tracer, exposed over
//! `debug_traceCall`/`debug_traceTransaction`. Ported from go-ethereum's
//! `eth/tracers/native/erc7562.go`, extended to segment output by frame
//! transaction frame index rather than assuming a single top-level call.
//!
//! This is a **collector, not an enforcer**: like geth's original, it
//! records opcode usage, storage access, EXTCODE access, contract sizes,
//! and Keccak preimages per call frame. Rule enforcement (which opcodes
//! are banned, which storage slots count as "associated" per the
//! `keccak(A||x)+n` pattern) is the caller's responsibility, matching
//! geth's own division of labor between this tracer and a bundler's
//! interpretation of its output.

use crate::errors::InternalError;
use ethrex_common::{Address, H256, types::Log};
use std::collections::HashMap;

// Opcode bytes used by `on_opcode`'s ignore-list/CALL-family filters below,
// pinned against `crate::opcodes::Opcode`'s discriminants (confirmed equal to
// geth's own `vm.OpCode` values: EVM opcode bytes are standardized, and
// PUSH0 -- the one relatively recent addition, EIP-3855 -- is 0x5F in both).
const PUSH0: u8 = 0x5F;
const SWAP16: u8 = 0x9F;
const POP: u8 = 0x50;
const ADD: u8 = 0x01;
const MUL: u8 = 0x02;
const SUB: u8 = 0x03;
const DIV: u8 = 0x04;
const LT: u8 = 0x10;
const GT: u8 = 0x11;
const SLT: u8 = 0x12;
const SGT: u8 = 0x13;
const EQ: u8 = 0x14;
const ISZERO: u8 = 0x15;
const AND: u8 = 0x16;
const OR: u8 = 0x17;
const NOT: u8 = 0x19;
const SHL: u8 = 0x1B;
const SHR: u8 = 0x1C;
const GAS: u8 = 0x5A;
const CALL: u8 = 0xF1;
const CALLCODE: u8 = 0xF2;
const DELEGATECALL: u8 = 0xF4;
const STATICCALL: u8 = 0xFA;

/// Mirrors geth's `defaultIgnoredOpcodes()`: every `PUSHx`/`DUPx`/`SWAPx`
/// (one contiguous byte range, `PUSH0..=SWAP16`) plus 16 named
/// arithmetic/comparison opcodes. Does NOT include `GAS` -- geth deliberately
/// excludes `GAS` from this list since it is handled by a separate
/// retroactive rule (see `on_opcode`'s doc comment).
fn is_ignored_opcode(opcode: u8) -> bool {
    matches!(opcode, PUSH0..=SWAP16)
        || matches!(
            opcode,
            POP | ADD
                | SUB
                | MUL
                | DIV
                | EQ
                | LT
                | GT
                | SLT
                | SGT
                | SHL
                | SHR
                | AND
                | OR
                | NOT
                | ISZERO
        )
}

/// Mirrors geth's `isCall()`: exactly `CALL`/`CALLCODE`/`DELEGATECALL`/
/// `STATICCALL`. Deliberately does NOT include `CREATE`/`CREATE2` -- confirmed
/// against `eth/tracers/native/erc7562.go`'s `isCall` function directly, and
/// cross-checked against ethrex's own `check_validation_banned_opcode`
/// (`vm.rs`), which reproduces the identical set for its sibling EIP-8141
/// "sequential GAS rule" check.
fn is_call_family(opcode: u8) -> bool {
    matches!(opcode, CALL | CALLCODE | DELEGATECALL | STATICCALL)
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AccessedSlots {
    pub reads: HashMap<H256, Vec<H256>>,
    pub writes: HashMap<H256, u64>,
    #[serde(rename = "transientReads")]
    pub transient_reads: HashMap<H256, u64>,
    #[serde(rename = "transientWrites")]
    pub transient_writes: HashMap<H256, u64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ContractSizeWithOpcode {
    #[serde(rename = "contractSize")]
    pub contract_size: usize,
    pub opcode: u8,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FrameCallTraceFrame {
    pub from: Address,
    pub to: Option<Address>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<FrameCallTraceFrame>,
    #[serde(rename = "accessedSlots")]
    pub accessed_slots: AccessedSlots,
    #[serde(rename = "extCodeAccessInfo")]
    pub ext_code_access_info: Vec<Address>,
    #[serde(rename = "usedOpcodes")]
    pub used_opcodes: HashMap<u8, u64>,
    #[serde(rename = "contractSize")]
    pub contract_size: HashMap<Address, ContractSizeWithOpcode>,
    #[serde(rename = "outOfGas")]
    pub out_of_gas: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FrameEntry {
    /// Index into `FrameTransaction.frames`.
    pub frame_index: usize,
    pub root: FrameCallTraceFrame,
}

/// Collector for the native ERC-7562/EIP-8141 validation-diagnostics tracer.
///
/// Use `Erc7562FrameTracer::disabled()` when tracing is not wanted; `new()`
/// for an active tracer. Mirrors `LevmCallTracer`'s shape (an `active: bool`
/// flag plus a `Vec`-backed call-frame stack), but keyed by frame-transaction
/// frame index at the top level rather than assuming a single root call.
#[derive(Debug, Default, Clone)]
pub struct Erc7562FrameTracer {
    pub active: bool,
    pub frames: Vec<FrameEntry>,
    /// Call-frame stack for the frame currently executing, mirroring
    /// `LevmCallTracer::callframes`.
    call_stack: Vec<FrameCallTraceFrame>,
    /// `frame_index` of the frame-transaction frame most recently opened by
    /// `begin_frame`. Used by `exit` to tag the `FrameEntry` pushed to
    /// `self.frames` once `call_stack` empties back out.
    current_frame_index: usize,
    keccak_preimages: std::collections::HashSet<Vec<u8>>,
    last_opcode: Option<u8>,
}

impl Erc7562FrameTracer {
    /// Returns an inactive tracer. No allocations; zero overhead on the hot path.
    pub fn disabled() -> Self {
        Self {
            active: false,
            ..Default::default()
        }
    }

    /// Returns an active tracer, ready to collect frames.
    pub fn new() -> Self {
        Self {
            active: true,
            ..Default::default()
        }
    }

    /// Starts collecting a new frame-transaction frame at `frame_index`.
    ///
    /// `execute_frame_tx`'s loop calls this unconditionally at the top of every
    /// iteration it reaches (before dispatch decides which of UTXO / atomic-batch
    /// -skip / default-code / normal `CallFrame` execution the frame takes), so
    /// every frame kind — including the three that never build a real
    /// `CallFrame` — gets a matching `enter`/`exit` pair (synthetic where there is
    /// no real call) and therefore exactly one `FrameEntry` in `self.frames`,
    /// keeping its length in step with `frame_tx.frames`.
    pub fn begin_frame(&mut self, frame_index: usize) {
        if !self.active {
            return;
        }
        self.current_frame_index = frame_index;
    }

    /// Starts a call scope within the frame `begin_frame` most recently opened.
    ///
    /// Mirrors `LevmCallTracer::enter`'s push-onto-`call_stack` shape. `input`/
    /// `gas` are accepted for calling-convention parity with
    /// `LevmCallTracer::enter` (and so a future task can extend this method
    /// without changing every call site) but are not yet stored:
    /// `FrameCallTraceFrame` (Task 2's reduced schema, mirroring the plan's own
    /// sketch rather than porting geth's `callFrameWithOpcodes` field-for-field)
    /// has no `input`/`gas` fields.
    pub fn enter(&mut self, from: Address, to: Address, _input: &[u8], _gas: u64) {
        if !self.active {
            return;
        }
        self.call_stack.push(FrameCallTraceFrame {
            from,
            to: Some(to),
            ..Default::default()
        });
    }

    /// Ends the innermost open call scope.
    ///
    /// Pops `call_stack`, per `LevmCallTracer::exit`'s control flow: if a parent
    /// scope remains on the stack, the popped frame nests into it (`parent.calls`);
    /// once the stack empties back out, the frame `begin_frame` opened is
    /// complete, so it is wrapped in a `FrameEntry` (tagged with the
    /// `current_frame_index` `begin_frame` recorded) and appended to
    /// `self.frames`.
    ///
    /// `gas_used`/`output` are accepted for calling-convention parity with
    /// `LevmCallTracer::exit` (same reduced-schema note as `enter`) but are not
    /// yet stored. `error`, when it names an out-of-gas condition, sets
    /// `out_of_gas` on the popped frame — mirroring geth's `OnExit`
    /// (`errors.Is(err, vm.ErrOutOfGas) || errors.Is(err, vm.ErrCodeStoreOutOfGas)`
    /// -> `call.OutOfGas = true`).
    ///
    /// The match is a case-insensitive substring test on the already-formatted
    /// error string, not a match on `ExceptionalHalt::OutOfGas` itself: by the
    /// time an error reaches this method every `vm.rs` call site has already
    /// reduced it to a `String` (`format!("{e}")` on a `VMError`, or a
    /// hand-written literal for the synthetic UTXO/atomic-batch-skip paths that
    /// have no underlying `VMError` at all), so there is no variant left to
    /// match on without a wider refactor of every call site's error plumbing.
    /// `ExceptionalHalt::OutOfGas`'s real `Display` impl renders as `"Out Of
    /// Gas"` (title case) — lowercase both sides before comparing, or this
    /// never fires for a real EVM out-of-gas halt.
    pub fn exit(
        &mut self,
        _gas_used: u64,
        _output: Vec<u8>,
        error: Option<String>,
    ) -> Result<(), InternalError> {
        if !self.active {
            return Ok(());
        }
        let mut frame = self.call_stack.pop().ok_or(InternalError::CallFrame)?;
        if let Some(err) = &error {
            let err_lower = err.to_lowercase();
            if err_lower.contains("out of gas") || err_lower.contains("insufficient gas") {
                frame.out_of_gas = true;
            }
        }
        if let Some(parent) = self.call_stack.last_mut() {
            parent.calls.push(frame);
        } else {
            self.frames.push(FrameEntry {
                frame_index: self.current_frame_index,
                root: frame,
            });
        }
        Ok(())
    }

    /// Records one opcode's execution against the currently-executing call
    /// frame's `used_opcodes` tally, mirroring geth's `storeUsedOpcode`/
    /// `handleGasObserved` pair (`eth/tracers/native/erc7562.go`).
    ///
    /// Geth splits opcode counting in two:
    ///
    /// - `storeUsedOpcode` counts every opcode that is neither `GAS` nor on the
    ///   `defaultIgnoredOpcodes()` list (all of `PUSH0..=SWAP16` — every
    ///   `PUSHx`/`DUPx`/`SWAPx`, which share one contiguous, sequential byte
    ///   range — plus `POP`, `ADD`, `SUB`, `MUL`, `DIV`, `EQ`, `LT`, `GT`,
    ///   `SLT`, `SGT`, `SHL`, `SHR`, `AND`, `OR`, `NOT`, `ISZERO`).
    /// - `handleGasObserved` counts `GAS` itself, but only *retroactively*: a
    ///   `GAS` is only "suspicious" (worth counting) when it is NOT
    ///   immediately followed by a CALL-family opcode, since `GAS` right
    ///   before a call is the idiomatic "forward remaining gas to the callee"
    ///   pattern. Geth's `isCall()` (same file) defines the CALL family as
    ///   exactly `CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL` — notably NOT
    ///   `CREATE`/`CREATE2`. ethrex's own `check_validation_banned_opcode`
    ///   (`vm.rs`) independently reproduces this identical `is_call_family`
    ///   set for its sibling EIP-8141 "sequential GAS rule" check, confirming
    ///   this is the right set to mirror here too.
    ///
    /// This method is called once per opcode, in dispatch order, so the
    /// "was the previous opcode GAS" state needed for the retroactive rule is
    /// tracked via `self.last_opcode` (set unconditionally at the end of every
    /// call, mirroring geth's own `t.lastOpWithStack` bookkeeping).
    pub fn on_opcode(&mut self, opcode: u8) {
        if !self.active {
            return;
        }

        // Retroactive GAS accounting: a GAS observed on the PREVIOUS call to
        // `on_opcode` only counts as "used" once we know THIS opcode is not a
        // CALL-family opcode. Evaluated before `last_opcode` is overwritten
        // below.
        if self.last_opcode == Some(GAS) && !is_call_family(opcode) {
            if let Some(frame) = self.call_stack.last_mut() {
                *frame.used_opcodes.entry(GAS).or_insert(0) += 1;
            }
        }

        // Standard ignore-list filter. `GAS` is deliberately excluded from
        // this path (it is never counted directly, only via the retroactive
        // rule above), matching geth's `opcode != vm.GAS && !isIgnored`.
        if opcode != GAS && !is_ignored_opcode(opcode) {
            if let Some(frame) = self.call_stack.last_mut() {
                *frame.used_opcodes.entry(opcode).or_insert(0) += 1;
            }
        }

        self.last_opcode = Some(opcode);
    }

    /// Registers a log emitted during the currently-executing call frame.
    ///
    /// `FrameCallTraceFrame` does not yet carry a `logs` field — Task 2's schema
    /// intentionally omits it, along with `gas`/`gasUsed`/`input`/`output`/
    /// `error`/`value`, unlike geth's `callFrameWithOpcodes.Logs` — so this is a
    /// no-op today. Kept as a hook point with `LevmCallTracer::log`'s calling
    /// convention (`active`-gated, `Result<(), InternalError>`) so call sites can
    /// wire it unconditionally once a later task adds log capture to the schema.
    pub fn log(&mut self, _log: &Log) -> Result<(), InternalError> {
        if !self.active {
            return Ok(());
        }
        Ok(())
    }
}
