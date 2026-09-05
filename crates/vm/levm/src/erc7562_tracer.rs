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
const RETURN: u8 = 0xF3;
const CALLCODE: u8 = 0xF2;
const DELEGATECALL: u8 = 0xF4;
const STATICCALL: u8 = 0xFA;
const REVERT: u8 = 0xFD;
const SLOAD: u8 = 0x54;
const SSTORE: u8 = 0x55;
const TLOAD: u8 = 0x5C;
const TSTORE: u8 = 0x5D;
// EXTCODECOPY (0x3C) and EXTCODEHASH (0x3F) opcode bytes are not pinned as
// consts here: unlike EXTCODESIZE, neither is compared against directly in
// this file (the suppression rule below only ever checks for EXTCODESIZE
// specifically) -- callers pass their own opcode byte, from
// `crate::opcodes::Opcode`, into `on_ext_opcode`/`on_contract_size_access`.
const EXTCODESIZE: u8 = 0x3B;

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

/// Whether `opcode` suppresses a retroactive `GAS` count when it is the
/// opcode immediately following an observed `GAS`.
///
/// Mirrors the COMBINED effect of two separate geth mechanisms
/// (`eth/tracers/native/erc7562.go`, `OnOpcode`, lines 386-407):
///
/// - `isCall()`-family opcodes (`CALL`/`CALLCODE`/`DELEGATECALL`/
///   `STATICCALL`) are excluded via `handleGasObserved`'s own
///   `!isCall(opcode)` condition -- the idiomatic "forward remaining gas to
///   the callee" pattern.
/// - `RETURN`/`REVERT` are excluded via a DIFFERENT code path:
///   `handleReturnRevert(opcode)` runs first in `OnOpcode`, unconditionally
///   clearing `t.lastOpWithStack` whenever the CURRENT opcode is `RETURN` or
///   `REVERT`; `handleGasObserved` is itself only called when
///   `t.lastOpWithStack != nil`, so a `RETURN`/`REVERT` immediately after a
///   `GAS` skips the retroactive count entirely, with the exact same net
///   effect as a call-family opcode would. (A prior version of this port
///   missed this second path, since it isn't part of `isCall()`/
///   `defaultIgnoredOpcodes()` -- it only surfaces by reading the full
///   `OnOpcode` dispatch order.)
fn suppresses_gas_lookback(opcode: u8) -> bool {
    is_call_family(opcode) || opcode == RETURN || opcode == REVERT
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
    /// Captures the `(opcode, target_address)` of the most recently executed
    /// `EXTCODESIZE`/`EXTCODEHASH`/`EXTCODECOPY`, to be examined by the NEXT
    /// call to `on_opcode` and then consumed (cleared). Mirrors geth's
    /// `t.lastOpWithStack` -- but narrowed to only the EXT-opcode case, since
    /// `last_opcode` above already independently tracks the GAS-lookback
    /// case. See `on_ext_opcode`'s doc comment for why this must be a
    /// one-instruction lookback rather than an immediate record.
    last_ext_access: Option<(u8, Address)>,
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
    /// - `RETURN`/`REVERT` ALSO suppress the retroactive `GAS` count, via a
    ///   separate geth mechanism (`handleReturnRevert`, called unconditionally
    ///   before `handleGasObserved`'s guard) rather than `isCall()` itself —
    ///   see `suppresses_gas_lookback`'s doc comment for the full mechanism.
    ///
    /// This method is called once per opcode, in dispatch order, so the
    /// "was the previous opcode GAS" state needed for the retroactive rule is
    /// tracked via `self.last_opcode` (set unconditionally at the end of every
    /// call, mirroring geth's own `t.lastOpWithStack` bookkeeping).
    pub fn on_opcode(&mut self, opcode: u8) {
        if !self.active {
            return;
        }

        // EXTCODE access lookback: an EXTCODESIZE/EXTCODEHASH/EXTCODECOPY
        // captured by `on_ext_opcode` one instruction ago (called from within
        // that opcode's own handler, which runs AFTER this method was called
        // for that earlier instruction) is now examined against the CURRENT
        // opcode, mirroring geth's `handleExtOpcodes`: suppressed only when
        // the captured opcode was specifically `EXTCODESIZE` and the CURRENT
        // opcode is `ISZERO` (the "check code exists" idiom ERC-7562's
        // [OP-051] exempts); every other combination records the captured
        // address. Consumed via `take()` regardless of outcome, so a second,
        // non-adjacent opcode never re-examines the same capture.
        if let Some((last_ext_opcode, addr)) = self.last_ext_access.take() {
            let suppressed = last_ext_opcode == EXTCODESIZE && opcode == ISZERO;
            if !suppressed {
                if let Some(frame) = self.call_stack.last_mut() {
                    frame.ext_code_access_info.push(addr);
                }
            }
        }

        // Retroactive GAS accounting: a GAS observed on the PREVIOUS call to
        // `on_opcode` only counts as "used" once we know THIS opcode is
        // neither a CALL-family opcode nor RETURN/REVERT. Evaluated before
        // `last_opcode` is overwritten below.
        if self.last_opcode == Some(GAS) && !suppresses_gas_lookback(opcode) {
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

    /// Records one `SLOAD`/`SSTORE`/`TLOAD`/`TSTORE` opcode's storage-slot
    /// access against the currently-executing call frame's `accessed_slots`,
    /// mirroring geth's `handleStorageAccess` (`eth/tracers/native/erc7562.go`,
    /// lines 424-445) exactly:
    ///
    /// - `SLOAD`: records the value currently at `slot` -- via
    ///   `original_value_fn`, ethrex's equivalent to geth's
    ///   `t.env.StateDB.GetState(addr, slot)` -- into `reads[slot]`, but ONLY
    ///   the first time `slot` is touched by a read OR a write in this frame.
    ///   Geth's guard checks BOTH `Reads` and `Writes` before recording
    ///   (`!rOk && !wOk`), not just `Reads`: a slot written then read must not
    ///   get a stale post-write value recorded as if it were the pre-existing
    ///   one. `original_value_fn` is a `FnOnce` precisely so the (potentially
    ///   non-trivial) state read it performs is only ever done when the guard
    ///   actually passes, matching geth's own conditional call to `GetState`.
    /// - `SSTORE`: increments a write COUNTER (`writes[slot] += 1`) -- unlike
    ///   `SLOAD`, no value is ever stored for a write.
    /// - `TLOAD`/`TSTORE`: increment their own transient counters
    ///   (`transient_reads[slot]` / `transient_writes[slot]`) unconditionally
    ///   on every touch -- neither has a "first touch" guard, unlike `SLOAD`.
    ///
    /// Any opcode other than these four is a no-op (mirrors geth's `OnOpcode`
    /// only ever calling `handleStorageAccess` for this exact set, reproduced
    /// here as an explicit guard so a caller may dispatch unconditionally).
    ///
    /// `_addr` is accepted for calling-convention parity with geth's
    /// `scope.Address()` (and so call sites building `original_value_fn`
    /// closures have the address in scope) but is not itself read here:
    /// `original_value_fn` already closes over whatever address/slot pair it
    /// needs to look the value up against.
    pub fn on_storage_access(
        &mut self,
        opcode: u8,
        slot: H256,
        _addr: Address,
        original_value_fn: impl FnOnce() -> H256,
    ) {
        if !self.active {
            return;
        }
        let Some(frame) = self.call_stack.last_mut() else {
            return;
        };
        match opcode {
            SLOAD => {
                let already_touched = frame.accessed_slots.reads.contains_key(&slot)
                    || frame.accessed_slots.writes.contains_key(&slot);
                if !already_touched {
                    frame
                        .accessed_slots
                        .reads
                        .entry(slot)
                        .or_default()
                        .push(original_value_fn());
                }
            }
            SSTORE => {
                *frame.accessed_slots.writes.entry(slot).or_insert(0) += 1;
            }
            TLOAD => {
                *frame
                    .accessed_slots
                    .transient_reads
                    .entry(slot)
                    .or_insert(0) += 1;
            }
            TSTORE => {
                *frame
                    .accessed_slots
                    .transient_writes
                    .entry(slot)
                    .or_insert(0) += 1;
            }
            _ => {}
        }
    }

    /// Captures an `EXTCODESIZE`/`EXTCODEHASH`/`EXTCODECOPY` opcode's target
    /// address, to be examined by the NEXT call to `on_opcode` -- mirrors
    /// geth's `handleExtOpcodes`, which is itself a ONE-INSTRUCTION LOOKBACK
    /// over `t.lastOpWithStack`, not an immediate record.
    ///
    /// # Why a lookback, not an immediate record
    ///
    /// geth's `OnOpcode` fires once per instruction, PRE-execution, with the
    /// stack still holding that instruction's own operands. It captures the
    /// current instruction's opcode + stack-top items into
    /// `t.lastOpWithStack` at the END of every `OnOpcode` call, then examines
    /// that SAME captured record one instruction later, when the NEXT
    /// `OnOpcode` call fires -- by which point the EXT* opcode has already
    /// executed and overwritten its own stack-top operand with its own
    /// result (a size, a hash, ...), so the target address is no longer
    /// readable from the CURRENT stack at that point. It has to have been
    /// captured one instruction earlier, while the EXT* opcode's own operand
    /// was still on top.
    ///
    /// ethrex's dispatch loop (`vm.rs::run_dispatch`) calls
    /// `self.on_opcode(opcode)` BEFORE that opcode's handler runs, and the
    /// handler itself calls THIS method (after already popping the target
    /// address off the stack for its own use) -- so by the time `on_opcode`
    /// is called for the NEXT instruction, `self.last_ext_access` has
    /// already been populated by the PREVIOUS instruction's handler,
    /// timing-equivalent to geth's own capture point relative to its own
    /// lookback check.
    ///
    /// Only ever called by the `EXTCODESIZE`/`EXTCODEHASH`/`EXTCODECOPY`
    /// handlers (`opcode_handlers/environment.rs`) -- CALL-family opcodes do
    /// NOT feed this method: `handleExtOpcodes` in geth only ever examines
    /// `isEXT()`, never `isCall()`. The CALL-family's own contract-size
    /// bookkeeping is a separate, IMMEDIATE check -- see
    /// `on_contract_size_access` below.
    pub fn on_ext_opcode(&mut self, opcode: u8, addr: Address) {
        if !self.active {
            return;
        }
        self.last_ext_access = Some((opcode, addr));
    }

    /// Records the code size at `addr` the first time it is touched by an
    /// `EXTCODEHASH`/`EXTCODESIZE`/`EXTCODECOPY` or `CALL`/`CALLCODE`/
    /// `DELEGATECALL`/`STATICCALL` opcode, mirroring geth's
    /// `handleAccessedContractSize` -- with one key difference from
    /// `on_ext_opcode` above: this one is evaluated IMMEDIATELY against the
    /// CURRENT opcode's own (not-yet-consumed) target address, no lookback.
    ///
    /// geth peeks the target address directly off the raw EVM stack: stack
    /// position 0 for EXT* opcodes (their sole/first argument IS the target
    /// address) but position 1 for CALL-family opcodes (whose own stack-top
    /// is the `gas` argument, with the target address one slot below it --
    /// `isEXT(opcode) ? 0 : 1`). ethrex's call sites, unlike geth's
    /// externally-bolted-on tracer, already pop and destructure their full
    /// argument tuple before calling this method (e.g. `OpCallHandler`'s own
    /// `let [gas, callee, value, ...] = *stack.pop()?` already resolved
    /// `callee` from the correct depth as an ordinary part of executing the
    /// opcode), so this method takes the already-resolved `addr` directly
    /// rather than re-deriving a stack position itself -- the n=0-vs-n=1
    /// distinction is satisfied by construction at each call site (each
    /// handler passes its OWN opcode's target-address variable), not by any
    /// stack-index logic living here.
    ///
    /// `code_len_fn` mirrors `on_storage_access`'s `original_value_fn`
    /// pattern: an `FnOnce` so the code-length lookup only happens on the
    /// guarded first-touch branch (`HashMap::entry().or_insert_with()`),
    /// matching geth's own conditional call to `StateDB.GetCode`. Every call
    /// site passes a value it already computed for the opcode's own
    /// execution (`account_code_length` for `EXTCODESIZE`, the fetched
    /// `Code`'s length for `EXTCODECOPY`/CALL-family, or the equivalent
    /// still-needed lookup for `EXTCODEHASH`, which computes no length of
    /// its own), so this is zero-cost on the common repeat-access path and
    /// at most one extra lookup on first access.
    pub fn on_contract_size_access(
        &mut self,
        opcode: u8,
        addr: Address,
        code_len_fn: impl FnOnce() -> usize,
    ) {
        if !self.active {
            return;
        }
        let Some(frame) = self.call_stack.last_mut() else {
            return;
        };
        frame
            .contract_size
            .entry(addr)
            .or_insert_with(|| ContractSizeWithOpcode {
                contract_size: code_len_fn(),
                opcode,
            });
    }

    /// Records a `KECCAK256` call's preimage bytes, mirroring geth's
    /// `storeKeccak` exactly: unconditional (no length filtering of any
    /// kind -- every `KECCAK256` call's preimage is stored regardless of
    /// size) and scoped to the WHOLE tracer (`self.keccak_preimages`), NOT
    /// to the currently-executing call frame, matching geth's
    /// `t.keccakPreimages` living on `erc7562Tracer` itself rather than on
    /// `callFrameWithOpcodes`. Task 2's scaffold already declared
    /// `keccak_preimages` as this top-level field, resolving in advance the
    /// scoping question the original task brief raised: preimages are
    /// shared across every frame of one frame transaction (not reset per
    /// call frame), so the `keccak(A||x)+n` associated-storage
    /// pattern-match a downstream consumer performs works regardless of
    /// which frame actually computed the hash.
    pub fn on_keccak(&mut self, preimage: Vec<u8>) {
        if !self.active {
            return;
        }
        self.keccak_preimages.insert(preimage);
    }

    /// Read-only accessor for the tracer-scoped `keccak_preimages` set.
    /// Needed because the field itself is private, matching the convention
    /// used throughout this struct (`call_stack`, `current_frame_index`,
    /// `last_opcode`, `last_ext_access` are all private bookkeeping); callers
    /// outside this module (including tests) reach it only through this
    /// accessor.
    pub fn keccak_preimages(&self) -> &std::collections::HashSet<Vec<u8>> {
        &self.keccak_preimages
    }
}
