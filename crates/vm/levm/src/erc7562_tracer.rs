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
        if let Some(err) = &error
            && (err.contains("out of gas") || err.contains("insufficient gas"))
        {
            frame.out_of_gas = true;
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
