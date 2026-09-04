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

use ethrex_common::{Address, H256};
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
}
