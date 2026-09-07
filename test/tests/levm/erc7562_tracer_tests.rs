//! Tests for the native ERC-7562/EIP-8141 validation-diagnostics tracer
//! (`Erc7562FrameTracer`). Extended by later tasks as the tracer gains
//! per-opcode instrumentation; these tests pin the `disabled()` construction
//! shape and the `begin_frame`/`enter`/`exit` push/pop-and-nest control flow
//! wired into `execute_frame_tx`'s frame loop.

use ethrex_common::{Address, H256};
use ethrex_levm::erc7562_tracer::Erc7562FrameTracer;
use ethrex_levm::errors::{ExceptionalHalt, VMError};

#[test]
fn a_disabled_tracer_has_no_frames() {
    let tracer = Erc7562FrameTracer::disabled();
    assert!(!tracer.active);
    assert!(tracer.frames.is_empty());
}

/// [fix round] Regression for a bug the final whole-plan review's fix round
/// itself introduced: once CALL/CREATE-family opcode handlers call
/// `enter`/`exit` unconditionally (needed so nested calls within a real frame
/// get their own scope -- see `nested_enter_nests_into_parent_call`), an
/// ORDINARY (non-frame) transaction's top-level CALL now also opens and
/// closes a root-level scope, with NO preceding `begin_frame` call (only
/// `execute_frame_tx`'s loop, which never runs for a non-frame transaction,
/// calls `begin_frame`). Before this fix, that root scope's `exit` would
/// still push a `FrameEntry` (tagged with the type's default `frame_index`),
/// producing spurious tracer output for a transaction that has no frames at
/// all -- contradicting `trace_call_erc7562`'s and `debug_traceCall`'s
/// documented "always empty for a non-frame call" behavior. An active tracer
/// used exactly like this (an `enter`/`exit` pair with no `begin_frame` ever
/// called) must produce zero `FrameEntry`s.
#[test]
fn a_call_scope_with_no_begin_frame_produces_no_frame_entry() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.exit(500, Vec::new(), None).unwrap();
    assert!(tracer.frames.is_empty());
}

#[test]
fn two_frames_produce_two_frame_entries() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.exit(500, Vec::new(), None).unwrap();
    tracer.begin_frame(1);
    tracer.enter(Address::zero(), Address::from_low_u64_be(2), &[], 2000);
    tracer.exit(1500, Vec::new(), None).unwrap();
    assert_eq!(tracer.frames.len(), 2);
    assert_eq!(tracer.frames[0].frame_index, 0);
    assert_eq!(tracer.frames[1].frame_index, 1);
    assert_eq!(tracer.frames[0].root.to, Some(Address::from_low_u64_be(1)));
    assert_eq!(tracer.frames[1].root.to, Some(Address::from_low_u64_be(2)));
}

#[test]
fn nested_enter_nests_into_parent_call() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.enter(
        Address::from_low_u64_be(1),
        Address::from_low_u64_be(2),
        &[],
        400,
    );
    tracer.exit(200, Vec::new(), None).unwrap();
    tracer.exit(500, Vec::new(), None).unwrap();
    assert_eq!(tracer.frames.len(), 1);
    assert_eq!(tracer.frames[0].root.calls.len(), 1);
    assert_eq!(
        tracer.frames[0].root.calls[0].to,
        Some(Address::from_low_u64_be(2))
    );
}

/// Regression test for a reported bug: the first version of this check did
/// `err.contains("out of gas")` (lowercase), but every real call site in
/// `vm.rs` passes `format!("{e}")` on a `VMError`/`ExceptionalHalt` — and
/// `ExceptionalHalt::OutOfGas`'s actual `Display` impl renders as `"Out Of
/// Gas"` (title case), which never matched. This test formats the *real*
/// error type exactly as `vm.rs`'s frame loop does
/// (`frame_failure = Some(format!("{e}"))`), rather than a hand-typed
/// literal, so it would have caught that bug.
#[test]
fn exit_with_real_out_of_gas_error_sets_out_of_gas_flag() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let err = format!("{}", VMError::ExceptionalHalt(ExceptionalHalt::OutOfGas));
    // Sanity-check the premise the whole test rests on: the real Display
    // output is title-cased, not the lowercase literal the old test used.
    assert_eq!(err, "Out Of Gas");
    tracer.exit(1000, Vec::new(), Some(err)).unwrap();
    assert!(tracer.frames[0].root.out_of_gas);
}

/// A failure unrelated to gas must not set `out_of_gas`, guarding against an
/// overly broad fix (e.g. `error.is_some()` alone).
#[test]
fn exit_with_unrelated_error_does_not_set_out_of_gas_flag() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let err = format!(
        "{}",
        VMError::ExceptionalHalt(ExceptionalHalt::StackOverflow)
    );
    tracer.exit(1000, Vec::new(), Some(err)).unwrap();
    assert!(!tracer.frames[0].root.out_of_gas);
}

/// The tracer's own synthetic, hand-written failure strings (used at the
/// UTXO / atomic-batch-skip / entry-access-cost call sites in `vm.rs`, which
/// have no underlying `VMError` to format) must also be matched
/// case-insensitively, and independently of the real-`VMError` path above.
#[test]
fn exit_with_lowercase_insufficient_gas_literal_sets_out_of_gas_flag() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer
        .exit(
            0,
            Vec::new(),
            Some("insufficient gas for frame entry access charge".to_string()),
        )
        .unwrap();
    assert!(tracer.frames[0].root.out_of_gas);
}

// --- `on_opcode` / used-opcode counting -------------------------------

/// Mirrors geth's `defaultIgnoredOpcodes()`: SLOAD (not on the ignore list)
/// is counted; ADD (one of the 16 named arithmetic/comparison opcodes on the
/// list) is not.
#[test]
fn on_opcode_counts_non_ignored_opcodes() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_opcode(0x54); // SLOAD
    tracer.on_opcode(0x54); // SLOAD again
    tracer.on_opcode(0x01); // ADD -- ignored, per default filter
    tracer.exit(500, Vec::new(), None).unwrap();
    let used = &tracer.frames[0].root.used_opcodes;
    assert_eq!(used.get(&0x54), Some(&2));
    assert_eq!(used.get(&0x01), None);
}

/// The `PUSHx`/`DUPx`/`SWAPx` range (`PUSH0..=SWAP16`, 0x5F..=0x9F) is
/// ignored at both its endpoints, not just somewhere in the middle.
#[test]
fn on_opcode_ignores_push_dup_swap_range_endpoints() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_opcode(0x5F); // PUSH0
    tracer.on_opcode(0x9F); // SWAP16
    tracer.exit(500, Vec::new(), None).unwrap();
    let used = &tracer.frames[0].root.used_opcodes;
    assert_eq!(used.get(&0x5F), None);
    assert_eq!(used.get(&0x9F), None);
}

/// [OP-012] Retroactive GAS accounting, geth's `handleGasObserved`: a `GAS`
/// immediately followed by a CALL-family opcode (`CALL`/`CALLCODE`/
/// `DELEGATECALL`/`STATICCALL`) is the idiomatic "forward remaining gas to
/// the callee" pattern and must NOT be counted.
#[test]
fn on_opcode_gas_followed_by_call_is_not_counted() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_opcode(0x5A); // GAS
    tracer.on_opcode(0xF1); // CALL
    tracer.exit(500, Vec::new(), None).unwrap();
    let used = &tracer.frames[0].root.used_opcodes;
    assert_eq!(used.get(&0x5A), None);
}

/// A `GAS` NOT immediately followed by a CALL-family opcode is a bare/
/// standalone gas read and must be counted -- one opcode later than every
/// other counted opcode, since the count only happens once the FOLLOWING
/// opcode is observed.
#[test]
fn on_opcode_gas_followed_by_non_call_is_counted() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_opcode(0x5A); // GAS
    tracer.on_opcode(0x01); // ADD -- not a call, so the preceding GAS counts
    tracer.exit(500, Vec::new(), None).unwrap();
    let used = &tracer.frames[0].root.used_opcodes;
    assert_eq!(used.get(&0x5A), Some(&1));
    // ADD itself is still ignored.
    assert_eq!(used.get(&0x01), None);
}

/// All four CALL-family opcodes suppress the preceding GAS, not just `CALL`
/// -- pins geth's exact `isCall()` set (`CALL`/`CALLCODE`/`DELEGATECALL`/
/// `STATICCALL`), which notably excludes `CREATE`/`CREATE2`.
#[test]
fn on_opcode_gas_suppressed_before_every_call_family_opcode() {
    for call_opcode in [0xF1u8, 0xF2, 0xF4, 0xFA] {
        let mut tracer = Erc7562FrameTracer::new();
        tracer.begin_frame(0);
        tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
        tracer.on_opcode(0x5A); // GAS
        tracer.on_opcode(call_opcode);
        tracer.exit(500, Vec::new(), None).unwrap();
        let used = &tracer.frames[0].root.used_opcodes;
        assert_eq!(
            used.get(&0x5A),
            None,
            "GAS before call-family opcode {call_opcode:#x} must not be counted"
        );
    }
}

/// `CREATE`/`CREATE2` are NOT part of geth's `isCall()` set, so a `GAS`
/// immediately before either one is a standalone read (counted), not a
/// gas-forwarding pattern.
#[test]
fn on_opcode_gas_before_create_is_counted() {
    for create_opcode in [0xF0u8, 0xF5] {
        let mut tracer = Erc7562FrameTracer::new();
        tracer.begin_frame(0);
        tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
        tracer.on_opcode(0x5A); // GAS
        tracer.on_opcode(create_opcode); // CREATE / CREATE2
        tracer.exit(500, Vec::new(), None).unwrap();
        let used = &tracer.frames[0].root.used_opcodes;
        assert_eq!(
            used.get(&0x5A),
            Some(&1),
            "GAS before {create_opcode:#x} (not a call-family opcode) must be counted"
        );
    }
}

/// A `GAS` that is the LAST opcode of a frame (no following opcode observed)
/// is never counted -- the retroactive rule only fires when a subsequent
/// opcode confirms it wasn't a gas-forwarding call, and no such opcode ever
/// arrives.
#[test]
fn on_opcode_trailing_gas_with_no_following_opcode_is_not_counted() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_opcode(0x5A); // GAS, then the frame ends
    tracer.exit(500, Vec::new(), None).unwrap();
    let used = &tracer.frames[0].root.used_opcodes;
    assert_eq!(used.get(&0x5A), None);
}

/// [OP-012, fix round] Real geth divergence found in review: `RETURN`/
/// `REVERT` ALSO suppress the retroactive `GAS` count, via a code path
/// separate from `isCall()` -- geth's `OnOpcode` runs `handleReturnRevert`
/// (which nils `t.lastOpWithStack` whenever the CURRENT opcode is `RETURN`/
/// `REVERT`) BEFORE the `if t.lastOpWithStack != nil { handleGasObserved(...) }`
/// guard, so a `GAS` immediately preceding either opcode is never counted --
/// the same net effect as preceding a call-family opcode, just reached
/// differently. `is_call_family` alone does not cover this since `RETURN`/
/// `REVERT` are not part of `isCall()`.
#[test]
fn on_opcode_gas_followed_by_return_is_not_counted() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_opcode(0x5A); // GAS
    tracer.on_opcode(0xF3); // RETURN
    tracer.exit(500, Vec::new(), None).unwrap();
    let used = &tracer.frames[0].root.used_opcodes;
    assert_eq!(used.get(&0x5A), None);
}

/// Same as above, for `REVERT` (0xFD) rather than `RETURN`.
#[test]
fn on_opcode_gas_followed_by_revert_is_not_counted() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_opcode(0x5A); // GAS
    tracer.on_opcode(0xFD); // REVERT
    tracer.exit(500, Vec::new(), None).unwrap();
    let used = &tracer.frames[0].root.used_opcodes;
    assert_eq!(used.get(&0x5A), None);
}

/// Pins every opcode byte literal hardcoded in `erc7562_tracer.rs`'s
/// `is_ignored_opcode`/`is_call_family`/`suppresses_gas_lookback` filters
/// against the canonical `Opcode` enum discriminant, mirroring the existing
/// `validation_observer_opcode_byte_pins` pattern in `eip8141_tests.rs`
/// (which guards `check_validation_banned_opcode`'s literals the same way).
/// Without this, a future change to `Opcode`'s discriminants could silently
/// desync `on_opcode`'s filtering with no test failure.
#[test]
fn erc7562_tracer_opcode_byte_pins() {
    use ethrex_levm::opcodes::Opcode;
    // Ignore-list range boundaries (PUSH0..=SWAP16 covers every PUSHx/DUPx/SWAPx).
    assert_eq!(u8::from(Opcode::PUSH0), 0x5F);
    assert_eq!(u8::from(Opcode::SWAP16), 0x9F);
    // Ignore-list named opcodes.
    assert_eq!(u8::from(Opcode::POP), 0x50);
    assert_eq!(u8::from(Opcode::ADD), 0x01);
    assert_eq!(u8::from(Opcode::SUB), 0x03);
    assert_eq!(u8::from(Opcode::MUL), 0x02);
    assert_eq!(u8::from(Opcode::DIV), 0x04);
    assert_eq!(u8::from(Opcode::EQ), 0x14);
    assert_eq!(u8::from(Opcode::LT), 0x10);
    assert_eq!(u8::from(Opcode::GT), 0x11);
    assert_eq!(u8::from(Opcode::SLT), 0x12);
    assert_eq!(u8::from(Opcode::SGT), 0x13);
    assert_eq!(u8::from(Opcode::SHL), 0x1B);
    assert_eq!(u8::from(Opcode::SHR), 0x1C);
    assert_eq!(u8::from(Opcode::AND), 0x16);
    assert_eq!(u8::from(Opcode::OR), 0x17);
    assert_eq!(u8::from(Opcode::NOT), 0x19);
    assert_eq!(u8::from(Opcode::ISZERO), 0x15);
    // GAS itself (excluded from the ignore list; handled retroactively).
    assert_eq!(u8::from(Opcode::GAS), 0x5A);
    // CALL-family (suppresses retroactive GAS count).
    assert_eq!(u8::from(Opcode::CALL), 0xF1);
    assert_eq!(u8::from(Opcode::CALLCODE), 0xF2);
    assert_eq!(u8::from(Opcode::DELEGATECALL), 0xF4);
    assert_eq!(u8::from(Opcode::STATICCALL), 0xFA);
    // RETURN/REVERT (also suppress retroactive GAS count).
    assert_eq!(u8::from(Opcode::RETURN), 0xF3);
    assert_eq!(u8::from(Opcode::REVERT), 0xFD);
}

/// Optional but cheap: exercises all 16 named ignore-list opcodes
/// individually (Step 1's sketch and `on_opcode_counts_non_ignored_opcodes`
/// only covered `ADD`), rather than relying solely on the byte-pin test and
/// manual audit for the other 15.
#[test]
fn on_opcode_ignores_all_16_named_arithmetic_comparison_opcodes() {
    const IGNORED_NAMED_OPCODES: [u8; 16] = [
        0x50, // POP
        0x01, // ADD
        0x03, // SUB
        0x02, // MUL
        0x04, // DIV
        0x14, // EQ
        0x10, // LT
        0x11, // GT
        0x12, // SLT
        0x13, // SGT
        0x1B, // SHL
        0x1C, // SHR
        0x16, // AND
        0x17, // OR
        0x19, // NOT
        0x15, // ISZERO
    ];
    for opcode in IGNORED_NAMED_OPCODES {
        let mut tracer = Erc7562FrameTracer::new();
        tracer.begin_frame(0);
        tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
        tracer.on_opcode(opcode);
        tracer.exit(500, Vec::new(), None).unwrap();
        let used = &tracer.frames[0].root.used_opcodes;
        assert_eq!(
            used.get(&opcode),
            None,
            "opcode {opcode:#x} should be on the default ignore list"
        );
    }
}

// Opcode byte literals used by the tests below, pinned against
// `crate::opcodes::Opcode`/geth's `vm.OpCode` (see
// `erc7562_tracer_opcode_byte_pins` above for the pattern this mirrors).
const SLOAD: u8 = 0x54;
const SSTORE: u8 = 0x55;
const TLOAD: u8 = 0x5C;
const TSTORE: u8 = 0x5D;

/// Step 2's own test: the first `SLOAD` of a slot records its pre-existing
/// value; a second `SLOAD` of the SAME slot must not overwrite it, mirroring
/// geth's `handleStorageAccess`'s `!rOk && !wOk` first-touch guard.
#[test]
fn first_sload_records_original_value_second_does_not_overwrite() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let slot = H256::from_low_u64_be(7);
    tracer.on_storage_access(SLOAD, slot, Address::from_low_u64_be(1), || {
        H256::from_low_u64_be(100)
    });
    tracer.on_storage_access(SLOAD, slot, Address::from_low_u64_be(1), || {
        H256::from_low_u64_be(999) // should be ignored
    });
    tracer.exit(500, Vec::new(), None).unwrap();
    let reads = &tracer.frames[0].root.accessed_slots.reads;
    assert_eq!(reads.get(&slot), Some(&vec![H256::from_low_u64_be(100)]));
}

/// The first-touch guard checks BOTH `reads` and `writes`, not just `reads`:
/// an `SSTORE` before any `SLOAD` must ALSO block the value-recording branch,
/// so a slot written-then-read never gets a stale post-write value recorded
/// as if it were the pre-existing one.
#[test]
fn sload_after_sstore_does_not_record_original_value() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let slot = H256::from_low_u64_be(7);
    let addr = Address::from_low_u64_be(1);
    tracer.on_storage_access(SSTORE, slot, addr, H256::zero);
    tracer.on_storage_access(SLOAD, slot, addr, || H256::from_low_u64_be(999));
    tracer.exit(500, Vec::new(), None).unwrap();
    let accessed = &tracer.frames[0].root.accessed_slots;
    assert!(
        !accessed.reads.contains_key(&slot),
        "the guard must check `writes` too, not just `reads`"
    );
    assert_eq!(accessed.writes.get(&slot), Some(&1));
}

/// `SSTORE` never stores a value -- only a write COUNTER that increments on
/// every touch, unlike `SLOAD`'s "first touch only" value recording.
#[test]
fn sstore_increments_write_counter_every_touch() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let slot = H256::from_low_u64_be(3);
    let addr = Address::from_low_u64_be(1);
    tracer.on_storage_access(SSTORE, slot, addr, H256::zero);
    tracer.on_storage_access(SSTORE, slot, addr, H256::zero);
    tracer.on_storage_access(SSTORE, slot, addr, H256::zero);
    tracer.exit(500, Vec::new(), None).unwrap();
    let accessed = &tracer.frames[0].root.accessed_slots;
    assert_eq!(accessed.writes.get(&slot), Some(&3));
    assert!(accessed.reads.is_empty());
}

/// `TLOAD` has no "first touch" guard at all (unlike `SLOAD`): every touch
/// increments `transient_reads`, and no value is ever recorded.
#[test]
fn tload_increments_transient_read_counter_every_touch_no_guard() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let slot = H256::from_low_u64_be(9);
    let addr = Address::from_low_u64_be(1);
    tracer.on_storage_access(TLOAD, slot, addr, || H256::from_low_u64_be(111));
    tracer.on_storage_access(TLOAD, slot, addr, || H256::from_low_u64_be(222));
    tracer.exit(500, Vec::new(), None).unwrap();
    let accessed = &tracer.frames[0].root.accessed_slots;
    assert_eq!(accessed.transient_reads.get(&slot), Some(&2));
    assert!(accessed.reads.is_empty(), "TLOAD must not touch `reads`");
}

/// `TSTORE` has no "first touch" guard either: every touch increments
/// `transient_writes`.
#[test]
fn tstore_increments_transient_write_counter_every_touch_no_guard() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let slot = H256::from_low_u64_be(11);
    let addr = Address::from_low_u64_be(1);
    tracer.on_storage_access(TSTORE, slot, addr, H256::zero);
    tracer.on_storage_access(TSTORE, slot, addr, H256::zero);
    tracer.on_storage_access(TSTORE, slot, addr, H256::zero);
    tracer.exit(500, Vec::new(), None).unwrap();
    let accessed = &tracer.frames[0].root.accessed_slots;
    assert_eq!(accessed.transient_writes.get(&slot), Some(&3));
    assert!(
        accessed.writes.is_empty(),
        "TSTORE must not touch the persistent `writes` counter"
    );
}

/// All four opcodes maintain independent counters/maps even when touching
/// the identical slot number: persistent storage (`reads`/`writes`) and
/// transient storage (`transient_reads`/`transient_writes`) never interfere.
#[test]
fn storage_and_transient_accesses_use_independent_counters() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let slot = H256::from_low_u64_be(42);
    let addr = Address::from_low_u64_be(1);
    tracer.on_storage_access(SLOAD, slot, addr, || H256::from_low_u64_be(1));
    tracer.on_storage_access(SSTORE, slot, addr, H256::zero);
    tracer.on_storage_access(TLOAD, slot, addr, H256::zero);
    tracer.on_storage_access(TSTORE, slot, addr, H256::zero);
    tracer.exit(500, Vec::new(), None).unwrap();
    let accessed = &tracer.frames[0].root.accessed_slots;
    assert_eq!(accessed.reads.get(&slot), Some(&vec![H256::from_low_u64_be(1)]));
    assert_eq!(accessed.writes.get(&slot), Some(&1));
    assert_eq!(accessed.transient_reads.get(&slot), Some(&1));
    assert_eq!(accessed.transient_writes.get(&slot), Some(&1));
}

/// A disabled tracer's `on_storage_access` is a complete no-op, matching
/// every other `active`-gated method on `Erc7562FrameTracer`.
#[test]
fn on_storage_access_is_a_noop_when_disabled() {
    let mut tracer = Erc7562FrameTracer::disabled();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let slot = H256::from_low_u64_be(1);
    let addr = Address::from_low_u64_be(1);
    tracer.on_storage_access(SLOAD, slot, addr, || H256::from_low_u64_be(1));
    tracer.on_storage_access(SSTORE, slot, addr, H256::zero);
    tracer.on_storage_access(TLOAD, slot, addr, H256::zero);
    tracer.on_storage_access(TSTORE, slot, addr, H256::zero);
    assert!(tracer.frames.is_empty());
}

// --- `on_ext_opcode` / EXTCODE access lookback ------------------------
//
// IMPORTANT: `on_ext_opcode` is NOT an immediate record. It mirrors geth's
// `handleExtOpcodes`, which is itself a ONE-INSTRUCTION LOOKBACK over
// `t.lastOpWithStack`: an EXTCODESIZE/EXTCODEHASH/EXTCODECOPY's target
// address is only actually pushed into `ext_code_access_info` once the
// FOLLOWING opcode is observed via `on_opcode` -- by which point the
// decision of whether to suppress it (the EXTCODESIZE-then-ISZERO
// "check code exists" idiom, ERC-7562's [OP-051] exemption) can be made.
// These tests always call `on_ext_opcode` immediately followed by
// `on_opcode(next)` to simulate the real dispatch sequence
// (`vm.rs::run_dispatch` calls `on_opcode` for every instruction; the
// EXT* opcode's own handler calls `on_ext_opcode` from within that same
// instruction's `eval()`, timing-equivalent to geth's own pre-execution
// capture), NOT a direct, standalone call taking an address argument with
// no following opcode.

const EXTCODESIZE: u8 = 0x3B;
const EXTCODECOPY: u8 = 0x3C;
const EXTCODEHASH: u8 = 0x3F;
const ISZERO: u8 = 0x15;
const ADD: u8 = 0x01;

/// [OP-051] `EXTCODESIZE` immediately followed by `ISZERO` -- the standard
/// "check code exists" idiom -- must NOT record the target address. This is
/// the corrected version of the brief's own Step 1 sketch: rather than a
/// direct `on_ext_opcode(0x3b, target)` call read back synchronously, the
/// suppression only takes effect once the FOLLOWING opcode (`ISZERO`) is
/// observed via `on_opcode`.
#[test]
fn extcodesize_immediately_followed_by_iszero_is_not_recorded() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let target = Address::from_low_u64_be(42);
    tracer.on_opcode(EXTCODESIZE); // dispatch loop's per-instruction hook
    tracer.on_ext_opcode(EXTCODESIZE, target); // handler captures its own target
    tracer.on_opcode(ISZERO); // lookback fires here: EXTCODESIZE + ISZERO -> suppressed
    tracer.exit(500, Vec::new(), None).unwrap();
    assert!(tracer.frames[0].root.ext_code_access_info.is_empty());
}

/// The exact same EXTCODESIZE capture, but followed by any OTHER opcode
/// (not ISZERO), must record the address -- the suppression is narrowly
/// scoped to the EXTCODESIZE-then-ISZERO pair specifically.
#[test]
fn extcodesize_followed_by_non_iszero_is_recorded() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let target = Address::from_low_u64_be(42);
    tracer.on_opcode(EXTCODESIZE);
    tracer.on_ext_opcode(EXTCODESIZE, target);
    tracer.on_opcode(ADD); // not ISZERO -- no suppression
    tracer.exit(500, Vec::new(), None).unwrap();
    assert_eq!(tracer.frames[0].root.ext_code_access_info, vec![target]);
}

/// `EXTCODEHASH` has no ISZERO-suppression idiom at all (only EXTCODESIZE
/// does) -- it is recorded on the very next opcode observed, regardless of
/// what that opcode is.
#[test]
fn extcodehash_is_recorded() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let target = Address::from_low_u64_be(42);
    tracer.on_opcode(EXTCODEHASH);
    tracer.on_ext_opcode(EXTCODEHASH, target);
    tracer.on_opcode(ISZERO); // even ISZERO -- suppression is EXTCODESIZE-specific
    tracer.exit(500, Vec::new(), None).unwrap();
    assert_eq!(tracer.frames[0].root.ext_code_access_info, vec![target]);
}

/// [fix round] Real geth divergence found in the final whole-plan review, same
/// class as `on_opcode_gas_followed_by_return_is_not_counted`: `RETURN`/
/// `REVERT` suppress a pending EXTCODE-access lookback too, via the same
/// `handleReturnRevert`-before-`handleExtOpcodes` ordering geth applies to the
/// GAS lookback. `suppresses_ext_lookback` covers this in `on_opcode`, but
/// (unlike the GAS case) had shipped with no direct regression test.
#[test]
fn extcodehash_followed_by_return_is_not_recorded() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let target = Address::from_low_u64_be(42);
    tracer.on_opcode(EXTCODEHASH);
    tracer.on_ext_opcode(EXTCODEHASH, target);
    tracer.on_opcode(0xF3); // RETURN -- suppresses the pending EXTCODEHASH capture
    tracer.exit(500, Vec::new(), None).unwrap();
    assert!(tracer.frames[0].root.ext_code_access_info.is_empty());
}

/// Same as above, for `REVERT` (0xFD) rather than `RETURN`.
#[test]
fn extcodehash_followed_by_revert_is_not_recorded() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let target = Address::from_low_u64_be(42);
    tracer.on_opcode(EXTCODEHASH);
    tracer.on_ext_opcode(EXTCODEHASH, target);
    tracer.on_opcode(0xFD); // REVERT -- suppresses the pending EXTCODEHASH capture
    tracer.exit(500, Vec::new(), None).unwrap();
    assert!(tracer.frames[0].root.ext_code_access_info.is_empty());
}

/// `EXTCODECOPY` behaves like `EXTCODEHASH`: no suppression idiom, recorded
/// on the next opcode regardless.
#[test]
fn extcodecopy_is_recorded() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let target = Address::from_low_u64_be(42);
    tracer.on_opcode(EXTCODECOPY);
    tracer.on_ext_opcode(EXTCODECOPY, target);
    tracer.on_opcode(ADD);
    tracer.exit(500, Vec::new(), None).unwrap();
    assert_eq!(tracer.frames[0].root.ext_code_access_info, vec![target]);
}

/// An EXT* capture with NO following opcode observed before the frame ends
/// is never recorded -- the lookback only fires once a subsequent
/// `on_opcode` call examines it, and none ever arrives. Mirrors
/// `on_opcode_trailing_gas_with_no_following_opcode_is_not_counted`'s
/// identical structure for the GAS lookback.
#[test]
fn trailing_ext_opcode_with_no_following_opcode_is_not_recorded() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let target = Address::from_low_u64_be(42);
    tracer.on_opcode(EXTCODEHASH);
    tracer.on_ext_opcode(EXTCODEHASH, target); // frame ends before any next on_opcode
    tracer.exit(500, Vec::new(), None).unwrap();
    assert!(tracer.frames[0].root.ext_code_access_info.is_empty());
}

/// A capture is consumed exactly once: a THIRD opcode after the
/// EXTCODESIZE/ISZERO pair must not re-trigger (or re-suppress) anything,
/// since `last_ext_access` is cleared (`take()`n) the moment it is examined.
#[test]
fn ext_access_capture_is_consumed_only_once() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let first = Address::from_low_u64_be(1);
    let second = Address::from_low_u64_be(2);
    tracer.on_opcode(EXTCODEHASH);
    tracer.on_ext_opcode(EXTCODEHASH, first);
    tracer.on_opcode(ADD); // consumes `first`'s capture -> recorded
    tracer.on_opcode(EXTCODESIZE);
    tracer.on_ext_opcode(EXTCODESIZE, second);
    tracer.on_opcode(ISZERO); // consumes `second`'s capture -> suppressed
    tracer.on_opcode(ADD); // no pending capture left -- must be a no-op
    tracer.exit(500, Vec::new(), None).unwrap();
    assert_eq!(tracer.frames[0].root.ext_code_access_info, vec![first]);
}

/// A disabled tracer's `on_ext_opcode` is a complete no-op.
#[test]
fn on_ext_opcode_is_a_noop_when_disabled() {
    let mut tracer = Erc7562FrameTracer::disabled();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_opcode(EXTCODESIZE);
    tracer.on_ext_opcode(EXTCODESIZE, Address::from_low_u64_be(42));
    tracer.on_opcode(ADD);
    assert!(tracer.frames.is_empty());
}

// --- `on_contract_size_access` -----------------------------------------
//
// Unlike `on_ext_opcode` above, this one is an IMMEDIATE check against the
// CURRENT opcode's own target address -- no lookback involved.

const CALL: u8 = 0xF1;

/// First access to an address records its code size and the triggering
/// opcode.
#[test]
fn contract_size_recorded_on_first_access() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let target = Address::from_low_u64_be(7);
    tracer.on_contract_size_access(EXTCODESIZE, target, || 123);
    tracer.exit(500, Vec::new(), None).unwrap();
    let sizes = &tracer.frames[0].root.contract_size;
    let entry = sizes.get(&target).expect("size must be recorded");
    assert_eq!(entry.contract_size, 123);
    assert_eq!(entry.opcode, EXTCODESIZE);
}

/// A SECOND access to the SAME address (even via a different opcode, and
/// even with a different reported size) must not overwrite the first
/// recording -- mirrors geth's "only record on first access" semantics.
#[test]
fn contract_size_second_access_does_not_overwrite() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let target = Address::from_low_u64_be(7);
    tracer.on_contract_size_access(EXTCODESIZE, target, || 123);
    tracer.on_contract_size_access(CALL, target, || 999);
    tracer.exit(500, Vec::new(), None).unwrap();
    let sizes = &tracer.frames[0].root.contract_size;
    let entry = sizes.get(&target).expect("size must be recorded");
    assert_eq!(entry.contract_size, 123);
    assert_eq!(entry.opcode, EXTCODESIZE);
}

/// The `code_len_fn` closure is only ever invoked on the first-access
/// branch (mirrors `on_storage_access`'s identical `FnOnce`-laziness
/// guarantee for `original_value_fn`): a second access's closure must never
/// run, even if it would panic.
#[test]
fn contract_size_closure_not_invoked_on_repeat_access() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let target = Address::from_low_u64_be(7);
    tracer.on_contract_size_access(EXTCODESIZE, target, || 123);
    tracer.on_contract_size_access(CALL, target, || panic!("must not be called"));
    tracer.exit(500, Vec::new(), None).unwrap();
    assert_eq!(
        tracer.frames[0].root.contract_size.get(&target).unwrap().contract_size,
        123
    );
}

/// Different addresses get independent entries.
#[test]
fn contract_size_tracks_multiple_addresses_independently() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    let a = Address::from_low_u64_be(1);
    let b = Address::from_low_u64_be(2);
    tracer.on_contract_size_access(EXTCODESIZE, a, || 10);
    tracer.on_contract_size_access(CALL, b, || 20);
    tracer.exit(500, Vec::new(), None).unwrap();
    let sizes = &tracer.frames[0].root.contract_size;
    assert_eq!(sizes.get(&a).unwrap().contract_size, 10);
    assert_eq!(sizes.get(&b).unwrap().contract_size, 20);
}

/// A disabled tracer's `on_contract_size_access` is a complete no-op.
#[test]
fn on_contract_size_access_is_a_noop_when_disabled() {
    let mut tracer = Erc7562FrameTracer::disabled();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_contract_size_access(EXTCODESIZE, Address::from_low_u64_be(7), || {
        panic!("must not be called when disabled")
    });
    assert!(tracer.frames.is_empty());
}

// --- `on_keccak` ---------------------------------------------------------
//
// Scoped to the WHOLE `Erc7562FrameTracer` (matching geth's
// `t.keccakPreimages` living on `erc7562Tracer` itself), not per call frame
// or per frame-transaction frame -- exposed via the `keccak_preimages()`
// accessor rather than a per-`FrameEntry` field.

/// A single `KECCAK256` call's preimage is recorded in the tracer-scoped set.
#[test]
fn keccak_preimage_is_recorded() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_keccak(b"hello".to_vec());
    tracer.exit(500, Vec::new(), None).unwrap();
    assert!(tracer.keccak_preimages().contains(&b"hello".to_vec()));
}

/// No length filtering of any kind -- an empty preimage is still recorded
/// (mirrors geth's `storeKeccak`, which never filters by length).
#[test]
fn keccak_empty_preimage_is_recorded() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_keccak(Vec::new());
    tracer.exit(500, Vec::new(), None).unwrap();
    assert!(tracer.keccak_preimages().contains(&Vec::<u8>::new()));
}

/// Preimages computed across DIFFERENT call frames of the SAME frame
/// transaction all land in the one shared, tracer-scoped set -- matching
/// geth's design intent that `keccak(A||x)+n` pattern-matching must work
/// regardless of which frame computed the hash.
#[test]
fn keccak_preimages_are_shared_across_call_frames() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_keccak(b"outer".to_vec());
    tracer.enter(
        Address::from_low_u64_be(1),
        Address::from_low_u64_be(2),
        &[],
        400,
    );
    tracer.on_keccak(b"inner".to_vec());
    tracer.exit(200, Vec::new(), None).unwrap();
    tracer.exit(500, Vec::new(), None).unwrap();
    let preimages = tracer.keccak_preimages();
    assert!(preimages.contains(&b"outer".to_vec()));
    assert!(preimages.contains(&b"inner".to_vec()));
}

/// Preimages persist across separate frame-transaction frames too (not just
/// nested call frames within one), consistent with the field being scoped
/// to the whole `Erc7562FrameTracer`, not reset by `begin_frame`.
#[test]
fn keccak_preimages_persist_across_frame_transaction_frames() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer.on_keccak(b"frame-zero".to_vec());
    tracer.exit(500, Vec::new(), None).unwrap();
    tracer.begin_frame(1);
    tracer.enter(Address::zero(), Address::from_low_u64_be(2), &[], 1000);
    tracer.on_keccak(b"frame-one".to_vec());
    tracer.exit(500, Vec::new(), None).unwrap();
    let preimages = tracer.keccak_preimages();
    assert!(preimages.contains(&b"frame-zero".to_vec()));
    assert!(preimages.contains(&b"frame-one".to_vec()));
}

/// A disabled tracer's `on_keccak` is a complete no-op.
#[test]
fn on_keccak_is_a_noop_when_disabled() {
    let mut tracer = Erc7562FrameTracer::disabled();
    tracer.on_keccak(b"hello".to_vec());
    assert!(tracer.keccak_preimages().is_empty());
}
