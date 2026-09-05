//! Tests for the native ERC-7562/EIP-8141 validation-diagnostics tracer
//! (`Erc7562FrameTracer`). Extended by later tasks as the tracer gains
//! per-opcode instrumentation; these tests pin the `disabled()` construction
//! shape and the `begin_frame`/`enter`/`exit` push/pop-and-nest control flow
//! wired into `execute_frame_tx`'s frame loop.

use ethrex_common::Address;
use ethrex_levm::erc7562_tracer::Erc7562FrameTracer;
use ethrex_levm::errors::{ExceptionalHalt, VMError};

#[test]
fn a_disabled_tracer_has_no_frames() {
    let tracer = Erc7562FrameTracer::disabled();
    assert!(!tracer.active);
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
