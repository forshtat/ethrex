//! Tests for the native ERC-7562/EIP-8141 validation-diagnostics tracer
//! (`Erc7562FrameTracer`). Extended by later tasks as the tracer gains
//! per-opcode instrumentation; these tests pin the `disabled()` construction
//! shape and the `begin_frame`/`enter`/`exit` push/pop-and-nest control flow
//! wired into `execute_frame_tx`'s frame loop.

use ethrex_common::Address;
use ethrex_levm::erc7562_tracer::Erc7562FrameTracer;

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

#[test]
fn exit_with_out_of_gas_error_sets_out_of_gas_flag() {
    let mut tracer = Erc7562FrameTracer::new();
    tracer.begin_frame(0);
    tracer.enter(Address::zero(), Address::from_low_u64_be(1), &[], 1000);
    tracer
        .exit(1000, Vec::new(), Some("out of gas".to_string()))
        .unwrap();
    assert!(tracer.frames[0].root.out_of_gas);
}
