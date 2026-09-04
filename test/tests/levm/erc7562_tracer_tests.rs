//! Tests for the native ERC-7562/EIP-8141 validation-diagnostics tracer
//! (`Erc7562FrameTracer`). Extended by later tasks as the tracer gains
//! VM-wiring and per-opcode instrumentation; this initial test pins the
//! `disabled()` construction shape.

use ethrex_levm::erc7562_tracer::Erc7562FrameTracer;

#[test]
fn a_disabled_tracer_has_no_frames() {
    let tracer = Erc7562FrameTracer::disabled();
    assert!(!tracer.active);
    assert!(tracer.frames.is_empty());
}
