//! RPC-level tests for the native ERC-7562/EIP-8141 frame tracer exposed over
//! `debug_traceCall`/`debug_traceTransaction` as `"tracer": "erc7562FrameTracer"`
//! (deliberately not geth's `"erc7562Tracer"` -- see `TracerType::Erc7562FrameTracer`'s
//! doc comment in `crates/networking/rpc/tracing.rs`: this tracer's output is an array of
//! `{frameIndex, root}` entries, not geth's single call tree, so a distinct wire name
//! forces an explicit client opt-in instead of a silent shape mismatch).
//!
//! `debug_traceCall`'s fixture-construction (`call_object`) mirrors
//! `trace_call_tests.rs`'s existing helper rather than duplicating it; the genesis-backed
//! `RpcApiContext` setup mirrors `simulate_frame_transaction_tests.rs`'s `context()` helper.

use std::{fs::File, io::BufReader, path::PathBuf};

use ethrex_rpc::rpc::{RpcApiContext, RpcHandler};
use ethrex_rpc::test_utils::default_context_with_storage;
use ethrex_rpc::tracing::{TraceCallRequest, TraceTransactionRequest};
use ethrex_storage::{EngineType, Store};
use serde_json::{Value, json};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// A genesis-backed context, so `debug_traceCall`'s default `"latest"` block and
/// `debug_traceTransaction`'s storage lookups have real state to resolve against.
async fn context() -> RpcApiContext {
    let file = File::open(workspace_root().join("fixtures/genesis/execution-api.json"))
        .expect("open genesis");
    let genesis = serde_json::from_reader(BufReader::new(file)).expect("parse genesis");
    let mut store = Store::new("store.db", EngineType::InMemory).expect("build store");
    store
        .add_initial_state(genesis)
        .await
        .expect("genesis state");
    default_context_with_storage(store).await
}

/// A minimal but complete `GenericTransaction` object for `debug_traceCall`'s first
/// param, mirroring `trace_call_tests.rs::call_object` exactly.
fn call_object() -> Value {
    json!({
        "from": "0x1000000000000000000000000000000000000000",
        "to": "0xc000000000000000000000000000000000000000",
        "input": "0x",
        "maxFeePerBlobGas": null,
        "wrapperVersion": null,
    })
}

/// Every element of an `Erc7562FrameTracer` response array must carry exactly the
/// `{frameIndex, root: {...}}` shape (`FrameEntry`'s serde output).
fn assert_frame_entries_shape(result: &Value) {
    let entries = result
        .as_array()
        .expect("erc7562FrameTracer result must be a JSON array");
    for entry in entries {
        let obj = entry.as_object().expect("each entry must be an object");
        assert!(
            obj.contains_key("frameIndex"),
            "entry missing frameIndex: {entry}"
        );
        assert!(
            obj.get("root").is_some_and(Value::is_object),
            "entry missing object root: {entry}"
        );
    }
}

/// `debug_traceCall` must accept `"tracer": "erc7562FrameTracer"` (rather than reject it
/// as an unknown tracer name) and return the frame-tracer's array shape.
///
/// `GenericTransaction` (the `debug_traceCall` request shape) cannot express a frame
/// transaction's `frames` list -- the call below is converted to an ordinary
/// `EIP1559Transaction` before execution, which never opens any
/// `Erc7562FrameTracer` frame -- so the array is expected to come back empty. That is
/// still a meaningful, non-error result: it proves the tracer name is recognized and
/// wired all the way through to a real `Evm`/`GeneralizedDatabase`-backed execution,
/// not just accepted at parse time.
#[tokio::test]
async fn debug_trace_call_accepts_erc7562_frame_tracer() {
    let params = Some(vec![
        call_object(),
        Value::Null,
        json!({ "tracer": "erc7562FrameTracer" }),
    ]);
    let result = TraceCallRequest::parse(&params)
        .expect("erc7562FrameTracer request must parse")
        .handle(context().await)
        .await
        .expect("erc7562FrameTracer call must be handled without error");

    assert_frame_entries_shape(&result);
    assert_eq!(
        result,
        json!([]),
        "a GenericTransaction can never be a frame transaction today, so the frame \
         tracer must report no frames rather than error"
    );
}

/// `debug_traceTransaction` must also accept `"tracer": "erc7562FrameTracer"` and route
/// the request all the way to the blockchain-layer lookup (proven by getting the
/// expected "not Found" error for an unknown hash, rather than a parse-time "unknown
/// tracer variant" error) -- unlike `debug_traceCall`, a transaction that has actually
/// been mined as `Transaction::FrameTransaction` would produce real, non-empty frames
/// through this same path.
#[tokio::test]
async fn debug_trace_transaction_accepts_erc7562_frame_tracer() {
    let unknown_hash = json!(format!("0x{}", "11".repeat(32)));
    let params = Some(vec![
        unknown_hash,
        json!({ "tracer": "erc7562FrameTracer" }),
    ]);
    let err = TraceTransactionRequest::parse(&params)
        .expect("erc7562FrameTracer request must parse")
        .handle(context().await)
        .await
        .expect_err("an unknown tx hash must fail lookup, not tracer dispatch");

    let msg = err.to_string();
    assert!(
        msg.contains("not Found"),
        "expected a storage lookup error (proving the tracer name was accepted and \
         dispatch reached the blockchain layer), got: {msg}"
    );
}
