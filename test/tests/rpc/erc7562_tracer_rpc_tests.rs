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

use std::{collections::BTreeMap, fs::File, io::BufReader, path::PathBuf};

use bytes::Bytes;
use ethrex_blockchain::payload::{BuildPayloadArgs, create_payload};
use ethrex_common::types::{
    DEFAULT_BUILDER_GAS_CEIL, ELASTICITY_MULTIPLIER, Frame, FrameMode, FrameTransaction, Genesis,
    GenesisAccount, Transaction,
};
use ethrex_common::{Address, H160, H256, U256};
use ethrex_crypto::NativeCrypto;
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

// ==================== debug_traceTransaction positive path (Important #7) ====================
//
// The test above only proves dispatch reaches the blockchain layer for an unknown
// hash. This section mines a REAL `Transaction::FrameTransaction` into a REAL block
// via the actual payload builder (`create_payload` + `Blockchain::build_payload_with_transactions`,
// the same machinery `test/tests/blockchain/eip7702_revert_authority_tests.rs` and
// `frame_blob_tx_tests.rs` use), so `debug_traceTransaction` looks up and re-executes
// an actually-mined frame transaction end to end.

/// `PUSH1 3 (APPROVE_EXECUTION_AND_PAYMENT); PUSH1 0; PUSH1 0; APPROVE; STOP`.
/// Lets a `self_verify` frame (`target == tx.sender`) approve both scopes itself,
/// so the transaction needs no outer `FrameSignature` at all.
fn approve_both_code() -> Bytes {
    Bytes::from(vec![0x60, 0x03, 0x60, 0x00, 0x60, 0x00, 0xAA, 0x00])
}

/// A Hegotá-active genesis whose only extra account is `sender`, funded and
/// seeded with [`approve_both_code`].
///
/// Built from the real `fixtures/genesis/execution-api.json` fixture (the same
/// one this file's own `context()` helper loads) rather than a hand-rolled
/// `ChainConfig`/`Genesis` literal: `Blockchain::add_block` below runs full
/// header validation, including `base_fee_per_gas` and the legacy
/// block-numbered forks/`terminal_total_difficulty` -- a minimal genesis
/// missing those (as several existing mempool-admission-only test fixtures in
/// this codebase are) builds a payload whose base fee mismatches what
/// `add_block` independently recomputes. The real fixture already carries
/// correct values for all of that; only `amsterdamTime`/`hegotaTime` (absent
/// from the fixture) need enabling, mirroring
/// `test/tests/blockchain/focil_tests.rs`'s own `config.hegota_time = Some(0)`
/// override of this same fixture.
async fn hegota_context_with_frame_sender(sender: Address) -> RpcApiContext {
    let file = File::open(workspace_root().join("fixtures/genesis/execution-api.json"))
        .expect("open genesis");
    let mut genesis: Genesis =
        serde_json::from_reader(BufReader::new(file)).expect("parse genesis");
    genesis.config.amsterdam_time = Some(0);
    genesis.config.hegota_time = Some(0);
    genesis.alloc.insert(
        sender,
        GenesisAccount {
            code: approve_both_code(),
            storage: BTreeMap::new(),
            balance: U256::from(10u64).pow(U256::from(20u64)),
            nonce: 0,
        },
    );

    let mut store =
        Store::new("erc7562-frame-trace-store", EngineType::InMemory).expect("build store");
    store
        .add_initial_state(genesis)
        .await
        .expect("genesis state");
    default_context_with_storage(store).await
}

/// A single `self_verify` VERIFY frame targeting `sender` (flags `0x03`, i.e.
/// `APPROVE_EXECUTION_AND_PAYMENT` permitted), so [`approve_both_code`] running in
/// it makes the whole transaction valid with no outer signature.
fn self_verify_frame_tx(chain_id: u64, sender: Address) -> FrameTransaction {
    FrameTransaction {
        chain_id,
        nonce_keys: vec![U256::zero()],
        nonce_seq: 0,
        sender,
        frames: vec![Frame {
            mode: u8::from(FrameMode::Verify),
            flags: 0x03,
            target: Some(sender),
            gas_limit: 100_000,
            state_limit: 0,
            value: U256::zero(),
            data: Bytes::new(),
        }],
        signatures: Vec::new(),
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 1_000_000_000,
        max_fee_per_blob_gas: U256::zero(),
        blob_versioned_hashes: Vec::new(),
        recent_root_references: Vec::new(),
        inner_hash: Default::default(),
        cached_canonical: Default::default(),
    }
}

/// Positive path for Important #7: mine a real frame transaction into a real
/// block, then trace it via `debug_traceTransaction` with
/// `"tracer": "erc7562FrameTracer"` and assert real, non-empty opcode-usage data
/// comes back -- unlike `debug_trace_call_accepts_erc7562_frame_tracer` above,
/// whose `GenericTransaction` can never be a frame transaction, an actually-mined
/// `Transaction::FrameTransaction` looked up by `debug_traceTransaction` DOES
/// produce real frames.
#[tokio::test]
async fn debug_trace_transaction_returns_a_real_trace_for_a_mined_frame_tx() {
    let sender = Address::from_low_u64_be(0xF00D_F00D);
    let context = hegota_context_with_frame_sender(sender).await;
    let chain_id = context.storage.get_chain_config().chain_id;

    let tx = Transaction::FrameTransaction(self_verify_frame_tx(chain_id, sender));
    let tx_hash = tx.hash(&NativeCrypto);

    let genesis_header = context
        .storage
        .get_block_header(0)
        .expect("read genesis header")
        .expect("genesis header must exist");
    let args = BuildPayloadArgs {
        parent: genesis_header.hash(),
        timestamp: genesis_header.timestamp + 12,
        fee_recipient: H160::zero(),
        random: H256::zero(),
        withdrawals: Some(Vec::new()),
        beacon_root: Some(H256::zero()),
        // Amsterdam+ (active in this genesis) requires a header slot number.
        slot_number: Some(1),
        version: 3,
        elasticity_multiplier: ELASTICITY_MULTIPLIER,
        gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
        inclusion_list_transactions: None,
    };
    let payload = create_payload(&args, &context.storage, Bytes::new()).expect("create payload");
    let build_result = context
        .blockchain
        .build_payload_with_transactions(payload, vec![tx])
        .expect("the self-verify frame transaction must build into a valid block");
    let block = build_result.payload;
    assert_eq!(
        block.body.transactions.len(),
        1,
        "the frame transaction must be included in the mined block"
    );

    let block_number = block.header.number;
    let block_hash = block.hash();
    context
        .blockchain
        .add_block(block)
        .expect("the built block must execute and validate");
    context
        .storage
        .forkchoice_update(vec![], block_number, block_hash, None, None)
        .await
        .expect("forkchoice update");

    let params = Some(vec![
        json!(format!("{tx_hash:#x}")),
        json!({ "tracer": "erc7562FrameTracer" }),
    ]);
    let result = TraceTransactionRequest::parse(&params)
        .expect("erc7562FrameTracer request must parse")
        .handle(context)
        .await
        .expect("tracing a real, mined frame transaction must succeed");

    assert_frame_entries_shape(&result);
    let entries = result
        .as_array()
        .expect("erc7562FrameTracer result must be a JSON array");
    assert!(
        !entries.is_empty(),
        "a mined self_verify frame tx must produce at least one FrameEntry, got {result}"
    );

    // Real opcode-usage data, proving this went through actual bytecode dispatch
    // rather than returning a shape-only stub.
    let root = entries[0]["root"]
        .as_object()
        .expect("entry must carry an object root");
    let used_opcodes = root
        .get("usedOpcodes")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("root must carry a usedOpcodes object: {root:?}"));
    assert!(
        !used_opcodes.is_empty(),
        "usedOpcodes must record real opcode usage from the mined frame's actual \
         execution, got {used_opcodes:?}"
    );
}
