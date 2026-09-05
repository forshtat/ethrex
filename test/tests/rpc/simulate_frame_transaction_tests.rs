use std::{collections::BTreeMap, fs::File, io::BufReader, path::PathBuf};

use bytes::Bytes;
use ethrex_common::types::{
    APPROVE_EXECUTION_AND_PAYMENT, ChainConfig, EIP1559Transaction, FRAME_SIG_SCHEME_SECP256K1,
    Frame, FrameMode, FrameSignature, FrameTransaction, Genesis, GenesisAccount, Transaction,
};
use ethrex_common::{Address, U256};
use ethrex_rpc::ethrex::SimulateFrameTransactionRequest;
use ethrex_rpc::rpc::{RpcApiContext, RpcHandler};
use ethrex_rpc::test_utils::default_context_with_storage;
use ethrex_rpc::utils::RpcErr;
use ethrex_storage::{EngineType, Store};
use serde_json::{Value, json};

/// Canonical (`type || payload`) hex, `0x`-prefixed, for a transaction.
fn raw_hex(tx: &Transaction) -> String {
    let mut buf = Vec::new();
    tx.encode_canonical(&mut buf);
    format!("0x{}", hex::encode(buf))
}

#[test]
fn parse_accepts_frame_tx_without_block() {
    let tx = Transaction::FrameTransaction(FrameTransaction::default());
    let params = Some(vec![json!(raw_hex(&tx))]);
    let parsed = SimulateFrameTransactionRequest::parse(&params).expect("frame tx accepted");
    assert!(matches!(
        parsed.transaction,
        Transaction::FrameTransaction(_)
    ));
    assert!(parsed.block.is_none());
}

#[test]
fn parse_accepts_optional_block_tag() {
    let tx = Transaction::FrameTransaction(FrameTransaction::default());
    let params = Some(vec![json!(raw_hex(&tx)), json!("latest")]);
    let parsed = SimulateFrameTransactionRequest::parse(&params).expect("frame tx accepted");
    assert!(parsed.block.is_some());
}

#[test]
fn parse_rejects_non_frame_tx() {
    let tx = Transaction::EIP1559Transaction(EIP1559Transaction::default());
    let params = Some(vec![json!(raw_hex(&tx))]);
    let err = SimulateFrameTransactionRequest::parse(&params).unwrap_err();
    assert!(matches!(err, RpcErr::BadParams(msg) if msg.contains("frame")));
}

#[test]
fn parse_rejects_missing_0x_prefix() {
    let params = Some(vec![json!("abcdef")]);
    let err = SimulateFrameTransactionRequest::parse(&params).unwrap_err();
    assert!(matches!(err, RpcErr::BadParams(_)));
}

#[test]
fn parse_rejects_empty_and_missing_params() {
    assert!(matches!(
        SimulateFrameTransactionRequest::parse(&Some(vec![])),
        Err(RpcErr::BadParams(_))
    ));
    assert!(matches!(
        SimulateFrameTransactionRequest::parse(&None),
        Err(RpcErr::BadParams(_))
    ));
}

#[test]
fn parse_rejects_too_many_params() {
    let tx = Transaction::FrameTransaction(FrameTransaction::default());
    let params = Some(vec![json!(raw_hex(&tx)), json!("latest"), json!("extra")]);
    assert!(matches!(
        SimulateFrameTransactionRequest::parse(&params),
        Err(RpcErr::BadParams(_))
    ));
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

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

fn sender() -> Address {
    Address::repeat_byte(0x11)
}

/// A frame tx whose prefix is one `SelfVerify` frame — the simplest of the four
/// admitted shapes — so anything reported invalid comes from the gate under test.
fn self_verify_tx() -> FrameTransaction {
    FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::zero()],
        nonce_seq: 0,
        sender: sender(),
        frames: vec![Frame {
            mode: FrameMode::Verify as u8,
            flags: APPROVE_EXECUTION_AND_PAYMENT,
            target: Some(sender()),
            gas_limit: 21_000,
            state_limit: 0,
            value: U256::zero(),
            data: Default::default(),
        }],
        signatures: vec![FrameSignature {
            scheme: FRAME_SIG_SCHEME_SECP256K1,
            signer: Some(sender()),
            msg: Default::default(),
            signature: Default::default(),
        }],
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 1_000,
        ..Default::default()
    }
}

async fn simulate(tx: FrameTransaction) -> serde_json::Value {
    let params = Some(vec![json!(raw_hex(&Transaction::FrameTransaction(tx)))]);
    SimulateFrameTransactionRequest::parse(&params)
        .expect("parse")
        .handle(context().await)
        .await
        .expect("handle")
}

#[tokio::test]
async fn simulate_rejects_nonce_keys_that_are_not_strictly_increasing() {
    // EIP-8250 static rule. Before the admission gates were wired in, a prefix
    // that simulated cleanly reported `valid: true` for a transaction the
    // mempool would refuse outright.
    let mut tx = self_verify_tx();
    tx.nonce_keys = vec![U256::from(5u64), U256::from(5u64)];

    let result = simulate(tx).await;

    assert_eq!(result["valid"], json!(false));
    let violation = result["violation"].as_str().expect("violation");
    assert!(
        violation.contains("nonce_keys"),
        "expected a nonce-key violation, got: {violation}"
    );
}

#[tokio::test]
async fn simulate_rejects_an_unauthenticated_sender() {
    // EIP-8141: `sender` is an unauthenticated field until the signature list
    // recovers to it. An empty SECP256K1 signature can never do that.
    let result = simulate(self_verify_tx()).await;

    assert_eq!(result["valid"], json!(false));
    let violation = result["violation"].as_str().expect("violation");
    assert!(
        violation.contains("signature"),
        "expected a signature violation, got: {violation}"
    );
}

// ---------------------------------------------------------------------------
// `trace: true` (opt-in Erc7562FrameTracer output) tests
//
// The tests above never reach the full-execution path (`execute_for_gas`):
// they are rejected earlier, by an unauthenticated signature or a structural
// gate, against the plain `execution-api.json` genesis (pre-Hegota). Exercising
// `trace: true` requires a transaction that actually EXECUTES, which requires
// Hegota to be active (`execute_frame_tx`'s `FrameTxPreFork` gate) and a
// sender whose code establishes a payer during the validation-prefix
// simulation -- so this section builds its own genesis, mirroring
// `mempool_tests.rs::setup_hegota_store`/`approve_code`/`minimal_valid_frame_tx`
// rather than the shared `execution-api.json` fixture `context()` uses above.
// ---------------------------------------------------------------------------

/// Sender for the Hegota-active fixtures below. Genesis seeds it with
/// `approve_execution_and_payment_code`, so its lone `self_verify` VERIFY
/// frame both authorizes execution and establishes itself as payer.
const HEGOTA_SENDER: Address = Address::repeat_byte(0x77);

/// `PUSH1 APPROVE_EXECUTION_AND_PAYMENT; PUSH1 0; PUSH1 0; APPROVE; STOP`.
/// Run in a VERIFY frame targeting the sender, this approves both execution
/// and payment, which is what the self_verify prefix simulation requires to
/// admit the transaction (mirrors `mempool_tests.rs::approve_code`).
fn approve_execution_and_payment_code() -> Bytes {
    Bytes::from(vec![
        0x60,
        APPROVE_EXECUTION_AND_PAYMENT,
        0x60,
        0x00,
        0x60,
        0x00,
        0xAA,
        0x00,
    ])
}

/// A fresh in-memory store whose genesis has Hegota active from block 0 (so a
/// frame transaction actually executes rather than hitting the `FrameTxPreFork`
/// gate) and seeds [`HEGOTA_SENDER`] with [`approve_execution_and_payment_code`].
async fn hegota_context() -> RpcApiContext {
    let genesis = Genesis {
        config: ChainConfig {
            chain_id: 0,
            shanghai_time: Some(0),
            amsterdam_time: Some(0),
            hegota_time: Some(0),
            ..Default::default()
        },
        gas_limit: 100_000_000,
        alloc: [(
            HEGOTA_SENDER,
            GenesisAccount {
                code: approve_execution_and_payment_code(),
                storage: BTreeMap::new(),
                balance: U256::zero(),
                nonce: 0,
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let mut store = Store::new("simulate-frame-tx-hegota-test", EngineType::InMemory)
        .expect("build store");
    store
        .add_initial_state(genesis)
        .await
        .expect("genesis state");
    default_context_with_storage(store).await
}

/// A single-frame `self_verify` transaction against [`HEGOTA_SENDER`] that fully
/// validates AND executes: zero fees (so the zero-balance sender needs no
/// funding) and an empty signature list, which `validate_frame_signatures`
/// authenticates vacuously (nothing to check against zero entries) -- the same
/// property `mempool_tests.rs::minimal_valid_frame_tx` relies on.
fn valid_self_verify_frame_tx() -> FrameTransaction {
    FrameTransaction {
        chain_id: 0,
        nonce_keys: vec![U256::zero()],
        nonce_seq: 0,
        sender: HEGOTA_SENDER,
        frames: vec![Frame {
            mode: FrameMode::Verify as u8,
            flags: APPROVE_EXECUTION_AND_PAYMENT,
            target: Some(HEGOTA_SENDER),
            // Below MAX_VERIFY_GAS (100_000): a VERIFY frame's gas_limit is charged
            // against the prefix's verify-gas budget, not just the per-tx cap.
            gas_limit: 50_000,
            state_limit: 0,
            value: U256::zero(),
            data: Bytes::new(),
        }],
        signatures: vec![],
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        ..Default::default()
    }
}

/// Runs `ethrex_simulateFrameTransaction` against `context`, with `latest` as
/// the explicit second param and `extra_param` (when present) as the third.
async fn simulate_in(
    context: RpcApiContext,
    tx: FrameTransaction,
    extra_param: Option<Value>,
) -> Value {
    let mut params = vec![
        json!(raw_hex(&Transaction::FrameTransaction(tx))),
        json!("latest"),
    ];
    if let Some(extra_param) = extra_param {
        params.push(extra_param);
    }
    SimulateFrameTransactionRequest::parse(&Some(params))
        .expect("parse")
        .handle(context)
        .await
        .expect("handle")
}

#[tokio::test]
async fn simulate_with_trace_true_returns_a_non_empty_erc7562_trace() {
    let result = simulate_in(
        hegota_context().await,
        valid_self_verify_frame_tx(),
        Some(json!({"trace": true})),
    )
    .await;

    assert_eq!(
        result["valid"], json!(true),
        "fixture must fully validate and execute for this test to be meaningful: {result}"
    );
    let trace = result["erc7562Trace"]
        .as_array()
        .unwrap_or_else(|| panic!("erc7562Trace must be a present, non-null array: {result}"));
    assert!(
        !trace.is_empty(),
        "a single-frame self_verify tx must produce at least one FrameEntry"
    );
    for entry in trace {
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

#[tokio::test]
async fn simulate_without_trace_reports_null_and_matches_trace_false() {
    // Omitting the third param entirely and passing an explicit `{"trace": false}`
    // must be indistinguishable -- both are "the pre-existing (untraced) behavior".
    let omitted = simulate_in(hegota_context().await, valid_self_verify_frame_tx(), None).await;
    let explicit_false = simulate_in(
        hegota_context().await,
        valid_self_verify_frame_tx(),
        Some(json!({"trace": false})),
    )
    .await;

    assert_eq!(
        omitted["valid"], json!(true),
        "fixture must fully validate and execute for this test to be meaningful: {omitted}"
    );
    assert_eq!(
        omitted["erc7562Trace"],
        Value::Null,
        "untraced execution must report erc7562Trace: null, got {omitted}"
    );
    assert_eq!(
        explicit_false, omitted,
        "{{\"trace\": false}} must be byte-for-byte identical to omitting the param"
    );
}

#[tokio::test]
async fn simulate_trace_true_changes_nothing_but_erc7562_trace() {
    let untraced = simulate_in(hegota_context().await, valid_self_verify_frame_tx(), None).await;
    let mut traced = simulate_in(
        hegota_context().await,
        valid_self_verify_frame_tx(),
        Some(json!({"trace": true})),
    )
    .await;

    assert!(
        traced["erc7562Trace"].is_array(),
        "trace:true must populate erc7562Trace: {traced}"
    );
    // Blank out the one field `trace: true` is allowed to change, then the two
    // results must be identical -- proving the new option is purely additive.
    traced["erc7562Trace"] = Value::Null;
    assert_eq!(
        traced, untraced,
        "trace:true must only add erc7562Trace, changing no other field"
    );
}

#[tokio::test]
async fn simulate_reports_max_cost_even_when_a_gate_rejects() {
    // `maxCost` is a pure function of the transaction fields, so a caller still
    // learns what the transaction would have cost.
    let mut tx = self_verify_tx();
    tx.nonce_keys = vec![];

    let result = simulate(tx).await;

    assert_eq!(result["valid"], json!(false));
    assert!(
        result["maxCost"]
            .as_str()
            .is_some_and(|c| c.starts_with("0x")),
        "maxCost must be reported on every path"
    );
}
