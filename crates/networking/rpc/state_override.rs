//! A State Override Set for `ethrex_simulateFrameTransaction`: per-account
//! balance, nonce, code and storage laid over the head state for one call, so a
//! test harness can describe a world without staging it on chain. Shaped like
//! geth's `eth_call` override set; only `balance`, `nonce`, `code` and `state`
//! (whole-storage replacement) are supported.

use std::{collections::BTreeMap, sync::Arc};

use ethrex_blockchain::vm::StoreVmDatabase;
use ethrex_common::{
    Address, H256, U256,
    constants::{EMPTY_KECCAK_HASH, EMPTY_TRIE_HASH},
    types::{AccountState, ChainConfig, Code, CodeMetadata},
};
use ethrex_crypto::NativeCrypto;
use ethrex_vm::{EvmError, VmDatabase};
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountOverrideJson {
    pub balance: Option<U256>,
    pub nonce: Option<ethrex_common::U64>,
    pub code: Option<String>,
    pub state: Option<BTreeMap<H256, H256>>,
}

pub type StateOverrideJson = BTreeMap<Address, AccountOverrideJson>;

#[derive(Debug, Clone, Default)]
struct AccountOverride {
    balance: Option<U256>,
    nonce: Option<u64>,
    code: Option<Code>,
    storage: Option<BTreeMap<H256, U256>>,
}

/// Parsed override set, shared by the simulation passes of one request.
#[derive(Debug, Clone, Default)]
pub struct StateOverrides(Arc<BTreeMap<Address, AccountOverride>>);

impl StateOverrides {
    pub fn parse(set: StateOverrideJson) -> Result<Self, String> {
        let mut out = BTreeMap::new();
        for (address, account) in set {
            let code = match account.code {
                Some(code) => {
                    let bytes = hex::decode(code.trim_start_matches("0x"))
                        .map_err(|error| format!("code of {address:#x}: {error}"))?;
                    Some(Code::from_bytecode(bytes.into(), &NativeCrypto))
                }
                None => None,
            };
            out.insert(
                address,
                AccountOverride {
                    balance: account.balance,
                    nonce: account.nonce.map(|nonce| nonce.as_u64()),
                    code,
                    storage: account.state.map(|slots| {
                        slots
                            .into_iter()
                            .map(|(slot, value)| {
                                (slot, U256::from_big_endian(value.as_bytes()))
                            })
                            .collect()
                    }),
                },
            );
        }
        Ok(Self(Arc::new(out)))
    }
}

/// [`StoreVmDatabase`] with a [`StateOverrides`] set laid over it.
#[derive(Clone)]
pub struct OverlaidDatabase {
    pub inner: StoreVmDatabase,
    pub overrides: StateOverrides,
}

impl OverlaidDatabase {
    fn overridden_code(&self, code_hash: H256) -> Option<&Code> {
        self.overrides
            .0
            .values()
            .filter_map(|account| account.code.as_ref())
            .find(|code| code.hash == code_hash)
    }
}

impl VmDatabase for OverlaidDatabase {
    fn get_account_state(&self, address: Address) -> Result<Option<AccountState>, EvmError> {
        let base = self.inner.get_account_state(address)?;
        let Some(over) = self.overrides.0.get(&address) else {
            return Ok(base);
        };
        let mut state = base.unwrap_or_default();
        if let Some(balance) = over.balance {
            state.balance = balance;
        }
        if let Some(nonce) = over.nonce {
            state.nonce = nonce;
        }
        if let Some(code) = &over.code {
            state.code_hash = if code.is_empty() {
                *EMPTY_KECCAK_HASH
            } else {
                code.hash
            };
        }
        if let Some(storage) = &over.storage {
            // Only emptiness of the root is observable (CREATE collision checks);
            // slot reads are answered from the override below.
            state.storage_root = if storage.values().all(U256::is_zero) {
                *EMPTY_TRIE_HASH
            } else {
                H256::repeat_byte(0x01)
            };
        }
        Ok(Some(state))
    }

    fn get_storage_slot(&self, address: Address, key: H256) -> Result<Option<U256>, EvmError> {
        match self.overrides.0.get(&address).and_then(|o| o.storage.as_ref()) {
            Some(storage) => Ok(storage.get(&key).copied()),
            None => self.inner.get_storage_slot(address, key),
        }
    }

    fn get_block_hash(&self, block_number: u64) -> Result<H256, EvmError> {
        self.inner.get_block_hash(block_number)
    }

    fn get_chain_config(&self) -> Result<ChainConfig, EvmError> {
        self.inner.get_chain_config()
    }

    fn get_account_code(&self, code_hash: H256) -> Result<Code, EvmError> {
        match self.overridden_code(code_hash) {
            Some(code) => Ok(code.clone()),
            None => self.inner.get_account_code(code_hash),
        }
    }

    fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, EvmError> {
        match self.overridden_code(code_hash) {
            Some(code) => Ok(CodeMetadata {
                length: code.len() as u64,
            }),
            None => self.inner.get_code_metadata(code_hash),
        }
    }
}
