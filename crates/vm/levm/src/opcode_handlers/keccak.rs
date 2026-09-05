//! # Keccak256 operations
//!
//! Includes the following opcodes:
//!   - `KECCAK256`

use crate::{
    errors::{OpcodeResult, VMError},
    gas_cost,
    memory::calculate_memory_size,
    opcode_handlers::OpcodeHandler,
    utils::size_offset_to_usize,
    vm::VM,
};
use ethrex_common::{U256, utils::u256_from_big_endian};

/// `keccak256("")` as a `U256`. Returned directly for zero-length input so we
/// skip the permutation entirely; the result is a well-known constant
/// (matches what other clients do).
const EMPTY_KECCAK_U256: U256 = U256([
    0x7bfad8045d85a470,
    0xe500b653ca82273b,
    0x927e7db2dcc703c0,
    0xc5d2460186f7233c,
]);

pub struct OpKeccak256Handler;
impl OpcodeHandler for OpKeccak256Handler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [offset, len] = *vm.current_call_frame.stack.pop()?;
        let (len, offset) = size_offset_to_usize(len, offset)?;

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::keccak256(
                calculate_memory_size(offset, len)?,
                vm.current_call_frame.memory.len(),
                len,
            )?)?;

        // ERC-7562/EIP-8141 validation-diagnostics: record this call's raw
        // preimage bytes, mirroring geth's `storeKeccak` -- unconditional,
        // no length filtering. `with_range` already zero-pads reads past the
        // current memory length (matching geth's `GetMemoryCopyPadded`), so
        // no separate padding logic is needed here. A second, independent
        // `with_range` call (rather than reusing the hashing one below) keeps
        // this hook trivially separable from the hash computation and its
        // own borrow of `vm.crypto`.
        if vm.erc7562_tracer.active {
            let preimage = vm
                .current_call_frame
                .memory
                .with_range(offset, len, <[u8]>::to_vec)?;
            vm.erc7562_tracer.on_keccak(preimage);
        }

        // Hash the memory range in place — `with_range` lends a borrow to keccak256
        // instead of allocating a throwaway `Bytes` copy (KECCAK256 fires ~15x/tx).
        // Bind `crypto` first so the closure doesn't capture `vm` while `memory` is
        // borrowed mutably.
        let hash = if len == 0 {
            EMPTY_KECCAK_U256
        } else {
            let crypto = vm.crypto;
            u256_from_big_endian(&vm.current_call_frame.memory.with_range(
                offset,
                len,
                |bytes| crypto.keccak256(bytes),
            )?)
        };
        vm.current_call_frame.stack.push(hash)?;

        Ok(OpcodeResult::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::constants::EMPTY_KECCAK_HASH;
    use ethrex_crypto::{Crypto, NativeCrypto};

    #[test]
    fn empty_keccak_const_matches_hash() {
        let expected = u256_from_big_endian(&NativeCrypto.keccak256(&[]));
        assert_eq!(EMPTY_KECCAK_U256, expected);
    }

    #[test]
    fn empty_keccak_const_matches_common_constant() {
        // Guards against drift between this const and `EMPTY_KECCAK_HASH`
        // in `ethrex_common::constants`.
        assert_eq!(
            EMPTY_KECCAK_U256,
            u256_from_big_endian(EMPTY_KECCAK_HASH.as_bytes())
        );
    }
}
