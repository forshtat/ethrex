//! # Environment operations
//!
//! Includes the following opcodes:
//!   - `ADDRESS`
//!   - `BALANCE`
//!   - `ORIGIN`
//!   - `GASPRICE`
//!   - `CALLER`
//!   - `CALLVALUE`
//!   - `CALLDATALOAD`
//!   - `CALLDATASIZE`
//!   - `CALLDATACOPY`
//!   - `CODESIZE`
//!   - `CODECOPY`
//!   - `EXTCODESIZE`
//!   - `EXTCODECOPY`
//!   - `EXTCODEHASH`
//!   - `RETURNDATASIZE`
//!   - `RETURNDATACOPY`

use crate::{
    errors::{ExceptionalHalt, OpcodeResult, VMError},
    gas_cost::{self},
    memory::calculate_memory_size,
    opcode_handlers::OpcodeHandler,
    opcodes::Opcode,
    utils::{size_offset_to_usize, u256_to_usize, word_to_address},
    vm::VM,
};
use ethrex_common::U256;
use std::mem;

/// Implementation for the `ADDRESS` opcode.
pub struct OpAddressHandler;
impl OpcodeHandler for OpAddressHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::ADDRESS)?;

        #[expect(unsafe_code, reason = "safe")]
        vm.current_call_frame.stack.push(U256(unsafe {
            let mut bytes: [u8; 32] = [0; 32];
            bytes[12..].copy_from_slice(&vm.current_call_frame.to.0);
            bytes.reverse();
            mem::transmute_copy::<[u8; 32], [u64; 4]>(&bytes)
        }))?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `BALANCE` opcode.
pub struct OpBalanceHandler;
impl OpcodeHandler for OpBalanceHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let address = word_to_address(vm.current_call_frame.stack.pop1()?);
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::balance(
                vm.substate.add_accessed_address(address),
                vm.env.config.fork,
            )?)?;

        // State access AFTER gas check passes
        let account_balance = vm.db.get_account(address)?.info.balance;

        // Record address touch for BAL (after gas check passes)
        if let Some(recorder) = vm.db.bal_recorder.as_mut() {
            recorder.record_touched_address(address);
        }

        vm.current_call_frame.stack.push(account_balance)?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `ORIGIN` opcode.
pub struct OpOriginHandler;
impl OpcodeHandler for OpOriginHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::ORIGIN)?;

        #[expect(unsafe_code, reason = "safe")]
        vm.current_call_frame.stack.push(U256(unsafe {
            let mut bytes: [u8; 32] = [0; 32];
            bytes[12..].copy_from_slice(&vm.env.origin.0);
            bytes.reverse();
            mem::transmute_copy::<[u8; 32], [u64; 4]>(&bytes)
        }))?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `GASPRICE` opcode.
pub struct OpGasPriceHandler;
impl OpcodeHandler for OpGasPriceHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::GASPRICE)?;

        vm.current_call_frame.stack.push(vm.env.gas_price)?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `CALLER` opcode.
pub struct OpCallerHandler;
impl OpcodeHandler for OpCallerHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::CALLER)?;

        #[expect(unsafe_code, reason = "safe")]
        vm.current_call_frame.stack.push(U256(unsafe {
            let mut bytes: [u8; 32] = [0; 32];
            bytes[12..].copy_from_slice(&vm.current_call_frame.msg_sender.0);
            bytes.reverse();
            mem::transmute_copy::<[u8; 32], [u64; 4]>(&bytes)
        }))?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `CALLVALUE` opcode.
pub struct OpCallValueHandler;
impl OpcodeHandler for OpCallValueHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::CALLVALUE)?;

        vm.current_call_frame
            .stack
            .push(vm.current_call_frame.msg_value)?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `CALLDATALOAD` opcode.
pub struct OpCallDataLoadHandler;
impl OpcodeHandler for OpCallDataLoadHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::CALLDATALOAD)?;

        let value_bytes = usize::try_from(vm.current_call_frame.stack.pop1()?)
            .ok()
            .and_then(|offset| vm.current_call_frame.calldata.get(offset..));
        #[expect(clippy::indexing_slicing, reason = "length is checked in match guard")]
        vm.current_call_frame.stack.push(match value_bytes {
            Some(data) if data.len() >= 32 => U256::from_big_endian(&data[..32]),
            Some(data) => {
                let mut bytes = [0; 32];
                bytes[..data.len()].copy_from_slice(data);
                U256::from_big_endian(&bytes)
            }
            None => U256::zero(),
        })?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `CALLDATASIZE` opcode.
pub struct OpCallDataSizeHandler;
impl OpcodeHandler for OpCallDataSizeHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::CALLDATASIZE)?;

        vm.current_call_frame
            .stack
            .push(U256::from(vm.current_call_frame.calldata.len()))?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `CALLDATACOPY` opcode.
pub struct OpCallDataCopyHandler;
impl OpcodeHandler for OpCallDataCopyHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [dst_offset, src_offset, len] = *vm.current_call_frame.stack.pop()?;
        let (len, dst_offset) = size_offset_to_usize(len, dst_offset)?;
        let src_offset = u256_to_usize(src_offset).unwrap_or(usize::MAX);

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::calldatacopy(
                calculate_memory_size(dst_offset, len)?,
                vm.current_call_frame.memory.len(),
                len,
            )?)?;

        if len > 0 {
            let data = vm
                .current_call_frame
                .calldata
                .get(src_offset..)
                .unwrap_or_default();
            let data = data.get(..len).unwrap_or(data);

            vm.current_call_frame.memory.store_data(dst_offset, data)?;
            if data.len() < len {
                #[expect(
                    clippy::arithmetic_side_effects,
                    reason = "data.len() < len guard ensures no underflow"
                )]
                vm.current_call_frame
                    .memory
                    .store_zeros(dst_offset + data.len(), len - data.len())?;
            }
        }

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `CODESIZE` opcode.
pub struct OpCodeSizeHandler;
impl OpcodeHandler for OpCodeSizeHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::CODESIZE)?;

        vm.current_call_frame
            .stack
            .push(vm.current_call_frame.bytecode.len().into())?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `CODECOPY` opcode.
pub struct OpCodeCopyHandler;
impl OpcodeHandler for OpCodeCopyHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [dst_offset, src_offset, len] = *vm.current_call_frame.stack.pop()?;
        let (len, dst_offset) = size_offset_to_usize(len, dst_offset)?;
        let src_offset = u256_to_usize(src_offset).unwrap_or(usize::MAX);

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::codecopy(
                calculate_memory_size(dst_offset, len)?,
                vm.current_call_frame.memory.len(),
                len,
            )?)?;

        if len > 0 {
            let data = vm
                .current_call_frame
                .bytecode
                .dispatch_buf()
                .get(src_offset..)
                .unwrap_or_default();
            let data = data.get(..len).unwrap_or(data);

            vm.current_call_frame.memory.store_data(dst_offset, data)?;
            if data.len() < len {
                #[expect(
                    clippy::arithmetic_side_effects,
                    reason = "data.len() < len guard ensures no underflow"
                )]
                vm.current_call_frame
                    .memory
                    .store_zeros(dst_offset + data.len(), len - data.len())?;
            }
        }

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `EXTCODESIZE` opcode.
pub struct OpExtCodeSizeHandler;
impl OpcodeHandler for OpExtCodeSizeHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let address = word_to_address(vm.current_call_frame.stack.pop1()?);
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::extcodesize(
                vm.substate.add_accessed_address(address),
                vm.env.config.fork,
            )?)?;

        // EIP-8141 mempool validation-trace: EXTCODESIZE target must exist and
        // not be EIP-7702-delegated (sender exempt).
        if vm.validation_observer.active {
            vm.validation_check_extcode_target(address)?;
        }

        // State access AFTER gas check passes (using optimized code length lookup)
        let account_code_length: usize = vm.db.get_code_length(address)?;

        // ERC-7562/EIP-8141 validation-diagnostics: capture the EXTCODESIZE
        // target for the one-instruction EXTCODE-access lookback (see
        // `on_ext_opcode`'s doc comment), and record the contract size at
        // first access -- reusing `account_code_length`, already computed
        // above for the opcode's own result, so this is a zero-cost reuse
        // rather than a second lookup.
        if vm.erc7562_tracer.active {
            vm.erc7562_tracer
                .on_ext_opcode(Opcode::EXTCODESIZE as u8, address);
            vm.erc7562_tracer.on_contract_size_access(
                Opcode::EXTCODESIZE as u8,
                address,
                || account_code_length,
            );
        }

        // Record address touch for BAL (after gas check passes)
        if let Some(recorder) = vm.db.bal_recorder.as_mut() {
            recorder.record_touched_address(address);
        }

        vm.current_call_frame.stack.push(account_code_length.into())?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `EXTCODECOPY` opcode.
pub struct OpExtCodeCopyHandler;
impl OpcodeHandler for OpExtCodeCopyHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [address, dst_offset, src_offset, len] = *vm.current_call_frame.stack.pop()?;
        let address = word_to_address(address);
        let (len, dst_offset) = size_offset_to_usize(len, dst_offset)?;
        let src_offset = u256_to_usize(src_offset).unwrap_or(usize::MAX);

        // ERC-7562/EIP-8141 validation-diagnostics: capture the EXTCODECOPY
        // target for the one-instruction EXTCODE-access lookback (see
        // `on_ext_opcode`'s doc comment).
        if vm.erc7562_tracer.active {
            vm.erc7562_tracer
                .on_ext_opcode(Opcode::EXTCODECOPY as u8, address);
        }

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::extcodecopy(
                len,
                calculate_memory_size(dst_offset, len)?,
                vm.current_call_frame.memory.len(),
                vm.substate.add_accessed_address(address),
                vm.env.config.fork,
            )?)?;

        // Record address touch for BAL (after gas check passes)
        if let Some(recorder) = vm.db.bal_recorder.as_mut() {
            recorder.record_touched_address(address);
        }

        // EIP-8141 mempool validation-trace: EXTCODECOPY target must exist and
        // not be EIP-7702-delegated (sender exempt).
        if vm.validation_observer.active {
            vm.validation_check_extcode_target(address)?;
        }

        // EELS reads the account's code unconditionally (even for size=0), so
        // fetch the code — not just the account — to keep the read observable
        // for execution witnesses (EIP-8025) and parallel-BAL access tracking.
        let code = vm.db.get_account_code(address)?;

        // ERC-7562/EIP-8141 validation-diagnostics: record the contract size
        // at first access, reusing the code just fetched above.
        if vm.erc7562_tracer.active {
            let code_len = code.code().len();
            vm.erc7562_tracer.on_contract_size_access(
                Opcode::EXTCODECOPY as u8,
                address,
                || code_len,
            );
        }

        if len > 0 {
            let data = code.dispatch_buf().get(src_offset..).unwrap_or_default();
            let data = data.get(..len).unwrap_or(data);

            vm.current_call_frame.memory.store_data(dst_offset, data)?;
            if data.len() < len {
                #[expect(
                    clippy::arithmetic_side_effects,
                    reason = "data.len() < len guard ensures no underflow"
                )]
                vm.current_call_frame
                    .memory
                    .store_zeros(dst_offset + data.len(), len - data.len())?;
            }
        }

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `EXTCODEHASH` opcode.
pub struct OpExtCodeHashHandler;
impl OpcodeHandler for OpExtCodeHashHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let address = word_to_address(vm.current_call_frame.stack.pop1()?);

        // ERC-7562/EIP-8141 validation-diagnostics: capture the EXTCODEHASH
        // target for the one-instruction EXTCODE-access lookback (see
        // `on_ext_opcode`'s doc comment).
        if vm.erc7562_tracer.active {
            vm.erc7562_tracer
                .on_ext_opcode(Opcode::EXTCODEHASH as u8, address);
        }

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::extcodehash(
                vm.substate.add_accessed_address(address),
                vm.env.config.fork,
            )?)?;

        // EIP-8141 mempool validation-trace: EXTCODEHASH target must exist and
        // not be EIP-7702-delegated (sender exempt).
        if vm.validation_observer.active {
            vm.validation_check_extcode_target(address)?;
        }

        let account = vm.db.get_account(address)?;
        let account_is_empty = account.is_empty();
        let account_code_hash = account.info.code_hash.0;

        // ERC-7562/EIP-8141 validation-diagnostics: record the contract size
        // at first access. Unlike EXTCODESIZE/EXTCODECOPY, this opcode
        // computes no code length of its own, so the lookup is done here
        // specifically for the tracer -- eagerly rather than lazily inside
        // `code_len_fn`, since `get_code_length` is fallible and this
        // method's closure signature is not; the extra lookup on a REPEAT
        // access is a minor, trace-mode-only cost.
        if vm.erc7562_tracer.active {
            let code_len = vm.db.get_code_length(address)?;
            vm.erc7562_tracer.on_contract_size_access(
                Opcode::EXTCODEHASH as u8,
                address,
                || code_len,
            );
        }

        // Record address touch for BAL (after gas check passes)
        if let Some(recorder) = vm.db.bal_recorder.as_mut() {
            recorder.record_touched_address(address);
        }

        if account_is_empty {
            vm.current_call_frame.stack.push_zero()?;
        } else {
            #[expect(unsafe_code, reason = "safe")]
            vm.current_call_frame.stack.push(U256(unsafe {
                let mut bytes = account_code_hash;
                bytes.reverse();
                mem::transmute_copy::<[u8; 32], [u64; 4]>(&bytes)
            }))?;
        }

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `RETURNDATASIZE` opcode.
pub struct OpReturnDataSizeHandler;
impl OpcodeHandler for OpReturnDataSizeHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        vm.current_call_frame
            .increase_consumed_gas(gas_cost::RETURNDATASIZE)?;

        vm.current_call_frame
            .stack
            .push(vm.current_call_frame.sub_return_data.len().into())?;

        Ok(OpcodeResult::Continue)
    }
}

/// Implementation for the `RETURNDATACOPY` opcode.
pub struct OpReturnDataCopyHandler;
impl OpcodeHandler for OpReturnDataCopyHandler {
    #[inline(always)]
    fn eval(vm: &mut VM<'_>) -> Result<OpcodeResult, VMError> {
        let [dst_offset, src_offset, len] = *vm.current_call_frame.stack.pop()?;
        let (len, dst_offset) = size_offset_to_usize(len, dst_offset)?;
        let src_offset = u256_to_usize(src_offset)?;

        vm.current_call_frame
            .increase_consumed_gas(gas_cost::returndatacopy(
                calculate_memory_size(dst_offset, len)?,
                vm.current_call_frame.memory.len(),
                len,
            )?)?;

        #[expect(
            clippy::arithmetic_side_effects,
            reason = "src_offset and len are validated by memory expansion"
        )]
        if src_offset + len > vm.current_call_frame.sub_return_data.len() {
            return Err(ExceptionalHalt::OutOfBounds.into());
        }

        if len > 0 {
            let data = vm
                .current_call_frame
                .sub_return_data
                .get(src_offset..)
                .unwrap_or_default();
            let data = data.get(..len).unwrap_or(data);

            vm.current_call_frame.memory.store_data(dst_offset, data)?;
            if data.len() < len {
                #[expect(
                    clippy::arithmetic_side_effects,
                    reason = "data.len() < len guard ensures no underflow"
                )]
                vm.current_call_frame
                    .memory
                    .store_zeros(dst_offset + data.len(), len - data.len())?;
            }
        }

        Ok(OpcodeResult::Continue)
    }
}
