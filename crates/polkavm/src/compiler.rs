use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use polkavm_assembler::{Assembler, Label};
use polkavm_common::error::{ExecutionError, Trap};
use polkavm_common::init::GuestProgramInit;
use polkavm_common::program::{InstructionVisitor, ProgramExport, RawInstruction};
use polkavm_common::zygote::{
    AddressTable, VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH, VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH,
};
use polkavm_common::abi::VM_CODE_ADDRESS_ALIGNMENT;

use crate::api::{BackendAccess, EngineState, ExecutionConfig, Module, OnHostcall, SandboxExt};
use crate::error::{bail, Error};

use crate::sandbox::{Sandbox, SandboxProgram, SandboxProgramInit, ExecuteArgs};
use crate::config::{GasMeteringKind, ModuleConfig, SandboxKind};

#[cfg(target_arch = "x86_64")]
mod amd64;

struct Compiler<'a> {
    asm: Assembler,
    exports: &'a [ProgramExport<'a>],
    instructions: &'a [RawInstruction],
    basic_block_by_jump_table_index: &'a [u32],
    jump_table_index_by_basic_block: &'a HashMap<u32, u32>,
    gas_cost_for_basic_block: &'a [u32],
    nth_basic_block_to_label: Vec<Label>,
    nth_basic_block_to_label_pending: Vec<Option<Label>>,
    pending_label_count: usize,
    jump_table: Vec<u8>,
    export_to_label: HashMap<u32, Label>,
    export_trampolines: Vec<u64>,
    debug_trace_execution: bool,
    ecall_label: Label,
    trap_label: Label,
    trace_label: Label,
    jump_table_label: Label,
    sandbox_kind: SandboxKind,
    gas_metering: Option<GasMeteringKind>,
    native_code_address: u64,
    address_table: AddressTable,
    vmctx_regs_offset: usize,
    vmctx_gas_offset: usize,
    is_last_instruction: bool,
}

struct CompilationResult<'a> {
    code: &'a [u8],
    jump_table: &'a [u8],
    export_trampolines: &'a [u64],
    sysreturn_address: u64,
    nth_instruction_to_code_offset_map: Vec<u32>,
}

impl<'a> Compiler<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: &ModuleConfig,
        instructions: &'a [RawInstruction],
        exports: &'a [ProgramExport<'a>],
        basic_block_by_jump_table_index: &'a [u32],
        jump_table_index_by_basic_block: &'a HashMap<u32, u32>,
        gas_cost_for_basic_block: &'a [u32],
        sandbox_kind: SandboxKind,
        address_table: AddressTable,
        vmctx_regs_offset: usize,
        vmctx_gas_offset: usize,
        debug_trace_execution: bool,
        native_code_address: u64,
        jump_count: usize,
        basic_block_count: usize,
    ) -> Self {
        let mut asm = Assembler::new();
        let ecall_label = asm.forward_declare_label();
        let trap_label = asm.forward_declare_label();
        let trace_label = asm.forward_declare_label();
        let jump_table_label = asm.forward_declare_label();

        let mut nth_basic_block_to_label = Vec::new();
        nth_basic_block_to_label.reserve(basic_block_count);

        let mut nth_basic_block_to_label_pending = Vec::new();
        nth_basic_block_to_label_pending.resize(basic_block_count, None);

        asm.reserve_code(instructions.len() * 16);
        asm.reserve_labels(basic_block_count * 2);
        asm.reserve_fixups(jump_count * 2);

        Compiler {
            asm,
            instructions,
            exports,
            basic_block_by_jump_table_index,
            jump_table_index_by_basic_block,
            gas_cost_for_basic_block,
            nth_basic_block_to_label,
            nth_basic_block_to_label_pending,
            pending_label_count: 0,
            jump_table: Default::default(),
            export_to_label: Default::default(),
            export_trampolines: Default::default(),
            ecall_label,
            trap_label,
            trace_label,
            jump_table_label,
            sandbox_kind,
            gas_metering: config.gas_metering,
            native_code_address,
            debug_trace_execution,
            address_table,
            vmctx_regs_offset,
            vmctx_gas_offset,
            is_last_instruction: false,
        }
    }

    fn finalize(&mut self) -> Result<CompilationResult, Error> {
        assert_eq!(self.asm.len(), 0);
        self.asm.set_origin(self.native_code_address);

        let mut nth_instruction_to_code_offset_map: Vec<u32> = Vec::with_capacity(self.instructions.len() + 1);
        polkavm_common::static_assert!(polkavm_common::zygote::VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE < u32::MAX);

        self.start_new_basic_block();

        for nth_instruction in 0..self.instructions.len() {
            let initial_length = self.asm.len();
            nth_instruction_to_code_offset_map.push(initial_length as u32);

            let instruction = self.instructions[nth_instruction];
            log::trace!("Compiling {}/{}: {}", nth_instruction, self.instructions.len() - 1, instruction);

            if self.debug_trace_execution {
                self.trace_execution(nth_instruction);
            }

            self.is_last_instruction = nth_instruction + 1 == self.instructions.len();
            instruction.visit(self);

            if !self.debug_trace_execution {
                let instruction_length = self.asm.len() - initial_length;
                assert!(
                    instruction_length <= VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH as usize,
                    "maximum instruction length of {} exceeded with {} bytes for instruction: {}",
                    VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH,
                    instruction_length,
                    instruction
                );
            }
        }

        let epilogue_start = self.asm.len();
        nth_instruction_to_code_offset_map.push(epilogue_start as u32);

        log::trace!("Emitting trampolines");

        // If the code abruptly ends make sure we trap.
        self.trap();

        if self.debug_trace_execution {
            self.emit_trace_trampoline();
        }

        self.emit_trap_trampoline();
        self.emit_ecall_trampoline();
        self.emit_export_trampolines();

        let label_sysreturn = self.emit_sysreturn();

        if self.pending_label_count > 0 {
            bail!("program is missing {} jump target(s)", self.pending_label_count);
        }

        let native_pointer_size = core::mem::size_of::<usize>();
        let jump_table_entry_size = native_pointer_size * VM_CODE_ADDRESS_ALIGNMENT as usize;
        self.jump_table.resize(self.basic_block_by_jump_table_index.len() * jump_table_entry_size, 0);

        // The very first entry is always invalid.
        assert_eq!(self.basic_block_by_jump_table_index[0], u32::MAX);

        for (jump_table_index, nth_basic_block) in self.basic_block_by_jump_table_index.iter().copied().enumerate().skip(1) {
            let label = self.nth_basic_block_to_label[nth_basic_block as usize];
            let offset = jump_table_index * jump_table_entry_size;
            let range = offset..offset + native_pointer_size;
            let address = self.native_code_address
                .checked_add_signed(self.asm.get_label_origin_offset_or_panic(label) as i64)
                .expect("overflow");

            log::trace!("Jump table: [0x{:x}] = 0x{:x}", self.native_code_address + range.start as u64, address);
            self.jump_table[range].copy_from_slice(&address.to_ne_bytes());
        }

        self.export_trampolines.reserve(self.exports.len());
        for export in self.exports {
            let label = self.export_to_label.get(&export.address()).unwrap();
            let native_address = self.native_code_address
                .checked_add_signed(self.asm.get_label_origin_offset_or_panic(*label) as i64)
                .expect("overflow");
            self.export_trampolines.push(native_address);
        }

        let epilogue_length = self.asm.len() - epilogue_start;
        assert!(
            epilogue_length <= VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH as usize,
            "maximum epilogue length of {} exceeded with {} bytes",
            VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH,
            epilogue_length
        );

        let sysreturn_address = self.native_code_address
            .checked_add_signed(self.asm.get_label_origin_offset_or_panic(label_sysreturn) as i64)
            .expect("overflow");

        match self.sandbox_kind {
            SandboxKind::Linux => {},
            SandboxKind::Generic => {
                let native_page_size = crate::sandbox::get_native_page_size();
                let padded_length = polkavm_common::utils::align_to_next_page_usize(native_page_size, self.asm.len()).unwrap();
                self.asm.resize(padded_length, Self::PADDING_BYTE);
                self.asm.define_label(self.jump_table_label);
            }
        }

        let code = self.asm.finalize();
        Ok(CompilationResult {
            code,
            jump_table: &self.jump_table,
            export_trampolines: &self.export_trampolines,
            sysreturn_address,
            nth_instruction_to_code_offset_map,
        })
    }

    #[inline(always)]
    fn push<T>(&mut self, inst: polkavm_assembler::Instruction<T>) where T: core::fmt::Display {
        self.asm.push(inst);
    }

    fn get_or_forward_declare_label(&mut self, nth_basic_block: u32) -> Label {
        match self.nth_basic_block_to_label.get(nth_basic_block as usize) {
            Some(label) => *label,
            None => match self.nth_basic_block_to_label_pending[nth_basic_block as usize] {
                Some(label) => label,
                None => {
                    let label = self.asm.forward_declare_label();
                    self.nth_basic_block_to_label_pending[nth_basic_block as usize] = Some(label);
                    self.pending_label_count += 1;
                    label
                }
            },
        }
    }

    fn define_label(&mut self, label: Label) {
        log::trace!("Label: {}", label);
        self.asm.define_label(label);
    }

    fn next_basic_block(&self) -> u32 {
        self.nth_basic_block_to_label.len() as u32
    }

    fn start_new_basic_block(&mut self) {
        if self.is_last_instruction {
            return;
        }

        let nth_basic_block = self.nth_basic_block_to_label.len();
        log::trace!("Starting new basic block: @{nth_basic_block:x}");

        let label = if let Some(label) = self.nth_basic_block_to_label_pending[nth_basic_block].take() {
            self.pending_label_count -= 1;
            label
        } else {
            self.asm.forward_declare_label()
        };

        self.define_label(label);
        self.nth_basic_block_to_label.push(label);

        if let Some(gas_metering) = self.gas_metering {
            let cost = self.gas_cost_for_basic_block[nth_basic_block];
            if cost > 0 {
                self.emit_gas_metering(gas_metering, cost);
            }
        }
    }
}

pub(crate) struct CompiledModule<S> where S: Sandbox {
    sandbox_program: S::Program,
    export_trampolines: Vec<u64>,
    nth_instruction_to_code_offset_map: Vec<u32>,
}

impl<S> CompiledModule<S> where S: Sandbox {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &ModuleConfig,
        instructions: &[RawInstruction],
        exports: &[ProgramExport],
        basic_block_by_jump_table_index: &[u32],
        jump_table_index_by_basic_block: &HashMap<u32, u32>,
        gas_cost_for_basic_block: &[u32],
        init: GuestProgramInit,
        debug_trace_execution: bool,
        jump_count: usize,
        basic_block_count: usize,
    ) -> Result<Self, Error> {
        crate::sandbox::assert_native_page_size();

        let address_space = S::reserve_address_space().map_err(Error::from_display)?;
        let native_code_address = crate::sandbox::SandboxAddressSpace::native_code_address(&address_space);
        let mut program_assembler = Compiler::new(
            config,
            instructions,
            exports,
            basic_block_by_jump_table_index,
            jump_table_index_by_basic_block,
            gas_cost_for_basic_block,
            S::KIND,
            S::address_table(),
            S::vmctx_regs_offset(),
            S::vmctx_gas_offset(),
            debug_trace_execution,
            native_code_address,
            jump_count,
            basic_block_count,
        );

        let result = program_assembler.finalize()?;
        let init = SandboxProgramInit::new(init)
            .with_code(result.code)
            .with_jump_table(result.jump_table)
            .with_sysreturn_address(result.sysreturn_address);

        let sandbox_program = S::prepare_program(init, address_space, config.gas_metering).map_err(Error::from_display)?;
        let export_trampolines = result.export_trampolines.to_owned();

        Ok(CompiledModule {
            sandbox_program,
            export_trampolines,
            nth_instruction_to_code_offset_map: result.nth_instruction_to_code_offset_map,
        })
    }

    pub fn machine_code(&self) -> Cow<[u8]> {
        self.sandbox_program.machine_code()
    }

    pub fn nth_instruction_to_code_offset_map(&self) -> &[u32] {
        &self.nth_instruction_to_code_offset_map
    }
}

pub(crate) struct CompiledInstance<S> where S: SandboxExt {
    engine_state: Arc<EngineState>,
    module: Module,
    sandbox: Option<S>,
}

impl<S> CompiledInstance<S> where S: SandboxExt {
    pub fn new(engine_state: Arc<EngineState>, module: Module) -> Result<CompiledInstance<S>, Error> {
        let mut args = ExecuteArgs::new();
        args.set_program(&S::as_compiled_module(&module).sandbox_program);

        let mut sandbox = S::reuse_or_spawn_sandbox(&engine_state, &module)?;
        sandbox
            .execute(args)
            .map_err(Error::from_display)
            .map_err(|error| error.context("instantiation failed: failed to upload the program into the sandbox"))?;

        Ok(CompiledInstance { engine_state, module, sandbox: Some(sandbox) })
    }

    pub fn call(&mut self, export_index: usize, on_hostcall: OnHostcall, config: &ExecutionConfig) -> Result<(), ExecutionError<Error>> {
        let address = S::as_compiled_module(&self.module).export_trampolines[export_index];
        let mut exec_args = ExecuteArgs::<S>::new();

        if config.reset_memory_after_execution {
            exec_args.set_reset_memory_after_execution();
        }

        if config.clear_program_after_execution {
            exec_args.set_clear_program_after_execution();
        }

        exec_args.set_call(address);
        exec_args.set_initial_regs(&config.initial_regs);
        if self.module.gas_metering().is_some() {
            if let Some(gas) = config.gas {
                exec_args.set_gas(gas);
            }
        }

        fn wrap_on_hostcall<S>(on_hostcall: OnHostcall<'_>) -> impl for <'r> FnMut(u32, S::Access<'r>) -> Result<(), Trap> + '_ where S: Sandbox {
            move |hostcall, access| {
                let access: BackendAccess = access.into();
                on_hostcall(hostcall, access)
            }
        }

        let mut on_hostcall = wrap_on_hostcall(on_hostcall);
        exec_args.set_on_hostcall(&mut on_hostcall);

        let sandbox = self.sandbox.as_mut().unwrap();
        let result = match sandbox.execute(exec_args) {
            Ok(()) => Ok(()),
            Err(ExecutionError::Trap(trap)) => Err(ExecutionError::Trap(trap)),
            Err(ExecutionError::Error(error)) => return Err(ExecutionError::Error(Error::from_display(error))),
            Err(ExecutionError::OutOfGas) => return Err(ExecutionError::OutOfGas),
        };

        if self.module.gas_metering().is_some() && sandbox.gas_remaining_impl().is_err() {
            return Err(ExecutionError::OutOfGas);
        }

        result
    }

    pub fn access(&'_ mut self) -> S::Access<'_> {
        self.sandbox.as_mut().unwrap().access()
    }

    pub fn sandbox(&self) -> &S {
        self.sandbox.as_ref().unwrap()
    }
}

impl<S> Drop for CompiledInstance<S> where S: SandboxExt {
    fn drop(&mut self) {
        S::recycle_sandbox(&self.engine_state, || {
            let mut sandbox = self.sandbox.take()?;
            let mut exec_args = ExecuteArgs::<S>::new();
            exec_args.set_clear_program_after_execution();
            exec_args.set_gas(polkavm_common::utils::Gas::MIN);
            exec_args.set_async(true);
            if let Err(error) = sandbox.execute(exec_args) {
                log::warn!("Failed to cache a sandbox worker process due to an error: {error}");
                None
            } else {
                Some(sandbox)
            }
        })
    }
}
