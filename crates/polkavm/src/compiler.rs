use std::borrow::Cow;
use std::collections::HashMap;

use polkavm_assembler::{Assembler, Label};
use polkavm_common::program::{ProgramExport, Instruction};
use polkavm_common::zygote::{
    AddressTable, VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH, VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH,
};
use polkavm_common::abi::VM_CODE_ADDRESS_ALIGNMENT;

use crate::api::VisitorWrapper;
use crate::error::{bail, Error};

use crate::sandbox::{Sandbox, SandboxProgram, SandboxInit};
use crate::config::{GasMeteringKind, ModuleConfig, SandboxKind};
use crate::utils::GuestInit;

#[cfg(target_arch = "x86_64")]
mod amd64;

pub(crate) struct Compiler<'a> {
    asm: Assembler,
    exports: &'a [ProgramExport<'a>],
    basic_block_by_jump_table_index: &'a [u32],
    jump_table_index_by_basic_block: &'a [u32],
    nth_basic_block_to_label: Vec<Label>,
    nth_basic_block_to_label_pending: Vec<Option<Label>>,
    nth_basic_block_to_machine_code_offset: Vec<usize>,
    pending_label_count: usize,
    jump_table: Vec<u8>,
    export_to_label: HashMap<u32, Label>,
    export_trampolines: Vec<u64>,
    debug_trace_execution: bool,
    ecall_label: Label,
    trap_label: Label,
    trace_label: Label,
    jump_table_label: Label,
    sbrk_label: Label,
    sandbox_kind: SandboxKind,
    gas_metering: Option<GasMeteringKind>,
    native_code_address: u64,
    address_table: AddressTable,
    vmctx_regs_offset: usize,
    vmctx_gas_offset: usize,
    vmctx_heap_info_offset: usize,
    nth_instruction_to_code_offset_map: Vec<u32>,
    init: GuestInit<'a>,
    is_last_instruction: bool,
}

struct CompilationResult<'a> {
    code: Vec<u8>,
    jump_table: Vec<u8>,
    export_trampolines: Vec<u64>,
    sysreturn_address: u64,
    nth_instruction_to_code_offset_map: Vec<u32>,
    init: GuestInit<'a>,
}

impl<'a> Compiler<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: &ModuleConfig,
        exports: &'a [ProgramExport<'a>],
        basic_block_by_jump_table_index: &'a [u32],
        jump_table_index_by_basic_block: &'a [u32],
        sandbox_kind: SandboxKind,
        address_table: AddressTable,
        vmctx_regs_offset: usize,
        vmctx_gas_offset: usize,
        vmctx_heap_info_offset: usize,
        debug_trace_execution: bool,
        native_code_address: u64,
        instruction_count: usize,
        basic_block_count: usize,
        init: GuestInit<'a>,
    ) -> Self {
        let mut asm = Assembler::new();
        let ecall_label = asm.forward_declare_label();
        let trap_label = asm.forward_declare_label();
        let trace_label = asm.forward_declare_label();
        let jump_table_label = asm.forward_declare_label();
        let sbrk_label = asm.forward_declare_label();

        let nth_basic_block_to_label = Vec::with_capacity(basic_block_count);
        let mut nth_basic_block_to_machine_code_offset = Vec::new();
        if config.gas_metering.is_some() {
            nth_basic_block_to_machine_code_offset.reserve(basic_block_count);
        }

        let mut nth_basic_block_to_label_pending = Vec::new();
        nth_basic_block_to_label_pending.resize(basic_block_count, None);

        let nth_instruction_to_code_offset_map: Vec<u32> = Vec::with_capacity(instruction_count + 1);
        polkavm_common::static_assert!(polkavm_common::zygote::VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE < u32::MAX);

        asm.reserve_code(instruction_count * 16);
        asm.reserve_labels(basic_block_count * 2);
        asm.reserve_fixups(basic_block_count);
        asm.set_origin(native_code_address);

        let mut compiler = Compiler {
            asm,
            exports,
            basic_block_by_jump_table_index,
            jump_table_index_by_basic_block,
            nth_basic_block_to_label,
            nth_basic_block_to_label_pending,
            nth_basic_block_to_machine_code_offset,
            pending_label_count: 0,
            jump_table: Default::default(),
            export_to_label: Default::default(),
            export_trampolines: Default::default(),
            ecall_label,
            trap_label,
            trace_label,
            jump_table_label,
            sbrk_label,
            sandbox_kind,
            gas_metering: config.gas_metering,
            native_code_address,
            debug_trace_execution,
            address_table,
            vmctx_regs_offset,
            vmctx_gas_offset,
            vmctx_heap_info_offset,
            nth_instruction_to_code_offset_map,
            init,
            is_last_instruction: instruction_count == 0,
        };

        compiler.start_new_basic_block();
        compiler
    }

    fn finalize(mut self, gas_cost_for_basic_block: &[u32]) -> Result<CompilationResult<'a>, Error> {
        let epilogue_start = self.asm.len();
        self.nth_instruction_to_code_offset_map.push(epilogue_start as u32);

        if self.gas_metering.is_some() {
            log::trace!("Finalizing block costs...");
            assert_eq!(gas_cost_for_basic_block.len(), self.nth_basic_block_to_machine_code_offset.len());
            let nth_basic_block_to_machine_code_offset = core::mem::take(&mut self.nth_basic_block_to_machine_code_offset);
            for (offset, &cost) in nth_basic_block_to_machine_code_offset.into_iter().zip(gas_cost_for_basic_block.iter()) {
                self.emit_weight(offset, cost);
            }
        }

        log::trace!("Emitting trampolines");

        if self.debug_trace_execution {
            self.emit_trace_trampoline();
        }

        self.emit_trap_trampoline();
        self.emit_ecall_trampoline();
        self.emit_sbrk_trampoline();
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
            let label = self.export_to_label.get(&export.jump_target()).unwrap();
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
            code: code.into(),
            jump_table: self.jump_table,
            export_trampolines: self.export_trampolines,
            sysreturn_address,
            nth_instruction_to_code_offset_map: self.nth_instruction_to_code_offset_map,
            init: self.init,
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
                    if nth_basic_block as usize >= self.nth_basic_block_to_label_pending.len() {
                        self.nth_basic_block_to_label_pending.resize(nth_basic_block as usize + 1, None);
                    }
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

    #[inline(always)]
    fn next_basic_block(&self) -> u32 {
        self.nth_basic_block_to_label.len() as u32
    }

    fn start_new_basic_block(&mut self) {
        if self.is_last_instruction {
            return;
        }

        let nth_basic_block = self.nth_basic_block_to_label.len();
        log::trace!("Starting new basic block: @{nth_basic_block:x}");

        let label = if let Some(label) = self.nth_basic_block_to_label_pending.get_mut(nth_basic_block).and_then(|value| value.take()) {
            self.pending_label_count -= 1;
            label
        } else {
            self.asm.forward_declare_label()
        };

        self.define_label(label);
        self.nth_basic_block_to_label.push(label);

        if let Some(gas_metering) = self.gas_metering {
            let offset = self.asm.len();
            self.nth_basic_block_to_machine_code_offset.push(offset);
            self.emit_gas_metering_stub(gas_metering);
        }
    }
}

impl<'a> VisitorWrapper<'a, Compiler<'a>> {
    fn current_instruction(&self) -> Instruction {
        Instruction::deserialize(&self.common.code[self.common.current_instruction_offset..]).expect("failed to deserialize instruction").1
    }

    #[cold]
    fn panic_on_too_long_instruction(&self, instruction_length: usize) -> ! {
        panic!(
            "maximum instruction length of {} exceeded with {} bytes for instruction: {}",
            VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH,
            instruction_length,
            self.current_instruction(),
        );
    }

    #[cold]
    fn trace_compiled_instruction(&self) {
        log::trace!("Compiling {}/{}: {}", self.common.nth_instruction + 1, self.common.instruction_count, self.current_instruction());
    }
}

impl<'a> crate::api::BackendVisitor for VisitorWrapper<'a, Compiler<'a>> {
    #[inline(always)]
    fn before_instruction(&mut self) {
        let initial_length = self.visitor.asm.len();
        self.nth_instruction_to_code_offset_map.push(initial_length as u32);

        if log::log_enabled!(log::Level::Trace) {
            self.trace_compiled_instruction();
        }

        if self.debug_trace_execution {
            self.visitor.trace_execution(self.common.nth_instruction);
        }

        self.is_last_instruction = self.common.is_last_instruction();
        self.asm.reserve::<8>();
    }

    fn after_instruction(&mut self) {
        if !self.debug_trace_execution {
            let offset = *self.nth_instruction_to_code_offset_map.last().unwrap() as usize;
            let instruction_length = self.asm.len() - offset;
            if instruction_length > VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH as usize {
                self.panic_on_too_long_instruction(instruction_length)
            }
        }
    }
}

impl<S> crate::api::BackendModule for CompiledModule<S> where S: Sandbox {
    type BackendVisitor<'a> = Compiler<'a>;
    type Aux = S::AddressSpace;

    fn create_visitor<'a>(
        config: &'a ModuleConfig,
        exports: &'a [ProgramExport],
        basic_block_by_jump_table_index: &'a [u32],
        jump_table_index_by_basic_block: &'a [u32],
        init: GuestInit<'a>,
        instruction_count: usize,
        basic_block_count: usize,
        debug_trace_execution: bool,
    ) -> Result<(Self::BackendVisitor<'a>, Self::Aux), Error> {
        let native_page_size = crate::sandbox::get_native_page_size();
        if native_page_size > config.page_size as usize || config.page_size as usize % native_page_size != 0 {
            return Err(format!("configured page size of {} is incompatible with the native page size of {}", config.page_size, native_page_size).into());
        }

        let address_space = S::reserve_address_space().map_err(Error::from_display)?;
        let native_code_address = crate::sandbox::SandboxAddressSpace::native_code_address(&address_space);
        let program_assembler = Compiler::new(
            config,
            exports,
            basic_block_by_jump_table_index,
            jump_table_index_by_basic_block,
            S::KIND,
            S::address_table(),
            S::vmctx_regs_offset(),
            S::vmctx_gas_offset(),
            S::vmctx_heap_info_offset(),
            debug_trace_execution,
            native_code_address,
            instruction_count,
            basic_block_count,
            init,
        );

        Ok((program_assembler, address_space))
    }

    fn finish_compilation<'a>(wrapper: VisitorWrapper<'a, Self::BackendVisitor<'a>>, address_space: Self::Aux) -> Result<(crate::api::Common<'a>, Self), Error> {
        let result = wrapper.visitor.finalize(&wrapper.common.gas_cost_for_basic_block)?;

        let init = SandboxInit {
            guest_init: result.init,
            code: &result.code,
            jump_table: &result.jump_table,
            sysreturn_address: result.sysreturn_address
        };

        let sandbox_program = S::prepare_program(init, address_space).map_err(Error::from_display)?;
        let export_trampolines = result.export_trampolines;

        let module = CompiledModule {
            sandbox_program,
            export_trampolines,
            nth_instruction_to_code_offset_map: result.nth_instruction_to_code_offset_map,
        };

        Ok((wrapper.common, module))
    }
}

pub(crate) struct CompiledModule<S> where S: Sandbox {
    pub(crate) sandbox_program: S::Program,
    pub(crate) export_trampolines: Vec<u64>,
    nth_instruction_to_code_offset_map: Vec<u32>,
}

impl<S> CompiledModule<S> where S: Sandbox {
    pub fn machine_code(&self) -> Cow<[u8]> {
        self.sandbox_program.machine_code()
    }

    pub fn nth_instruction_to_code_offset_map(&self) -> &[u32] {
        &self.nth_instruction_to_code_offset_map
    }
}
