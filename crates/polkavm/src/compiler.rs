use core::marker::PhantomData;
use std::collections::HashMap;
use std::sync::Arc;

use polkavm_assembler::{Assembler, Label};
use polkavm_common::abi::VM_CODE_ADDRESS_ALIGNMENT;
use polkavm_common::program::{
    is_jump_target_valid, InstructionVisitor, Instructions, JumpTable, ParsedInstruction, ProgramCounter, ProgramExport, RawReg,
};
use polkavm_common::zygote::VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH;

use crate::error::Error;

use crate::api::RuntimeInstructionSet;
use crate::config::{GasMeteringKind, ModuleConfig, SandboxKind};
use crate::gas::GasVisitor;
use crate::mutex::Mutex;
use crate::sandbox::{Sandbox, SandboxInit, SandboxProgram};
use crate::utils::{FlatMap, GuestInit};

#[cfg(target_arch = "x86_64")]
mod amd64;

/// The address to which to jump to for invalid dynamic jumps.
///
/// This needs to be at least 0x800000000000 on modern CPUs, but ideally should have
/// the most significant bit set to be future proof.
///
/// Why 0x800000000000? This constant is 48-bit (a single '1' followed by 47 '0's) which is
/// how many bits of virtual address space most modern CPUs support, and we deliberately want
/// to have an address which is bigger than this.
///
/// If the CPU encounters a jump instruction, and that instruction tells it to go to an address which
/// fits into 48 bits, then that might be a jump to somewhere valid, so the CPU has no choice but to
/// execute it, and clobber the instruction pointer with the target address in the process.
///
/// However, if it is a jump to an address that does *not* fit into 48 bits then the CPU can immediately
/// generate a page fault without even trying to jump there, leaving the original value of the instruction
/// pointer alone, which is exactly what we want.
pub const JUMP_TABLE_INVALID_ADDRESS: usize = 0xfa6f29540376ba8a;

const CONTINUE_BASIC_BLOCK: usize = 0;
const END_BASIC_BLOCK: usize = 1;
const END_BASIC_BLOCK_INVALID: usize = 2;

struct CachePerCompilation {
    assembler: Assembler,
    program_counter_to_label: FlatMap<Label>,
    gas_metering_stub_offsets: Vec<usize>,
    gas_cost_for_basic_block: Vec<u32>,
    export_to_label: HashMap<u32, Label>,
}

struct CachePerModule {
    program_counter_to_machine_code_offset_list: Vec<(ProgramCounter, u32)>,
    program_counter_to_machine_code_offset_map: HashMap<ProgramCounter, u32>,
}

#[derive(Default)]
struct Cache {
    per_compilation: Vec<CachePerCompilation>,
    per_module: Vec<CachePerModule>,
}

#[derive(Clone, Default)]
pub(crate) struct CompilerCache(Arc<Mutex<Cache>>);

pub(crate) struct CompilerVisitor<'a, S>
where
    S: Sandbox,
{
    init: GuestInit<'a>,
    jump_table: JumpTable<'a>,
    code: &'a [u8],
    bitmask: &'a [u8],
    asm: Assembler,
    program_counter_to_label: FlatMap<Label>,
    step_tracing: bool,
    ecall_label: Label,
    export_to_label: HashMap<u32, Label>,
    exports: &'a [ProgramExport<&'a [u8]>],
    gas_metering: Option<GasMeteringKind>,
    gas_visitor: GasVisitor,
    jump_table_label: Label,
    program_counter_to_machine_code_offset_list: Vec<(ProgramCounter, u32)>,
    program_counter_to_machine_code_offset_map: HashMap<ProgramCounter, u32>,
    gas_metering_stub_offsets: Vec<usize>,
    gas_cost_for_basic_block: Vec<u32>,
    code_length: u32,
    sbrk_label: Label,
    step_label: Label,
    trap_label: Label,
    invalid_jump_label: Label,
    instruction_set: RuntimeInstructionSet,

    _phantom: PhantomData<S>,
}

#[repr(transparent)]
pub(crate) struct ArchVisitor<'r, 'a, S>(pub &'r mut CompilerVisitor<'a, S>)
where
    S: Sandbox;

impl<'r, 'a, S> core::ops::Deref for ArchVisitor<'r, 'a, S>
where
    S: Sandbox,
{
    type Target = CompilerVisitor<'a, S>;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'r, 'a, S> core::ops::DerefMut for ArchVisitor<'r, 'a, S>
where
    S: Sandbox,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl<'a, S> CompilerVisitor<'a, S>
where
    S: Sandbox,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        cache: &CompilerCache,
        config: &'a ModuleConfig,
        instruction_set: RuntimeInstructionSet,
        jump_table: JumpTable<'a>,
        code: &'a [u8],
        bitmask: &'a [u8],
        exports: &'a [ProgramExport<&'a [u8]>],
        step_tracing: bool,
        code_length: u32,
        init: GuestInit<'a>,
    ) -> Result<(Self, S::AddressSpace), Error>
    where
        S: Sandbox,
    {
        let native_page_size = crate::sandbox::get_native_page_size();
        if native_page_size > config.page_size as usize || config.page_size as usize % native_page_size != 0 {
            return Err(format!(
                "configured page size of {} is incompatible with the native page size of {}",
                config.page_size, native_page_size
            )
            .into());
        }

        let address_space = S::reserve_address_space().map_err(Error::from_display)?;
        let native_code_origin = crate::sandbox::SandboxAddressSpace::native_code_origin(&address_space);

        let (per_compilation_cache, per_module_cache) = {
            let mut cache = cache.0.lock();
            (cache.per_compilation.pop(), cache.per_module.pop())
        };

        let mut asm;
        let mut gas_metering_stub_offsets: Vec<usize>;
        let mut gas_cost_for_basic_block: Vec<u32>;
        let program_counter_to_label;
        let export_to_label;

        if let Some(per_compilation_cache) = per_compilation_cache {
            asm = per_compilation_cache.assembler;
            program_counter_to_label = FlatMap::new_reusing_memory(per_compilation_cache.program_counter_to_label, code_length + 2);
            gas_metering_stub_offsets = per_compilation_cache.gas_metering_stub_offsets;
            gas_cost_for_basic_block = per_compilation_cache.gas_cost_for_basic_block;
            export_to_label = per_compilation_cache.export_to_label;
        } else {
            asm = Assembler::new();
            program_counter_to_label = FlatMap::new(code_length + 2);
            gas_metering_stub_offsets = Vec::new();
            gas_cost_for_basic_block = Vec::new();
            export_to_label = HashMap::new();
        }

        let program_counter_to_machine_code_offset_list: Vec<(ProgramCounter, u32)>;
        let program_counter_to_machine_code_offset_map: HashMap<ProgramCounter, u32>;
        if let Some(per_module_cache) = per_module_cache {
            program_counter_to_machine_code_offset_list = per_module_cache.program_counter_to_machine_code_offset_list;
            program_counter_to_machine_code_offset_map = per_module_cache.program_counter_to_machine_code_offset_map;
        } else {
            program_counter_to_machine_code_offset_list = Vec::with_capacity(code_length as usize);
            program_counter_to_machine_code_offset_map = HashMap::with_capacity(exports.len());
        }

        let ecall_label = asm.forward_declare_label();
        let trap_label = asm.forward_declare_label();
        let invalid_jump_label = asm.forward_declare_label();
        let step_label = asm.forward_declare_label();
        let jump_table_label = asm.forward_declare_label();
        let sbrk_label = asm.forward_declare_label();

        polkavm_common::static_assert!(polkavm_common::zygote::VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE < u32::MAX);

        if config.gas_metering.is_some() {
            gas_metering_stub_offsets.reserve(code_length as usize);
            gas_cost_for_basic_block.reserve(code_length as usize);
        }

        asm.set_origin(native_code_origin);

        let mut visitor = CompilerVisitor {
            gas_visitor: GasVisitor::default(),
            asm,
            exports,
            program_counter_to_label,
            init,
            jump_table,
            code,
            bitmask,
            export_to_label,
            ecall_label,
            trap_label,
            invalid_jump_label,
            step_label,
            jump_table_label,
            sbrk_label,
            gas_metering: config.gas_metering,
            step_tracing,
            program_counter_to_machine_code_offset_list,
            program_counter_to_machine_code_offset_map,
            gas_metering_stub_offsets,
            gas_cost_for_basic_block,
            code_length,
            instruction_set,
            _phantom: PhantomData,
        };

        ArchVisitor(&mut visitor).emit_trap_trampoline();
        ArchVisitor(&mut visitor).emit_ecall_trampoline();
        ArchVisitor(&mut visitor).emit_sbrk_trampoline();

        if step_tracing {
            ArchVisitor(&mut visitor).emit_step_trampoline();
        }

        log::trace!("Emitting code...");
        visitor
            .program_counter_to_machine_code_offset_list
            .push((ProgramCounter(0), visitor.asm.len() as u32));

        visitor.force_start_new_basic_block(0, visitor.is_jump_target_valid(0));
        Ok((visitor, address_space))
    }

    fn is_jump_target_valid(&self, offset: u32) -> bool {
        is_jump_target_valid(self.instruction_set, self.code, self.bitmask, offset)
    }

    pub(crate) fn finish_compilation(
        mut self,
        global: &S::GlobalState,
        cache: &CompilerCache,
        address_space: S::AddressSpace,
    ) -> Result<CompiledModule<S>, Error>
    where
        S: Sandbox,
    {
        log::trace!("Finishing compilation...");
        let invalid_code_offset_address = self.asm.origin() + self.asm.len() as u64;
        self.emit_trap_epilogue();
        self.program_counter_to_machine_code_offset_list.shrink_to_fit();

        let mut gas_metering_stub_offsets = core::mem::take(&mut self.gas_metering_stub_offsets);
        let mut gas_cost_for_basic_block = core::mem::take(&mut self.gas_cost_for_basic_block);
        if self.gas_metering.is_some() {
            log::trace!("Finalizing block costs...");
            assert_eq!(gas_metering_stub_offsets.len(), gas_cost_for_basic_block.len());
            for (&native_code_offset, &cost) in gas_metering_stub_offsets.iter().zip(gas_cost_for_basic_block.iter()) {
                log::trace!("  0x{:08x}: {}", self.asm.origin() + native_code_offset as u64, cost);
                ArchVisitor(&mut self).emit_weight(native_code_offset, cost);
            }
        }

        let label_sysenter = ArchVisitor(&mut self).emit_sysenter();
        let label_sysreturn = ArchVisitor(&mut self).emit_sysreturn();
        let native_code_origin = self.asm.origin();

        let jump_table_length = (self.jump_table.len() as usize + 1) * VM_CODE_ADDRESS_ALIGNMENT as usize;
        let mut native_jump_table = S::allocate_jump_table(global, jump_table_length).map_err(Error::from_display)?;
        {
            let native_jump_table = native_jump_table.as_mut();
            native_jump_table[..VM_CODE_ADDRESS_ALIGNMENT as usize].fill(JUMP_TABLE_INVALID_ADDRESS); // First entry is always invalid.
            native_jump_table[jump_table_length..].fill(JUMP_TABLE_INVALID_ADDRESS); // Fill in the padding, since the size is page-aligned.

            for (jump_table_index, code_offset) in self.jump_table.iter().enumerate() {
                let mut address = JUMP_TABLE_INVALID_ADDRESS;
                if let Some(label) = self.program_counter_to_label.get(code_offset.0) {
                    if let Some(native_code_offset) = self.asm.get_label_origin_offset(label) {
                        address = native_code_origin.checked_add_signed(native_code_offset as i64).expect("overflow") as usize;
                    }
                }

                native_jump_table[(jump_table_index + 1) * VM_CODE_ADDRESS_ALIGNMENT as usize] = address;
            }
        }

        assert!(self.program_counter_to_machine_code_offset_map.is_empty());
        for export in self.exports {
            let native_offset = if let Ok(index) = self
                .program_counter_to_machine_code_offset_list
                .binary_search_by_key(&export.program_counter(), |&(code_offset, _)| code_offset)
            {
                self.program_counter_to_machine_code_offset_list[index].1
            } else {
                self.program_counter_to_machine_code_offset_list.last().unwrap().1
            };

            log::trace!(
                "Export at {}: {} => 0x{:08x}",
                export.program_counter(),
                export.symbol(),
                native_code_origin + u64::from(native_offset)
            );
            self.program_counter_to_machine_code_offset_map
                .insert(export.program_counter(), native_offset);
        }

        let sysenter_address = native_code_origin
            .checked_add_signed(self.asm.get_label_origin_offset_or_panic(label_sysenter) as i64)
            .expect("overflow");

        let sysreturn_address = native_code_origin
            .checked_add_signed(self.asm.get_label_origin_offset_or_panic(label_sysreturn) as i64)
            .expect("overflow");

        match S::KIND {
            SandboxKind::Linux => {}
            SandboxKind::Generic => {
                let native_page_size = crate::sandbox::get_native_page_size();
                let padded_length = polkavm_common::utils::align_to_next_page_usize(native_page_size, self.asm.len()).unwrap();
                self.asm.resize(padded_length, ArchVisitor::<S>::PADDING_BYTE);
                self.asm.define_label(self.jump_table_label);
            }
        }

        let module = {
            let init = SandboxInit {
                guest_init: self.init,
                code: &self.asm.finalize(),
                jump_table: native_jump_table,
                sysenter_address,
                sysreturn_address,
            };

            let sandbox_program = S::prepare_program(global, init, address_space).map_err(Error::from_display)?;
            CompiledModule {
                sandbox_program,
                native_code_origin,
                program_counter_to_machine_code_offset_list: self.program_counter_to_machine_code_offset_list,
                program_counter_to_machine_code_offset_map: self.program_counter_to_machine_code_offset_map,
                cache: cache.clone(),
                invalid_code_offset_address,
            }
        };

        {
            let mut cache = cache.0.lock();
            if cache.per_compilation.is_empty() {
                self.asm.clear();
                self.program_counter_to_label.clear();
                self.export_to_label.clear();
                gas_metering_stub_offsets.clear();
                gas_cost_for_basic_block.clear();

                cache.per_compilation.push(CachePerCompilation {
                    assembler: self.asm,
                    program_counter_to_label: self.program_counter_to_label,
                    export_to_label: self.export_to_label,
                    gas_metering_stub_offsets,
                    gas_cost_for_basic_block,
                });
            }
        }

        Ok(module)
    }

    #[inline(always)]
    fn force_start_new_basic_block(&mut self, program_counter: u32, is_valid_jump_target: bool) {
        log::trace!("Starting new basic block at: {program_counter}");
        if is_valid_jump_target {
            if let Some(label) = self.program_counter_to_label.get(program_counter) {
                log::trace!("Label: {label} -> {program_counter} -> {:08x}", self.asm.current_address());
                self.asm.define_label(label);
            } else {
                let label = self.asm.create_label();
                log::trace!("Label: {label} -> {program_counter} -> {:08x}", self.asm.current_address());
                self.program_counter_to_label.insert(program_counter, label);
            }
        }

        if self.step_tracing {
            self.step(program_counter);
        }

        if let Some(gas_metering) = self.gas_metering {
            self.gas_metering_stub_offsets.push(self.asm.len());
            ArchVisitor(self).emit_gas_metering_stub(gas_metering);
        }
    }

    fn before_instruction(&self, program_counter: u32) {
        if log::log_enabled!(log::Level::Trace) {
            self.trace_compiled_instruction(program_counter);
        }
    }

    fn after_instruction<const KIND: usize>(&mut self, program_counter: u32, args_length: u32) {
        assert!(KIND == CONTINUE_BASIC_BLOCK || KIND == END_BASIC_BLOCK || KIND == END_BASIC_BLOCK_INVALID);

        if cfg!(debug_assertions) && !self.step_tracing {
            let offset = self.program_counter_to_machine_code_offset_list.last().unwrap().1 as usize;
            let instruction_length = self.asm.len() - offset;
            if instruction_length > VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH as usize {
                self.panic_on_too_long_instruction(program_counter, instruction_length)
            }
        }

        let next_program_counter = program_counter + args_length + 1;
        self.program_counter_to_machine_code_offset_list
            .push((ProgramCounter(next_program_counter), self.asm.len() as u32));

        if KIND == END_BASIC_BLOCK || KIND == END_BASIC_BLOCK_INVALID {
            if self.gas_metering.is_some() {
                let cost = self.gas_visitor.take_block_cost().unwrap();
                self.gas_cost_for_basic_block.push(cost);
            }

            let can_jump_into_new_basic_block = KIND != END_BASIC_BLOCK_INVALID && (next_program_counter as usize) < self.code.len();
            debug_assert_eq!(self.is_jump_target_valid(next_program_counter), can_jump_into_new_basic_block);
            self.force_start_new_basic_block(next_program_counter, can_jump_into_new_basic_block);
        } else if self.step_tracing {
            self.step(next_program_counter);
        }
    }

    #[inline(never)]
    #[cold]
    fn step(&mut self, program_counter: u32) {
        ArchVisitor(self).trace_execution(program_counter);
    }

    #[cold]
    fn current_instruction(&self, program_counter: u32) -> impl core::fmt::Display {
        struct MaybeInstruction(Option<ParsedInstruction>);
        impl core::fmt::Display for MaybeInstruction {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                if let Some(instruction) = self.0 {
                    instruction.fmt(fmt)
                } else {
                    write!(fmt, "<NONE>")
                }
            }
        }

        MaybeInstruction(Instructions::new_bounded(self.instruction_set, self.code, self.bitmask, program_counter).next())
    }

    #[cold]
    fn panic_on_too_long_instruction(&self, program_counter: u32, instruction_length: usize) -> ! {
        panic!(
            "maximum instruction length of {} exceeded with {} bytes for instruction: {}",
            VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH,
            instruction_length,
            self.current_instruction(program_counter),
        );
    }

    #[inline(never)]
    #[cold]
    fn trace_compiled_instruction(&self, program_counter: u32) {
        log::trace!("Compiling {}", self.current_instruction(program_counter));
    }

    fn get_or_forward_declare_label(&mut self, program_counter: u32) -> Option<Label> {
        match self.program_counter_to_label.get(program_counter) {
            Some(label) => Some(label),
            None => {
                if program_counter > self.program_counter_to_label.len() {
                    return None;
                }

                let label = self.asm.forward_declare_label();
                log::trace!("Label: {label} -> {program_counter} (forward declare)");

                self.program_counter_to_label.insert(program_counter, label);
                Some(label)
            }
        }
    }

    fn define_label(&mut self, label: Label) {
        log::trace!("Label: {} -> {:08x}", label, self.asm.current_address());
        self.asm.define_label(label);
    }

    fn emit_trap_epilogue(&mut self) {
        self.before_instruction(self.code_length);
        self.gas_visitor.trap();
        ArchVisitor(self).trap_without_modifying_program_counter();

        if self.gas_metering.is_some() {
            let cost = self.gas_visitor.take_block_cost().unwrap();
            self.gas_cost_for_basic_block.push(cost);
        }
    }
}

impl<'a, S> polkavm_common::program::ParsingVisitor for CompilerVisitor<'a, S>
where
    S: Sandbox,
{
    type ReturnTy = ();

    fn load_i32(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn load_u64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn store_u64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn store_imm_indirect_u64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: u32, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn store_indirect_u64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn load_indirect_i32(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn load_indirect_u64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn add_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn and_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn xor_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn or_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn mul_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn mul_upper_signed_signed_imm_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn mul_upper_unsigned_unsigned_imm_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn set_less_than_unsigned_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn set_less_than_signed_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn shift_logical_left_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn shift_logical_right_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn shift_arithmetic_right_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn set_greater_than_unsigned_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn set_greater_than_signed_64_imm(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn shift_logical_right_64_imm_alt(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn shift_arithmetic_right_64_imm_alt(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn shift_logical_left_64_imm_alt(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn add_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn sub_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn and_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn xor_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn or_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn mul_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn mul_upper_signed_signed_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn mul_upper_unsigned_unsigned_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn mul_upper_signed_unsigned_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn set_less_than_unsigned_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn set_less_than_signed_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn shift_logical_left_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn shift_logical_right_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn shift_arithmetic_right_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn div_unsigned_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn div_signed_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn rem_unsigned_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn rem_signed_64(&mut self, code_offset: u32, args_length: u32, _: RawReg, _: RawReg, _: RawReg) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }
    fn store_imm_u64(&mut self, code_offset: u32, args_length: u32, _: u32, _: u32) -> Self::ReturnTy {
        self.trap(code_offset, args_length)
    }

    #[inline(always)]
    fn invalid(&mut self, code_offset: u32, args_length: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.trap();
        ArchVisitor(self).invalid(code_offset);
        self.after_instruction::<END_BASIC_BLOCK_INVALID>(code_offset, args_length);
    }

    #[inline(always)]
    fn trap(&mut self, code_offset: u32, args_length: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.trap();
        ArchVisitor(self).trap(code_offset);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn fallthrough(&mut self, code_offset: u32, args_length: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.fallthrough();
        ArchVisitor(self).fallthrough();
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn sbrk(&mut self, code_offset: u32, args_length: u32, d: RawReg, s: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.sbrk(d, s);
        ArchVisitor(self).sbrk(d, s);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn ecalli(&mut self, code_offset: u32, args_length: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.ecalli(imm);
        ArchVisitor(self).ecalli(code_offset, args_length, imm);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn set_less_than_unsigned(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_less_than_unsigned(d, s1, s2);
        ArchVisitor(self).set_less_than_unsigned(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn set_less_than_signed(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_less_than_signed(d, s1, s2);
        ArchVisitor(self).set_less_than_signed(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn shift_logical_right(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_right(d, s1, s2);
        ArchVisitor(self).shift_logical_right(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn shift_arithmetic_right(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_arithmetic_right(d, s1, s2);
        ArchVisitor(self).shift_arithmetic_right(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn shift_logical_left(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_left(d, s1, s2);
        ArchVisitor(self).shift_logical_left(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn xor(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.xor(d, s1, s2);
        ArchVisitor(self).xor(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn and(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.and(d, s1, s2);
        ArchVisitor(self).and(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn or(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.or(d, s1, s2);
        ArchVisitor(self).or(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn add(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.add(d, s1, s2);
        ArchVisitor(self).add(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn sub(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.sub(d, s1, s2);
        ArchVisitor(self).sub(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn mul(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul(d, s1, s2);
        ArchVisitor(self).mul(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn mul_upper_signed_signed(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_upper_signed_signed(d, s1, s2);
        ArchVisitor(self).mul_upper_signed_signed(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn mul_upper_unsigned_unsigned(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_upper_unsigned_unsigned(d, s1, s2);
        ArchVisitor(self).mul_upper_unsigned_unsigned(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn mul_upper_signed_unsigned(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_upper_signed_unsigned(d, s1, s2);
        ArchVisitor(self).mul_upper_signed_unsigned(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn div_unsigned(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.div_unsigned(d, s1, s2);
        ArchVisitor(self).div_unsigned(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn div_signed(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.div_signed(d, s1, s2);
        ArchVisitor(self).div_signed(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn rem_unsigned(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.rem_unsigned(d, s1, s2);
        ArchVisitor(self).rem_unsigned(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn rem_signed(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.rem_signed(d, s1, s2);
        ArchVisitor(self).rem_signed(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn mul_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_imm(d, s1, s2);
        ArchVisitor(self).mul_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn mul_upper_signed_signed_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_upper_signed_signed_imm(d, s1, s2);
        ArchVisitor(self).mul_upper_signed_signed_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn mul_upper_unsigned_unsigned_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_upper_unsigned_unsigned_imm(d, s1, s2);
        ArchVisitor(self).mul_upper_unsigned_unsigned_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn set_less_than_unsigned_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_less_than_unsigned_imm(d, s1, s2);
        ArchVisitor(self).set_less_than_unsigned_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn set_less_than_signed_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_less_than_signed_imm(d, s1, s2);
        ArchVisitor(self).set_less_than_signed_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn set_greater_than_unsigned_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_greater_than_unsigned_imm(d, s1, s2);
        ArchVisitor(self).set_greater_than_unsigned_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn set_greater_than_signed_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_greater_than_signed_imm(d, s1, s2);
        ArchVisitor(self).set_greater_than_signed_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn shift_logical_right_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_right_imm(d, s1, s2);
        ArchVisitor(self).shift_logical_right_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn shift_arithmetic_right_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_arithmetic_right_imm(d, s1, s2);
        ArchVisitor(self).shift_arithmetic_right_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn shift_logical_left_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_left_imm(d, s1, s2);
        ArchVisitor(self).shift_logical_left_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn shift_logical_right_imm_alt(&mut self, code_offset: u32, args_length: u32, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_right_imm_alt(d, s2, s1);
        ArchVisitor(self).shift_logical_right_imm_alt(d, s2, s1);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn shift_arithmetic_right_imm_alt(&mut self, code_offset: u32, args_length: u32, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_arithmetic_right_imm_alt(d, s2, s1);
        ArchVisitor(self).shift_arithmetic_right_imm_alt(d, s2, s1);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn shift_logical_left_imm_alt(&mut self, code_offset: u32, args_length: u32, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_left_imm_alt(d, s2, s1);
        ArchVisitor(self).shift_logical_left_imm_alt(d, s2, s1);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn or_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.or_imm(d, s, imm);
        ArchVisitor(self).or_imm(d, s, imm);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn and_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.and_imm(d, s, imm);
        ArchVisitor(self).and_imm(d, s, imm);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn xor_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.xor_imm(d, s, imm);
        ArchVisitor(self).xor_imm(d, s, imm);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn move_reg(&mut self, code_offset: u32, args_length: u32, d: RawReg, s: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.move_reg(d, s);
        ArchVisitor(self).move_reg(d, s);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn cmov_if_zero(&mut self, code_offset: u32, args_length: u32, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.cmov_if_zero(d, s, c);
        ArchVisitor(self).cmov_if_zero(d, s, c);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn cmov_if_not_zero(&mut self, code_offset: u32, args_length: u32, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.cmov_if_not_zero(d, s, c);
        ArchVisitor(self).cmov_if_not_zero(d, s, c);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn cmov_if_zero_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.cmov_if_zero_imm(d, c, s);
        ArchVisitor(self).cmov_if_zero_imm(d, c, s);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn cmov_if_not_zero_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.cmov_if_not_zero_imm(d, c, s);
        ArchVisitor(self).cmov_if_not_zero_imm(d, c, s);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn add_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.add_imm(d, s, imm);
        ArchVisitor(self).add_imm(d, s, imm);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn negate_and_add_imm(&mut self, code_offset: u32, args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.negate_and_add_imm(d, s1, s2);
        ArchVisitor(self).negate_and_add_imm(d, s1, s2);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_imm_indirect_u8(&mut self, code_offset: u32, args_length: u32, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_indirect_u8(base, offset, value);
        ArchVisitor(self).store_imm_indirect_u8(base, offset, value);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_imm_indirect_u16(&mut self, code_offset: u32, args_length: u32, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_indirect_u16(base, offset, value);
        ArchVisitor(self).store_imm_indirect_u16(base, offset, value);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_imm_indirect_u32(&mut self, code_offset: u32, args_length: u32, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_indirect_u32(base, offset, value);
        ArchVisitor(self).store_imm_indirect_u32(base, offset, value);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_indirect_u8(&mut self, code_offset: u32, args_length: u32, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_indirect_u8(src, base, offset);
        ArchVisitor(self).store_indirect_u8(src, base, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_indirect_u16(&mut self, code_offset: u32, args_length: u32, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_indirect_u16(src, base, offset);
        ArchVisitor(self).store_indirect_u16(src, base, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_indirect_u32(&mut self, code_offset: u32, args_length: u32, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_indirect_u32(src, base, offset);
        ArchVisitor(self).store_indirect_u32(src, base, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_imm_u8(&mut self, code_offset: u32, args_length: u32, value: u32, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_u8(value, offset);
        ArchVisitor(self).store_imm_u8(value, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_imm_u16(&mut self, code_offset: u32, args_length: u32, value: u32, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_u16(value, offset);
        ArchVisitor(self).store_imm_u16(value, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_imm_u32(&mut self, code_offset: u32, args_length: u32, value: u32, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_u32(value, offset);
        ArchVisitor(self).store_imm_u32(value, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_u8(&mut self, code_offset: u32, args_length: u32, src: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_u8(src, offset);
        ArchVisitor(self).store_u8(src, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_u16(&mut self, code_offset: u32, args_length: u32, src: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_u16(src, offset);
        ArchVisitor(self).store_u16(src, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn store_u32(&mut self, code_offset: u32, args_length: u32, src: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_u32(src, offset);
        ArchVisitor(self).store_u32(src, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_indirect_u8(&mut self, code_offset: u32, args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_indirect_u8(dst, base, offset);
        ArchVisitor(self).load_indirect_u8(dst, base, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_indirect_i8(&mut self, code_offset: u32, args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_indirect_i8(dst, base, offset);
        ArchVisitor(self).load_indirect_i8(dst, base, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_indirect_u16(&mut self, code_offset: u32, args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_indirect_u16(dst, base, offset);
        ArchVisitor(self).load_indirect_u16(dst, base, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_indirect_i16(&mut self, code_offset: u32, args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_indirect_i16(dst, base, offset);
        ArchVisitor(self).load_indirect_i16(dst, base, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_indirect_u32(&mut self, code_offset: u32, args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_indirect_u32(dst, base, offset);
        ArchVisitor(self).load_indirect_u32(dst, base, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_u8(&mut self, code_offset: u32, args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_u8(dst, offset);
        ArchVisitor(self).load_u8(dst, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_i8(&mut self, code_offset: u32, args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_i8(dst, offset);
        ArchVisitor(self).load_i8(dst, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_u16(&mut self, code_offset: u32, args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_u16(dst, offset);
        ArchVisitor(self).load_u16(dst, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_i16(&mut self, code_offset: u32, args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_i16(dst, offset);
        ArchVisitor(self).load_i16(dst, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_u32(&mut self, code_offset: u32, args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_u32(dst, offset);
        ArchVisitor(self).load_u32(dst, offset);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_unsigned(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_unsigned(s1, s2, imm);
        ArchVisitor(self).branch_less_unsigned(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_signed(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_signed(s1, s2, imm);
        ArchVisitor(self).branch_less_signed(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_or_equal_unsigned(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_or_equal_unsigned(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_unsigned(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_or_equal_signed(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_or_equal_signed(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_signed(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_eq(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_eq(s1, s2, imm);
        ArchVisitor(self).branch_eq(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_not_eq(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_not_eq(s1, s2, imm);
        ArchVisitor(self).branch_not_eq(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_eq_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_eq_imm(s1, s2, imm);
        ArchVisitor(self).branch_eq_imm(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_not_eq_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_not_eq_imm(s1, s2, imm);
        ArchVisitor(self).branch_not_eq_imm(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_unsigned_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_unsigned_imm(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_signed_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_signed_imm(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_or_equal_unsigned_imm(
        &mut self,
        code_offset: u32,
        args_length: u32,
        s1: RawReg,
        s2: u32,
        imm: u32,
    ) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_or_equal_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_unsigned_imm(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_or_equal_signed_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_or_equal_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_signed_imm(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_or_equal_unsigned_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_or_equal_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_or_equal_unsigned_imm(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_or_equal_signed_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_or_equal_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_or_equal_signed_imm(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_unsigned_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_unsigned_imm(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_signed_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_signed_imm(s1, s2, imm);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_imm(&mut self, code_offset: u32, args_length: u32, dst: RawReg, value: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_imm(dst, value);
        ArchVisitor(self).load_imm(dst, value);
        self.after_instruction::<CONTINUE_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_imm_and_jump(&mut self, code_offset: u32, args_length: u32, ra: RawReg, value: u32, target: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_imm_and_jump(ra, value, target);
        ArchVisitor(self).load_imm_and_jump(ra, value, target);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn load_imm_and_jump_indirect(
        &mut self,
        code_offset: u32,
        args_length: u32,
        ra: RawReg,
        base: RawReg,
        value: u32,
        offset: u32,
    ) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_imm_and_jump_indirect(ra, base, value, offset);
        ArchVisitor(self).load_imm_and_jump_indirect(ra, base, value, offset);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn jump(&mut self, code_offset: u32, args_length: u32, target: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.jump(target);
        ArchVisitor(self).jump(target);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }

    #[inline(always)]
    fn jump_indirect(&mut self, code_offset: u32, args_length: u32, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.jump_indirect(base, offset);
        ArchVisitor(self).jump_indirect(base, offset);
        self.after_instruction::<END_BASIC_BLOCK>(code_offset, args_length);
    }
}

pub(crate) struct CompiledModule<S>
where
    S: Sandbox,
{
    pub(crate) sandbox_program: S::Program,
    pub(crate) native_code_origin: u64,
    // A sorted list which maps guest code offsets to native code offsets.
    program_counter_to_machine_code_offset_list: Vec<(ProgramCounter, u32)>,
    // Maps guest code offsets for exports to native code offsets.
    // Used to make sure calls into exports are always O(1) instead of O(log n).
    program_counter_to_machine_code_offset_map: HashMap<ProgramCounter, u32>,
    cache: CompilerCache,
    pub(crate) invalid_code_offset_address: u64,
}

impl<S> CompiledModule<S>
where
    S: Sandbox,
{
    pub fn machine_code(&self) -> &[u8] {
        self.sandbox_program.machine_code()
    }

    pub fn program_counter_to_machine_code_offset(&self) -> &[(ProgramCounter, u32)] {
        &self.program_counter_to_machine_code_offset_list
    }

    pub fn lookup_native_code_address(&self, program_counter: ProgramCounter) -> Option<u64> {
        self.program_counter_to_machine_code_offset_map
            .get(&program_counter)
            .copied()
            .or_else(|| {
                let index = self
                    .program_counter_to_machine_code_offset_list
                    .binary_search_by_key(&program_counter, |&(pc, _)| pc)
                    .ok()?;
                Some(self.program_counter_to_machine_code_offset_list[index].1)
            })
            .map(|native_offset| self.native_code_origin + u64::from(native_offset))
    }

    pub fn program_counter_by_native_code_address(&self, address: u64, strict: bool) -> Option<ProgramCounter> {
        let offset = address - self.native_code_origin;
        let index = match self
            .program_counter_to_machine_code_offset_list
            .binary_search_by_key(&offset, |&(_, native_offset)| u64::from(native_offset))
        {
            Ok(index) => index,
            Err(index) => {
                if !strict && index > 0 && index < self.program_counter_to_machine_code_offset_list.len() {
                    index - 1
                } else {
                    return None;
                }
            }
        };

        Some(self.program_counter_to_machine_code_offset_list[index].0)
    }
}

impl<S> Drop for CompiledModule<S>
where
    S: Sandbox,
{
    fn drop(&mut self) {
        let mut program_counter_to_machine_code_offset_list = core::mem::take(&mut self.program_counter_to_machine_code_offset_list);
        let mut program_counter_to_machine_code_offset_map = core::mem::take(&mut self.program_counter_to_machine_code_offset_map);
        {
            let mut cache = self.cache.0.lock();
            if cache.per_module.is_empty() {
                program_counter_to_machine_code_offset_list.clear();
                program_counter_to_machine_code_offset_map.clear();
                cache.per_module.push(CachePerModule {
                    program_counter_to_machine_code_offset_list,
                    program_counter_to_machine_code_offset_map,
                });
            }
        }
    }
}
