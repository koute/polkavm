use alloc::borrow::Cow;
use std::collections::HashMap;
use std::sync::Mutex;

use polkavm_assembler::{Assembler, Label};
use polkavm_common::program::{ParsedInstruction, ProgramExport, Instructions, JumpTable, Reg};
use polkavm_common::zygote::{
    AddressTable, VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH, VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH,
};
use polkavm_common::abi::VM_CODE_ADDRESS_ALIGNMENT;

use crate::error::Error;

use crate::sandbox::{Sandbox, SandboxProgram, SandboxInit};
use crate::config::{GasMeteringKind, ModuleConfig, SandboxKind};
use crate::utils::{FlatMap, GuestInit};
use crate::gas::GasVisitor;

#[cfg(target_arch = "x86_64")]
mod amd64;

struct Cached {
    assembler: Assembler,
}

#[derive(Default)]
struct Cache {
    cached: Vec<Cached>
}

#[derive(Default)]
pub(crate) struct CompilerCache(Mutex<Cache>);

pub(crate) struct CompilerVisitor<'a> {
    pub(crate) current_code_offset: u32,

    init: GuestInit<'a>,
    jump_table: JumpTable<'a>,
    code: &'a [u8],
    bitmask: &'a [u8],
    address_table: AddressTable,
    asm: Assembler,
    basic_block_pending: bool,
    code_offset_to_label: FlatMap<Label>,
    debug_trace_execution: bool,
    ecall_label: Label,
    export_to_label: HashMap<u32, Label>,
    exports: &'a [ProgramExport<'a>],
    gas_metering: Option<GasMeteringKind>,
    gas_visitor: GasVisitor,
    jump_table_label: Label,
    code_offset_to_native_code_offset: Vec<(u32, u32)>,
    gas_metering_stub_offsets: Vec<usize>,
    gas_cost_for_basic_block: Vec<u32>,
    code_length: u32,
    sandbox_kind: SandboxKind,
    sbrk_label: Label,
    trace_label: Label,
    trap_label: Label,
    vmctx_gas_offset: usize,
    vmctx_heap_info_offset: usize,
    vmctx_regs_offset: usize,
}

#[repr(transparent)]
pub(crate) struct ArchVisitor<'r, 'a>(pub &'r mut CompilerVisitor<'a>);

impl<'r, 'a> core::ops::Deref for ArchVisitor<'r, 'a> {
    type Target = CompilerVisitor<'a>;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'r, 'a> core::ops::DerefMut for ArchVisitor<'r, 'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl<'a> CompilerVisitor<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new<S>(
        cache: &CompilerCache,
        config: &'a ModuleConfig,
        jump_table: JumpTable<'a>,
        code: &'a [u8],
        bitmask: &'a [u8],
        exports: &'a [ProgramExport<'a>],
        debug_trace_execution: bool,
        code_length: u32,
        init: GuestInit<'a>,
    ) -> Result<(Self, S::AddressSpace), Error> where S: Sandbox {
        let native_page_size = crate::sandbox::get_native_page_size();
        if native_page_size > config.page_size as usize || config.page_size as usize % native_page_size != 0 {
            return Err(format!("configured page size of {} is incompatible with the native page size of {}", config.page_size, native_page_size).into());
        }

        let address_space = S::reserve_address_space().map_err(Error::from_display)?;
        let native_code_address = crate::sandbox::SandboxAddressSpace::native_code_address(&address_space);

        let mut asm = Assembler::new();
        let cached = {
            let mut cache = match cache.0.lock() {
                Ok(cache) => cache,
                Err(poison) => poison.into_inner(),
            };

            cache.cached.pop()
        };

        if let Some(cached) = cached {
            asm = cached.assembler;
        }

        let ecall_label = asm.forward_declare_label();
        let trap_label = asm.forward_declare_label();
        let trace_label = asm.forward_declare_label();
        let jump_table_label = asm.forward_declare_label();
        let sbrk_label = asm.forward_declare_label();

        let code_offset_to_label = FlatMap::new(code_length);
        let code_offset_to_native_code_offset: Vec<(u32, u32)> = Vec::with_capacity(code_length as usize);
        polkavm_common::static_assert!(polkavm_common::zygote::VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE < u32::MAX);

        let mut gas_metering_stub_offsets: Vec<usize> = Vec::new();
        let mut gas_cost_for_basic_block: Vec<u32> = Vec::new();

        if config.gas_metering.is_some() {
            gas_metering_stub_offsets.reserve(code_length as usize);
            gas_cost_for_basic_block.reserve(code_length as usize);
        }

        asm.set_origin(native_code_address);

        let mut visitor = CompilerVisitor {
            current_code_offset: 0,
            gas_visitor: GasVisitor::default(),
            asm,
            exports,
            code_offset_to_label,
            init,
            jump_table,
            code,
            bitmask,
            export_to_label: Default::default(),
            ecall_label,
            trap_label,
            trace_label,
            jump_table_label,
            sbrk_label,
            sandbox_kind: S::KIND,
            gas_metering: config.gas_metering,
            debug_trace_execution,
            address_table: S::address_table(),
            vmctx_regs_offset: S::vmctx_regs_offset(),
            vmctx_gas_offset: S::vmctx_gas_offset(),
            vmctx_heap_info_offset: S::vmctx_heap_info_offset(),
            code_offset_to_native_code_offset,
            gas_metering_stub_offsets,
            gas_cost_for_basic_block,
            code_length,
            basic_block_pending: true,
        };

        ArchVisitor(&mut visitor).emit_trap_trampoline();
        ArchVisitor(&mut visitor).emit_ecall_trampoline();
        ArchVisitor(&mut visitor).emit_sbrk_trampoline();

        if debug_trace_execution {
            ArchVisitor(&mut visitor).emit_trace_trampoline();
        }

        Ok((visitor, address_space))
    }

    pub(crate) fn finish_compilation<S>(mut self, cache: &CompilerCache, address_space: S::AddressSpace) -> Result<CompiledModule<S>, Error> where S: Sandbox {
        let epilogue_start = self.asm.len();
        self.code_offset_to_native_code_offset.push((self.code_length, epilogue_start as u32));
        self.code_offset_to_native_code_offset.shrink_to_fit();

        if self.gas_metering.is_some() {
            log::trace!("Finalizing block costs...");
            let gas_metering_stub_offsets = core::mem::take(&mut self.gas_metering_stub_offsets);
            let gas_cost_for_basic_block = core::mem::take(&mut self.gas_cost_for_basic_block);
            assert_eq!(gas_metering_stub_offsets.len(), gas_cost_for_basic_block.len());
            for (native_code_offset, cost) in gas_metering_stub_offsets.into_iter().zip(gas_cost_for_basic_block.into_iter()) {
                ArchVisitor(&mut self).emit_weight(native_code_offset, cost);
            }
        }

        log::trace!("Emitting export trampolines");
        ArchVisitor(&mut self).emit_export_trampolines();

        let label_sysreturn = ArchVisitor(&mut self).emit_sysreturn();

        let native_code_address = self.asm.origin();
        let native_pointer_size = core::mem::size_of::<usize>();
        let jump_table_entry_size = native_pointer_size * VM_CODE_ADDRESS_ALIGNMENT as usize;

        let mut native_jump_table = vec![0; (self.jump_table.len() as usize + 1) * jump_table_entry_size];
        for (jump_table_index, code_offset) in self.jump_table.iter().enumerate() {
            let Some(label) = self.code_offset_to_label.get(code_offset) else { continue };
            let Some(native_code_offset) = self.asm.get_label_origin_offset(label) else { continue };
            let jump_table_offset = (jump_table_index + 1) * jump_table_entry_size;
            let range = jump_table_offset..jump_table_offset + native_pointer_size;
            let address = native_code_address.checked_add_signed(native_code_offset as i64).expect("overflow");

            log::trace!("Jump table: [{}] = 0x{:x}", jump_table_index + 1, address);
            native_jump_table[range].copy_from_slice(&address.to_ne_bytes());
        }

        let mut export_trampolines = HashMap::with_capacity(self.exports.len());
        for export in self.exports {
            let label = self.export_to_label.get(&export.target_code_offset()).unwrap();
            let native_address = native_code_address
                .checked_add_signed(self.asm.get_label_origin_offset_or_panic(*label) as i64)
                .expect("overflow");

            export_trampolines.entry(export.target_code_offset()).or_insert(native_address);
        }

        let epilogue_length = self.asm.len() - epilogue_start;
        assert!(
            epilogue_length <= VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH as usize,
            "maximum epilogue length of {} exceeded with {} bytes",
            VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH,
            epilogue_length
        );

        let sysreturn_address = native_code_address
            .checked_add_signed(self.asm.get_label_origin_offset_or_panic(label_sysreturn) as i64)
            .expect("overflow");

        match self.sandbox_kind {
            SandboxKind::Linux => {},
            SandboxKind::Generic => {
                let native_page_size = crate::sandbox::get_native_page_size();
                let padded_length = polkavm_common::utils::align_to_next_page_usize(native_page_size, self.asm.len()).unwrap();
                self.asm.resize(padded_length, ArchVisitor::PADDING_BYTE);
                self.asm.define_label(self.jump_table_label);
            }
        }

        let module = {
            let init = SandboxInit {
                guest_init: self.init,
                code: &self.asm.finalize(),
                jump_table: &native_jump_table,
                sysreturn_address,
            };

            let sandbox_program = S::prepare_program(init, address_space).map_err(Error::from_display)?;
            CompiledModule {
                sandbox_program,
                export_trampolines,
                code_offset_to_native_code_offset: self.code_offset_to_native_code_offset
            }
        };

        {
            let mut cache = match cache.0.lock() {
                Ok(cache) => cache,
                Err(poison) => poison.into_inner(),
            };

            if cache.cached.is_empty() {
                cache.cached.push(Cached {
                    assembler: self.asm,
                });
            }
        }

        Ok(module)
    }

    fn start_new_basic_block(&mut self) {
        if self.gas_metering.is_some() {
            let cost = self.gas_visitor.take_block_cost().unwrap();
            self.gas_cost_for_basic_block.push(cost);
        }

        self.basic_block_pending = true;
    }

    #[inline(always)]
    fn before_instruction(&mut self) {
        if self.basic_block_pending {
            self.handle_pending_basic_block();
        }

        self.code_offset_to_native_code_offset.push((self.current_code_offset, self.asm.len() as u32));

        if log::log_enabled!(log::Level::Trace) {
            self.trace_compiled_instruction();
        }

        if self.debug_trace_execution {
            ArchVisitor(self).trace_execution();
        }

        self.asm.reserve::<8>();
    }

    #[inline(never)]
    fn handle_pending_basic_block(&mut self) {
        let code_offset = self.current_code_offset;
        self.basic_block_pending = false;

        log::trace!("Starting new basic block at: {code_offset}");
        if let Some(label) = self.code_offset_to_label.get(code_offset) {
            log::trace!("Label: {label} -> {code_offset} -> {:08x}", self.asm.current_address());
            self.asm.define_label(label);
        } else {
            let label = self.asm.create_label();
            log::trace!("Label: {label} -> {code_offset} -> {:08x}", self.asm.current_address());
            self.code_offset_to_label.insert(code_offset, label);
        }

        if let Some(gas_metering) = self.gas_metering {
            self.gas_metering_stub_offsets.push(self.asm.len());
            ArchVisitor(self).emit_gas_metering_stub(gas_metering);
        }
    }

    fn after_instruction(&mut self) {
        if cfg!(debug_assertions) && !self.debug_trace_execution {
            let offset = self.code_offset_to_native_code_offset.last().unwrap().1 as usize;
            let instruction_length = self.asm.len() - offset;
            if instruction_length > VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH as usize {
                self.panic_on_too_long_instruction(instruction_length)
            }
        }
    }

    fn current_instruction(&self) -> impl core::fmt::Display {
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
        MaybeInstruction(Instructions::new(self.code, self.bitmask, self.current_code_offset).next())
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

    #[inline(never)]
    #[cold]
    fn trace_compiled_instruction(&self) {
        log::trace!("Compiling {}", self.current_instruction());
    }

    fn get_or_forward_declare_label(&mut self, code_offset: u32) -> Label {
        match self.code_offset_to_label.get(code_offset) {
            Some(label) => label,
            None => {
                let label = self.asm.forward_declare_label();
                log::trace!("Label: {label} -> {code_offset} (forward declare)");

                self.code_offset_to_label.insert(code_offset, label);
                label
            }
        }
    }

    fn define_label(&mut self, label: Label) {
        log::trace!("Label: {} -> {:08x}", label, self.asm.current_address());
        self.asm.define_label(label);
    }
}

impl<'a> polkavm_common::program::ParsingVisitor for CompilerVisitor<'a> {
    #[cfg_attr(not(debug_assertions), inline)]
    fn on_pre_visit(&mut self, offset: usize, _opcode: u8) -> Self::ReturnTy {
        self.current_code_offset = offset as u32;
    }
}

impl<'a> polkavm_common::program::InstructionVisitor for CompilerVisitor<'a> {
    type ReturnTy = ();

    #[inline(always)]
    fn trap(&mut self) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.trap();
        ArchVisitor(self).trap();
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn fallthrough(&mut self) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.fallthrough();
        ArchVisitor(self).fallthrough();
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn sbrk(&mut self, d: Reg, s: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.sbrk(d, s);
        ArchVisitor(self).sbrk(d, s);
        self.after_instruction();
    }

    #[inline(always)]
    fn ecalli(&mut self, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.ecalli(imm);
        ArchVisitor(self).ecalli(imm);
        self.after_instruction();
    }

    #[inline(always)]
    fn set_less_than_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.set_less_than_unsigned(d, s1, s2);
        ArchVisitor(self).set_less_than_unsigned(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn set_less_than_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.set_less_than_signed(d, s1, s2);
        ArchVisitor(self).set_less_than_signed(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn shift_logical_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.shift_logical_right(d, s1, s2);
        ArchVisitor(self).shift_logical_right(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn shift_arithmetic_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.shift_arithmetic_right(d, s1, s2);
        ArchVisitor(self).shift_arithmetic_right(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn shift_logical_left(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.shift_logical_left(d, s1, s2);
        ArchVisitor(self).shift_logical_left(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn xor(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.xor(d, s1, s2);
        ArchVisitor(self).xor(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn and(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.and(d, s1, s2);
        ArchVisitor(self).and(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn or(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.or(d, s1, s2);
        ArchVisitor(self).or(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn add(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.add(d, s1, s2);
        ArchVisitor(self).add(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn sub(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.sub(d, s1, s2);
        ArchVisitor(self).sub(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn mul(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.mul(d, s1, s2);
        ArchVisitor(self).mul(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn mul_upper_signed_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.mul_upper_signed_signed(d, s1, s2);
        ArchVisitor(self).mul_upper_signed_signed(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn mul_upper_unsigned_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.mul_upper_unsigned_unsigned(d, s1, s2);
        ArchVisitor(self).mul_upper_unsigned_unsigned(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn mul_upper_signed_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.mul_upper_signed_unsigned(d, s1, s2);
        ArchVisitor(self).mul_upper_signed_unsigned(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn div_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.div_unsigned(d, s1, s2);
        ArchVisitor(self).div_unsigned(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn div_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.div_signed(d, s1, s2);
        ArchVisitor(self).div_signed(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn rem_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.rem_unsigned(d, s1, s2);
        ArchVisitor(self).rem_unsigned(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn rem_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.rem_signed(d, s1, s2);
        ArchVisitor(self).rem_signed(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn mul_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.mul_imm(d, s1, s2);
        ArchVisitor(self).mul_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn mul_upper_signed_signed_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.mul_upper_signed_signed_imm(d, s1, s2);
        ArchVisitor(self).mul_upper_signed_signed_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn mul_upper_unsigned_unsigned_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.mul_upper_unsigned_unsigned_imm(d, s1, s2);
        ArchVisitor(self).mul_upper_unsigned_unsigned_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn set_less_than_unsigned_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.set_less_than_unsigned_imm(d, s1, s2);
        ArchVisitor(self).set_less_than_unsigned_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn set_less_than_signed_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.set_less_than_signed_imm(d, s1, s2);
        ArchVisitor(self).set_less_than_signed_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn set_greater_than_unsigned_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.set_greater_than_unsigned_imm(d, s1, s2);
        ArchVisitor(self).set_greater_than_unsigned_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn set_greater_than_signed_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.set_greater_than_signed_imm(d, s1, s2);
        ArchVisitor(self).set_greater_than_signed_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn shift_logical_right_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.shift_logical_right_imm(d, s1, s2);
        ArchVisitor(self).shift_logical_right_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn shift_arithmetic_right_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.shift_arithmetic_right_imm(d, s1, s2);
        ArchVisitor(self).shift_arithmetic_right_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn shift_logical_left_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.shift_logical_left_imm(d, s1, s2);
        ArchVisitor(self).shift_logical_left_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn shift_logical_right_imm_alt(&mut self, d: Reg, s2: Reg, s1: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.shift_logical_right_imm_alt(d, s2, s1);
        ArchVisitor(self).shift_logical_right_imm_alt(d, s2, s1);
        self.after_instruction();
    }

    #[inline(always)]
    fn shift_arithmetic_right_imm_alt(&mut self, d: Reg, s2: Reg, s1: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.shift_arithmetic_right_imm_alt(d, s2, s1);
        ArchVisitor(self).shift_arithmetic_right_imm_alt(d, s2, s1);
        self.after_instruction();
    }

    #[inline(always)]
    fn shift_logical_left_imm_alt(&mut self, d: Reg, s2: Reg, s1: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.shift_logical_left_imm_alt(d, s2, s1);
        ArchVisitor(self).shift_logical_left_imm_alt(d, s2, s1);
        self.after_instruction();
    }

    #[inline(always)]
    fn or_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.or_imm(d, s, imm);
        ArchVisitor(self).or_imm(d, s, imm);
        self.after_instruction();
    }

    #[inline(always)]
    fn and_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.and_imm(d, s, imm);
        ArchVisitor(self).and_imm(d, s, imm);
        self.after_instruction();
    }

    #[inline(always)]
    fn xor_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.xor_imm(d, s, imm);
        ArchVisitor(self).xor_imm(d, s, imm);
        self.after_instruction();
    }

    #[inline(always)]
    fn move_reg(&mut self, d: Reg, s: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.move_reg(d, s);
        ArchVisitor(self).move_reg(d, s);
        self.after_instruction();
    }

    #[inline(always)]
    fn cmov_if_zero(&mut self, d: Reg, s: Reg, c: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.cmov_if_zero(d, s, c);
        ArchVisitor(self).cmov_if_zero(d, s, c);
        self.after_instruction();
    }

    #[inline(always)]
    fn cmov_if_not_zero(&mut self, d: Reg, s: Reg, c: Reg) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.cmov_if_not_zero(d, s, c);
        ArchVisitor(self).cmov_if_not_zero(d, s, c);
        self.after_instruction();
    }

    #[inline(always)]
    fn cmov_if_zero_imm(&mut self, d: Reg, c: Reg, s: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.cmov_if_zero_imm(d, c, s);
        ArchVisitor(self).cmov_if_zero_imm(d, c, s);
        self.after_instruction();
    }

    #[inline(always)]
    fn cmov_if_not_zero_imm(&mut self, d: Reg, c: Reg, s: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.cmov_if_not_zero_imm(d, c, s);
        ArchVisitor(self).cmov_if_not_zero_imm(d, c, s);
        self.after_instruction();
    }

    #[inline(always)]
    fn add_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.add_imm(d, s, imm);
        ArchVisitor(self).add_imm(d, s, imm);
        self.after_instruction();
    }

    #[inline(always)]
    fn negate_and_add_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.negate_and_add_imm(d, s1, s2);
        ArchVisitor(self).negate_and_add_imm(d, s1, s2);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_imm_indirect_u8(&mut self, base: Reg, offset: u32, value: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_imm_indirect_u8(base, offset, value);
        ArchVisitor(self).store_imm_indirect_u8(base, offset, value);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_imm_indirect_u16(&mut self, base: Reg, offset: u32, value: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_imm_indirect_u16(base, offset, value);
        ArchVisitor(self).store_imm_indirect_u16(base, offset, value);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_imm_indirect_u32(&mut self, base: Reg, offset: u32, value: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_imm_indirect_u32(base, offset, value);
        ArchVisitor(self).store_imm_indirect_u32(base, offset, value);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_indirect_u8(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_indirect_u8(src, base, offset);
        ArchVisitor(self).store_indirect_u8(src, base, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_indirect_u16(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_indirect_u16(src, base, offset);
        ArchVisitor(self).store_indirect_u16(src, base, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_indirect_u32(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_indirect_u32(src, base, offset);
        ArchVisitor(self).store_indirect_u32(src, base, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_imm_u8(&mut self, value: u32, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_imm_u8(value, offset);
        ArchVisitor(self).store_imm_u8(value, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_imm_u16(&mut self, value: u32, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_imm_u16(value, offset);
        ArchVisitor(self).store_imm_u16(value, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_imm_u32(&mut self, value: u32, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_imm_u32(value, offset);
        ArchVisitor(self).store_imm_u32(value, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_u8(&mut self, src: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_u8(src, offset);
        ArchVisitor(self).store_u8(src, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_u16(&mut self, src: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_u16(src, offset);
        ArchVisitor(self).store_u16(src, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn store_u32(&mut self, src: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.store_u32(src, offset);
        ArchVisitor(self).store_u32(src, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_indirect_u8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_indirect_u8(dst, base, offset);
        ArchVisitor(self).load_indirect_u8(dst, base, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_indirect_i8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_indirect_i8(dst, base, offset);
        ArchVisitor(self).load_indirect_i8(dst, base, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_indirect_u16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_indirect_u16(dst, base, offset);
        ArchVisitor(self).load_indirect_u16(dst, base, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_indirect_i16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_indirect_i16(dst, base, offset);
        ArchVisitor(self).load_indirect_i16(dst, base, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_indirect_u32(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_indirect_u32(dst, base, offset);
        ArchVisitor(self).load_indirect_u32(dst, base, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_u8(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_u8(dst, offset);
        ArchVisitor(self).load_u8(dst, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_i8(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_i8(dst, offset);
        ArchVisitor(self).load_i8(dst, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_u16(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_u16(dst, offset);
        ArchVisitor(self).load_u16(dst, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_i16(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_i16(dst, offset);
        ArchVisitor(self).load_i16(dst, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_u32(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_u32(dst, offset);
        ArchVisitor(self).load_u32(dst, offset);
        self.after_instruction();
    }

    #[inline(always)]
    fn branch_less_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_less_unsigned(s1, s2, imm);
        ArchVisitor(self).branch_less_unsigned(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_less_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_less_signed(s1, s2, imm);
        ArchVisitor(self).branch_less_signed(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_or_equal_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_greater_or_equal_unsigned(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_unsigned(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_or_equal_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_greater_or_equal_signed(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_signed(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_eq(s1, s2, imm);
        ArchVisitor(self).branch_eq(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_not_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_not_eq(s1, s2, imm);
        ArchVisitor(self).branch_not_eq(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_eq_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_eq_imm(s1, s2, imm);
        ArchVisitor(self).branch_eq_imm(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_not_eq_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_not_eq_imm(s1, s2, imm);
        ArchVisitor(self).branch_not_eq_imm(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_less_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_less_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_unsigned_imm(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_less_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_less_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_signed_imm(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_greater_or_equal_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_unsigned_imm(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_or_equal_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_greater_or_equal_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_signed_imm(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_less_or_equal_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_less_or_equal_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_or_equal_unsigned_imm(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_less_or_equal_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_less_or_equal_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_or_equal_signed_imm(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_greater_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_unsigned_imm(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.branch_greater_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_signed_imm(s1, s2, imm);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn load_imm(&mut self, dst: Reg, value: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_imm(dst, value);
        ArchVisitor(self).load_imm(dst, value);
        self.after_instruction();
    }

    #[inline(always)]
    fn load_imm_and_jump(&mut self, ra: Reg, value: u32, target: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_imm_and_jump(ra, value, target);
        ArchVisitor(self).load_imm_and_jump(ra, value, target);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn load_imm_and_jump_indirect(&mut self, ra: Reg, base: Reg, value: u32, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.load_imm_and_jump_indirect(ra, base, value, offset);
        ArchVisitor(self).load_imm_and_jump_indirect(ra, base, value, offset);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.jump(target);
        ArchVisitor(self).jump(target);
        self.after_instruction();
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn jump_indirect(&mut self, base: Reg, offset: u32) -> Self::ReturnTy {
        self.before_instruction();
        self.gas_visitor.jump_indirect(base, offset);
        ArchVisitor(self).jump_indirect(base, offset);
        self.after_instruction();
        self.start_new_basic_block();
    }
}

pub(crate) struct CompiledModule<S> where S: Sandbox {
    pub(crate) sandbox_program: S::Program,
    pub(crate) export_trampolines: HashMap<u32, u64>,
    code_offset_to_native_code_offset: Vec<(u32, u32)>,
}

impl<S> CompiledModule<S> where S: Sandbox {
    pub fn machine_code(&self) -> Cow<[u8]> {
        self.sandbox_program.machine_code()
    }

    pub fn code_offset_to_native_code_offset(&self) -> &[(u32, u32)] {
        &self.code_offset_to_native_code_offset
    }
}
