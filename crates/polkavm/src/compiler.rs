use alloc::borrow::Cow;
use core::marker::PhantomData;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use polkavm_assembler::{Assembler, Label};
use polkavm_common::abi::VM_CODE_ADDRESS_ALIGNMENT;
use polkavm_common::program::{InstructionVisitor, Instructions, JumpTable, ParsedInstruction, ProgramExport, RawReg};
use polkavm_common::zygote::{VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH, VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH};

use crate::error::Error;

use crate::config::{GasMeteringKind, ModuleConfig, SandboxKind};
use crate::gas::GasVisitor;
use crate::sandbox::{Sandbox, SandboxInit, SandboxProgram};
use crate::utils::{FlatMap, GuestInit};

#[cfg(target_arch = "x86_64")]
mod amd64;

struct CachePerCompilation {
    assembler: Assembler,
    code_offset_to_label: FlatMap<Label>,
    gas_metering_stub_offsets: Vec<usize>,
    gas_cost_for_basic_block: Vec<u32>,
    export_to_label: HashMap<u32, Label>,
}

struct CachePerModule {
    code_offset_to_native_code_offset: Vec<(u32, u32)>,
    export_trampolines: HashMap<u32, u64>,
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
    code_offset_to_label: FlatMap<Label>,
    debug_trace_execution: bool,
    ecall_label: Label,
    export_to_label: HashMap<u32, Label>,
    exports: &'a [ProgramExport<&'a [u8]>],
    gas_metering: Option<GasMeteringKind>,
    gas_visitor: GasVisitor,
    jump_table_label: Label,
    code_offset_to_native_code_offset: Vec<(u32, u32)>,
    gas_metering_stub_offsets: Vec<usize>,
    gas_cost_for_basic_block: Vec<u32>,
    code_length: u32,
    sbrk_label: Label,
    trace_label: Label,
    trap_label: Label,

    // Not used during compilation, but smuggled until the compilation is finished.
    export_trampolines: HashMap<u32, u64>,

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
        jump_table: JumpTable<'a>,
        code: &'a [u8],
        bitmask: &'a [u8],
        exports: &'a [ProgramExport<&'a [u8]>],
        debug_trace_execution: bool,
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
        let native_code_address = crate::sandbox::SandboxAddressSpace::native_code_address(&address_space);

        let (per_compilation_cache, per_module_cache) = {
            let mut cache = match cache.0.lock() {
                Ok(cache) => cache,
                Err(poison) => poison.into_inner(),
            };

            (cache.per_compilation.pop(), cache.per_module.pop())
        };

        let mut asm;
        let mut gas_metering_stub_offsets: Vec<usize>;
        let mut gas_cost_for_basic_block: Vec<u32>;
        let code_offset_to_label;
        let export_to_label;

        if let Some(per_compilation_cache) = per_compilation_cache {
            asm = per_compilation_cache.assembler;
            code_offset_to_label = FlatMap::new_reusing_memory(per_compilation_cache.code_offset_to_label, code_length);
            gas_metering_stub_offsets = per_compilation_cache.gas_metering_stub_offsets;
            gas_cost_for_basic_block = per_compilation_cache.gas_cost_for_basic_block;
            export_to_label = per_compilation_cache.export_to_label;
        } else {
            asm = Assembler::new();
            code_offset_to_label = FlatMap::new(code_length);
            gas_metering_stub_offsets = Vec::new();
            gas_cost_for_basic_block = Vec::new();
            export_to_label = HashMap::new();
        }

        let code_offset_to_native_code_offset: Vec<(u32, u32)>;
        let export_trampolines;
        if let Some(per_module_cache) = per_module_cache {
            code_offset_to_native_code_offset = per_module_cache.code_offset_to_native_code_offset;
            export_trampolines = per_module_cache.export_trampolines;
        } else {
            code_offset_to_native_code_offset = Vec::with_capacity(code_length as usize);
            export_trampolines = HashMap::with_capacity(exports.len());
        }

        let ecall_label = asm.forward_declare_label();
        let trap_label = asm.forward_declare_label();
        let trace_label = asm.forward_declare_label();
        let jump_table_label = asm.forward_declare_label();
        let sbrk_label = asm.forward_declare_label();

        polkavm_common::static_assert!(polkavm_common::zygote::VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE < u32::MAX);

        if config.gas_metering.is_some() {
            gas_metering_stub_offsets.reserve(code_length as usize);
            gas_cost_for_basic_block.reserve(code_length as usize);
        }

        asm.set_origin(native_code_address);

        let mut visitor = CompilerVisitor {
            gas_visitor: GasVisitor::default(),
            asm,
            exports,
            code_offset_to_label,
            init,
            jump_table,
            code,
            bitmask,
            export_to_label,
            ecall_label,
            trap_label,
            trace_label,
            jump_table_label,
            sbrk_label,
            gas_metering: config.gas_metering,
            debug_trace_execution,
            code_offset_to_native_code_offset,
            gas_metering_stub_offsets,
            gas_cost_for_basic_block,
            code_length,
            export_trampolines,
            _phantom: PhantomData,
        };

        ArchVisitor(&mut visitor).emit_trap_trampoline();
        ArchVisitor(&mut visitor).emit_ecall_trampoline();
        ArchVisitor(&mut visitor).emit_sbrk_trampoline();

        if debug_trace_execution {
            ArchVisitor(&mut visitor).emit_trace_trampoline();
        }

        visitor.force_start_new_basic_block(0);
        Ok((visitor, address_space))
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
        // Finish with a trap in case the code doesn't end with a basic block terminator.
        ArchVisitor(&mut self).trap();

        let epilogue_start = self.asm.len();
        self.code_offset_to_native_code_offset
            .push((self.code_length, epilogue_start as u32));
        self.code_offset_to_native_code_offset.shrink_to_fit();

        let mut gas_metering_stub_offsets = core::mem::take(&mut self.gas_metering_stub_offsets);
        let mut gas_cost_for_basic_block = core::mem::take(&mut self.gas_cost_for_basic_block);
        if self.gas_metering.is_some() {
            log::trace!("Finalizing block costs...");
            assert_eq!(gas_metering_stub_offsets.len(), gas_cost_for_basic_block.len());
            for (&native_code_offset, &cost) in gas_metering_stub_offsets.iter().zip(gas_cost_for_basic_block.iter()) {
                ArchVisitor(&mut self).emit_weight(native_code_offset, cost);
            }
        }

        log::trace!("Emitting export trampolines");
        ArchVisitor(&mut self).emit_export_trampolines();

        let label_sysreturn = ArchVisitor(&mut self).emit_sysreturn();
        let native_code_address = self.asm.origin();

        let jump_table_length = (self.jump_table.len() as usize + 1) * VM_CODE_ADDRESS_ALIGNMENT as usize;
        let mut native_jump_table = S::allocate_jump_table(global, jump_table_length).map_err(Error::from_display)?;
        {
            let native_jump_table = native_jump_table.as_mut();
            native_jump_table[..VM_CODE_ADDRESS_ALIGNMENT as usize].fill(0); // First entry is always invalid.
            native_jump_table[jump_table_length..].fill(0); // Fill in the padding, since the size is page-aligned.

            for (jump_table_index, code_offset) in self.jump_table.iter().enumerate() {
                let mut address = 0;
                if let Some(label) = self.code_offset_to_label.get(code_offset) {
                    if let Some(native_code_offset) = self.asm.get_label_origin_offset(label) {
                        address = native_code_address.checked_add_signed(native_code_offset as i64).expect("overflow") as usize;
                    }
                }

                native_jump_table[(jump_table_index + 1) * VM_CODE_ADDRESS_ALIGNMENT as usize] = address;
            }
        }

        let mut export_trampolines = self.export_trampolines;
        assert!(export_trampolines.is_empty());
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
                sysreturn_address,
            };

            let sandbox_program = S::prepare_program(global, init, address_space).map_err(Error::from_display)?;
            CompiledModule {
                sandbox_program,
                export_trampolines,
                code_offset_to_native_code_offset: self.code_offset_to_native_code_offset,
                cache: cache.clone(),
            }
        };

        {
            let mut cache = match cache.0.lock() {
                Ok(cache) => cache,
                Err(poison) => poison.into_inner(),
            };

            if cache.per_compilation.is_empty() {
                self.asm.clear();
                self.code_offset_to_label.clear();
                self.export_to_label.clear();
                gas_metering_stub_offsets.clear();
                gas_cost_for_basic_block.clear();

                cache.per_compilation.push(CachePerCompilation {
                    assembler: self.asm,
                    code_offset_to_label: self.code_offset_to_label,
                    export_to_label: self.export_to_label,
                    gas_metering_stub_offsets,
                    gas_cost_for_basic_block,
                });
            }
        }

        Ok(module)
    }

    #[inline(always)]
    fn start_new_basic_block(&mut self, code_offset: u32, args_length: u32) {
        if self.gas_metering.is_some() {
            let cost = self.gas_visitor.take_block_cost().unwrap();
            self.gas_cost_for_basic_block.push(cost);
        }

        let next_code_offset = code_offset + args_length + 1;
        let is_last_instruction = next_code_offset as usize >= self.code.len();
        if !is_last_instruction {
            self.force_start_new_basic_block(next_code_offset);
        }
    }

    #[inline(always)]
    fn force_start_new_basic_block(&mut self, next_code_offset: u32) {
        log::trace!("Starting new basic block at: {next_code_offset}");
        if let Some(label) = self.code_offset_to_label.get(next_code_offset) {
            log::trace!("Label: {label} -> {next_code_offset} -> {:08x}", self.asm.current_address());
            self.asm.define_label(label);
        } else {
            let label = self.asm.create_label();
            log::trace!("Label: {label} -> {next_code_offset} -> {:08x}", self.asm.current_address());
            self.code_offset_to_label.insert(next_code_offset, label);
        }

        if let Some(gas_metering) = self.gas_metering {
            self.gas_metering_stub_offsets.push(self.asm.len());
            ArchVisitor(self).emit_gas_metering_stub(gas_metering);
        }
    }

    #[inline(always)]
    fn before_instruction(&mut self, code_offset: u32) {
        self.code_offset_to_native_code_offset.push((code_offset, self.asm.len() as u32));

        if log::log_enabled!(log::Level::Trace) {
            self.trace_compiled_instruction(code_offset);
        }

        if self.debug_trace_execution {
            ArchVisitor(self).trace_execution(code_offset);
        }
    }

    fn after_instruction(&mut self, code_offset: u32) {
        if cfg!(debug_assertions) && !self.debug_trace_execution {
            let offset = self.code_offset_to_native_code_offset.last().unwrap().1 as usize;
            let instruction_length = self.asm.len() - offset;
            if instruction_length > VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH as usize {
                self.panic_on_too_long_instruction(code_offset, instruction_length)
            }
        }
    }

    fn current_instruction(&self, code_offset: u32) -> impl core::fmt::Display {
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
        MaybeInstruction(Instructions::new(self.code, self.bitmask, code_offset).next())
    }

    #[cold]
    fn panic_on_too_long_instruction(&self, code_offset: u32, instruction_length: usize) -> ! {
        panic!(
            "maximum instruction length of {} exceeded with {} bytes for instruction: {}",
            VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH,
            instruction_length,
            self.current_instruction(code_offset),
        );
    }

    #[inline(never)]
    #[cold]
    fn trace_compiled_instruction(&self, code_offset: u32) {
        log::trace!("Compiling {}", self.current_instruction(code_offset));
    }

    fn get_or_forward_declare_label(&mut self, code_offset: u32) -> Option<Label> {
        match self.code_offset_to_label.get(code_offset) {
            Some(label) => Some(label),
            None => {
                if code_offset > self.code_offset_to_label.len() {
                    return None;
                }

                let label = self.asm.forward_declare_label();
                log::trace!("Label: {label} -> {code_offset} (forward declare)");

                self.code_offset_to_label.insert(code_offset, label);
                Some(label)
            }
        }
    }

    fn define_label(&mut self, label: Label) {
        log::trace!("Label: {} -> {:08x}", label, self.asm.current_address());
        self.asm.define_label(label);
    }
}

impl<'a, S> polkavm_common::program::ParsingVisitor for CompilerVisitor<'a, S>
where
    S: Sandbox,
{
    type ReturnTy = ();

    fn load_i32(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.load_u32(code_offset, _args_length, dst, offset)
    }
    fn load_u64(&mut self, _: u32, _: u32, _: RawReg, _: u32) -> Self::ReturnTy {
        todo!()
    }
    fn store_u64(&mut self, _: u32, _: u32, _: RawReg, _: u32) -> Self::ReturnTy {
        todo!()
    }
    fn store_imm_indirect_u64(&mut self, _: u32, _: u32, _: RawReg, _: u32, _: u32) -> Self::ReturnTy {
        todo!()
    }
    fn store_indirect_u64(&mut self, _: u32, _: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        todo!()
    }
    fn load_indirect_i32(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.load_indirect_u32(code_offset, _args_length, dst, base, offset)
    }
    fn load_indirect_u64(&mut self, _: u32, _: u32, _: RawReg, _: RawReg, _: u32) -> Self::ReturnTy {
        todo!()
    }
    fn store_imm_u64(&mut self, _: u32, _: u32, _: u32, _: u32) -> Self::ReturnTy {
        todo!()
    }
    fn addw(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn subw(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn andw(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn xorw(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn orw(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn mulw(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn addw_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        todo!()
    }
    fn andw_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        todo!()
    }
    fn xorw_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        todo!()
    }
    fn orw_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        todo!()
    }
    fn mulw_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        todo!()
    }
    fn set_less_than_signed_w_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        todo!()
    }
    fn set_less_than_unsigned_w_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        todo!()
    }
    fn shift_logical_left_w_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        todo!()
    }
    fn set_less_than_unsigned_w(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn set_less_than_signed_w(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn shift_logical_right_w_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        todo!()
    }
    fn shift_arithmetic_right_w_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        todo!()
    }
    fn set_greater_than_unsigned_w_imm(
        &mut self,
        _code_offset: u32,
        _args_length: u32,
        _d: RawReg,
        _s1: RawReg,
        _s2: u32,
    ) -> Self::ReturnTy {
        todo!()
    }
    fn set_greater_than_signed_w_imm(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        todo!()
    }
    fn shift_logical_left_w(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn shift_logical_right_w(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn shift_arithmetic_right_w(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn shift_logical_right_w_imm_alt(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s2: RawReg, _s1: u32) -> Self::ReturnTy {
        todo!()
    }
    fn shift_arithmetic_right_w_imm_alt(
        &mut self,
        _code_offset: u32,
        _args_length: u32,
        _d: RawReg,
        _s2: RawReg,
        _s1: u32,
    ) -> Self::ReturnTy {
        todo!()
    }
    fn shift_logical_left_w_imm_alt(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s2: RawReg, _s1: u32) -> Self::ReturnTy {
        todo!()
    }
    fn div_unsigned_w(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn div_signed_w(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn rem_signed_w(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }
    fn rem_unsigned_w(&mut self, _code_offset: u32, _args_length: u32, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        todo!()
    }

    #[inline(always)]
    fn trap(&mut self, code_offset: u32, args_length: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.trap();
        ArchVisitor(self).trap();
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn fallthrough(&mut self, code_offset: u32, args_length: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.fallthrough();
        ArchVisitor(self).fallthrough();
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn sbrk(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.sbrk(d, s);
        ArchVisitor(self).sbrk(d, s);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn ecalli(&mut self, code_offset: u32, _args_length: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.ecalli(imm);
        ArchVisitor(self).ecalli(imm);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn set_less_than_unsigned(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_less_than_unsigned(d, s1, s2);
        ArchVisitor(self).set_less_than_unsigned(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn set_less_than_signed(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_less_than_signed(d, s1, s2);
        ArchVisitor(self).set_less_than_signed(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn shift_logical_right(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_right(d, s1, s2);
        ArchVisitor(self).shift_logical_right(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn shift_arithmetic_right(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_arithmetic_right(d, s1, s2);
        ArchVisitor(self).shift_arithmetic_right(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn shift_logical_left(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_left(d, s1, s2);
        ArchVisitor(self).shift_logical_left(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn xor(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.xor(d, s1, s2);
        ArchVisitor(self).xor(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn and(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.and(d, s1, s2);
        ArchVisitor(self).and(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn or(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.or(d, s1, s2);
        ArchVisitor(self).or(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn add(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.add(d, s1, s2);
        ArchVisitor(self).add(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn sub(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.sub(d, s1, s2);
        ArchVisitor(self).sub(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn mul(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul(d, s1, s2);
        ArchVisitor(self).mul(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn mul_upper_signed_signed(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_upper_signed_signed(d, s1, s2);
        ArchVisitor(self).mul_upper_signed_signed(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn mul_upper_unsigned_unsigned(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_upper_unsigned_unsigned(d, s1, s2);
        ArchVisitor(self).mul_upper_unsigned_unsigned(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn mul_upper_signed_unsigned(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_upper_signed_unsigned(d, s1, s2);
        ArchVisitor(self).mul_upper_signed_unsigned(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn div_unsigned(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.div_unsigned(d, s1, s2);
        ArchVisitor(self).div_unsigned(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn div_signed(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.div_signed(d, s1, s2);
        ArchVisitor(self).div_signed(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn rem_unsigned(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.rem_unsigned(d, s1, s2);
        ArchVisitor(self).rem_unsigned(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn rem_signed(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.rem_signed(d, s1, s2);
        ArchVisitor(self).rem_signed(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn mul_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_imm(d, s1, s2);
        ArchVisitor(self).mul_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn mul_upper_signed_signed_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_upper_signed_signed_imm(d, s1, s2);
        ArchVisitor(self).mul_upper_signed_signed_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn mul_upper_unsigned_unsigned_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.mul_upper_unsigned_unsigned_imm(d, s1, s2);
        ArchVisitor(self).mul_upper_unsigned_unsigned_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn set_less_than_unsigned_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_less_than_unsigned_imm(d, s1, s2);
        ArchVisitor(self).set_less_than_unsigned_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn set_less_than_signed_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_less_than_signed_imm(d, s1, s2);
        ArchVisitor(self).set_less_than_signed_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn set_greater_than_unsigned_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_greater_than_unsigned_imm(d, s1, s2);
        ArchVisitor(self).set_greater_than_unsigned_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn set_greater_than_signed_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.set_greater_than_signed_imm(d, s1, s2);
        ArchVisitor(self).set_greater_than_signed_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn shift_logical_right_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_right_imm(d, s1, s2);
        ArchVisitor(self).shift_logical_right_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn shift_arithmetic_right_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_arithmetic_right_imm(d, s1, s2);
        ArchVisitor(self).shift_arithmetic_right_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn shift_logical_left_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_left_imm(d, s1, s2);
        ArchVisitor(self).shift_logical_left_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn shift_logical_right_imm_alt(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_right_imm_alt(d, s2, s1);
        ArchVisitor(self).shift_logical_right_imm_alt(d, s2, s1);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn shift_arithmetic_right_imm_alt(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_arithmetic_right_imm_alt(d, s2, s1);
        ArchVisitor(self).shift_arithmetic_right_imm_alt(d, s2, s1);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn shift_logical_left_imm_alt(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.shift_logical_left_imm_alt(d, s2, s1);
        ArchVisitor(self).shift_logical_left_imm_alt(d, s2, s1);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn or_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.or_imm(d, s, imm);
        ArchVisitor(self).or_imm(d, s, imm);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn and_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.and_imm(d, s, imm);
        ArchVisitor(self).and_imm(d, s, imm);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn xor_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.xor_imm(d, s, imm);
        ArchVisitor(self).xor_imm(d, s, imm);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn move_reg(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.move_reg(d, s);
        ArchVisitor(self).move_reg(d, s);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn cmov_if_zero(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.cmov_if_zero(d, s, c);
        ArchVisitor(self).cmov_if_zero(d, s, c);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn cmov_if_not_zero(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.cmov_if_not_zero(d, s, c);
        ArchVisitor(self).cmov_if_not_zero(d, s, c);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn cmov_if_zero_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.cmov_if_zero_imm(d, c, s);
        ArchVisitor(self).cmov_if_zero_imm(d, c, s);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn cmov_if_not_zero_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.cmov_if_not_zero_imm(d, c, s);
        ArchVisitor(self).cmov_if_not_zero_imm(d, c, s);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn add_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.add_imm(d, s, imm);
        ArchVisitor(self).add_imm(d, s, imm);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn negate_and_add_imm(&mut self, code_offset: u32, _args_length: u32, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.negate_and_add_imm(d, s1, s2);
        ArchVisitor(self).negate_and_add_imm(d, s1, s2);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_imm_indirect_u8(&mut self, code_offset: u32, _args_length: u32, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_indirect_u8(base, offset, value);
        ArchVisitor(self).store_imm_indirect_u8(base, offset, value);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_imm_indirect_u16(&mut self, code_offset: u32, _args_length: u32, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_indirect_u16(base, offset, value);
        ArchVisitor(self).store_imm_indirect_u16(base, offset, value);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_imm_indirect_u32(&mut self, code_offset: u32, _args_length: u32, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_indirect_u32(base, offset, value);
        ArchVisitor(self).store_imm_indirect_u32(base, offset, value);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_indirect_u8(&mut self, code_offset: u32, _args_length: u32, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_indirect_u8(src, base, offset);
        ArchVisitor(self).store_indirect_u8(src, base, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_indirect_u16(&mut self, code_offset: u32, _args_length: u32, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_indirect_u16(src, base, offset);
        ArchVisitor(self).store_indirect_u16(src, base, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_indirect_u32(&mut self, code_offset: u32, _args_length: u32, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_indirect_u32(src, base, offset);
        ArchVisitor(self).store_indirect_u32(src, base, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_imm_u8(&mut self, code_offset: u32, _args_length: u32, value: u32, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_u8(value, offset);
        ArchVisitor(self).store_imm_u8(value, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_imm_u16(&mut self, code_offset: u32, _args_length: u32, value: u32, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_u16(value, offset);
        ArchVisitor(self).store_imm_u16(value, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_imm_u32(&mut self, code_offset: u32, _args_length: u32, value: u32, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_imm_u32(value, offset);
        ArchVisitor(self).store_imm_u32(value, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_u8(&mut self, code_offset: u32, _args_length: u32, src: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_u8(src, offset);
        ArchVisitor(self).store_u8(src, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_u16(&mut self, code_offset: u32, _args_length: u32, src: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_u16(src, offset);
        ArchVisitor(self).store_u16(src, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn store_u32(&mut self, code_offset: u32, _args_length: u32, src: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.store_u32(src, offset);
        ArchVisitor(self).store_u32(src, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_indirect_u8(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_indirect_u8(dst, base, offset);
        ArchVisitor(self).load_indirect_u8(dst, base, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_indirect_i8(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_indirect_i8(dst, base, offset);
        ArchVisitor(self).load_indirect_i8(dst, base, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_indirect_u16(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_indirect_u16(dst, base, offset);
        ArchVisitor(self).load_indirect_u16(dst, base, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_indirect_i16(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_indirect_i16(dst, base, offset);
        ArchVisitor(self).load_indirect_i16(dst, base, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_indirect_u32(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_indirect_u32(dst, base, offset);
        ArchVisitor(self).load_indirect_u32(dst, base, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_u8(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_u8(dst, offset);
        ArchVisitor(self).load_u8(dst, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_i8(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_i8(dst, offset);
        ArchVisitor(self).load_i8(dst, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_u16(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_u16(dst, offset);
        ArchVisitor(self).load_u16(dst, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_i16(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_i16(dst, offset);
        ArchVisitor(self).load_i16(dst, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_u32(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_u32(dst, offset);
        ArchVisitor(self).load_u32(dst, offset);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn branch_less_unsigned(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_unsigned(s1, s2, imm);
        ArchVisitor(self).branch_less_unsigned(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_signed(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_signed(s1, s2, imm);
        ArchVisitor(self).branch_less_signed(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_or_equal_unsigned(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_or_equal_unsigned(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_unsigned(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_or_equal_signed(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_or_equal_signed(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_signed(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_eq(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_eq(s1, s2, imm);
        ArchVisitor(self).branch_eq(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_not_eq(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_not_eq(s1, s2, imm);
        ArchVisitor(self).branch_not_eq(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_eq_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_eq_imm(s1, s2, imm);
        ArchVisitor(self).branch_eq_imm(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_not_eq_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_not_eq_imm(s1, s2, imm);
        ArchVisitor(self).branch_not_eq_imm(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_unsigned_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_unsigned_imm(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_signed_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_signed_imm(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
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
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_or_equal_signed_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_or_equal_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_or_equal_signed_imm(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_or_equal_unsigned_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_or_equal_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_or_equal_unsigned_imm(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_less_or_equal_signed_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_less_or_equal_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_less_or_equal_signed_imm(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_unsigned_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_unsigned_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_unsigned_imm(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn branch_greater_signed_imm(&mut self, code_offset: u32, args_length: u32, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.branch_greater_signed_imm(s1, s2, imm);
        ArchVisitor(self).branch_greater_signed_imm(s1, s2, imm);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn load_imm(&mut self, code_offset: u32, _args_length: u32, dst: RawReg, value: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_imm(dst, value);
        ArchVisitor(self).load_imm(dst, value);
        self.after_instruction(code_offset);
    }

    #[inline(always)]
    fn load_imm_and_jump(&mut self, code_offset: u32, args_length: u32, ra: RawReg, value: u32, target: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.load_imm_and_jump(ra, value, target);
        ArchVisitor(self).load_imm_and_jump(ra, value, target);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
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
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn jump(&mut self, code_offset: u32, args_length: u32, target: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.jump(target);
        ArchVisitor(self).jump(target);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }

    #[inline(always)]
    fn jump_indirect(&mut self, code_offset: u32, args_length: u32, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.before_instruction(code_offset);
        self.gas_visitor.jump_indirect(base, offset);
        ArchVisitor(self).jump_indirect(base, offset);
        self.after_instruction(code_offset);
        self.start_new_basic_block(code_offset, args_length);
    }
}

pub(crate) struct CompiledModule<S>
where
    S: Sandbox,
{
    pub(crate) sandbox_program: S::Program,
    pub(crate) export_trampolines: HashMap<u32, u64>,
    code_offset_to_native_code_offset: Vec<(u32, u32)>,
    cache: CompilerCache,
}

impl<S> CompiledModule<S>
where
    S: Sandbox,
{
    pub fn machine_code(&self) -> Cow<[u8]> {
        self.sandbox_program.machine_code()
    }

    pub fn code_offset_to_native_code_offset(&self) -> &[(u32, u32)] {
        &self.code_offset_to_native_code_offset
    }
}

impl<S> Drop for CompiledModule<S>
where
    S: Sandbox,
{
    fn drop(&mut self) {
        let mut code_offset_to_native_code_offset = core::mem::take(&mut self.code_offset_to_native_code_offset);
        let mut export_trampolines = core::mem::take(&mut self.export_trampolines);
        {
            let mut cache = match self.cache.0.lock() {
                Ok(cache) => cache,
                Err(poison) => poison.into_inner(),
            };

            if cache.per_module.is_empty() {
                code_offset_to_native_code_offset.clear();
                export_trampolines.clear();
                cache.per_module.push(CachePerModule {
                    code_offset_to_native_code_offset,
                    export_trampolines,
                });
            }
        }
    }
}
