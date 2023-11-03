use std::borrow::Cow;
use std::collections::HashMap;

use polkavm_assembler::{Assembler, Label};
use polkavm_common::error::{ExecutionError, Trap};
use polkavm_common::init::GuestProgramInit;
use polkavm_common::program::{InstructionVisitor, Opcode, ProgramExport, RawInstruction};
use polkavm_common::zygote::{
    VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH, VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH,
};

use crate::api::{BackendAccess, ExecutionConfig, Module, OnHostcall, AsCompiledModule};
use crate::error::{bail, Error};

use crate::sandbox::{Sandbox, SandboxConfig, SandboxProgram, SandboxProgramInit, ExecuteArgs};
use crate::config::SandboxKind;

#[cfg(target_arch = "x86_64")]
mod amd64;

struct Compiler<'a> {
    asm: Assembler,
    exports: &'a [ProgramExport<'a>],
    instructions: &'a [RawInstruction],
    pc_to_label: HashMap<u32, Label>,
    pc_to_label_pending: HashMap<u32, Label>,
    next_instruction: Option<RawInstruction>,
    max_jump_target: u32,
    jump_table: Vec<u8>,
    export_to_label: HashMap<u32, Label>,
    export_trampolines: Vec<u64>,
    debug_trace_execution: bool,
    ecall_label: Label,
    trap_label: Label,
    trace_label: Label,
    jump_table_label: Label,
    sandbox_kind: SandboxKind,
    native_code_address: u64,

    /// Whether we're compiling a 64-bit program. Currently totally broken and mostly unimplemented.
    // TODO: Fix this.
    regs_are_64bit: bool,
}

struct CompilationResult<'a> {
    code: &'a [u8],
    jump_table: &'a [u8],
    export_trampolines: &'a [u64],
    sysreturn_address: u64,
    nth_instruction_to_code_offset_map: Vec<u32>,
}

impl<'a> Compiler<'a> {
    fn new(
        instructions: &'a [RawInstruction],
        exports: &'a [ProgramExport<'a>],
        sandbox_kind: SandboxKind,
        debug_trace_execution: bool,
        native_code_address: u64,
    ) -> Self {
        let mut asm = Assembler::new();
        let ecall_label = asm.forward_declare_label();
        let trap_label = asm.forward_declare_label();
        let trace_label = asm.forward_declare_label();
        let jump_table_label = asm.forward_declare_label();

        Compiler {
            asm,
            instructions,
            exports,
            pc_to_label: Default::default(),
            pc_to_label_pending: Default::default(),
            next_instruction: None,
            max_jump_target: 0,
            jump_table: Default::default(),
            export_to_label: Default::default(),
            export_trampolines: Default::default(),
            ecall_label,
            trap_label,
            trace_label,
            jump_table_label,
            sandbox_kind,
            native_code_address,
            regs_are_64bit: false,
            debug_trace_execution,
        }
    }

    fn finalize(&mut self) -> Result<CompilationResult, Error> {
        assert_eq!(self.asm.len(), 0);
        self.asm.set_origin(self.native_code_address);

        let mut nth_instruction_to_code_offset_map: Vec<u32> = Vec::with_capacity(self.instructions.len());
        polkavm_common::static_assert!(polkavm_common::zygote::VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE < u32::MAX);

        for nth_instruction in 0..self.instructions.len() {
            self.next_instruction = self.instructions.get(nth_instruction + 1).copied();

            let initial_length = self.asm.len();
            nth_instruction_to_code_offset_map.push(initial_length as u32);

            let instruction = self.instructions[nth_instruction];
            log::trace!("Compiling {}/{}: {}", nth_instruction, self.instructions.len() - 1, instruction);

            if self.debug_trace_execution && !matches!(instruction.op(), Opcode::jump_target) {
                self.trace_execution(nth_instruction);
            }

            instruction.visit(self).map_err(Error::from_static_str)?;

            if self.debug_trace_execution && matches!(instruction.op(), Opcode::jump_target) {
                self.trace_execution(nth_instruction);
            }

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
        self.trap().map_err(Error::from_static_str)?;

        if self.debug_trace_execution {
            self.emit_trace_trampoline();
        }

        self.emit_trap_trampoline();
        self.emit_ecall_trampoline();
        self.emit_export_trampolines();

        let label_sysreturn = self.emit_sysreturn();

        if !self.pc_to_label_pending.is_empty() {
            for pc in self.pc_to_label_pending.keys() {
                log::debug!("Missing jump target: @{:x}", pc * 4);
            }

            bail!("program is missing {} jump target(s)", self.pc_to_label_pending.len());
        }

        let native_pointer_size = core::mem::size_of::<usize>();
        self.jump_table.resize((self.max_jump_target as usize + 1) * native_pointer_size, 0);

        for (pc, label) in self.pc_to_label.drain() {
            let pc = pc as usize;
            let range = pc * native_pointer_size..(pc + 1) * native_pointer_size;
            let address = self.native_code_address
                .checked_add_signed(self.asm.get_label_offset(label) as i64)
                .expect("overflow");

            log::trace!("Jump table: [0x{:x}] = 0x{:x}", self.native_code_address + range.start as u64, address);
            self.jump_table[range].copy_from_slice(&address.to_ne_bytes());
        }

        self.export_trampolines.reserve(self.exports.len());
        for export in self.exports {
            let label = self.export_to_label.get(&export.address()).unwrap();
            let native_address = self.native_code_address
                .checked_add_signed(self.asm.get_label_offset(*label) as i64)
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
            .checked_add_signed(self.asm.get_label_offset(label_sysreturn) as i64)
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

    fn push(&mut self, inst: impl polkavm_assembler::Instruction) {
        self.asm.push(inst);
    }

    fn get_or_forward_declare_label(&mut self, pc: u32) -> Label {
        match self.pc_to_label.get(&pc) {
            Some(label) => *label,
            None => match self.pc_to_label_pending.get(&pc) {
                Some(label) => *label,
                None => {
                    let label = self.asm.forward_declare_label();
                    self.pc_to_label_pending.insert(pc, label);
                    label
                }
            },
        }
    }

    fn next_instruction_jump_target(&self) -> Option<u32> {
        let inst = self.next_instruction?;
        if inst.raw_op() == Opcode::jump_target as u8 {
            Some(inst.raw_imm_or_reg().checked_mul(4)?)
        } else {
            None
        }
    }
}

pub struct CompiledModule<S> where S: Sandbox {
    sandbox_program: S::Program,
    export_trampolines: Vec<u64>,
    nth_instruction_to_code_offset_map: Vec<u32>,
}

impl<S> CompiledModule<S> where S: Sandbox {
    pub fn new(
        instructions: &[RawInstruction],
        exports: &[ProgramExport],
        init: GuestProgramInit,
        debug_trace_execution: bool,
    ) -> Result<Self, Error> {
        crate::sandbox::assert_native_page_size();

        let address_space = S::reserve_address_space().map_err(Error::from_display)?;
        let native_code_address = crate::sandbox::SandboxAddressSpace::native_code_address(&address_space);
        let mut program_assembler = Compiler::new(instructions, exports, S::KIND, debug_trace_execution, native_code_address);
        let result = program_assembler.finalize()?;

        let init = SandboxProgramInit::new(init)
            .with_code(result.code)
            .with_jump_table(result.jump_table)
            .with_sysreturn_address(result.sysreturn_address);

        let sandbox_program = S::prepare_program(init, address_space).map_err(Error::from_display)?;
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

pub(crate) struct CompiledInstance<S> {
    module: Module,
    sandbox: S,
}

impl<S> CompiledInstance<S> where S: Sandbox, Module: AsCompiledModule<S> {
    pub fn new(module: Module) -> Result<CompiledInstance<S>, Error> {
        let compiled_module = module
            .as_compiled_module()
            .expect("internal error: tried to spawn a compiled instance without a compiled module");

        let mut sandbox_config = S::Config::default();
        sandbox_config.enable_logger(cfg!(test) || module.is_debug_trace_execution_enabled());

        // TODO: This is really slow as it will always spawn a new process from scratch. Cache this.
        let mut sandbox = S::spawn(&sandbox_config)
            .map_err(Error::from_display)
            .map_err(|error| error.context("instantiation failed: failed to create a sandbox"))?;

        let mut args = ExecuteArgs::new();
        args.set_program(&compiled_module.sandbox_program);
        sandbox
            .execute(args)
            .map_err(Error::from_display)
            .map_err(|error| error.context("instantiation failed: failed to upload the program into the sandbox"))?;

        Ok(CompiledInstance { module, sandbox })
    }

    pub fn call(&mut self, export_index: usize, on_hostcall: OnHostcall, config: &ExecutionConfig) -> Result<(), ExecutionError<Error>> {
        let compiled_module = self
            .module
            .as_compiled_module()
            .expect("internal error: tried to call into a compiled instance without a compiled module");

        let address = compiled_module.export_trampolines[export_index];
        let mut exec_args = ExecuteArgs::<S>::new();

        if config.reset_memory_after_execution {
            exec_args.set_reset_memory_after_execution();
        }

        if config.clear_program_after_execution {
            exec_args.set_clear_program_after_execution();
        }

        exec_args.set_call(address);
        exec_args.set_initial_regs(&config.initial_regs);

        fn wrap_on_hostcall<S>(on_hostcall: OnHostcall<'_>) -> impl for <'r> FnMut(u64, S::Access<'r>) -> Result<(), Trap> + '_ where S: Sandbox {
            move |hostcall, access| {
                let access: BackendAccess = access.into();
                on_hostcall(hostcall, access)
            }
        }


        let mut on_hostcall = wrap_on_hostcall(on_hostcall);
        exec_args.set_on_hostcall(&mut on_hostcall);

        match self.sandbox.execute(exec_args) {
            Ok(()) => Ok(()),
            Err(ExecutionError::Error(error)) => Err(ExecutionError::Error(Error::from_display(error))),
            Err(ExecutionError::Trap(trap)) => Err(ExecutionError::Trap(trap)),
        }
    }

    pub fn access(&'_ mut self) -> S::Access<'_> {
        self.sandbox.access()
    }

    pub fn sandbox(&self) -> &S {
        &self.sandbox
    }
}
