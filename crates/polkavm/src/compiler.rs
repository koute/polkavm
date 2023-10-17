use std::collections::HashMap;

use polkavm_assembler::{Assembler, Label};
use polkavm_common::error::{ExecutionError, Trap};
use polkavm_common::init::GuestProgramInit;
use polkavm_common::program::{InstructionVisitor, Opcode, ProgramExport, RawInstruction, Reg};
use polkavm_common::utils::{Access, AsUninitSliceMut};
use polkavm_common::zygote::{
    VM_ADDR_JUMP_TABLE, VM_ADDR_NATIVE_CODE, VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH, VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH,
};

use crate::api::{BackendAccess, ExecutionConfig, Module, OnHostcall};
use crate::error::{bail, Error};
use crate::sandbox_linux::{ExecuteArgs, Sandbox, SandboxAccess, SandboxConfig, SandboxProgram, SandboxProgramInit};

pub const IS_SUPPORTED: bool = true;

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

    /// Whether we're compiling a 64-bit program. Currently totally broken and mostly unimplemented.
    // TODO: Fix this.
    regs_are_64bit: bool,
}

struct CompilationResult<'a> {
    code: &'a [u8],
    jump_table: &'a [u8],
    export_trampolines: &'a [u64],
    sysreturn_address: u64,
}

impl<'a> Compiler<'a> {
    fn new(instructions: &'a [RawInstruction], exports: &'a [ProgramExport<'a>], debug_trace_execution: bool) -> Self {
        let mut asm = Assembler::new();
        let ecall_label = asm.forward_declare_label();
        let trap_label = asm.forward_declare_label();
        let trace_label = asm.forward_declare_label();

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
            regs_are_64bit: false,
            debug_trace_execution,
        }
    }

    fn finalize(&mut self) -> Result<CompilationResult, Error> {
        assert_eq!(self.asm.len(), 0);
        self.asm.set_origin(VM_ADDR_NATIVE_CODE);

        for nth_instruction in 0..self.instructions.len() {
            self.next_instruction = self.instructions.get(nth_instruction + 1).copied();

            let initial_length = self.asm.len();
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
            let address = VM_ADDR_NATIVE_CODE
                .checked_add_signed(self.asm.get_label_offset(label) as i64)
                .expect("overflow");
            log::trace!("Jump table: [0x{:x}] = 0x{:x}", VM_ADDR_JUMP_TABLE + range.start as u64, address);
            self.jump_table[range].copy_from_slice(&address.to_ne_bytes());
        }

        self.export_trampolines.reserve(self.exports.len());
        for export in self.exports {
            let label = self.export_to_label.get(&export.address()).unwrap();
            let native_address = VM_ADDR_NATIVE_CODE
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

        let sysreturn_address = VM_ADDR_NATIVE_CODE
            .checked_add_signed(self.asm.get_label_offset(label_sysreturn) as i64)
            .expect("overflow");
        let code = self.asm.finalize();
        Ok(CompilationResult {
            code,
            jump_table: &self.jump_table,
            export_trampolines: &self.export_trampolines,
            sysreturn_address,
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

pub struct CompiledModule {
    sandbox_program: SandboxProgram,
    export_trampolines: Vec<u64>,
}

impl CompiledModule {
    pub fn new(
        instructions: &[RawInstruction],
        exports: &[ProgramExport],
        init: GuestProgramInit,
        debug_trace_execution: bool,
    ) -> Result<Self, Error> {
        let mut program_assembler = Compiler::new(instructions, exports, debug_trace_execution);
        let result = program_assembler.finalize()?;

        let init = SandboxProgramInit::new(init)
            .with_code(result.code)
            .with_jump_table(result.jump_table)
            .with_sysreturn_address(result.sysreturn_address);

        let sandbox_program = SandboxProgram::new(init).map_err(Error::from_display)?;
        let export_trampolines = result.export_trampolines.to_owned();

        Ok(CompiledModule {
            sandbox_program,
            export_trampolines,
        })
    }
}

pub struct CompiledAccess<'a>(SandboxAccess<'a>);

impl<'a> Access<'a> for CompiledAccess<'a> {
    type Error = Trap;

    fn get_reg(&self, reg: Reg) -> u32 {
        self.0.get_reg(reg)
    }

    fn set_reg(&mut self, reg: Reg, value: u32) {
        self.0.set_reg(reg, value)
    }

    fn read_memory_into_slice<'slice, T>(&self, address: u32, buffer: &'slice mut T) -> Result<&'slice mut [u8], Self::Error>
    where
        T: ?Sized + AsUninitSliceMut,
    {
        let buffer = buffer.as_uninit_slice_mut();
        let length = buffer.len();
        self.0.read_memory_into_slice(address, buffer).map_err(|error| {
            log::error!(
                "Out of range read in 0x{:x}-0x{:x} ({} bytes): {error}",
                address,
                (address as u64 + length as u64) as u32,
                length
            );
            Trap::default()
        })
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
        self.0.write_memory(address, data).map_err(|error| {
            log::error!(
                "Out of range write in 0x{:x}-0x{:x} ({} bytes): {error}",
                address,
                (address as u64 + data.len() as u64) as u32,
                data.len()
            );
            Trap::default()
        })
    }

    fn program_counter(&self) -> Option<u32> {
        self.0.program_counter()
    }

    fn native_program_counter(&self) -> Option<u64> {
        self.0.native_program_counter()
    }
}

pub(crate) struct CompiledInstance {
    module: Module,
    sandbox: Sandbox,
}

impl CompiledInstance {
    pub fn new(module: Module) -> Result<CompiledInstance, Error> {
        let compiled_module = module
            .compiled_module()
            .expect("internal error: tried to spawn a compiled instance without a compiled module");
        let mut sandbox_config = SandboxConfig::new();
        sandbox_config.enable_logger(cfg!(test) || module.is_debug_trace_execution_enabled());

        // TODO: This is really slow as it will always spawn a new process from scratch. Cache this.
        let mut sandbox = Sandbox::spawn(&sandbox_config)
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
            .compiled_module()
            .expect("internal error: tried to call into a compiled instance without a compiled module");

        let address = compiled_module.export_trampolines[export_index];
        let mut exec_args = ExecuteArgs::new();

        if config.reset_memory_after_execution {
            exec_args.set_reset_memory_after_execution();
        }

        if config.clear_program_after_execution {
            exec_args.set_clear_program_after_execution();
        }

        exec_args.set_call(address);
        exec_args.set_initial_regs(&config.initial_regs);
        let mut on_hostcall = move |hostcall: u64, access: SandboxAccess| -> Result<(), Trap> {
            on_hostcall(hostcall, BackendAccess::Compiled(CompiledAccess(access)))
        };
        exec_args.set_on_hostcall(&mut on_hostcall);
        match self.sandbox.execute(exec_args) {
            Ok(()) => Ok(()),
            Err(ExecutionError::Error(error)) => Err(ExecutionError::Error(Error::from_display(error))),
            Err(ExecutionError::Trap(trap)) => Err(ExecutionError::Trap(trap)),
        }
    }

    pub fn access(&mut self) -> CompiledAccess {
        CompiledAccess(self.sandbox.access())
    }
}
