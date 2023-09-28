use crate::api::BackendAccess;
use crate::api::ExecutionConfig;
use crate::api::Module;
use crate::interpreter::{InterpretedInstance, InterpreterContext};
use crate::source_cache::SourceCache;
use core::mem::MaybeUninit;
use polkavm_common::error::Trap;
use polkavm_common::program::{Opcode, ProgramExport, Reg};
use polkavm_common::utils::Access;

pub(crate) struct Tracer {
    module: Module,
    source_cache: SourceCache,
    crosscheck_interpreter: Option<InterpretedInstance>,
    crosscheck_reg: Option<(Reg, u32)>,
    crosscheck_store: Option<(u32, u32)>,
    crosscheck_store_bytes: [u8; 8],
    crosscheck_reset_memory_after_execution: bool,
    current_function: Option<usize>,
    current_inline_stack: Vec<usize>,

    enable_store_crosschecks: bool,
}

impl Tracer {
    pub fn new(module: Module) -> Self {
        Tracer {
            crosscheck_interpreter: if module.compiled_module().is_some() {
                InterpretedInstance::new(module.clone()).ok()
            } else {
                None
            },
            module,
            source_cache: SourceCache::default(),
            crosscheck_reg: None,
            crosscheck_store: None,
            crosscheck_store_bytes: Default::default(),
            crosscheck_reset_memory_after_execution: false,
            current_function: None,
            current_inline_stack: Vec::new(),

            // TODO: Make this configurable.
            enable_store_crosschecks: false,
        }
    }

    pub fn on_before_call(&mut self, export_index: usize, export: &ProgramExport, config: &ExecutionConfig) {
        let target = self
            .module
            .instruction_by_jump_target(export.address())
            .expect("internal error: invalid export address");
        log::trace!("Calling export: '{}' (at #{})", export.prototype().name(), target);

        if let Some(ref mut interpreter) = self.crosscheck_interpreter {
            self.crosscheck_reset_memory_after_execution = config.reset_memory_after_execution;
            interpreter.prepare_for_call(export_index, config);
        }
    }

    pub fn on_after_call(&mut self) {
        if let Some(ref mut interpreter) = self.crosscheck_interpreter {
            if self.crosscheck_reset_memory_after_execution {
                interpreter.reset_memory();
            }
        }
    }

    pub fn on_trace(&mut self, access: &mut BackendAccess) -> Result<(), Trap> {
        assert!(self.module.is_debug_trace_execution_enabled());

        self.crosscheck_last_instruction(access)?;

        let program_counter = access
            .program_counter()
            .expect("internal error: tracer called without valid program counter");
        self.trace_current_instruction_source(program_counter, access);

        let instruction = self.module.instructions()[program_counter as usize];
        if let Some(native_address) = access.native_program_counter() {
            log::trace!("0x{native_address:x}: #{program_counter}: {instruction}");
        } else {
            log::trace!("#{program_counter}: {instruction}");
        }

        self.step_crosscheck_interpreter(program_counter)?;
        Ok(())
    }

    pub fn on_set_reg_in_hostcall(&mut self, reg: Reg, value: u32) {
        if let Some(ref mut interpreter) = self.crosscheck_interpreter {
            interpreter.access().set_reg(reg, value);
        }
    }

    pub fn on_memory_write_in_hostcall(&mut self, address: u32, data: &[u8], success: bool) -> Result<(), Trap> {
        if let Some(ref mut interpreter) = self.crosscheck_interpreter {
            let expected_result = interpreter.access().write_memory(address, data);
            let expected_success = expected_result.is_ok();
            if success != expected_result.is_ok() {
                let address_end = address as u64 + data.len() as u64;
                log::error!("Memory write in hostcall mismatch when writing to 0x{address:x}..0x{address_end:x}! (crosscheck interpreter = {expected_success}, actual = {success})");
            }
        }

        Ok(())
    }

    fn crosscheck_last_instruction(&mut self, access: &mut BackendAccess) -> Result<(), Trap> {
        if let Some((reg, expected_value)) = self.crosscheck_reg.take() {
            let value = access.get_reg(reg);
            if value != expected_value {
                log::error!("Register value mismatch! Crosscheck interpreter has {reg} = 0x{expected_value:x}, actual execution has {reg} = 0x{value:x}");
                return Err(Trap::default());
            }
        }

        if let Some((address, length)) = self.crosscheck_store.take() {
            let bytes_expected = &self.crosscheck_store_bytes[..length as usize];
            let mut bytes_actual: [MaybeUninit<u8>; 8] = [MaybeUninit::uninit(); 8];
            let bytes_actual = match access.read_memory_into_slice(address, &mut bytes_actual[..length as usize]) {
                Ok(bytes_actual) => bytes_actual,
                Err(error) => {
                    log::error!(
                        "Store value mismatch! Couldn't fetch memory at [0x{address:x}..+{length}] from the actual execution: {error}"
                    );
                    return Err(Trap::default());
                }
            };
            if bytes_actual != bytes_expected {
                log::error!("Store value mismatch! Crosscheck interpreter has [0x{address:x}..+{length}] = {bytes_expected:?}, actual execution has [0x{address:x}..+{length}] = {bytes_actual:?}");
                return Err(Trap::default());
            }
        }

        Ok(())
    }

    fn trace_current_instruction_source(&mut self, program_counter: u32, access: &mut BackendAccess) {
        #[cfg(not(windows))]
        const VT_DARK: &str = "\x1B[1;30m";
        #[cfg(not(windows))]
        const VT_GREEN: &str = "\x1B[1;32m";
        #[cfg(not(windows))]
        const VT_RESET: &str = "\x1B[0m";

        #[cfg(windows)]
        const VT_DARK: &str = "";
        #[cfg(windows)]
        const VT_GREEN: &str = "";
        #[cfg(windows)]
        const VT_RESET: &str = "";

        let Some(blob) = self.module.blob() else { return };
        let info = match blob.get_function_debug_info(program_counter) {
            Err(error) => {
                log::warn!("Failed to get debug info for instruction #{program_counter}: {error}");
                self.current_function = None;
                self.current_inline_stack.clear();
                return;
            }
            Ok(None) => {
                log::trace!("  (f) (none)");
                self.current_function = None;
                self.current_inline_stack.clear();
                return;
            }
            // TODO: The compiler can merge multiple functions into one. Make `get_function_debug_info` return an iterator and handle it.
            Ok(Some(info)) => info,
        };

        if self.current_function != Some(info.entry_index()) {
            self.current_function = Some(info.entry_index());
            let offset = program_counter - info.instruction_range().start;
            let function_name = info.full_name();
            if let Some(location) = info.location() {
                log::trace!("  (f) '{function_name}' + {offset} {VT_DARK}[{location}]{VT_RESET}");
                if offset == 0 {
                    if let Some(source_line) = self.source_cache.lookup_source_line(location) {
                        log::trace!("   | {VT_GREEN}{source_line}{VT_RESET}");
                    }

                    for reg in [Reg::A0, Reg::A1, Reg::A2, Reg::A3, Reg::A4, Reg::A5] {
                        let value = access.get_reg(reg);
                        log::trace!("{reg} = 0x{value:x}");
                    }
                }
            } else {
                log::trace!("  (f) '{function_name}' + {offset}");
            }
        }

        // TODO: This is inefficient.
        let mut depth = 0;
        for (nth_inline, inline_info) in info.inlined().enumerate() {
            let inline_info = match inline_info {
                Ok(inline_info) => inline_info,
                Err(error) => {
                    log::warn!("Failed to get inline frame for instruction #{program_counter}: {error}");
                    break;
                }
            };

            let inline_range = inline_info.instruction_range();
            if !inline_range.contains(&program_counter) {
                continue;
            }

            if self.current_inline_stack.len() > depth {
                if self.current_inline_stack[depth] == nth_inline {
                    depth += 1;
                    continue;
                } else {
                    self.current_inline_stack.truncate(depth);
                }
            }

            assert_eq!(self.current_inline_stack.len(), depth);
            self.current_inline_stack.push(nth_inline);

            let inline_offset = program_counter - inline_info.instruction_range().start;
            let inline_function_name = inline_info.full_name();
            if let Some(inline_location) = inline_info.location() {
                log::trace!("  ({depth}) '{inline_function_name}' + {inline_offset} {VT_DARK}[{inline_location}]{VT_RESET}");
                if let Some(inline_source_line) = self.source_cache.lookup_source_line(inline_location) {
                    log::trace!("   | {VT_GREEN}{inline_source_line}{VT_RESET}");
                }
            } else {
                log::trace!("  ({depth}) '{inline_function_name}' + {inline_offset}");
            }

            depth += 1;
        }
    }

    fn step_crosscheck_interpreter(&mut self, program_counter: u32) -> Result<(), Trap> {
        let Some(ref mut interpreter) = self.crosscheck_interpreter else {
            return Ok(());
        };

        let expected_program_counter = interpreter.access().program_counter().unwrap();
        if expected_program_counter != program_counter {
            log::error!("Program counter mismatch! Crosscheck interpreter returned #{expected_program_counter}, actual execution returned #{program_counter}");
            return Err(Trap::default());
        }

        let instruction = self.module.instructions()[program_counter as usize];
        if matches!(instruction.op(), Opcode::trap) {
            return Ok(());
        }

        let mut on_hostcall = |_hostcall: u64, _access: BackendAccess<'_>| -> Result<(), Trap> { Ok(()) };

        let mut on_set_reg = |reg: Reg, value: u32| -> Result<(), Trap> {
            assert!(self.crosscheck_reg.is_none());
            self.crosscheck_reg = Some((reg, value));
            Ok(())
        };

        let mut on_store = |address: u32, data: &[u8]| -> Result<(), Trap> {
            if self.enable_store_crosschecks {
                assert!(self.crosscheck_store.is_none());
                assert!(data.len() <= 8);
                self.crosscheck_store = Some((address, data.len() as u32));
                self.crosscheck_store_bytes[..data.len()].copy_from_slice(data);
            }
            Ok(())
        };

        let mut ctx = InterpreterContext::default();
        ctx.set_on_hostcall(&mut on_hostcall);
        ctx.set_on_set_reg(&mut on_set_reg);
        ctx.set_on_store(&mut on_store);

        if let Err(error) = interpreter.step_once(ctx) {
            log::error!("Crosscheck interpreter encountered error: {}", error);
            return Err(Trap::default());
        }

        Ok(())
    }
}
