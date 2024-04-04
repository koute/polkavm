use crate::api::BackendAccess;
use crate::api::ExecuteArgs;
use crate::api::Module;
use crate::interpreter::{InterpretedInstance, InterpreterContext};
use crate::source_cache::SourceCache;
use core::mem::MaybeUninit;
use polkavm_common::error::Trap;
use polkavm_common::program::{FrameKind, Opcode, Reg};
use polkavm_common::utils::Access;

pub(crate) struct Tracer {
    module: Module,
    source_cache: SourceCache,
    program_counter_history: [u32; 8],
    program_counter_history_position: usize,
    crosscheck_interpreter: Option<InterpretedInstance>,
    crosscheck_reg: Option<(Reg, u32)>,
    crosscheck_store: Option<(u32, u32)>,
    crosscheck_store_bytes: [u8; 8],
    crosscheck_execution_flags: u32,
    current_line_program_position: Option<(usize, usize)>,
    current_source_location: Option<(u32, u32)>,

    enable_store_crosschecks: bool,
}

impl Tracer {
    pub fn new(module: &Module) -> Self {
        Tracer {
            program_counter_history: [!0; 8],
            program_counter_history_position: 0,
            crosscheck_interpreter: if module.compiled_module().is_some() {
                Some(InterpretedInstance::new_from_module(module.clone()))
            } else {
                None
            },
            module: module.clone(),
            source_cache: SourceCache::default(),
            crosscheck_reg: None,
            crosscheck_store: None,
            crosscheck_store_bytes: Default::default(),
            crosscheck_execution_flags: 0,
            current_line_program_position: None,
            current_source_location: None,

            // TODO: Make this configurable.
            enable_store_crosschecks: false,
        }
    }

    pub fn on_before_execute(&mut self, args: &ExecuteArgs) {
        if let Some(ref mut interpreter) = self.crosscheck_interpreter {
            self.crosscheck_execution_flags = args.flags;
            interpreter.prepare_for_execution(args);
        }
    }

    pub fn on_after_execute(&mut self) {
        if let Some(ref mut interpreter) = self.crosscheck_interpreter {
            interpreter.finish_execution(self.crosscheck_execution_flags);
        }
    }

    pub fn on_trace(&mut self, access: &mut BackendAccess) -> Result<(), Trap> {
        assert!(self.module.is_debug_trace_execution_enabled());

        self.crosscheck_last_instruction(access)?;

        let program_counter = access
            .program_counter()
            .expect("internal error: tracer called without valid program counter");

        self.trace_current_instruction_source(program_counter);

        if let Some(native_address) = access.native_program_counter() {
            let instruction = self.module.instructions()[program_counter as usize];
            log::trace!("0x{native_address:x}: #{program_counter}: {instruction}");
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
                let address_end = u64::from(address) + data.len() as u64;
                log::error!("Memory write in hostcall mismatch when writing to 0x{address:x}..0x{address_end:x}! (crosscheck interpreter = {expected_success}, actual = {success})");
            }
        }

        Ok(())
    }

    fn debug_print_history(&self) {
        log::error!("Program counter history:");
        for nth in (0..self.program_counter_history.len()).rev() {
            let pc = self.program_counter_history[(self.program_counter_history_position + nth) % self.program_counter_history.len()];
            if pc == !0 {
                continue;
            }

            self.module.debug_print_location(log::Level::Error, pc);
        }
    }

    fn crosscheck_last_instruction(&mut self, access: &mut BackendAccess) -> Result<(), Trap> {
        if let Some((reg, expected_value)) = self.crosscheck_reg.take() {
            let value = access.get_reg(reg);
            if value != expected_value {
                log::error!("Register value mismatch! Crosscheck interpreter has {reg} = 0x{expected_value:x}, actual execution has {reg} = 0x{value:x}");
                self.debug_print_history();
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

    fn trace_current_instruction_source(&mut self, program_counter: u32) {
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

        if !log::log_enabled!(log::Level::Trace) {
            return;
        }

        let blob = self.module.blob();
        let mut line_program = match blob.get_debug_line_program_at(program_counter) {
            Err(error) => {
                log::warn!("Failed to get line program for instruction #{program_counter}: {error}");
                self.current_source_location = None;
                return;
            }
            Ok(None) => {
                log::trace!("  (f) (none)");
                self.current_source_location = None;
                return;
            }
            Ok(Some(line_program)) => line_program,
        };

        let line_program_index = line_program.entry_index();

        // TODO: Running the whole region program on every instruction is horribly inefficient.
        let location_ref = loop {
            let region_info = match line_program.run() {
                Ok(Some(region_info)) => region_info,
                Ok(None) => {
                    debug_assert!(false, "region should have been found in line program but wasn't");
                    break None;
                }
                Err(error) => {
                    log::warn!("Failed to run line program for instruction #{program_counter}: {error}");
                    self.current_source_location = None;
                    return;
                }
            };

            if !region_info.instruction_range().contains(&program_counter) {
                continue;
            }

            let new_line_program_position = (line_program_index, region_info.entry_index());
            if self.current_line_program_position == Some(new_line_program_position) {
                log::trace!("  {VT_DARK}(location unchanged){VT_RESET}");
                return;
            }

            self.current_line_program_position = Some(new_line_program_position);

            let mut location_ref = None;
            for frame in region_info.frames() {
                let full_name = match frame.full_name() {
                    Ok(full_name) => full_name,
                    Err(error) => {
                        log::warn!("Failed to fetch a frame full name at #{program_counter}: {error}");
                        self.current_source_location = None;
                        return;
                    }
                };

                let location = match frame.location() {
                    Ok(location) => location,
                    Err(error) => {
                        log::warn!("Failed to fetch a frame location at #{program_counter}: {error}");
                        self.current_source_location = None;
                        return;
                    }
                };

                let kind = match frame.kind() {
                    FrameKind::Enter => 'f',
                    FrameKind::Call => 'c',
                    FrameKind::Line => 'l',
                };

                if let Some(location) = location {
                    log::trace!("  ({kind}) '{full_name}' {VT_DARK}[{location}]{VT_RESET}");
                } else {
                    log::trace!("  ({kind}) '{full_name}'");
                }

                location_ref = if let (Some(offset), Some(line)) = (frame.path_debug_string_offset(), frame.line()) {
                    Some((offset, line))
                } else {
                    None
                };
            }

            break location_ref;
        };

        if self.current_source_location == location_ref {
            return;
        }

        self.current_source_location = location_ref;
        let Some((path_offset, line)) = location_ref else {
            return;
        };

        let Ok(path) = blob.get_debug_string(path_offset) else {
            return;
        };

        if let Some(source_line) = self.source_cache.lookup_source_line(path, line) {
            log::trace!("   | {VT_GREEN}{source_line}{VT_RESET}");
        }
    }

    fn step_crosscheck_interpreter(&mut self, program_counter: u32) -> Result<(), Trap> {
        let Some(ref mut interpreter) = self.crosscheck_interpreter else {
            return Ok(());
        };

        let expected_program_counter = interpreter.access().program_counter().unwrap();
        if expected_program_counter != program_counter {
            log::error!("Program counter mismatch! Crosscheck interpreter returned #{expected_program_counter}, actual execution returned #{program_counter}");
            self.module.debug_print_location(log::Level::Error, expected_program_counter);
            self.module.debug_print_location(log::Level::Error, program_counter);
            self.debug_print_history();
            return Err(Trap::default());
        }

        self.program_counter_history[self.program_counter_history_position] = program_counter;
        self.program_counter_history_position = (self.program_counter_history_position + 1) % self.program_counter_history.len();

        let instruction = self.module.instructions()[program_counter as usize];
        if matches!(instruction.opcode(), Opcode::trap) {
            return Ok(());
        }

        let mut on_hostcall = |_hostcall: u32, _access: BackendAccess<'_>| -> Result<(), Trap> { Ok(()) };
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
            self.debug_print_history();
            return Err(Trap::default());
        }

        Ok(())
    }
}
