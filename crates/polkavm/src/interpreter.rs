use crate::api::{BackendAccess, ExecuteArgs, HostcallHandler, MemoryAccessError, Module};
use crate::error::Error;
use crate::utils::GuestInit;
use crate::utils::{FlatMap, RegImm};
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use polkavm_common::abi::VM_ADDR_RETURN_TO_HOST;
use polkavm_common::error::Trap;
use polkavm_common::operation::*;
use polkavm_common::program::{Instruction, InstructionVisitor, ParsedInstruction, RawReg, Reg};
use polkavm_common::utils::{align_to_next_page_usize, byte_slice_init, Access, AsUninitSliceMut, Gas};
use polkavm_common::{
    VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION, VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION, VM_RPC_FLAG_RESET_MEMORY_BEFORE_EXECUTION,
};

type ExecutionError<E = core::convert::Infallible> = polkavm_common::error::ExecutionError<E>;

// Define a custom trait instead of just using `Into<RegImm>` to make sure this is always inlined.
trait IntoRegImm {
    fn into(self) -> RegImm;
}

impl IntoRegImm for RawReg {
    #[inline(always)]
    fn into(self) -> RegImm {
        RegImm::Reg(self)
    }
}

impl IntoRegImm for u32 {
    #[inline(always)]
    fn into(self) -> RegImm {
        RegImm::Imm(self)
    }
}

pub(crate) struct InterpretedModule {
    ro_data: Vec<u8>,
    rw_data: Vec<u8>,
}

impl InterpretedModule {
    pub fn new(init: GuestInit) -> Result<Self, Error> {
        let memory_map = init.memory_map().map_err(Error::from_static_str)?;
        let mut ro_data: Vec<_> = init.ro_data.into();
        ro_data.resize(memory_map.ro_data_size() as usize, 0);

        Ok(InterpretedModule {
            ro_data,
            rw_data: init.rw_data.into(),
        })
    }
}

pub(crate) type OnSetReg<'a> = &'a mut dyn FnMut(Reg, u32) -> Result<(), Trap>;
pub(crate) type OnStore<'a> = &'a mut dyn for<'r> FnMut(u32, &'r [u8]) -> Result<(), Trap>;

#[derive(Default)]
pub(crate) struct InterpreterContext<'a> {
    on_hostcall: Option<HostcallHandler<'a>>,
    on_set_reg: Option<OnSetReg<'a>>,
    on_store: Option<OnStore<'a>>,
}

impl<'a> InterpreterContext<'a> {
    pub fn set_on_hostcall(&mut self, on_hostcall: HostcallHandler<'a>) {
        self.on_hostcall = Some(on_hostcall);
    }

    pub fn set_on_set_reg(&mut self, on_set_reg: OnSetReg<'a>) {
        self.on_set_reg = Some(on_set_reg);
    }

    pub fn set_on_store(&mut self, on_store: OnStore<'a>) {
        self.on_store = Some(on_store);
    }
}

pub(crate) struct BasicMemory {
    rw_data: Vec<u8>,
    stack: Vec<u8>,
    is_memory_dirty: bool,
    heap_size: u32,
}

impl BasicMemory {
    fn new() -> Self {
        Self {
            rw_data: Vec::new(),
            stack: Vec::new(),
            is_memory_dirty: false,
            heap_size: 0,
        }
    }

    fn new_reusing(memory: &mut BasicMemory) -> Self {
        let mut new_memory = Self::new();
        memory.rw_data.clear();
        memory.stack.clear();
        new_memory.rw_data = core::mem::take(&mut memory.rw_data);
        new_memory.stack = core::mem::take(&mut memory.stack);
        new_memory
    }

    fn heap_size(&self) -> u32 {
        self.heap_size
    }

    fn mark_dirty(&mut self) {
        self.is_memory_dirty = true;
    }

    fn reset(&mut self, module: &Module) {
        if self.is_memory_dirty {
            self.force_reset(module);
        }
    }

    fn force_reset(&mut self, module: &Module) {
        self.rw_data.clear();
        self.stack.clear();
        self.heap_size = 0;
        self.is_memory_dirty = false;

        if let Some(interpreted_module) = module.interpreted_module().as_ref() {
            self.rw_data.extend_from_slice(&interpreted_module.rw_data);
            self.rw_data.resize(module.memory_map().rw_data_size() as usize, 0);
            self.stack.resize(module.memory_map().stack_size() as usize, 0);
        }
    }

    #[inline]
    fn get_memory_slice<'a>(&'a self, module: &'a Module, address: u32, length: u32) -> Option<&'a [u8]> {
        let memory_map = module.memory_map();
        let (start, memory_slice) = if address >= memory_map.stack_address_low() {
            (memory_map.stack_address_low(), &self.stack)
        } else if address >= memory_map.rw_data_address() {
            (memory_map.rw_data_address(), &self.rw_data)
        } else if address >= memory_map.ro_data_address() {
            let module = module.interpreted_module().unwrap();
            (memory_map.ro_data_address(), &module.ro_data)
        } else {
            return None;
        };

        let offset = address - start;
        memory_slice.get(offset as usize..offset as usize + length as usize)
    }

    #[inline]
    fn get_memory_slice_mut(&mut self, module: &Module, address: u32, length: u32) -> Option<&mut [u8]> {
        let memory_map = module.memory_map();
        let (start, memory_slice) = if address >= memory_map.stack_address_low() {
            (memory_map.stack_address_low(), &mut self.stack)
        } else if address >= memory_map.rw_data_address() {
            (memory_map.rw_data_address(), &mut self.rw_data)
        } else {
            return None;
        };

        self.is_memory_dirty = true;
        let offset = (address - start) as usize;
        memory_slice.get_mut(offset..offset + length as usize)
    }

    fn sbrk(&mut self, module: &Module, size: u32) -> Option<u32> {
        let new_heap_size = self.heap_size.checked_add(size)?;
        let memory_map = module.memory_map();
        if new_heap_size > memory_map.max_heap_size() {
            return None;
        }

        log::trace!("sbrk: +{} (heap size: {} -> {})", size, self.heap_size, new_heap_size);

        self.heap_size = new_heap_size;
        let heap_top = memory_map.heap_base() + new_heap_size;
        if heap_top as usize > memory_map.rw_data_address() as usize + self.rw_data.len() {
            let new_size = align_to_next_page_usize(memory_map.page_size() as usize, heap_top as usize).unwrap()
                - memory_map.rw_data_address() as usize;
            log::trace!("sbrk: growing memory: {} -> {}", self.rw_data.len(), new_size);
            self.rw_data.resize(new_size, 0);
        }

        Some(heap_top)
    }
}

#[derive(Copy, Clone)]
#[repr(transparent)]
struct GasCost(NonZeroU32);

impl GasCost {
    fn new(cost: u32) -> Self {
        GasCost(NonZeroU32::new(cost + 1).expect("invalid gas"))
    }

    fn get(self) -> u32 {
        self.0.get() - 1
    }
}

pub(crate) struct InterpretedInstance {
    module: Module,
    memory: BasicMemory,
    regs: [u32; Reg::ALL.len()],
    instruction_offset: u32,
    instruction_length: u32,
    return_to_host: bool,
    cycle_counter: u64,
    gas_cost_for_block: FlatMap<GasCost>,
    gas_remaining: Option<i64>,
    in_new_execution: bool,
    compiled_offset_for_block: FlatMap<NonZeroU32>,
    compiled_instructions: Vec<ParsedInstruction>,
    compiled_offset: usize,
}

impl InterpretedInstance {
    pub fn new_from_module(module: Module) -> Self {
        let mut instance = Self {
            compiled_offset_for_block: FlatMap::new(module.code_len()),
            compiled_instructions: Default::default(),
            gas_cost_for_block: FlatMap::new(module.code_len()),
            module,
            memory: BasicMemory::new(),
            regs: [0; Reg::ALL.len()],
            instruction_offset: 0,
            instruction_length: 0,
            return_to_host: true,
            cycle_counter: 0,
            gas_remaining: None,
            in_new_execution: false,
            compiled_offset: 0,
        };

        instance.initialize_module();
        instance
    }

    pub fn execute(&mut self, mut args: ExecuteArgs) -> Result<(), ExecutionError<Error>> {
        self.prepare_for_execution(&args);

        let mut ctx = InterpreterContext::default();
        if let Some(hostcall_handler) = args.hostcall_handler.take() {
            ctx.set_on_hostcall(hostcall_handler);
        }

        let result = if args.entry_point.is_some() { self.run(ctx) } else { Ok(()) };

        self.finish_execution(args.flags);
        result
    }

    pub fn run(&mut self, ctx: InterpreterContext) -> Result<(), ExecutionError<Error>> {
        if log::log_enabled!(target: "polkavm", log::Level::Debug)
            || log::log_enabled!(target: "polkavm::interpreter", log::Level::Debug)
            || cfg!(test)
        {
            self.run_impl::<true>(ctx)
        } else {
            self.run_impl::<false>(ctx)
        }
    }

    #[inline(never)]
    fn run_impl<const DEBUG: bool>(&mut self, ctx: InterpreterContext) -> Result<(), ExecutionError<Error>> {
        #[cold]
        fn translate_error(error: ExecutionError) -> ExecutionError<Error> {
            match error {
                ExecutionError::Trap(trap) => ExecutionError::Trap(trap),
                ExecutionError::OutOfGas => ExecutionError::OutOfGas,
                ExecutionError::Error(_) => unreachable!(),
            }
        }

        #[cold]
        fn trap() -> ExecutionError<Error> {
            ExecutionError::Trap(Default::default())
        }

        self.memory.mark_dirty();

        if self.in_new_execution {
            self.in_new_execution = false;
            if let Err(error) = self.on_start_new_basic_block::<DEBUG>() {
                return Err(translate_error(error));
            }
        }

        let mut visitor = Visitor::<DEBUG> { inner: self, ctx };
        loop {
            visitor.inner.cycle_counter += 1;
            let Some(&instruction) = visitor.inner.compiled_instructions.get(visitor.inner.compiled_offset) else {
                if DEBUG {
                    log::trace!("Trap at {}: no instruction found", visitor.inner.instruction_offset);
                }
                return Err(trap());
            };

            visitor.inner.instruction_offset = instruction.offset;
            visitor.inner.instruction_length = instruction.length;
            visitor.trace_current_instruction(&instruction);
            if let Err(error) = instruction.visit(&mut visitor) {
                return Err(translate_error(error));
            }

            if visitor.inner.return_to_host {
                break;
            }
        }

        Ok(())
    }

    pub fn step_once(&mut self, ctx: InterpreterContext) -> Result<(), ExecutionError> {
        if self.in_new_execution {
            self.in_new_execution = false;
            self.on_start_new_basic_block::<true>()?;
        }

        self.cycle_counter += 1;
        let Some(mut instructions) = self.module.instructions_at(self.instruction_offset) else {
            return Err(ExecutionError::Trap(Default::default()));
        };

        let Some(instruction) = instructions.next() else {
            return Err(ExecutionError::Trap(Default::default()));
        };

        self.instruction_offset = instruction.offset;
        self.instruction_length = instruction.length;
        let mut visitor = Visitor::<true> { inner: self, ctx };

        visitor.trace_current_instruction(&instruction);
        instruction.visit(&mut visitor)?;

        Ok(())
    }

    fn clear_instance(&mut self) {
        *self = Self {
            memory: BasicMemory::new_reusing(&mut self.memory),
            ..Self::new_from_module(Module::empty())
        };
    }

    pub fn reset_memory(&mut self) {
        self.memory.reset(&self.module);
    }

    pub fn sbrk(&mut self, size: u32) -> Option<u32> {
        self.memory.sbrk(&self.module, size)
    }

    fn initialize_module(&mut self) {
        if self.module.gas_metering().is_some() {
            self.gas_remaining = Some(0);
        }

        self.memory.force_reset(&self.module);
    }

    pub fn prepare_for_execution(&mut self, args: &ExecuteArgs) {
        if let Some(module) = args.module {
            if module.interpreted_module().is_none() {
                panic!("internal_error: an interpreter cannot be created from the given module");
            }

            self.clear_instance();
            self.module = module.clone();
            self.initialize_module();
        }

        if let Some(regs) = args.regs {
            self.regs.copy_from_slice(regs);
        }

        if self.module.gas_metering().is_some() {
            if let Some(gas) = args.gas {
                self.gas_remaining = Some(gas.get() as i64);
            }
        } else {
            self.gas_remaining = None;
        }

        if let Some(entry_point) = args.entry_point {
            self.instruction_offset = entry_point;
        }

        if args.flags & VM_RPC_FLAG_RESET_MEMORY_BEFORE_EXECUTION != 0 {
            self.reset_memory();
        }

        if args.sbrk > 0 {
            self.sbrk(args.sbrk).expect("internal error: sbrk failed");
        }

        self.return_to_host = false;
        self.in_new_execution = true;
    }

    pub fn finish_execution(&mut self, flags: u32) {
        if flags & VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION != 0 {
            self.clear_instance();
        } else if flags & VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION != 0 {
            self.reset_memory();
        }
    }

    pub fn access(&mut self) -> InterpretedAccess {
        InterpretedAccess { instance: self }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn on_start_new_basic_block<const DEBUG: bool>(&mut self) -> Result<(), ExecutionError> {
        let instruction_offset = self.instruction_offset;
        if let Some(compiled_offset) = self.compiled_offset_for_block.get(instruction_offset) {
            self.compiled_offset = (compiled_offset.get() - 1) as usize;
        } else {
            self.compiled_offset = self.compiled_instructions.len();
            self.compile_block::<DEBUG>()?;
        }

        if self.gas_remaining.is_some() {
            let gas_cost: i64 = if let Some(cost) = self.gas_cost_for_block.get(instruction_offset) {
                u64::from(cost.get()) as i64
            } else {
                self.calculate_gas_cost()
            };

            let gas_remaining = self.gas_remaining.as_mut().unwrap();
            if DEBUG {
                log::trace!(
                    "Consume gas at at {}: {} ({} -> {})",
                    instruction_offset,
                    gas_cost,
                    *gas_remaining,
                    *gas_remaining - gas_cost
                );
            }

            *gas_remaining -= gas_cost;
            if *gas_remaining < 0 {
                return Err(ExecutionError::OutOfGas);
            }
        }

        Ok(())
    }

    #[inline(never)]
    #[cold]
    fn calculate_gas_cost(&mut self) -> i64 {
        let instruction_offset = self.instruction_offset;
        let Some(instructions) = self.module.instructions_at(instruction_offset) else {
            return 0;
        };

        let cost = crate::gas::calculate_for_block(instructions);
        if cost == 0 {
            return 0;
        }

        self.gas_cost_for_block.insert(instruction_offset, GasCost::new(cost));
        u64::from(cost) as i64
    }

    #[inline(never)]
    #[cold]
    fn compile_block<const DEBUG: bool>(&mut self) -> Result<(), ExecutionError> {
        let Some(instructions) = self.module.instructions_at(self.instruction_offset) else {
            return Err(ExecutionError::Trap(Default::default()));
        };

        if DEBUG {
            log::debug!("Compiling block at {}:", self.instruction_offset);
        }

        let starting_offset = self.compiled_instructions.len();
        for instruction in instructions {
            if DEBUG {
                log::debug!(
                    "  [{}]: {}: {}",
                    self.compiled_instructions.len(),
                    instruction.offset,
                    instruction.kind
                );
            }

            self.compiled_instructions.push(instruction);
            if instruction.opcode().starts_new_basic_block() {
                break;
            }
        }

        if self.compiled_instructions.len() == starting_offset {
            return Ok(());
        }

        self.compiled_offset_for_block
            .insert(self.instruction_offset, NonZeroU32::new((starting_offset + 1) as u32).unwrap());

        Ok(())
    }

    fn check_gas(&mut self) -> Result<(), ExecutionError> {
        if let Some(ref mut gas_remaining) = self.gas_remaining {
            if *gas_remaining < 0 {
                return Err(ExecutionError::OutOfGas);
            }
        }

        Ok(())
    }
}

pub struct InterpretedAccess<'a> {
    instance: &'a mut InterpretedInstance,
}

impl<'a> Access<'a> for InterpretedAccess<'a> {
    type Error = MemoryAccessError<&'static str>;

    fn get_reg(&self, reg: Reg) -> u32 {
        self.instance.regs[reg as usize]
    }

    fn set_reg(&mut self, reg: Reg, value: u32) {
        self.instance.regs[reg as usize] = value;
    }

    fn read_memory_into_slice<'slice, T>(&self, address: u32, buffer: &'slice mut T) -> Result<&'slice mut [u8], Self::Error>
    where
        T: ?Sized + AsUninitSliceMut,
    {
        let buffer: &mut [MaybeUninit<u8>] = buffer.as_uninit_slice_mut();
        let Some(slice) = self
            .instance
            .memory
            .get_memory_slice(&self.instance.module, address, buffer.len() as u32)
        else {
            return Err(MemoryAccessError {
                address,
                length: buffer.len() as u64,
                error: "out of range read",
            });
        };

        Ok(byte_slice_init(buffer, slice))
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
        let Some(slice) = self
            .instance
            .memory
            .get_memory_slice_mut(&self.instance.module, address, data.len() as u32)
        else {
            return Err(MemoryAccessError {
                address,
                length: data.len() as u64,
                error: "out of range write",
            });
        };

        slice.copy_from_slice(data);
        Ok(())
    }

    fn sbrk(&mut self, size: u32) -> Option<u32> {
        self.instance.sbrk(size)
    }

    fn heap_size(&self) -> u32 {
        self.instance.memory.heap_size()
    }

    fn program_counter(&self) -> Option<u32> {
        Some(self.instance.instruction_offset)
    }

    fn native_program_counter(&self) -> Option<u64> {
        None
    }

    fn gas_remaining(&self) -> Option<Gas> {
        let gas = self.instance.gas_remaining?;
        Some(Gas::new(gas as u64).unwrap_or(Gas::MIN))
    }

    fn consume_gas(&mut self, gas: u64) {
        if let Some(ref mut gas_remaining) = self.instance.gas_remaining {
            *gas_remaining = gas_remaining.checked_sub_unsigned(gas).unwrap_or(-1);
        }
    }
}

struct Visitor<'a, 'b, const DEBUG: bool> {
    inner: &'a mut InterpretedInstance,
    ctx: InterpreterContext<'b>,
}

impl<'a, 'b, const DEBUG: bool> Visitor<'a, 'b, DEBUG> {
    #[inline(always)]
    fn get(&self, regimm: impl IntoRegImm) -> u32 {
        match regimm.into() {
            RegImm::Reg(reg) => self.inner.regs[reg.get() as usize],
            RegImm::Imm(value) => value,
        }
    }

    #[inline(always)]
    fn set(&mut self, dst: RawReg, value: u32) -> Result<(), ExecutionError> {
        let dst = dst.get();
        self.inner.regs[dst as usize] = value;

        if DEBUG {
            log::trace!("{dst} = 0x{value:x}");
        }

        if let Some(on_set_reg) = self.ctx.on_set_reg.as_mut() {
            let result = (on_set_reg)(dst, value);
            Ok(result.map_err(ExecutionError::Trap)?)
        } else {
            Ok(())
        }
    }

    #[inline(always)]
    fn set3(
        &mut self,
        dst: RawReg,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        callback: impl Fn(u32, u32) -> u32,
    ) -> Result<(), ExecutionError> {
        let s1 = self.get(s1);
        let s2 = self.get(s2);
        self.set(dst, callback(s1, s2))?;
        self.on_next_instruction();

        Ok(())
    }

    fn branch(
        &mut self,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        target: u32,
        callback: impl Fn(u32, u32) -> bool,
    ) -> Result<(), ExecutionError> {
        let s1 = self.get(s1);
        let s2 = self.get(s2);
        if callback(s1, s2) {
            self.inner.instruction_offset = target;
        } else {
            self.on_next_instruction();
        }

        self.inner.on_start_new_basic_block::<DEBUG>()
    }

    #[inline(always)]
    fn on_next_instruction(&mut self) {
        self.inner.instruction_offset += self.inner.instruction_length;
        self.inner.compiled_offset += 1;
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn load<T: LoadTy>(&mut self, dst: RawReg, base: Option<RawReg>, offset: u32) -> Result<(), ExecutionError> {
        assert!(core::mem::size_of::<T>() >= 1);

        let address = base.map_or(0, |base| self.inner.regs[base.get() as usize]).wrapping_add(offset);
        let length = core::mem::size_of::<T>() as u32;
        let Some(slice) = self.inner.memory.get_memory_slice(&self.inner.module, address, length) else {
            if DEBUG {
                log::debug!(
                    "Load of {length} bytes from 0x{address:x} failed! (pc = {pc}, cycle = {cycle})",
                    pc = self.inner.instruction_offset,
                    cycle = self.inner.cycle_counter
                );

                self.inner
                    .module
                    .debug_print_location(log::Level::Debug, self.inner.instruction_offset);
            }

            return Err(ExecutionError::Trap(Default::default()));
        };

        if DEBUG {
            log::trace!("{dst} = {kind} [0x{address:x}]", kind = core::any::type_name::<T>());
        }

        let value = T::from_slice(slice);
        self.set(dst, value)?;
        self.on_next_instruction();

        Ok(())
    }

    fn store<T: StoreTy>(&mut self, src: impl IntoRegImm, base: Option<RawReg>, offset: u32) -> Result<(), ExecutionError> {
        assert!(core::mem::size_of::<T>() >= 1);

        let address = base.map_or(0, |base| self.inner.regs[base.get() as usize]).wrapping_add(offset);
        let value = match src.into() {
            RegImm::Reg(src) => {
                let src = src.get();
                let value = self.inner.regs[src as usize];
                if DEBUG {
                    log::trace!("{kind} [0x{address:x}] = {src} = 0x{value:x}", kind = core::any::type_name::<T>());
                }

                value
            }
            RegImm::Imm(value) => {
                if DEBUG {
                    log::trace!("{kind} [0x{address:x}] = 0x{value:x}", kind = core::any::type_name::<T>());
                }

                value
            }
        };

        let length = core::mem::size_of::<T>() as u32;
        let Some(slice) = self.inner.memory.get_memory_slice_mut(&self.inner.module, address, length) else {
            if DEBUG {
                log::debug!(
                    "Store of {length} bytes to 0x{address:x} failed! (pc = {pc}, cycle = {cycle})",
                    pc = self.inner.instruction_offset,
                    cycle = self.inner.cycle_counter
                );

                self.inner
                    .module
                    .debug_print_location(log::Level::Debug, self.inner.instruction_offset);
            }

            return Err(ExecutionError::Trap(Default::default()));
        };

        let value = T::into_bytes(value);
        slice.copy_from_slice(value.as_ref());

        if let Some(on_store) = self.ctx.on_store.as_mut() {
            (on_store)(address, value.as_ref()).map_err(ExecutionError::Trap)?;
        }

        self.on_next_instruction();
        Ok(())
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn jump_indirect_impl(&mut self, call: Option<(RawReg, u32)>, base: RawReg, offset: u32) -> Result<(), ExecutionError> {
        let base = base.get();
        let target = self.inner.regs[base as usize].wrapping_add(offset);
        if let Some((ra, return_address)) = call {
            self.set(ra, return_address)?;
        }

        if target == VM_ADDR_RETURN_TO_HOST {
            self.inner.return_to_host = true;
            return Ok(());
        }

        let Some(instruction_offset) = self.inner.module.jump_table().get_by_address(target) else {
            if DEBUG {
                log::trace!("Indirect jump to address {target}: INVALID");
            }
            return Err(ExecutionError::Trap(Default::default()));
        };

        if DEBUG {
            log::trace!("Indirect jump to address {target}: {instruction_offset}");
        }

        self.inner.instruction_offset = instruction_offset;
        self.inner.on_start_new_basic_block::<DEBUG>()
    }

    #[inline(always)]
    fn trace_current_instruction(&self, instruction: &Instruction) {
        if DEBUG {
            log::trace!(
                "[{}]: {}..{}: {instruction}",
                self.inner.compiled_offset,
                self.inner.instruction_offset,
                self.inner.instruction_offset + self.inner.instruction_length
            );
        }
    }
}

trait LoadTy {
    fn from_slice(xs: &[u8]) -> u32;
}

impl LoadTy for u8 {
    fn from_slice(xs: &[u8]) -> u32 {
        u32::from(xs[0])
    }
}

impl LoadTy for i8 {
    fn from_slice(xs: &[u8]) -> u32 {
        i32::from(xs[0] as i8) as u32
    }
}

impl LoadTy for u16 {
    fn from_slice(xs: &[u8]) -> u32 {
        u32::from(u16::from_le_bytes([xs[0], xs[1]]))
    }
}

impl LoadTy for i16 {
    fn from_slice(xs: &[u8]) -> u32 {
        i32::from(i16::from_le_bytes([xs[0], xs[1]])) as u32
    }
}

impl LoadTy for u32 {
    fn from_slice(xs: &[u8]) -> u32 {
        u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]])
    }
}

trait StoreTy: Sized {
    type Array: AsRef<[u8]>;
    fn into_bytes(value: u32) -> Self::Array;
}

impl StoreTy for u8 {
    type Array = [u8; 1];

    #[inline(always)]
    fn into_bytes(value: u32) -> Self::Array {
        (value as u8).to_le_bytes()
    }
}

impl StoreTy for u16 {
    type Array = [u8; 2];

    #[inline(always)]
    fn into_bytes(value: u32) -> Self::Array {
        (value as u16).to_le_bytes()
    }
}

impl StoreTy for u32 {
    type Array = [u8; 4];

    #[inline(always)]
    fn into_bytes(value: u32) -> Self::Array {
        value.to_le_bytes()
    }
}

impl<'a, 'b, const DEBUG: bool> InstructionVisitor for Visitor<'a, 'b, DEBUG> {
    type ReturnTy = Result<(), ExecutionError>;

    fn trap(&mut self) -> Self::ReturnTy {
        log::debug!("Trap at {}: explicit trap", self.inner.instruction_offset);
        Err(ExecutionError::Trap(Default::default()))
    }

    fn fallthrough(&mut self) -> Self::ReturnTy {
        self.on_next_instruction();
        self.inner.on_start_new_basic_block::<DEBUG>()
    }

    fn sbrk(&mut self, dst: RawReg, size: RawReg) -> Self::ReturnTy {
        let size = self.get(size);
        let result = self.inner.sbrk(size).unwrap_or(0);
        self.set(dst, result)?;
        self.on_next_instruction();

        Ok(())
    }

    fn ecalli(&mut self, imm: u32) -> Self::ReturnTy {
        if let Some(on_hostcall) = self.ctx.on_hostcall.as_mut() {
            self.inner.instruction_offset += self.inner.instruction_length; // TODO: Call self.on_next_instruction().
            self.inner.compiled_offset += 1;

            let access = BackendAccess::Interpreted(self.inner.access());
            (on_hostcall)(imm, access).map_err(ExecutionError::Trap)?;
            self.inner.check_gas()?;
            Ok(())
        } else {
            log::debug!("Hostcall called without any hostcall handler set!");
            Err(ExecutionError::Trap(Default::default()))
        }
    }

    fn set_less_than_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| u32::from(s1 < s2))
    }

    fn set_less_than_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| u32::from((s1 as i32) < (s2 as i32)))
    }

    fn shift_logical_right(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_shr)
    }

    fn shift_arithmetic_right(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| ((s1 as i32).wrapping_shr(s2)) as u32)
    }

    fn shift_logical_left(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_shl)
    }

    fn xor(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1 ^ s2)
    }

    fn and(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1 & s2)
    }

    fn or(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1 | s2)
    }

    fn add(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_add)
    }

    fn sub(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_sub)
    }

    fn negate_and_add_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s2.wrapping_sub(s1))
    }

    fn mul(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_mul)
    }

    fn mul_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_mul)
    }

    fn mul_upper_signed_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| mulh(s1 as i32, s2 as i32) as u32)
    }

    fn mul_upper_signed_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| mulh(s1 as i32, s2 as i32) as u32)
    }

    fn mul_upper_unsigned_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, mulhu)
    }

    fn mul_upper_unsigned_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, mulhu)
    }

    fn mul_upper_signed_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| mulhsu(s1 as i32, s2) as u32)
    }

    fn div_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, divu)
    }

    fn div_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| div(s1 as i32, s2 as i32) as u32)
    }

    fn rem_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, remu)
    }

    fn rem_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| rem(s1 as i32, s2 as i32) as u32)
    }

    fn set_less_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| u32::from(s1 < s2))
    }

    fn set_greater_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| u32::from(s1 > s2))
    }

    fn set_less_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| u32::from((s1 as i32) < (s2 as i32)))
    }

    fn set_greater_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| u32::from((s1 as i32) > (s2 as i32)))
    }

    fn shift_logical_right_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_shr)
    }

    fn shift_logical_right_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_shr)
    }

    fn shift_arithmetic_right_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| ((s1 as i32) >> s2) as u32)
    }

    fn shift_arithmetic_right_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| ((s1 as i32) >> s2) as u32)
    }

    fn shift_logical_left_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_shl)
    }

    fn shift_logical_left_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_shl)
    }

    fn or_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1 | s2)
    }

    fn and_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1 & s2)
    }

    fn xor_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1 ^ s2)
    }

    fn load_imm(&mut self, dst: RawReg, imm: u32) -> Self::ReturnTy {
        self.set(dst, imm)?;
        self.on_next_instruction();

        Ok(())
    }

    fn move_reg(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let imm = self.get(s);
        self.set(d, imm)?;
        self.on_next_instruction();

        Ok(())
    }

    fn cmov_if_zero(&mut self, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        if self.get(c) == 0 {
            let value = self.get(s);
            self.set(d, value)?;
        }

        self.on_next_instruction();
        Ok(())
    }

    fn cmov_if_zero_imm(&mut self, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        if self.get(c) == 0 {
            self.set(d, s)?;
        }

        self.on_next_instruction();
        Ok(())
    }

    fn cmov_if_not_zero(&mut self, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        if self.get(c) != 0 {
            let value = self.get(s);
            self.set(d, value)?;
        }

        self.on_next_instruction();
        Ok(())
    }

    fn cmov_if_not_zero_imm(&mut self, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        if self.get(c) != 0 {
            self.set(d, s)?;
        }

        self.on_next_instruction();
        Ok(())
    }

    fn add_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.set3(d, s1, s2, u32::wrapping_add)
    }

    fn store_imm_u8(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        self.store::<u8>(value, None, offset)
    }

    fn store_imm_u16(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        self.store::<u16>(value, None, offset)
    }

    fn store_imm_u32(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        self.store::<u32>(value, None, offset)
    }

    fn store_imm_indirect_u8(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        self.store::<u8>(value, Some(base), offset)
    }

    fn store_imm_indirect_u16(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        self.store::<u16>(value, Some(base), offset)
    }

    fn store_imm_indirect_u32(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        self.store::<u32>(value, Some(base), offset)
    }

    fn store_indirect_u8(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.store::<u8>(src, Some(base), offset)
    }

    fn store_indirect_u16(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.store::<u16>(src, Some(base), offset)
    }

    fn store_indirect_u32(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.store::<u32>(src, Some(base), offset)
    }

    fn store_u8(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        self.store::<u8>(src, None, offset)
    }

    fn store_u16(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        self.store::<u16>(src, None, offset)
    }

    fn store_u32(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        self.store::<u32>(src, None, offset)
    }

    fn load_u8(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.load::<u8>(dst, None, offset)
    }

    fn load_i8(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.load::<i8>(dst, None, offset)
    }

    fn load_u16(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.load::<u16>(dst, None, offset)
    }

    fn load_i16(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.load::<i16>(dst, None, offset)
    }

    fn load_u32(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.load::<u32>(dst, None, offset)
    }

    fn load_indirect_u8(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.load::<u8>(dst, Some(base), offset)
    }

    fn load_indirect_i8(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.load::<i8>(dst, Some(base), offset)
    }

    fn load_indirect_u16(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.load::<u16>(dst, Some(base), offset)
    }

    fn load_indirect_i16(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.load::<i16>(dst, Some(base), offset)
    }

    fn load_indirect_u32(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.load::<u32>(dst, Some(base), offset)
    }

    fn branch_less_unsigned(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 < s2)
    }

    fn branch_less_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 < s2)
    }

    fn branch_less_signed(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| (s1 as i32) < (s2 as i32))
    }

    fn branch_less_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| (s1 as i32) < (s2 as i32))
    }

    fn branch_eq(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 == s2)
    }

    fn branch_eq_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 == s2)
    }

    fn branch_not_eq(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 != s2)
    }

    fn branch_not_eq_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 != s2)
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 >= s2)
    }

    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 >= s2)
    }

    fn branch_greater_or_equal_signed(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| (s1 as i32) >= (s2 as i32))
    }

    fn branch_greater_or_equal_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| (s1 as i32) >= (s2 as i32))
    }

    fn branch_less_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 <= s2)
    }

    fn branch_less_or_equal_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| (s1 as i32) <= (s2 as i32))
    }

    fn branch_greater_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 > s2)
    }

    fn branch_greater_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| (s1 as i32) > (s2 as i32))
    }

    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        if DEBUG {
            log::trace!("Jump to: {target}");
        }

        self.inner.instruction_offset = target;
        self.inner.on_start_new_basic_block::<DEBUG>()
    }

    fn jump_indirect(&mut self, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.jump_indirect_impl(None, base, offset)
    }

    fn load_imm_and_jump(&mut self, ra: RawReg, value: u32, target: u32) -> Self::ReturnTy {
        self.load_imm(ra, value)?;
        self.jump(target)
    }

    fn load_imm_and_jump_indirect(&mut self, ra: RawReg, base: RawReg, value: u32, offset: u32) -> Self::ReturnTy {
        self.jump_indirect_impl(Some((ra, value)), base, offset)
    }
}
