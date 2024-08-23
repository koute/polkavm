#![allow(unknown_lints)] // Because of `non_local_definitions` on older rustc versions.
#![allow(non_local_definitions)]
use crate::api::{MemoryAccessError, Module, RegValue};
use crate::error::Error;
use crate::gas::GasVisitor;
use crate::utils::{FlatMap, GuestInit, InterruptKind, Segfault};
use crate::{Gas, GasMeteringKind, ProgramCounter};
use alloc::boxed::Box;
use alloc::collections::btree_map::Entry;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use polkavm_common::abi::VM_ADDR_RETURN_TO_HOST;
use polkavm_common::operation::*;
use polkavm_common::program::{asm, InstructionVisitor, RawReg, Reg};
use polkavm_common::utils::{align_to_next_page_usize, byte_slice_init, slice_assume_init_mut};

type Target = usize;

#[derive(Copy, Clone)]
pub enum RegImm {
    Reg(Reg),
    Imm(u32),
}

impl From<Reg> for RegImm {
    #[inline]
    fn from(reg: Reg) -> Self {
        RegImm::Reg(reg)
    }
}

impl From<u32> for RegImm {
    #[inline]
    fn from(value: u32) -> Self {
        RegImm::Imm(value)
    }
}

// Define a custom trait instead of just using `Into<RegImm>` to make sure this is always inlined.
trait IntoRegImm {
    fn into(self) -> RegImm;
}

impl IntoRegImm for Reg {
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

pub(crate) struct BasicMemory {
    rw_data: Vec<u8>,
    stack: Vec<u8>,
    aux: Vec<u8>,
    is_memory_dirty: bool,
    heap_size: u32,
}

impl BasicMemory {
    fn new() -> Self {
        Self {
            rw_data: Vec::new(),
            stack: Vec::new(),
            aux: Vec::new(),
            is_memory_dirty: false,
            heap_size: 0,
        }
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
        self.aux.clear();
        self.heap_size = 0;
        self.is_memory_dirty = false;

        if let Some(interpreted_module) = module.interpreted_module().as_ref() {
            self.rw_data.extend_from_slice(&interpreted_module.rw_data);
            self.rw_data.resize(module.memory_map().rw_data_size() as usize, 0);
            self.stack.resize(module.memory_map().stack_size() as usize, 0);

            // TODO: Do this lazily?
            self.aux.resize(module.memory_map().aux_data_size() as usize, 0);
        }
    }

    #[inline]
    fn get_memory_slice<'a>(&'a self, module: &'a Module, address: u32, length: u32) -> Option<&'a [u8]> {
        let memory_map = module.memory_map();
        let (start, memory_slice) = if address >= memory_map.aux_data_address() {
            (memory_map.aux_data_address(), &self.aux)
        } else if address >= memory_map.stack_address_low() {
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
    fn get_memory_slice_mut<const IS_EXTERNAL: bool>(&mut self, module: &Module, address: u32, length: u32) -> Option<&mut [u8]> {
        let memory_map = module.memory_map();
        let (start, memory_slice) = if IS_EXTERNAL && address >= memory_map.aux_data_address() {
            (memory_map.aux_data_address(), &mut self.aux)
        } else if address >= memory_map.stack_address_low() {
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
        let Some(new_heap_size) = self.heap_size.checked_add(size) else {
            log::trace!(
                "sbrk: heap size overflow; ignoring request: heap_size={} + size={} > 0xffffffff",
                self.heap_size,
                size
            );
            return None;
        };
        let memory_map = module.memory_map();
        if new_heap_size > memory_map.max_heap_size() {
            log::trace!(
                "sbrk: new heap size is too large; ignoring request: {} > {}",
                new_heap_size,
                memory_map.max_heap_size()
            );
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

fn empty_page(page_size: u32) -> Box<[u8]> {
    let mut page = Vec::new();
    page.reserve_exact(page_size as usize);
    page.resize(page_size as usize, 0);
    page.into()
}

pub(crate) struct DynamicMemory {
    pages: BTreeMap<u32, Box<[u8]>>,
}

impl DynamicMemory {
    fn new() -> Self {
        Self { pages: BTreeMap::new() }
    }

    fn clear(&mut self) {
        self.pages.clear()
    }
}

macro_rules! emit {
    ($self:ident, $handler_name:ident($($args:tt)*)) => {
        $self.compiled_handlers.push(raw_handlers::$handler_name::<DEBUG> as Handler);
        $self.compiled_args.push(Args::$handler_name($($args)*));
    };
}

macro_rules! emit_branch {
    ($self:ident, $name:ident, $s1:ident, $s2:ident, $i:ident) => {
        let target_true = ProgramCounter($i);
        if !$self.is_branch_valid(target_true) {
            emit!($self, invalid_branch($self.program_counter));
        } else {
            let target_false = $self.next_program_counter();
            emit!($self, $name($s1, $s2, target_true, target_false));
        }
    };
}

fn each_page(module: &Module, address: u32, length: u32, callback: impl FnMut(u32, usize, usize, usize)) {
    let page_size = module.memory_map().page_size();
    let page_address_lo = module.round_to_page_size_down(address);
    let page_address_hi = module.round_to_page_size_down(address + (length - 1));
    each_page_impl(page_size, page_address_lo, page_address_hi, address, length, callback)
}

fn each_page_impl(
    page_size: u32,
    page_address_lo: u32,
    page_address_hi: u32,
    address: u32,
    length: u32,
    mut callback: impl FnMut(u32, usize, usize, usize),
) {
    let page_size = page_size as usize;
    let mut page_address_lo = page_address_lo as usize;
    let page_address_hi = page_address_hi as usize;
    let length = length as usize;

    let initial_page_offset = address as usize - page_address_lo;
    let initial_chunk_length = core::cmp::min(length, page_size - initial_page_offset);
    callback(page_address_lo as u32, initial_page_offset, 0, initial_chunk_length);

    if page_address_lo == page_address_hi {
        return;
    }

    page_address_lo += page_size;
    let mut buffer_offset = initial_chunk_length;
    while page_address_lo < page_address_hi {
        callback(page_address_lo as u32, 0, buffer_offset, page_size);
        buffer_offset += page_size;
        page_address_lo += page_size;
    }

    callback(page_address_lo as u32, 0, buffer_offset, length - buffer_offset)
}

#[test]
fn test_each_page() {
    fn run(address: u32, length: u32) -> Vec<(u32, usize, usize, usize)> {
        let page_size = 4096;
        let page_address_lo = address / page_size * page_size;
        let page_address_hi = (address + (length - 1)) / page_size * page_size;
        let mut output = Vec::new();
        each_page_impl(
            page_size,
            page_address_lo,
            page_address_hi,
            address,
            length,
            |page_address, page_offset, buffer_offset, length| {
                output.push((page_address, page_offset, buffer_offset, length));
            },
        );
        output
    }

    #[rustfmt::skip]
    assert_eq!(run(0, 4096), alloc::vec![
        (0, 0, 0, 4096)
    ]);

    #[rustfmt::skip]
    assert_eq!(run(0, 100), alloc::vec![
        (0, 0, 0, 100)
    ]);

    #[rustfmt::skip]
    assert_eq!(run(96, 4000), alloc::vec![
        (0, 96, 0, 4000)
    ]);

    #[rustfmt::skip]
    assert_eq!(run(4000, 200), alloc::vec![
        (   0, 4000, 0,   96),
        (4096,    0, 96, 104),
    ]);

    #[rustfmt::skip]
    assert_eq!(run(4000, 5000), alloc::vec![
        (   0, 4000,     0,   96),
        (4096,    0,    96, 4096),
        (8192,    0,  4192,  808),
    ]);
}

pub(crate) struct InterpretedInstance {
    module: Module,
    basic_memory: BasicMemory,
    dynamic_memory: DynamicMemory,
    regs: [u32; Reg::ALL.len()],
    program_counter: ProgramCounter,
    program_counter_valid: bool,
    next_program_counter: Option<ProgramCounter>,
    next_program_counter_changed: bool,
    cycle_counter: u64,
    gas: i64,
    compiled_offset_for_block: FlatMap<NonZeroU32>,
    compiled_handlers: Vec<Handler>,
    compiled_args: Vec<Args>,
    compiled_offset: usize,
    interrupt: InterruptKind,
    step_tracing: bool,
}

impl InterpretedInstance {
    pub fn new_from_module(module: Module, force_step_tracing: bool) -> Self {
        let step_tracing = module.is_step_tracing() || force_step_tracing;
        let mut instance = Self {
            compiled_offset_for_block: FlatMap::new(module.code_len()),
            compiled_handlers: Default::default(),
            compiled_args: Default::default(),
            module,
            basic_memory: BasicMemory::new(),
            dynamic_memory: DynamicMemory::new(),
            regs: [0; Reg::ALL.len()],
            program_counter: ProgramCounter(!0),
            program_counter_valid: false,
            next_program_counter: None,
            next_program_counter_changed: true,
            cycle_counter: 0,
            gas: 0,
            compiled_offset: 0,
            interrupt: InterruptKind::Finished,
            step_tracing,
        };

        instance.initialize_module();
        instance
    }

    pub fn reg(&self, reg: Reg) -> RegValue {
        self.regs[reg as usize]
    }

    pub fn set_reg(&mut self, reg: Reg, value: u32) {
        self.regs[reg as usize] = value;
    }

    pub fn gas(&self) -> Gas {
        self.gas
    }

    pub fn set_gas(&mut self, gas: Gas) {
        self.gas = gas;
    }

    pub fn program_counter(&self) -> Option<ProgramCounter> {
        if !self.program_counter_valid {
            None
        } else {
            Some(self.program_counter)
        }
    }

    pub fn next_program_counter(&self) -> Option<ProgramCounter> {
        self.next_program_counter
    }

    pub fn set_next_program_counter(&mut self, pc: ProgramCounter) {
        self.program_counter_valid = false;
        self.next_program_counter = Some(pc);
        self.next_program_counter_changed = true;
    }

    #[allow(clippy::unused_self)]
    pub fn next_native_program_counter(&self) -> Option<usize> {
        None
    }

    pub fn read_memory_into<'slice>(
        &self,
        address: u32,
        buffer: &'slice mut [MaybeUninit<u8>],
    ) -> Result<&'slice mut [u8], MemoryAccessError> {
        if !self.module.is_dynamic_paging() {
            let Some(slice) = self.basic_memory.get_memory_slice(&self.module, address, buffer.len() as u32) else {
                return Err(MemoryAccessError::OutOfRangeAccess {
                    address,
                    length: buffer.len() as u64,
                });
            };

            Ok(byte_slice_init(buffer, slice))
        } else {
            each_page(
                &self.module,
                address,
                buffer.len() as u32,
                |page_address, page_offset, buffer_offset, length| {
                    assert!(buffer_offset + length <= buffer.len());
                    assert!(page_offset + length <= self.module.memory_map().page_size() as usize);
                    let page = self.dynamic_memory.pages.get(&page_address);

                    // SAFETY: Buffers are non-overlapping and the ranges are in-bounds.
                    unsafe {
                        let dst = buffer.as_mut_ptr().cast::<u8>().add(buffer_offset);
                        if let Some(page) = page {
                            let src = page.as_ptr().add(page_offset);
                            core::ptr::copy_nonoverlapping(src, dst, length);
                        } else {
                            core::ptr::write_bytes(dst, 0, length);
                        }
                    }
                },
            );

            // SAFETY: The buffer was initialized.
            Ok(unsafe { slice_assume_init_mut(buffer) })
        }
    }

    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryAccessError> {
        if !self.module.is_dynamic_paging() {
            let Some(slice) = self
                .basic_memory
                .get_memory_slice_mut::<true>(&self.module, address, data.len() as u32)
            else {
                return Err(MemoryAccessError::OutOfRangeAccess {
                    address,
                    length: data.len() as u64,
                });
            };

            slice.copy_from_slice(data);
        } else {
            let dynamic_memory = &mut self.dynamic_memory;
            let page_size = self.module.memory_map().page_size();
            each_page(
                &self.module,
                address,
                data.len() as u32,
                move |page_address, page_offset, buffer_offset, length| {
                    let page = dynamic_memory.pages.entry(page_address).or_insert_with(|| empty_page(page_size));
                    page[page_offset..page_offset + length].copy_from_slice(&data[buffer_offset..buffer_offset + length]);
                },
            );
        }

        Ok(())
    }

    pub fn zero_memory(&mut self, address: u32, length: u32) -> Result<(), MemoryAccessError> {
        if !self.module.is_dynamic_paging() {
            let Some(slice) = self.basic_memory.get_memory_slice_mut::<true>(&self.module, address, length) else {
                return Err(MemoryAccessError::OutOfRangeAccess {
                    address,
                    length: u64::from(length),
                });
            };

            slice.fill(0);
        } else {
            let dynamic_memory = &mut self.dynamic_memory;
            let page_size = self.module.memory_map().page_size();
            each_page(
                &self.module,
                address,
                length,
                move |page_address, page_offset, _, length| match dynamic_memory.pages.entry(page_address) {
                    Entry::Occupied(mut entry) => {
                        let page = entry.get_mut();
                        page[page_offset..page_offset + length].fill(0);
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(empty_page(page_size));
                    }
                },
            );
        }

        Ok(())
    }

    pub fn free_pages(&mut self, address: u32, length: u32) {
        debug_assert!(self.module.is_multiple_of_page_size(address));
        debug_assert_ne!(length, 0);

        if !self.module.is_dynamic_paging() {
            todo!()
        } else {
            let dynamic_memory = &mut self.dynamic_memory;
            each_page(&self.module, address, length, move |page_address, _, _, _| {
                dynamic_memory.pages.remove(&page_address);
            });
        }
    }

    pub fn heap_size(&self) -> u32 {
        if !self.module.is_dynamic_paging() {
            self.basic_memory.heap_size()
        } else {
            todo!()
        }
    }

    pub fn sbrk(&mut self, size: u32) -> Option<u32> {
        if !self.module.is_dynamic_paging() {
            self.basic_memory.sbrk(&self.module, size)
        } else {
            todo!()
        }
    }

    #[allow(clippy::unused_self)]
    pub fn pid(&self) -> Option<u32> {
        None
    }

    pub fn run(&mut self) -> Result<InterruptKind, Error> {
        #[allow(clippy::collapsible_else_if)]
        if log::log_enabled!(target: "polkavm", log::Level::Debug)
            || log::log_enabled!(target: "polkavm::interpreter", log::Level::Debug)
            || cfg!(test)
        {
            if !self.step_tracing {
                Ok(self.run_impl::<true, false>())
            } else {
                Ok(self.run_impl::<true, true>())
            }
        } else {
            if !self.step_tracing {
                Ok(self.run_impl::<false, false>())
            } else {
                Ok(self.run_impl::<false, true>())
            }
        }
    }

    #[inline(never)]
    fn run_impl<const DEBUG: bool, const STEP_TRACING: bool>(&mut self) -> InterruptKind {
        if !self.module.is_dynamic_paging() {
            self.basic_memory.mark_dirty();
        }

        if self.next_program_counter_changed {
            let Some(program_counter) = self.next_program_counter.take() else {
                panic!("failed to run: next program counter is not set");
            };

            self.program_counter = program_counter;
            self.compiled_offset = self.resolve_arbitrary_jump::<DEBUG>(program_counter).unwrap_or(TARGET_OUT_OF_RANGE);

            if DEBUG {
                log::debug!("Starting execution at: {} [{}]", program_counter, self.compiled_offset);
            }
        } else if DEBUG {
            log::trace!("Implicitly resuming at: [{}]", self.compiled_offset);
        }

        let mut offset = self.compiled_offset;
        loop {
            if DEBUG {
                self.cycle_counter += 1;
            }

            let handler = self.compiled_handlers[offset];
            let mut visitor = Visitor { inner: self };
            if let Some(next_offset) = handler(&mut visitor) {
                offset = next_offset;
                self.compiled_offset = offset;
            } else {
                return self.interrupt.clone();
            }
        }
    }

    pub fn reset_memory(&mut self) {
        if !self.module.is_dynamic_paging() {
            self.basic_memory.reset(&self.module);
        } else {
            self.dynamic_memory.clear();
        }
    }

    fn initialize_module(&mut self) {
        if self.module.gas_metering().is_some() {
            self.gas = 0;
        }

        if !self.module.is_dynamic_paging() {
            self.basic_memory.force_reset(&self.module);
        } else {
            self.dynamic_memory.clear();
        }

        self.compile_out_of_range_stub();
    }

    #[inline(always)]
    fn pack_target(index: usize, is_first_in_basic_block: bool) -> NonZeroU32 {
        let mut index = index as u32;
        if is_first_in_basic_block {
            index |= 1 << 31;
        }

        NonZeroU32::new(index).unwrap()
    }

    #[inline(always)]
    fn unpack_target(value: NonZeroU32) -> (bool, Target) {
        ((value.get() >> 31) == 1, ((value.get() << 1) >> 1) as usize)
    }

    fn resolve_jump<const DEBUG: bool>(&mut self, program_counter: ProgramCounter) -> Option<Target> {
        if let Some(compiled_offset) = self.compiled_offset_for_block.get(program_counter.0) {
            let (is_first, target) = Self::unpack_target(compiled_offset);
            if !is_first {
                return None;
            }

            return Some(target);
        }

        self.compile_block::<DEBUG>(program_counter)
    }

    fn resolve_arbitrary_jump<const DEBUG: bool>(&mut self, program_counter: ProgramCounter) -> Option<Target> {
        if let Some(compiled_offset) = self.compiled_offset_for_block.get(program_counter.0) {
            let (_, target) = Self::unpack_target(compiled_offset);
            return Some(target);
        }

        self.compile_block::<DEBUG>(program_counter)
    }

    #[inline(never)]
    #[cold]
    fn compile_block<const DEBUG: bool>(&mut self, program_counter: ProgramCounter) -> Option<Target> {
        let mut instructions = self.module.instructions_at(program_counter)?;

        if program_counter.0 > 0
            && !instructions
                .clone()
                .next_back()
                .map_or(true, |instruction| instruction.starts_new_basic_block())
        {
            return None;
        }

        let origin = self.compiled_handlers.len();
        if DEBUG {
            log::debug!("Compiling block:");
        }

        let mut gas_visitor = GasVisitor::default();
        let mut charge_gas_index = None;
        let mut is_first = true;
        let mut is_properly_terminated = false;
        let mut last_program_counter = program_counter;
        while let Some(instruction) = instructions.next() {
            self.compiled_offset_for_block
                .insert(instruction.offset.0, Self::pack_target(self.compiled_handlers.len(), is_first));

            is_first = false;

            if self.step_tracing {
                if DEBUG {
                    log::debug!("  [{}]: {}: step", self.compiled_handlers.len(), instruction.offset);
                }
                emit!(self, step(instruction.offset));
            }

            if self.module.gas_metering().is_some() {
                if charge_gas_index.is_none() {
                    if DEBUG {
                        log::debug!("  [{}]: {}: charge_gas", self.compiled_handlers.len(), instruction.offset);
                    }

                    charge_gas_index = Some((instruction.offset, self.compiled_handlers.len()));
                    emit!(self, charge_gas(instruction.offset, 0));
                }
                instruction.visit(&mut gas_visitor);
            }

            if DEBUG {
                log::debug!("  [{}]: {}: {}", self.compiled_handlers.len(), instruction.offset, instruction.kind);
            }

            instruction.visit(&mut Compiler::<DEBUG, false> {
                program_counter: instruction.offset,
                instruction_length: instruction.length,
                compiled_handlers: &mut self.compiled_handlers,
                compiled_args: &mut self.compiled_args,
                module: &self.module,
            });

            last_program_counter = instruction.next_offset();
            if instruction.opcode().starts_new_basic_block() {
                is_properly_terminated =
                    instruction.opcode() != polkavm_common::program::Opcode::fallthrough || instructions.next().is_some();
                break;
            }
        }

        if !is_properly_terminated {
            let instruction = polkavm_common::program::ParsedInstruction {
                kind: polkavm_common::program::Instruction::trap,
                offset: last_program_counter,
                length: 1,
            };

            if self.step_tracing {
                if DEBUG {
                    log::debug!("  [{}]: {}: step", self.compiled_handlers.len(), instruction.offset);
                }
                emit!(self, step(instruction.offset));
            }

            if DEBUG {
                log::debug!("  [{}]: {}: trap (implicit)", self.compiled_handlers.len(), instruction.offset);
            }

            if self.module.gas_metering().is_some() {
                instruction.visit(&mut gas_visitor);
            }

            instruction.visit(&mut Compiler::<DEBUG, false> {
                program_counter: instruction.offset,
                instruction_length: instruction.length,
                compiled_handlers: &mut self.compiled_handlers,
                compiled_args: &mut self.compiled_args,
                module: &self.module,
            });
        }

        if let Some((program_counter, index)) = charge_gas_index {
            let gas_cost = gas_visitor.take_block_cost().unwrap();
            self.compiled_args[index] = Args::charge_gas(program_counter, gas_cost);
        }

        if self.compiled_handlers.len() == origin {
            return None;
        }

        Some(origin)
    }

    fn compile_out_of_range_stub(&mut self) {
        const DEBUG: bool = false;
        if self.step_tracing {
            emit!(self, step_out_of_range());
        }

        let gas_cost = if self.module.gas_metering().is_some() {
            crate::gas::trap_cost()
        } else {
            0
        };

        emit!(self, out_of_range(gas_cost));
    }
}

struct Visitor<'a> {
    inner: &'a mut InterpretedInstance,
}

impl<'a> Visitor<'a> {
    #[inline(always)]
    fn get(&self, regimm: impl IntoRegImm) -> u32 {
        match regimm.into() {
            RegImm::Reg(reg) => self.inner.regs[reg as usize],
            RegImm::Imm(value) => value,
        }
    }

    #[inline(always)]
    fn go_to_next_instruction(&mut self) -> Option<Target> {
        Some(self.inner.compiled_offset + 1)
    }

    #[inline(always)]
    fn set<const DEBUG: bool>(&mut self, dst: Reg, value: u32) {
        if DEBUG {
            log::trace!("  {dst} = 0x{value:x}");
        }

        self.inner.regs[dst as usize] = value;
    }

    #[inline(always)]
    fn set3<const DEBUG: bool>(
        &mut self,
        dst: Reg,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        callback: impl Fn(u32, u32) -> u32,
    ) -> Option<Target> {
        let s1 = self.get(s1);
        let s2 = self.get(s2);
        self.set::<DEBUG>(dst, callback(s1, s2));
        self.go_to_next_instruction()
    }

    fn branch<const DEBUG: bool>(
        &mut self,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        target_true: Target,
        target_false: Target,
        callback: impl Fn(u32, u32) -> bool,
    ) -> Option<Target> {
        let s1 = self.get(s1);
        let s2 = self.get(s2);
        if callback(s1, s2) {
            Some(target_true)
        } else {
            Some(target_false)
        }
    }

    fn segfault_impl(&mut self, program_counter: ProgramCounter, page_address: u32) -> Option<Target> {
        self.inner.program_counter = program_counter;
        self.inner.program_counter_valid = true;
        self.inner.next_program_counter = Some(program_counter);
        self.inner.interrupt = InterruptKind::Segfault(Segfault {
            page_address,
            page_size: self.inner.module.memory_map().page_size(),
        });

        None
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn load<T: LoadTy, const DEBUG: bool, const IS_DYNAMIC: bool>(
        &mut self,
        program_counter: ProgramCounter,
        dst: Reg,
        base: Option<Reg>,
        offset: u32,
    ) -> Option<Target> {
        debug_assert_eq!(IS_DYNAMIC, self.inner.module.is_dynamic_paging());
        assert!(core::mem::size_of::<T>() >= 1);

        let address = base.map_or(0, |base| self.inner.regs[base as usize]).wrapping_add(offset);
        let length = core::mem::size_of::<T>() as u32;
        let value = if !IS_DYNAMIC {
            let Some(slice) = self.inner.basic_memory.get_memory_slice(&self.inner.module, address, length) else {
                if DEBUG {
                    log::debug!(
                        "Load of {length} bytes from 0x{address:x} failed! (pc = {program_counter}, cycle = {cycle})",
                        cycle = self.inner.cycle_counter
                    );
                }

                return trap_impl::<DEBUG>(self, program_counter);
            };

            T::from_slice(slice)
        } else {
            let Some(address_end) = address.checked_add(length) else {
                return trap_impl::<DEBUG>(self, program_counter);
            };

            let page_address_lo = self.inner.module.round_to_page_size_down(address);
            let page_address_hi = self.inner.module.round_to_page_size_down(address_end - 1);
            if page_address_lo == page_address_hi {
                if let Some(page) = self.inner.dynamic_memory.pages.get_mut(&page_address_lo) {
                    let offset = address as usize - page_address_lo as usize;
                    T::from_slice(&page[offset..offset + core::mem::size_of::<T>()])
                } else {
                    return self.segfault_impl(program_counter, page_address_lo);
                }
            } else {
                let mut iter = self.inner.dynamic_memory.pages.range(page_address_lo..=page_address_hi);
                let lo = iter.next();
                let hi = iter.next();

                match (lo, hi) {
                    (Some((_, lo)), Some((_, hi))) => {
                        let page_size = self.inner.module.memory_map().page_size() as usize;
                        let lo_len = page_address_hi as usize - address as usize;
                        let hi_len = core::mem::size_of::<T>() - lo_len;
                        let mut buffer = [0; 4];
                        buffer[..lo_len].copy_from_slice(&lo[page_size - lo_len..]);
                        buffer[lo_len..].copy_from_slice(&hi[..hi_len]);
                        T::from_slice(&buffer)
                    }
                    (None, _) => {
                        return self.segfault_impl(program_counter, page_address_lo);
                    }
                    (Some((page_address, _)), _) => {
                        let missing_page_address = if *page_address == page_address_lo {
                            page_address_hi
                        } else {
                            page_address_lo
                        };

                        return self.segfault_impl(program_counter, missing_page_address);
                    }
                }
            }
        };

        if DEBUG {
            log::trace!("  {dst} = {kind} [0x{address:x}] = 0x{value:x}", kind = core::any::type_name::<T>());
        }

        self.set::<false>(dst, value);
        self.go_to_next_instruction()
    }

    fn store<T: StoreTy, const DEBUG: bool, const IS_DYNAMIC: bool>(
        &mut self,
        program_counter: ProgramCounter,
        src: impl IntoRegImm,
        base: Option<Reg>,
        offset: u32,
    ) -> Option<Target> {
        debug_assert_eq!(IS_DYNAMIC, self.inner.module.is_dynamic_paging());
        assert!(core::mem::size_of::<T>() >= 1);

        let address = base.map_or(0, |base| self.inner.regs[base as usize]).wrapping_add(offset);
        let value = match src.into() {
            RegImm::Reg(src) => {
                let value = self.inner.regs[src as usize];
                if DEBUG {
                    log::trace!("  {kind} [0x{address:x}] = {src} = 0x{value:x}", kind = core::any::type_name::<T>());
                }

                value
            }
            RegImm::Imm(value) => {
                if DEBUG {
                    log::trace!("  {kind} [0x{address:x}] = 0x{value:x}", kind = core::any::type_name::<T>());
                }

                value
            }
        };

        let length = core::mem::size_of::<T>() as u32;
        let value = T::into_bytes(value);

        if !IS_DYNAMIC {
            let Some(slice) = self
                .inner
                .basic_memory
                .get_memory_slice_mut::<false>(&self.inner.module, address, length)
            else {
                if DEBUG {
                    log::debug!(
                        "Store of {length} bytes to 0x{address:x} failed! (pc = {program_counter}, cycle = {cycle})",
                        cycle = self.inner.cycle_counter
                    );
                }

                return trap_impl::<DEBUG>(self, program_counter);
            };
            slice.copy_from_slice(value.as_ref());
        } else {
            let Some(address_end) = address.checked_add(length) else {
                return trap_impl::<DEBUG>(self, program_counter);
            };

            let page_address_lo = self.inner.module.round_to_page_size_down(address);
            let page_address_hi = self.inner.module.round_to_page_size_down(address_end - 1);
            if page_address_lo == page_address_hi {
                if let Some(page) = self.inner.dynamic_memory.pages.get_mut(&page_address_lo) {
                    let offset = address as usize - page_address_lo as usize;
                    let value = value.as_ref();
                    page[offset..offset + value.len()].copy_from_slice(value);
                } else {
                    return self.segfault_impl(program_counter, page_address_lo);
                }
            } else {
                let mut iter = self.inner.dynamic_memory.pages.range_mut(page_address_lo..=page_address_hi);
                let lo = iter.next();
                let hi = iter.next();

                match (lo, hi) {
                    (Some((_, lo)), Some((_, hi))) => {
                        let value = value.as_ref();
                        let page_size = self.inner.module.memory_map().page_size() as usize;
                        let lo_len = page_address_hi as usize - address as usize;
                        let hi_len = value.len() - lo_len;
                        lo[page_size - lo_len..].copy_from_slice(&value[..lo_len]);
                        hi[..hi_len].copy_from_slice(&value[lo_len..]);
                    }
                    (None, _) => {
                        return self.segfault_impl(program_counter, page_address_lo);
                    }
                    (Some((page_address, _)), _) => {
                        let missing_page_address = if *page_address == page_address_lo {
                            page_address_hi
                        } else {
                            page_address_lo
                        };

                        return self.segfault_impl(program_counter, missing_page_address);
                    }
                }
            }
        };

        self.go_to_next_instruction()
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn jump_indirect_impl<const DEBUG: bool>(&mut self, program_counter: ProgramCounter, dynamic_address: u32) -> Option<Target> {
        if dynamic_address == VM_ADDR_RETURN_TO_HOST {
            self.inner.program_counter = ProgramCounter(!0);
            self.inner.program_counter_valid = false;
            self.inner.next_program_counter = None;
            self.inner.next_program_counter_changed = true;
            self.inner.interrupt = InterruptKind::Finished;
            return None;
        }

        let Some(target) = self.inner.module.jump_table().get_by_address(dynamic_address) else {
            if DEBUG {
                log::trace!("Indirect jump to dynamic address {dynamic_address}: invalid (bad jump table index)");
            }

            return trap_impl::<DEBUG>(self, program_counter);
        };

        if let Some(target) = self.inner.resolve_jump::<DEBUG>(target) {
            if DEBUG {
                log::trace!("Indirect jump to dynamic address {dynamic_address}: {target}");
            }

            Some(target)
        } else {
            if DEBUG {
                log::trace!("Indirect jump to dynamic address {dynamic_address}: invalid (bad target)");
            }

            trap_impl::<DEBUG>(self, program_counter)
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

#[derive(Copy, Clone, Default)]
#[repr(C)]
struct Args {
    a0: u32,
    a1: u32,
    a2: u32,
    a3: u32,
}

type Handler = for<'a, 'b> fn(visitor: &'a mut Visitor<'b>) -> Option<Target>;

macro_rules! define_interpreter {
    (@define $handler_name:ident $body:block $self:ident) => {{
        impl Args {
            pub fn $handler_name() -> Args {
                Args::default()
            }
        }

        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: u32) => {{
        impl Args {
            pub fn $handler_name(a0: u32) -> Args {
                Args {
                    a0,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = args.a0;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter) -> Args {
                Args {
                    a0: a0.0,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = ProgramCounter(args.a0);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: u32) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter, a1: u32) -> Args {
                Args {
                    a0: a0.0,
                    a1,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = args.a1;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: ProgramCounter) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter, a1: ProgramCounter) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.0,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = ProgramCounter(args.a1);

        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: u32, $a2:ident: u32) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter, a1: u32, a2: u32) -> Args {
                Args {
                    a0: a0.0,
                    a1,
                    a2,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = args.a1;
        let $a2 = args.a2;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: u32) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: u32) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.into() as u32,
                    a2,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = args.a2;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: u32, $a3:ident: u32) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: u32, a3: u32) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.into() as u32,
                    a2,
                    a3,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = args.a2;
        let $a3 = args.a3;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: Reg, $a3:ident: u32) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: impl Into<Reg>, a3: u32) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.into() as u32,
                    a2: a2.into() as u32,
                    a3,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = transmute_reg(args.a2);
        let $a3 = args.a3;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: Reg, $a3:ident: u32, $a4:ident: u32) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: impl Into<Reg>, a3: u32, a4: u32) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.into() as u32 | ((a2.into() as u32) << 4),
                    a2: a3,
                    a3: a4,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = transmute_reg(args.a1 & 0b1111);
        let $a2 = transmute_reg(args.a1 >> 4);
        let $a3 = args.a2;
        let $a4 = args.a3;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1: a1.into() as u32,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: Reg) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: impl Into<Reg>) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1: a1.into() as u32,
                    a2: a2.into() as u32,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = transmute_reg(args.a2);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: u32) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: u32) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1: a1.into() as u32,
                    a2,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = args.a2;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: u32) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: u32) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = args.a1;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: u32, $a2:ident: u32) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: u32, a2: u32) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1,
                    a2,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = args.a1;
        let $a2 = args.a2;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Target) => {{
        impl Args {
            pub fn $handler_name(a0: Target) -> Args {
                Args {
                    a0: a0 as u32,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = args.a0 as Target;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: Target) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: Target) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1: a1.into() as u32,
                    a2: a2 as u32,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = args.a2 as Target;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: Target, $a3:ident: Target) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: Target, a3: Target) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1: a1.into() as u32,
                    a2: a2 as u32,
                    a3: a3 as u32,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = args.a2 as Target;
        let $a3 = args.a3 as Target;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: u32, $a2:ident: Target, $a3:ident: Target) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: impl Into<Reg>, a1: u32, a2: Target, a3: Target) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1,
                    a2: a2 as u32,
                    a3: a3 as u32,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = args.a1;
        let $a2 = args.a2 as Target;
        let $a3 = args.a3 as Target;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: ProgramCounter) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: ProgramCounter) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1: a1.into() as u32,
                    a2: a2.0,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = ProgramCounter(args.a2);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: ProgramCounter, $a3:ident: ProgramCounter) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: ProgramCounter, a3: ProgramCounter) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1: a1.into() as u32,
                    a2: a2.0,
                    a3: a3.0,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = ProgramCounter(args.a2);
        let $a3 = ProgramCounter(args.a3);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: u32, $a2:ident: ProgramCounter, $a3:ident: ProgramCounter) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: impl Into<Reg>, a1: u32, a2: ProgramCounter, a3: ProgramCounter) -> Args {
                Args {
                    a0: a0.into() as u32,
                    a1,
                    a2: a2.0,
                    a3: a3.0,
                    ..Args::default()
                }
            }
        }

        let args = $self.inner.compiled_args[$self.inner.compiled_offset];
        let $a0 = transmute_reg(args.a0);
        let $a1 = args.a1;
        let $a2 = ProgramCounter(args.a2);
        let $a3 = ProgramCounter(args.a3);
        $body
    }};

    (@arg_names $handler_name:ident, $a0:ident: $a0_ty:ty, $a1:ident: $a1_ty:ty, $a2:ident: $a2_ty:ty) => {
        asm::$handler_name($a0, $a1, $a2)
    };

    ($(
        fn $handler_name:ident<const DEBUG: bool>($self:ident: &mut Visitor $($arg:tt)*) -> Option<Target> $body:block
    )+) => {
        mod raw_handlers {
            use super::*;
            $(
                #[allow(clippy::needless_lifetimes)]
                pub fn $handler_name<'a, 'b, const DEBUG: bool>($self: &'a mut Visitor<'b>) -> Option<Target> {
                    define_interpreter!(@define $handler_name $body $self $($arg)*)
                }
            )+
        }
    };
}

#[inline(always)]
fn transmute_reg(value: u32) -> Reg {
    debug_assert!(Reg::from_raw(value).is_some());

    // SAFETY: The `value` passed in here is always constructed through `reg as u32` so this is always safe.
    unsafe { core::mem::transmute(value) }
}

fn trap_impl<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter) -> Option<Target> {
    visitor.inner.program_counter = program_counter;
    visitor.inner.program_counter_valid = true;
    visitor.inner.next_program_counter = None;
    visitor.inner.next_program_counter_changed = true;
    visitor.inner.interrupt = InterruptKind::Trap;
    None
}

fn not_enough_gas_impl<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, new_gas: i64) -> Option<Target> {
    match visitor.inner.module.gas_metering().unwrap() {
        GasMeteringKind::Async => {
            visitor.inner.gas = new_gas;
            visitor.inner.program_counter_valid = false;
            visitor.inner.next_program_counter = None;
            visitor.inner.next_program_counter_changed = true;
        }
        GasMeteringKind::Sync => {
            visitor.inner.program_counter = program_counter;
            visitor.inner.program_counter_valid = true;
            visitor.inner.next_program_counter = Some(program_counter);
            visitor.inner.next_program_counter_changed = false;
        }
    }

    visitor.inner.interrupt = InterruptKind::NotEnoughGas;
    None
}

const TARGET_OUT_OF_RANGE: Target = 0;

macro_rules! handle_unresolved_branch {
    ($debug:expr, $visitor:ident, $s1:ident, $s2:ident, $tt:ident, $tf:ident, $name:ident) => {{
        if DEBUG {
            log::trace!("[{}]: jump {} if {} {} {}", $visitor.inner.compiled_offset, $tt, $s1, $debug, $s2);
        }

        let target_false = $visitor.inner.resolve_jump::<DEBUG>($tf).unwrap_or(TARGET_OUT_OF_RANGE);
        if let Some(target_true) = $visitor.inner.resolve_jump::<DEBUG>($tt) {
            let offset = $visitor.inner.compiled_offset;
            $visitor.inner.compiled_handlers[offset] = raw_handlers::$name::<DEBUG> as Handler;
            $visitor.inner.compiled_args[offset] = Args::$name($s1, $s2, target_true, target_false);
            Some(offset)
        } else {
            todo!()
        }
    }};
}

define_interpreter! {
    fn charge_gas<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, gas_cost: u32) -> Option<Target> {
        let new_gas = visitor.inner.gas - i64::from(gas_cost);

        if DEBUG {
            log::trace!("[{}]: charge_gas: {gas_cost} ({} -> {})", visitor.inner.compiled_offset, visitor.inner.gas, new_gas);
        }

        if new_gas < 0 {
            not_enough_gas_impl::<DEBUG>(visitor, program_counter, new_gas)
        } else {
            visitor.inner.gas = new_gas;
            visitor.go_to_next_instruction()
        }
    }

    fn out_of_range<const DEBUG: bool>(visitor: &mut Visitor, gas: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: trap (out of range)", visitor.inner.compiled_offset);
        }

        let program_counter = visitor.inner.program_counter;
        let new_gas = visitor.inner.gas - i64::from(gas);
        if new_gas < 0 {
            not_enough_gas_impl::<DEBUG>(visitor, program_counter, new_gas)
        } else {
            log::debug!("Trap at {}: explicit trap", program_counter);

            visitor.inner.gas = new_gas;
            trap_impl::<DEBUG>(visitor, program_counter)
        }
    }

    fn step<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: step", visitor.inner.compiled_offset);
        }

        visitor.inner.program_counter = program_counter;
        visitor.inner.program_counter_valid = true;
        visitor.inner.next_program_counter = Some(program_counter);
        visitor.inner.next_program_counter_changed = false;
        visitor.inner.interrupt = InterruptKind::Step;
        visitor.inner.compiled_offset += 1;
        None
    }

    fn step_out_of_range<const DEBUG: bool>(visitor: &mut Visitor) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: step (out of range)", visitor.inner.compiled_offset);
        }

        visitor.inner.program_counter_valid = true;
        visitor.inner.next_program_counter = Some(visitor.inner.program_counter);
        visitor.inner.next_program_counter_changed = false;
        visitor.inner.interrupt = InterruptKind::Step;
        visitor.inner.compiled_offset += 1;
        None
    }

    fn fallthrough<const DEBUG: bool>(visitor: &mut Visitor) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: fallthrough", visitor.inner.compiled_offset);
        }

        visitor.go_to_next_instruction()
    }

    fn trap<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: trap", visitor.inner.compiled_offset);
        }

        log::debug!("Trap at {}: explicit trap", program_counter);
        trap_impl::<DEBUG>(visitor, program_counter)
    }

    fn invalid_branch<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter) -> Option<Target> {
        log::debug!("Trap at {}: invalid branch", program_counter);
        trap_impl::<DEBUG>(visitor, program_counter)
    }

    fn sbrk<const DEBUG: bool>(visitor: &mut Visitor, dst: Reg, size: Reg) -> Option<Target> {
        let size = visitor.get(size);
        let result = visitor.inner.sbrk(size).unwrap_or(0);
        visitor.set::<DEBUG>(dst, result);
        visitor.go_to_next_instruction()
    }

    fn ecalli<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, hostcall_number: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: ecalli {hostcall_number}", visitor.inner.compiled_offset);
        }

        let length = visitor.inner.module.instructions_at(program_counter).unwrap().next().unwrap().length;
        visitor.inner.program_counter = program_counter;
        visitor.inner.program_counter_valid = true;
        visitor.inner.next_program_counter = Some(ProgramCounter(program_counter.0 + length));
        visitor.inner.next_program_counter_changed = true;
        visitor.inner.interrupt = InterruptKind::Ecalli(hostcall_number);
        None
    }

    fn set_less_than_unsigned<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::set_less_than_unsigned(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| u32::from(s1 < s2))
    }

    fn set_less_than_signed<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::set_less_than_signed(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| u32::from((s1 as i32) < (s2 as i32)))
    }

    fn shift_logical_right<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::shift_logical_right(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_shr)
    }

    fn shift_arithmetic_right<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::shift_arithmetic_right(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| ((s1 as i32).wrapping_shr(s2)) as u32)
    }

    fn shift_logical_left<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::shift_logical_left(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_shl)
    }

    fn xor<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::xor(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| s1 ^ s2)
    }

    fn and<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::and(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| s1 & s2)
    }

    fn or<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::or(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| s1 | s2)
    }

    fn add<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::add(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_add)
    }

    fn sub<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::sub(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_sub)
    }

    fn negate_and_add_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::negate_and_add_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| s2.wrapping_sub(s1))
    }

    fn mul<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::mul(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_mul)
    }

    fn mul_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::mul_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_mul)
    }

    fn mul_upper_signed_signed<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::mul_upper_signed_signed(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| mulh(s1 as i32, s2 as i32) as u32)
    }

    fn mul_upper_signed_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::mul_upper_signed_signed_imm(d, s1, s2));
        }


        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| mulh(s1 as i32, s2 as i32) as u32)
    }

    fn mul_upper_unsigned_unsigned<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::mul_upper_unsigned_unsigned(d, s1, s2));
        }


        visitor.set3::<DEBUG>(d, s1, s2, mulhu)
    }

    fn mul_upper_unsigned_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::mul_upper_unsigned_unsigned_imm(d, s1, s2));
        }


        visitor.set3::<DEBUG>(d, s1, s2, mulhu)
    }

    fn mul_upper_signed_unsigned<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::mul_upper_signed_unsigned(d, s1, s2));
        }


        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| mulhsu(s1 as i32, s2) as u32)
    }

    fn div_unsigned<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::div_unsigned(d, s1, s2));
        }


        visitor.set3::<DEBUG>(d, s1, s2, divu)
    }

    fn div_signed<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::div_signed(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| div(s1 as i32, s2 as i32) as u32)
    }

    fn rem_unsigned<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::rem_unsigned(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, remu)
    }

    fn rem_signed<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::rem_signed(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| rem(s1 as i32, s2 as i32) as u32)
    }

    fn set_less_than_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::set_less_than_unsigned_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| u32::from(s1 < s2))
    }

    fn set_greater_than_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::set_greater_than_unsigned_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| u32::from(s1 > s2))
    }

    fn set_less_than_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::set_less_than_signed_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| u32::from((s1 as i32) < (s2 as i32)))
    }

    fn set_greater_than_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::set_greater_than_signed_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| u32::from((s1 as i32) > (s2 as i32)))
    }

    fn shift_logical_right_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::shift_logical_right_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_shr)
    }

    fn shift_logical_right_imm_alt<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s2: Reg, s1: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::shift_logical_right_imm_alt(d, s2, s1));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_shr)
    }

    fn shift_arithmetic_right_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::shift_arithmetic_right_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| ((s1 as i32) >> s2) as u32)
    }

    fn shift_arithmetic_right_imm_alt<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s2: Reg, s1: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::shift_arithmetic_right_imm_alt(d, s2, s1));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| ((s1 as i32) >> s2) as u32)
    }

    fn shift_logical_left_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::shift_logical_left_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_shl)
    }

    fn shift_logical_left_imm_alt<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s2: Reg, s1: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::shift_logical_left_imm_alt(d, s2, s1));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_shl)
    }

    fn or_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::or_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| s1 | s2)
    }

    fn and_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::and_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| s1 & s2)
    }

    fn xor_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::xor_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, |s1, s2| s1 ^ s2)
    }

    fn load_imm<const DEBUG: bool>(visitor: &mut Visitor, dst: Reg, imm: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_imm(dst, imm));
        }

        visitor.set::<DEBUG>(dst, imm);
        visitor.go_to_next_instruction()
    }

    fn move_reg<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::move_reg(d, s));
        }

        let imm = visitor.get(s);
        visitor.set::<DEBUG>(d, imm);
        visitor.go_to_next_instruction()
    }

    fn cmov_if_zero<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s: Reg, c: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::cmov_if_zero(d, s, c));
        }

        if visitor.get(c) == 0 {
            let value = visitor.get(s);
            visitor.set::<DEBUG>(d, value);
        }

        visitor.go_to_next_instruction()
    }

    fn cmov_if_zero_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, c: Reg, s: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::cmov_if_zero_imm(d, c, s));
        }

        if visitor.get(c) == 0 {
            visitor.set::<DEBUG>(d, s);
        }

        visitor.go_to_next_instruction()
    }

    fn cmov_if_not_zero<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s: Reg, c: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::cmov_if_not_zero(d, s, c));
        }

        if visitor.get(c) != 0 {
            let value = visitor.get(s);
            visitor.set::<DEBUG>(d, value);
        }

        visitor.go_to_next_instruction()
    }

    fn cmov_if_not_zero_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, c: Reg, s: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::cmov_if_not_zero_imm(d, c, s));
        }

        if visitor.get(c) != 0 {
            visitor.set::<DEBUG>(d, s);
        }

        visitor.go_to_next_instruction()
    }

    fn add_imm<const DEBUG: bool>(visitor: &mut Visitor, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::add_imm(d, s1, s2));
        }

        visitor.set3::<DEBUG>(d, s1, s2, u32::wrapping_add)
    }

    fn store_imm_u8_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_u8(offset, value));
        }

        visitor.store::<u8, DEBUG, false>(program_counter, value, None, offset)
    }

    fn store_imm_u8_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_u8(offset, value));
        }

        visitor.store::<u8, DEBUG, true>(program_counter, value, None, offset)
    }

    fn store_imm_u16_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_u16(offset, value));
        }

        visitor.store::<u16, DEBUG, false>(program_counter, value, None, offset)
    }

    fn store_imm_u16_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_u16(offset, value));
        }

        visitor.store::<u16, DEBUG, true>(program_counter, value, None, offset)
    }

    fn store_imm_u32_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_u32(offset, value));
        }

        visitor.store::<u32, DEBUG, false>(program_counter, value, None, offset)
    }

    fn store_imm_u32_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_u32(offset, value));
        }

        visitor.store::<u32, DEBUG, true>(program_counter, value, None, offset)
    }

    fn store_imm_indirect_u8_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, base: Reg, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_indirect_u8(base, offset, value));
        }

        visitor.store::<u8, DEBUG, false>(program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u8_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, base: Reg, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_indirect_u8(base, offset, value));
        }

        visitor.store::<u8, DEBUG, true>(program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u16_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, base: Reg, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_indirect_u16(base, offset, value));
        }

        visitor.store::<u16, DEBUG, false>(program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u16_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, base: Reg, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_indirect_u16(base, offset, value));
        }

        visitor.store::<u16, DEBUG, true>(program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u32_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, base: Reg, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_indirect_u32(base, offset, value));
        }

        visitor.store::<u32, DEBUG, false>(program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u32_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, base: Reg, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_imm_indirect_u32(base, offset, value));
        }

        visitor.store::<u32, DEBUG, true>(program_counter, value, Some(base), offset)
    }

    fn store_indirect_u8_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_indirect_u8(src, base, offset));
        }

        visitor.store::<u8, DEBUG, false>(program_counter, src, Some(base), offset)
    }

    fn store_indirect_u8_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_indirect_u8(src, base, offset));
        }

        visitor.store::<u8, DEBUG, true>(program_counter, src, Some(base), offset)
    }

    fn store_indirect_u16_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_indirect_u16(src, base, offset));
        }

        visitor.store::<u16, DEBUG, false>(program_counter, src, Some(base), offset)
    }

    fn store_indirect_u16_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_indirect_u16(src, base, offset));
        }

        visitor.store::<u16, DEBUG, true>(program_counter, src, Some(base), offset)
    }

    fn store_indirect_u32_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_indirect_u32(src, base, offset));
        }

        visitor.store::<u32, DEBUG, false>(program_counter, src, Some(base), offset)
    }

    fn store_indirect_u32_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_indirect_u32(src, base, offset));
        }

        visitor.store::<u32, DEBUG, true>(program_counter, src, Some(base), offset)
    }

    fn store_u8_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_u8(src, offset));
        }

        visitor.store::<u8, DEBUG, false>(program_counter, src, None, offset)
    }

    fn store_u8_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_u8(src, offset));
        }

        visitor.store::<u8, DEBUG, true>(program_counter, src, None, offset)
    }

    fn store_u16_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_u16(src, offset));
        }

        visitor.store::<u16, DEBUG, false>(program_counter, src, None, offset)
    }

    fn store_u16_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_u16(src, offset));
        }

        visitor.store::<u16, DEBUG, true>(program_counter, src, None, offset)
    }

    fn store_u32_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_u32(src, offset));
        }

        visitor.store::<u32, DEBUG, false>(program_counter, src, None, offset)
    }

    fn store_u32_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, src: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::store_u32(src, offset));
        }

        visitor.store::<u32, DEBUG, true>(program_counter, src, None, offset)
    }

    fn load_u8_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_u8(dst, offset));
        }

        visitor.load::<u8, DEBUG, false>(program_counter, dst, None, offset)
    }

    fn load_u8_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_u8(dst, offset));
        }

        visitor.load::<u8, DEBUG, true>(program_counter, dst, None, offset)
    }

    fn load_i8_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_i8(dst, offset));
        }

        visitor.load::<i8, DEBUG, false>(program_counter, dst, None, offset)
    }

    fn load_i8_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_i8(dst, offset));
        }

        visitor.load::<i8, DEBUG, true>(program_counter, dst, None, offset)
    }

    fn load_u16_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_u16(dst, offset));
        }

        visitor.load::<u16, DEBUG, false>(program_counter, dst, None, offset)
    }

    fn load_u16_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_u16(dst, offset));
        }

        visitor.load::<u16, DEBUG, true>(program_counter, dst, None, offset)
    }

    fn load_i16_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_i16(dst, offset));
        }

        visitor.load::<i16, DEBUG, false>(program_counter, dst, None, offset)
    }

    fn load_i16_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_i16(dst, offset));
        }

        visitor.load::<i16, DEBUG, true>(program_counter, dst, None, offset)
    }

    fn load_u32_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_u32(dst, offset));
        }

        visitor.load::<u32, DEBUG, false>(program_counter, dst, None, offset)
    }

    fn load_u32_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_u32(dst, offset));
        }

        visitor.load::<u32, DEBUG, true>(program_counter, dst, None, offset)
    }

    fn load_indirect_u8_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_indirect_u8(dst, base, offset));
        }

        visitor.load::<u8, DEBUG, false>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u8_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_indirect_u8(dst, base, offset));
        }

        visitor.load::<u8, DEBUG, true>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_i8_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_indirect_i8(dst, base, offset));
        }

        visitor.load::<i8, DEBUG, false>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_i8_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_indirect_i8(dst, base, offset));
        }

        visitor.load::<i8, DEBUG, true>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u16_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_indirect_u16(dst, base, offset));
        }

        visitor.load::<u16, DEBUG, false>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u16_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_indirect_u16(dst, base, offset));
        }

        visitor.load::<u16, DEBUG, true>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_i16_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_indirect_i16(dst, base, offset));
        }

        visitor.load::<i16, DEBUG, false>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_i16_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_indirect_i16(dst, base, offset));
        }

        visitor.load::<i16, DEBUG, true>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u32_basic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_indirect_u32(dst, base, offset));
        }

        visitor.load::<u32, DEBUG, false>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u32_dynamic<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_indirect_u32(dst, base, offset));
        }

        visitor.load::<u32, DEBUG, true>(program_counter, dst, Some(base), offset)
    }

    fn branch_less_unsigned<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <u {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 < s2)
    }

    fn branch_less_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <u {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 < s2)
    }

    fn branch_less_signed<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <s {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| (s1 as i32) < (s2 as i32))
    }

    fn branch_less_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <s {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| (s1 as i32) < (s2 as i32))
    }

    fn branch_eq<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} == {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 == s2)
    }

    fn branch_eq_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} == {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 == s2)
    }

    fn branch_not_eq<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} != {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 != s2)
    }

    fn branch_not_eq_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} != {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 != s2)
    }

    fn branch_greater_or_equal_unsigned<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=u {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 >= s2)
    }

    fn branch_greater_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=u {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 >= s2)
    }

    fn branch_greater_or_equal_signed<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=s {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| (s1 as i32) >= (s2 as i32))
    }

    fn branch_greater_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=s {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| (s1 as i32) >= (s2 as i32))
    }

    fn branch_less_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <=u {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 <= s2)
    }

    fn branch_less_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <=s {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| (s1 as i32) <= (s2 as i32))
    }

    fn branch_greater_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >u {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 > s2)
    }

    fn branch_greater_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >s {s2}", visitor.inner.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| (s1 as i32) > (s2 as i32))
    }

    fn jump<const DEBUG: bool>(visitor: &mut Visitor, target: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{target}", visitor.inner.compiled_offset);
        }

        Some(target)
    }

    fn jump_indirect<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::jump_indirect(base, offset));
        }

        let dynamic_address = visitor.get(base).wrapping_add(offset);
        visitor.jump_indirect_impl::<DEBUG>(program_counter, dynamic_address)
    }

    fn load_imm_and_jump_indirect<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, ra: Reg, base: Reg, value: u32, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.inner.compiled_offset, asm::load_imm_and_jump_indirect(ra, base, value, offset));
        }

        let dynamic_address = visitor.get(base).wrapping_add(offset);
        visitor.set::<DEBUG>(ra, value);
        visitor.jump_indirect_impl::<DEBUG>(program_counter, dynamic_address)
    }

    fn unresolved_branch_less_unsigned<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<u", visitor, s1, s2, tt, tf, branch_less_unsigned)
    }

    fn unresolved_branch_less_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<u", visitor, s1, s2, tt, tf, branch_less_unsigned_imm)
    }

    fn unresolved_branch_less_signed<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<s", visitor, s1, s2, tt, tf, branch_less_signed)
    }

    fn unresolved_branch_less_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<s", visitor, s1, s2, tt, tf, branch_less_signed_imm)
    }

    fn unresolved_branch_eq<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("==", visitor, s1, s2, tt, tf, branch_eq)
    }

    fn unresolved_branch_eq_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("==", visitor, s1, s2, tt, tf, branch_eq_imm)
    }

    fn unresolved_branch_not_eq<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("!=", visitor, s1, s2, tt, tf, branch_not_eq)
    }

    fn unresolved_branch_not_eq_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("!=", visitor, s1, s2, tt, tf, branch_not_eq_imm)
    }

    fn unresolved_branch_greater_or_equal_unsigned<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">=u", visitor, s1, s2, tt, tf, branch_greater_or_equal_unsigned)
    }

    fn unresolved_branch_greater_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">=u", visitor, s1, s2, tt, tf, branch_greater_or_equal_unsigned_imm)
    }

    fn unresolved_branch_greater_or_equal_signed<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">=s", visitor, s1, s2, tt, tf, branch_greater_or_equal_signed)
    }

    fn unresolved_branch_greater_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">=s", visitor, s1, s2, tt, tf, branch_greater_or_equal_signed_imm)
    }

    fn unresolved_branch_greater_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">u", visitor, s1, s2, tt, tf, branch_greater_unsigned_imm)
    }

    fn unresolved_branch_greater_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">s", visitor, s1, s2, tt, tf, branch_greater_signed_imm)
    }

    fn unresolved_branch_less_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<=u", visitor, s1, s2, tt, tf, branch_less_or_equal_unsigned_imm)
    }

    fn unresolved_branch_less_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut Visitor, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<=s", visitor, s1, s2, tt, tf, branch_less_or_equal_signed_imm)
    }

    fn unresolved_jump<const DEBUG: bool>(visitor: &mut Visitor, program_counter: ProgramCounter, jump_to: ProgramCounter) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump {jump_to}", visitor.inner.compiled_offset);
        }

        if let Some(target) = visitor.inner.resolve_jump::<DEBUG>(jump_to) {
            let offset = visitor.inner.compiled_offset;
            if offset + 1 == target {
                visitor.inner.compiled_handlers[offset] = raw_handlers::fallthrough::<DEBUG> as Handler;
                visitor.inner.compiled_args[offset] = Args::fallthrough();
            } else {
                visitor.inner.compiled_handlers[offset] = raw_handlers::jump::<DEBUG> as Handler;
                visitor.inner.compiled_args[offset] = Args::jump(target);
            }

            Some(target)
        } else {
            trap_impl::<DEBUG>(visitor, program_counter)
        }
    }
}

struct Compiler<'a, const DEBUG: bool, const STEP_TRACING: bool> {
    program_counter: ProgramCounter,
    instruction_length: u32,
    compiled_handlers: &'a mut Vec<Handler>,
    compiled_args: &'a mut Vec<Args>,
    module: &'a Module,
}

impl<'a, const DEBUG: bool, const STEP_TRACING: bool> Compiler<'a, DEBUG, STEP_TRACING> {
    fn next_program_counter(&self) -> ProgramCounter {
        ProgramCounter(self.program_counter.0 + self.instruction_length)
    }

    fn is_branch_valid(&mut self, target: ProgramCounter) -> bool {
        let Some(mut instructions) = self.module.instructions_at(target) else {
            log::debug!("  invalid branch to {target}: out of range offset");
            return false;
        };

        if let Some(previous_instruction) = instructions.next_back() {
            if !previous_instruction.starts_new_basic_block() {
                log::debug!("  invalid branch to {target}: previous insruction doesn't start an new basic block");
                return false;
            }
        }

        true
    }
}

impl<'a, const DEBUG: bool, const STEP_TRACING: bool> InstructionVisitor for Compiler<'a, DEBUG, STEP_TRACING> {
    type ReturnTy = ();

    fn trap(&mut self) -> Self::ReturnTy {
        emit!(self, trap(self.program_counter));
    }

    fn fallthrough(&mut self) -> Self::ReturnTy {
        let target = self.next_program_counter();
        emit!(self, unresolved_jump(self.program_counter, target));
    }

    fn sbrk(&mut self, dst: RawReg, size: RawReg) -> Self::ReturnTy {
        emit!(self, sbrk(dst, size));
    }

    fn ecalli(&mut self, imm: u32) -> Self::ReturnTy {
        emit!(self, ecalli(self.program_counter, imm));
    }

    fn set_less_than_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, set_less_than_unsigned(d, s1, s2));
    }

    fn set_less_than_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, set_less_than_signed(d, s1, s2));
    }

    fn shift_logical_right(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, shift_logical_right(d, s1, s2));
    }

    fn shift_arithmetic_right(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right(d, s1, s2));
    }

    fn shift_logical_left(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, shift_logical_left(d, s1, s2));
    }

    fn xor(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, xor(d, s1, s2));
    }

    fn and(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, and(d, s1, s2));
    }

    fn or(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, or(d, s1, s2));
    }

    fn add(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, add(d, s1, s2));
    }

    fn sub(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, sub(d, s1, s2));
    }

    fn negate_and_add_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, negate_and_add_imm(d, s1, s2));
    }

    fn mul(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, mul(d, s1, s2));
    }

    fn mul_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, mul_imm(d, s1, s2));
    }

    fn mul_upper_signed_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, mul_upper_signed_signed(d, s1, s2));
    }

    fn mul_upper_signed_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, mul_upper_signed_signed_imm(d, s1, s2));
    }

    fn mul_upper_unsigned_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, mul_upper_unsigned_unsigned(d, s1, s2));
    }

    fn mul_upper_unsigned_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, mul_upper_unsigned_unsigned_imm(d, s1, s2));
    }

    fn mul_upper_signed_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, mul_upper_signed_unsigned(d, s1, s2));
    }

    fn div_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, div_unsigned(d, s1, s2));
    }

    fn div_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, div_signed(d, s1, s2));
    }

    fn rem_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, rem_unsigned(d, s1, s2));
    }

    fn rem_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, rem_signed(d, s1, s2));
    }

    fn set_less_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, set_less_than_unsigned_imm(d, s1, s2));
    }

    fn set_greater_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, set_greater_than_unsigned_imm(d, s1, s2));
    }

    fn set_less_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, set_less_than_signed_imm(d, s1, s2));
    }

    fn set_greater_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, set_greater_than_signed_imm(d, s1, s2));
    }

    fn shift_logical_right_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_right_imm(d, s1, s2));
    }

    fn shift_logical_right_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_right_imm_alt(d, s2, s1));
    }

    fn shift_arithmetic_right_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_imm(d, s1, s2));
    }

    fn shift_arithmetic_right_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_imm_alt(d, s2, s1));
    }

    fn shift_logical_left_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_left_imm(d, s1, s2));
    }

    fn shift_logical_left_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_left_imm_alt(d, s2, s1));
    }

    fn or_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, or_imm(d, s1, s2));
    }

    fn and_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, and_imm(d, s1, s2));
    }

    fn xor_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, xor_imm(d, s1, s2));
    }

    fn load_imm(&mut self, dst: RawReg, imm: u32) -> Self::ReturnTy {
        emit!(self, load_imm(dst, imm));
    }

    fn move_reg(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        emit!(self, move_reg(d, s));
    }

    fn cmov_if_zero(&mut self, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        emit!(self, cmov_if_zero(d, s, c));
    }

    fn cmov_if_zero_imm(&mut self, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        emit!(self, cmov_if_zero_imm(d, c, s));
    }

    fn cmov_if_not_zero(&mut self, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        emit!(self, cmov_if_not_zero(d, s, c));
    }

    fn cmov_if_not_zero_imm(&mut self, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        emit!(self, cmov_if_not_zero_imm(d, c, s));
    }

    fn add_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, add_imm(d, s1, s2));
    }

    fn store_imm_u8(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_imm_u8_basic(self.program_counter, offset, value));
        } else {
            emit!(self, store_imm_u8_dynamic(self.program_counter, offset, value));
        }
    }

    fn store_imm_u16(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_imm_u16_basic(self.program_counter, offset, value));
        } else {
            emit!(self, store_imm_u16_dynamic(self.program_counter, offset, value));
        }
    }

    fn store_imm_u32(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_imm_u32_basic(self.program_counter, offset, value));
        } else {
            emit!(self, store_imm_u32_dynamic(self.program_counter, offset, value));
        }
    }

    fn store_imm_indirect_u8(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_imm_indirect_u8_basic(self.program_counter, base, offset, value));
        } else {
            emit!(self, store_imm_indirect_u8_dynamic(self.program_counter, base, offset, value));
        }
    }

    fn store_imm_indirect_u16(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_imm_indirect_u16_basic(self.program_counter, base, offset, value));
        } else {
            emit!(self, store_imm_indirect_u16_dynamic(self.program_counter, base, offset, value));
        }
    }

    fn store_imm_indirect_u32(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_imm_indirect_u32_basic(self.program_counter, base, offset, value));
        } else {
            emit!(self, store_imm_indirect_u32_dynamic(self.program_counter, base, offset, value));
        }
    }

    fn store_indirect_u8(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_indirect_u8_basic(self.program_counter, src, base, offset));
        } else {
            emit!(self, store_indirect_u8_dynamic(self.program_counter, src, base, offset));
        }
    }

    fn store_indirect_u16(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_indirect_u16_basic(self.program_counter, src, base, offset));
        } else {
            emit!(self, store_indirect_u16_dynamic(self.program_counter, src, base, offset));
        }
    }

    fn store_indirect_u32(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_indirect_u32_basic(self.program_counter, src, base, offset));
        } else {
            emit!(self, store_indirect_u32_dynamic(self.program_counter, src, base, offset));
        }
    }

    fn store_u8(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_u8_basic(self.program_counter, src, offset));
        } else {
            emit!(self, store_u8_dynamic(self.program_counter, src, offset));
        }
    }

    fn store_u16(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_u16_basic(self.program_counter, src, offset));
        } else {
            emit!(self, store_u16_dynamic(self.program_counter, src, offset));
        }
    }

    fn store_u32(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, store_u32_basic(self.program_counter, src, offset));
        } else {
            emit!(self, store_u32_dynamic(self.program_counter, src, offset));
        }
    }

    fn load_u8(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, load_u8_basic(self.program_counter, dst, offset));
        } else {
            emit!(self, load_u8_dynamic(self.program_counter, dst, offset));
        }
    }

    fn load_i8(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, load_i8_basic(self.program_counter, dst, offset));
        } else {
            emit!(self, load_i8_dynamic(self.program_counter, dst, offset));
        }
    }

    fn load_u16(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, load_u16_basic(self.program_counter, dst, offset));
        } else {
            emit!(self, load_u16_dynamic(self.program_counter, dst, offset));
        }
    }

    fn load_i16(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, load_i16_basic(self.program_counter, dst, offset));
        } else {
            emit!(self, load_i16_dynamic(self.program_counter, dst, offset));
        }
    }

    fn load_u32(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, load_u32_basic(self.program_counter, dst, offset));
        } else {
            emit!(self, load_u32_dynamic(self.program_counter, dst, offset));
        }
    }

    fn load_indirect_u8(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, load_indirect_u8_basic(self.program_counter, dst, base, offset));
        } else {
            emit!(self, load_indirect_u8_dynamic(self.program_counter, dst, base, offset));
        }
    }

    fn load_indirect_i8(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, load_indirect_i8_basic(self.program_counter, dst, base, offset));
        } else {
            emit!(self, load_indirect_i8_dynamic(self.program_counter, dst, base, offset));
        }
    }

    fn load_indirect_u16(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, load_indirect_u16_basic(self.program_counter, dst, base, offset));
        } else {
            emit!(self, load_indirect_u16_dynamic(self.program_counter, dst, base, offset));
        }
    }

    fn load_indirect_i16(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, load_indirect_i16_basic(self.program_counter, dst, base, offset));
        } else {
            emit!(self, load_indirect_i16_dynamic(self.program_counter, dst, base, offset));
        }
    }

    fn load_indirect_u32(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.module.is_dynamic_paging() {
            emit!(self, load_indirect_u32_basic(self.program_counter, dst, base, offset));
        } else {
            emit!(self, load_indirect_u32_dynamic(self.program_counter, dst, base, offset));
        }
    }

    fn branch_less_unsigned(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_unsigned, s1, s2, i);
    }

    fn branch_less_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_unsigned_imm, s1, s2, i);
    }

    fn branch_less_signed(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_signed, s1, s2, i);
    }

    fn branch_less_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_signed_imm, s1, s2, i);
    }

    fn branch_eq(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_eq, s1, s2, i);
    }

    fn branch_eq_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_eq_imm, s1, s2, i);
    }

    fn branch_not_eq(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_not_eq, s1, s2, i);
    }

    fn branch_not_eq_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_not_eq_imm, s1, s2, i);
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_unsigned, s1, s2, i);
    }

    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_unsigned_imm, s1, s2, i);
    }

    fn branch_greater_or_equal_signed(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_signed, s1, s2, i);
    }

    fn branch_greater_or_equal_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_signed_imm, s1, s2, i);
    }

    fn branch_less_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_or_equal_unsigned_imm, s1, s2, i);
    }

    fn branch_less_or_equal_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_or_equal_signed_imm, s1, s2, i);
    }

    fn branch_greater_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_unsigned_imm, s1, s2, i);
    }

    fn branch_greater_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_signed_imm, s1, s2, i);
    }

    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        emit!(self, unresolved_jump(self.program_counter, ProgramCounter(target)));
    }

    fn jump_indirect(&mut self, base: RawReg, offset: u32) -> Self::ReturnTy {
        emit!(self, jump_indirect(self.program_counter, base, offset));
    }

    fn load_imm_and_jump(&mut self, dst: RawReg, imm: u32, target: u32) -> Self::ReturnTy {
        emit!(self, load_imm(dst, imm));
        emit!(self, unresolved_jump(self.program_counter, ProgramCounter(target)));
    }

    fn load_imm_and_jump_indirect(&mut self, ra: RawReg, base: RawReg, value: u32, offset: u32) -> Self::ReturnTy {
        emit!(self, load_imm_and_jump_indirect(self.program_counter, ra, base, value, offset));
    }
}
