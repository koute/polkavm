#![allow(unknown_lints)] // Because of `non_local_definitions` on older rustc versions.
#![allow(non_local_definitions)]
#![allow(clippy::unused_self)]
#![allow(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::as_conversions)]
use crate::api::{MemoryAccessError, MemoryProtection, Module, RegValue, SetCacheSizeLimitArgs};
use crate::error::Error;
use crate::gas::{CostModelKind, GasVisitor};
use crate::utils::{FlatMap, InterruptKind, Segfault};
use crate::{Gas, GasMeteringKind, ProgramCounter};
use alloc::boxed::Box;
use alloc::collections::btree_map::Entry;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use core::ops::Range;
use polkavm_common::abi::VM_ADDR_RETURN_TO_HOST;
use polkavm_common::cast::cast;
use polkavm_common::operation::*;
use polkavm_common::program::{
    asm, interpreter_calculate_cache_num_entries, CodeBlockBitmap, CodeBlockBitmapBox, InstructionSet, InstructionVisitor, RawReg, Reg,
    CODE_BLOCK_SIZE, INTERPRETER_CACHE_ENTRY_SIZE, INTERPRETER_FLATMAP_ENTRY_SIZE,
};
use polkavm_common::utils::{align_to_next_page_usize, slice_assume_init_mut, ArcBytes, GasVisitorT};

type Target = u32;

#[cfg(feature = "interpreter-musttail-dispatch")]
type HandlerResult = InterruptKind;
#[cfg(not(feature = "interpreter-musttail-dispatch"))]
type HandlerResult = Target;

// `become` is parse-gated; hiding it in a macro keeps the parser happy when the feature is off.
#[cfg(feature = "interpreter-musttail-dispatch")]
macro_rules! tail_call {
    ($e:expr) => {
        become $e
    };
}

#[derive(Copy, Clone)]
pub enum RegImm {
    Reg(Reg),
    Imm(i32),
}

impl From<Reg> for RegImm {
    #[inline]
    fn from(reg: Reg) -> Self {
        RegImm::Reg(reg)
    }
}

impl From<i32> for RegImm {
    #[inline]
    fn from(value: i32) -> Self {
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

impl IntoRegImm for i32 {
    #[inline(always)]
    fn into(self) -> RegImm {
        RegImm::Imm(self)
    }
}

trait Memory {
    fn memory_state(instance: &InterpretedInstance) -> &Self;
    fn memory_state_mut(instance: &mut InterpretedInstance) -> &mut Self;

    fn load_impl<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        dst: Reg,
        address: u32,
    ) -> Target;
    fn store_impl<T: StoreTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        address: u32,
        value: i64,
    ) -> Target;
}

#[repr(align(64))]
struct CacheAligned<T>(pub T);

#[repr(C)]
struct StandardMemory {
    ro_data_size: usize,
    rw_data_original: ArcBytes,
    rw_data_size: usize,
    heap_size: u32,
    stack_size: usize,
    accessible_aux_size: usize,

    max_allocation_size: usize,
    guest_memory_limit: usize,

    stack_address_low: u32,
    stack_address_high: u32,

    _align: CacheAligned<()>,

    aux_data_address: u32,
    stack_address_low_resident: u32,
    rw_data_address: u32,
    ro_data_address: u32,

    stack: Vec<u8>,
    rw_data: Vec<u8>,
    ro_data: ArcBytes,
    aux: Vec<u8>,
}

impl StandardMemory {
    fn new() -> Self {
        Self {
            ro_data: Default::default(),
            ro_data_size: 0,
            rw_data_original: Default::default(),
            rw_data: Default::default(),
            rw_data_size: 0,
            heap_size: 0,
            stack: Default::default(),
            stack_size: 0,
            aux: Default::default(),
            accessible_aux_size: usize::MAX,

            max_allocation_size: usize::MAX,
            guest_memory_limit: usize::MAX,

            aux_data_address: 0,
            stack_address_low: 0,
            stack_address_low_resident: 0,
            stack_address_high: 0,
            rw_data_address: 0,
            ro_data_address: 0,
            _align: CacheAligned(()),
        }
    }
}

#[allow(clippy::transmute_ptr_to_ptr)]
#[inline]
fn transmute_to_uninit(slice: &[u8]) -> &[MaybeUninit<u8>] {
    // SAFETY: Transmuting `&[u8]` into `&[MaybeUninit<u8>]` is safe since the layout of `[MaybeUninit<u8>]` is guaranteed to be the same as `[u8]`.
    unsafe { core::mem::transmute(slice) }
}

// Resize in chunks for efficiency.
const RESIZE_GRANULARITY: usize = 4096;

enum SliceOrLength<'a> {
    Slice(&'a [u8]),
    Length(usize),
}

impl<'a> SliceOrLength<'a> {
    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Slice(slice) => slice.len(),
            Self::Length(length) => *length,
        }
    }

    #[inline]
    fn copy_into(&self, target: &mut [u8]) {
        match self {
            Self::Slice(slice) => target.copy_from_slice(slice),
            Self::Length(length) => {
                debug_assert_eq!(target.len(), *length);
                target.fill(0)
            }
        }
    }
}

fn reserve_memory<T>(
    vec: &mut Vec<T>,
    minimum_length: usize,
    maximum_allocation_size_in_bytes: usize,
    memory_limit: usize,
    memory_used: usize,
) -> bool {
    const {
        assert!(core::mem::size_of::<T>() > 0);
        assert!(RESIZE_GRANULARITY % core::mem::size_of::<T>() == 0);
    }

    if vec.capacity() >= minimum_length {
        return true;
    }

    let memory_used = memory_used + vec.capacity();
    let minimum_bytes = minimum_length * core::mem::size_of::<T>();
    if minimum_bytes > maximum_allocation_size_in_bytes || memory_used >= memory_limit {
        return false;
    }

    let target_bytes = minimum_bytes
        .next_power_of_two()
        .max(RESIZE_GRANULARITY)
        .min(maximum_allocation_size_in_bytes);

    let extra_bytes = target_bytes - vec.capacity();
    if extra_bytes > memory_limit - memory_used {
        return false;
    }

    let target_elements = target_bytes / core::mem::size_of::<T>();
    let current_elements = vec.len();
    vec.reserve_exact(target_elements - current_elements);
    vec.capacity() >= minimum_length
}

enum PrepareWriteResult {
    Ok(Range<usize>),
    OutOfRangeAccess,
    MemoryLimitReached,
}

impl StandardMemory {
    fn accessible_aux_size(&self) -> u32 {
        cast(self.accessible_aux_size).to_u32_or_debug_panic()
    }

    fn set_accessible_aux_size(&mut self, size: u32) {
        self.accessible_aux_size = cast(size).to_usize();
        self.aux.truncate(self.accessible_aux_size);
    }

    fn read_memory_into<'slice>(
        &mut self,
        address: u32,
        buffer: &'slice mut [MaybeUninit<u8>],
    ) -> Result<&'slice mut [u8], MemoryAccessError> {
        if address >= self.aux_data_address {
            let offset = cast(address - self.aux_data_address).to_usize();
            let offset_end = offset + buffer.len();

            if offset_end <= self.accessible_aux_size {
                let resident_range = offset.min(self.aux.len())..offset_end.min(self.aux.len());
                buffer[..resident_range.len()].copy_from_slice(&transmute_to_uninit(&self.aux)[resident_range.clone()]);
                buffer[resident_range.len()..].fill(MaybeUninit::new(0));

                // SAFETY: The buffer was initialized.
                return Ok(unsafe { slice_assume_init_mut(buffer) });
            }
        } else if address >= self.stack_address_low {
            let offset = cast(address - self.stack_address_low).to_usize();
            let offset_end = offset + buffer.len();

            if offset_end <= self.stack_size {
                let resident_offset = self.stack_size - self.stack.len();
                let non_resident_range = offset.min(resident_offset)..offset_end.min(resident_offset);
                let resident_range = offset.max(resident_offset) - resident_offset..offset_end.max(resident_offset) - resident_offset;
                buffer[..non_resident_range.len()].fill(MaybeUninit::new(0));
                buffer[non_resident_range.len()..].copy_from_slice(&transmute_to_uninit(&self.stack)[resident_range]);

                // SAFETY: The buffer was initialized.
                return Ok(unsafe { slice_assume_init_mut(buffer) });
            }
        } else if address >= self.rw_data_address {
            let offset = cast(address - self.rw_data_address).to_usize();
            let offset_end = offset + buffer.len();

            if offset_end <= self.rw_data_size {
                let resident_range = offset.min(self.rw_data.len())..offset_end.min(self.rw_data.len());
                buffer[..resident_range.len()].copy_from_slice(&transmute_to_uninit(&self.rw_data)[resident_range.clone()]);

                let non_resident_range =
                    (offset + resident_range.len()).min(self.rw_data_original.len())..offset_end.min(self.rw_data_original.len());
                buffer[resident_range.len()..resident_range.len() + non_resident_range.len()]
                    .copy_from_slice(&transmute_to_uninit(&self.rw_data_original)[non_resident_range.clone()]);
                buffer[resident_range.len() + non_resident_range.len()..].fill(MaybeUninit::new(0));

                // SAFETY: The buffer was initialized.
                return Ok(unsafe { slice_assume_init_mut(buffer) });
            }
        } else if address >= self.ro_data_address {
            let offset = cast(address - self.ro_data_address).to_usize();
            let offset_end = offset + buffer.len();

            if offset_end <= self.ro_data_size {
                let src_range = offset.min(self.ro_data.len())..offset_end.min(self.ro_data.len());
                buffer[..src_range.len()].copy_from_slice(&transmute_to_uninit(&self.ro_data)[src_range.clone()]);
                buffer[src_range.len()..].fill(MaybeUninit::new(0));

                // SAFETY: The buffer was initialized.
                return Ok(unsafe { slice_assume_init_mut(buffer) });
            }
        }

        Err(MemoryAccessError::OutOfRangeAccess {
            address,
            length: cast(buffer.len()).to_u64(),
        })
    }

    fn zero_or_write_memory(&mut self, address: u32, contents: SliceOrLength) -> Result<(), MemoryAccessError> {
        if address >= self.aux_data_address {
            let range = {
                let offset = cast(address - self.aux_data_address).to_usize();
                offset..offset + contents.len()
            };

            if let Some(target) = self.aux.get_mut(range.clone()) {
                contents.copy_into(target);
                return Ok(());
            }

            if range.end <= self.accessible_aux_size {
                if !self.aux_resize(range.end) {
                    return Err(MemoryAccessError::MemoryLimitReached);
                }

                if let Some(target) = self.aux.get_mut(range) {
                    contents.copy_into(target);
                    return Ok(());
                }
            }
        } else if address >= self.stack_address_low {
            match self.prepare_stack_write(cast(address).to_usize(), contents.len()) {
                PrepareWriteResult::Ok(range) => {
                    if let Some(target) = self.stack.get_mut(range) {
                        contents.copy_into(target);
                        return Ok(());
                    }
                }
                PrepareWriteResult::MemoryLimitReached => {
                    return Err(MemoryAccessError::MemoryLimitReached);
                }
                PrepareWriteResult::OutOfRangeAccess => {}
            }
        } else if address >= self.rw_data_address {
            let range = {
                let offset = cast(address - self.rw_data_address).to_usize();
                offset..offset + contents.len()
            };

            if let Some(target) = self.rw_data.get_mut(range.clone()) {
                contents.copy_into(target);
                return Ok(());
            }

            if range.end <= self.rw_data_size {
                if self.rw_data_resize(range.end) {
                    contents.copy_into(&mut self.rw_data[range]);
                    return Ok(());
                } else {
                    return Err(MemoryAccessError::MemoryLimitReached);
                }
            }
        }

        Err(MemoryAccessError::OutOfRangeAccess {
            address,
            length: cast(contents.len()).to_u64(),
        })
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryAccessError> {
        self.zero_or_write_memory(address, SliceOrLength::Slice(data))
    }

    fn zero_memory(&mut self, address: u32, length: u32, memory_protection: Option<MemoryProtection>) -> Result<(), MemoryAccessError> {
        debug_assert!(memory_protection.is_none());
        self.zero_or_write_memory(address, SliceOrLength::Length(cast(length).to_usize()))
    }

    fn heap_size(&self) -> u32 {
        self.heap_size
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
        if cast(heap_top).to_usize() > cast(memory_map.rw_data_address()).to_usize() + self.rw_data_size {
            let new_size = align_to_next_page_usize(cast(memory_map.page_size()).to_usize(), cast(heap_top).to_usize()).unwrap()
                - cast(memory_map.rw_data_address()).to_usize();

            log::trace!("sbrk: growing memory: {} -> {}", self.rw_data_size, new_size);
            self.rw_data_size = new_size;
        }

        Some(heap_top)
    }

    fn mark_dirty(&mut self) {}

    fn reset_memory(&mut self, module: &Module) {
        let memory_map = module.memory_map();
        self.ro_data = module.blob().ro_data_arc().clone();
        self.ro_data_size = cast(memory_map.ro_data_size()).to_usize();
        self.rw_data.clear();
        self.rw_data_original = module.blob().rw_data_arc().clone();
        self.rw_data_size = cast(memory_map.rw_data_size()).to_usize();
        self.heap_size = 0;
        self.stack.clear();
        self.stack_size = cast(memory_map.stack_size()).to_usize();
        self.aux.clear();
        self.accessible_aux_size = cast(memory_map.aux_data_size()).to_usize();

        self.aux_data_address = memory_map.aux_data_address();
        self.stack_address_low = memory_map.stack_address_low();
        self.stack_address_high = memory_map.stack_address_high();
        self.stack_address_low_resident = self.stack_address_high;
        self.rw_data_address = memory_map.rw_data_address();
        self.ro_data_address = memory_map.ro_data_address();
    }

    #[must_use]
    #[cold]
    fn rw_data_resize(&mut self, required_size: usize) -> bool {
        if !reserve_memory(
            &mut self.rw_data,
            required_size,
            self.max_allocation_size,
            self.guest_memory_limit,
            self.stack.capacity() + self.aux.capacity(),
        ) {
            return false;
        }

        debug_assert!(self.rw_data.capacity().is_power_of_two());
        debug_assert!(self.rw_data.capacity() <= self.max_allocation_size);

        let new_length = self.rw_data.capacity().min(required_size.next_multiple_of(RESIZE_GRANULARITY));
        if self.rw_data.len() < self.rw_data_original.len() {
            let new_length_partial = new_length.min(self.rw_data_original.len());
            let old_length = self.rw_data.len();
            let bytes_to_copy = new_length_partial - old_length;

            // TODO: Use `write_copy_of_slice` once we switch to Rust 0.93.0.
            self.rw_data.spare_capacity_mut()[..bytes_to_copy]
                .copy_from_slice(transmute_to_uninit(&self.rw_data_original[old_length..old_length + bytes_to_copy]));

            debug_assert_eq!(self.rw_data.len() + bytes_to_copy, new_length_partial);

            // SAFETY: We've initialized the spare capacity, so calling `set_len` is safe.
            unsafe {
                self.rw_data.set_len(new_length_partial);
            }
        }

        debug_assert!(new_length <= self.rw_data.capacity());
        self.rw_data.resize(new_length, 0);

        true
    }

    #[must_use]
    #[cold]
    fn stack_resize(&mut self, required_size: usize) -> bool {
        let mut new_stack = Vec::new();
        if !reserve_memory(
            &mut new_stack,
            required_size,
            self.max_allocation_size,
            self.guest_memory_limit,
            self.rw_data.capacity() + self.aux.capacity(),
        ) {
            return false;
        }

        debug_assert!(new_stack.capacity().is_power_of_two());
        debug_assert!(new_stack.capacity() <= self.max_allocation_size);

        let new_size = new_stack.capacity().min(self.stack_size);
        let uninitialized = &mut new_stack.spare_capacity_mut()[..new_size];
        let new_space = new_size - self.stack.len();
        uninitialized[..new_space].fill(MaybeUninit::new(0));
        uninitialized[new_space..].copy_from_slice(transmute_to_uninit(&self.stack));

        // SAFETY: The buffer is fully initialized.
        unsafe {
            new_stack.set_len(new_size);
        }

        self.stack = new_stack;
        self.stack_address_low_resident = self.stack_address_high - cast(self.stack.len()).to_u32_or_debug_panic();
        true
    }

    #[must_use]
    fn prepare_stack_write(&mut self, address: usize, length: usize) -> PrepareWriteResult {
        let stack_hi = cast(self.stack_address_high).to_usize();
        if address + length > stack_hi {
            return PrepareWriteResult::OutOfRangeAccess;
        }

        let required_size = stack_hi - address;
        if required_size > self.stack.len() {
            if required_size > self.stack_size {
                return PrepareWriteResult::OutOfRangeAccess;
            }

            if !self.stack_resize(required_size) {
                return PrepareWriteResult::MemoryLimitReached;
            }
        }

        let stack_lo = stack_hi - self.stack.len();
        let offset = address - stack_lo;
        PrepareWriteResult::Ok(offset..offset + length)
    }

    #[must_use]
    #[cold]
    fn aux_resize(&mut self, required_size: usize) -> bool {
        if !reserve_memory(
            &mut self.aux,
            required_size,
            self.max_allocation_size,
            self.guest_memory_limit,
            self.rw_data.capacity() + self.stack.capacity(),
        ) {
            return false;
        }

        debug_assert!(self.aux.capacity().is_power_of_two());
        debug_assert!(self.aux.capacity() <= self.max_allocation_size);

        let new_length = self.aux.capacity().min(required_size.next_multiple_of(RESIZE_GRANULARITY));
        debug_assert!(new_length <= self.aux.capacity());
        self.aux.resize(new_length, 0);
        true
    }

    #[cold]
    #[inline(never)]
    fn store_impl_slow<T: StoreTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        address: u32,
        value: i64,
    ) -> Target {
        macro_rules! range {
            ($base_address:expr) => {{
                let offset = cast(address - $base_address).to_usize();
                let offset_end = offset + core::mem::size_of::<T>();
                offset..offset_end
            }};
        }

        if address >= Self::memory_state(instance).stack_address_low {
            match Self::memory_state_mut(instance).prepare_stack_write(cast(address).to_usize(), core::mem::size_of::<T>()) {
                PrepareWriteResult::Ok(range) => {
                    if let Some(subslice) = Self::memory_state_mut(instance).stack.get_mut(range) {
                        let value = T::into_bytes(value);
                        subslice.copy_from_slice(value.as_ref());
                        instance.on_store_ok::<T, DEBUG>(compiled_offset)
                    } else {
                        instance.on_store_trap::<T, DEBUG>(address)
                    }
                }
                PrepareWriteResult::OutOfRangeAccess => instance.on_store_trap::<T, DEBUG>(address),
                PrepareWriteResult::MemoryLimitReached => instance.on_store_trap_due_to_memory_limit::<T, DEBUG>(address),
            }
        } else if address >= Self::memory_state(instance).rw_data_address {
            let range = range!(Self::memory_state(instance).rw_data_address);
            if let Some(subslice) = Self::memory_state_mut(instance).rw_data.get_mut(range.clone()) {
                let value = T::into_bytes(value);
                subslice.copy_from_slice(value.as_ref());
                return instance.on_store_ok::<T, DEBUG>(compiled_offset);
            }

            if range.end > Self::memory_state(instance).rw_data_size {
                return instance.on_store_trap::<T, DEBUG>(address);
            }

            if !Self::memory_state_mut(instance).rw_data_resize(range.end) {
                return instance.on_store_trap_due_to_memory_limit::<T, DEBUG>(address);
            }

            if let Some(subslice) = Self::memory_state_mut(instance).rw_data.get_mut(range) {
                let value = T::into_bytes(value);
                subslice.copy_from_slice(value.as_ref());
                instance.on_store_ok::<T, DEBUG>(compiled_offset)
            } else {
                instance.on_store_trap::<T, DEBUG>(address)
            }
        } else {
            instance.on_store_trap::<T, DEBUG>(address)
        }
    }

    fn load_rw_data_slow<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        dst: Reg,
        address: u32,
        range: Range<usize>,
    ) -> Target {
        let state = Self::memory_state(instance);
        if range.end > state.rw_data_size {
            instance.on_load_trap::<T, DEBUG>(address)
        } else {
            let mut buffer = T::Slice::default();

            let resident_range = range.start.min(state.rw_data.len())..range.end.min(state.rw_data.len());
            buffer[..resident_range.len()].copy_from_slice(&state.rw_data[resident_range.clone()]);

            let non_resident_range =
                (range.start + resident_range.len()).min(state.rw_data_original.len())..range.end.min(state.rw_data_original.len());
            buffer[resident_range.len()..resident_range.len() + non_resident_range.len()]
                .copy_from_slice(&state.rw_data_original[non_resident_range]);

            instance.on_load_ok::<T, DEBUG>(compiled_offset, dst, address, T::from_slice(buffer.as_ref()))
        }
    }

    fn load_ro_data_slow<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        dst: Reg,
        address: u32,
        range: Range<usize>,
    ) -> Target {
        let state = Self::memory_state(instance);
        if range.end > state.ro_data_size {
            instance.on_load_trap::<T, DEBUG>(address)
        } else {
            let mut buffer = T::Slice::default();
            let src_range = range.start.min(state.ro_data.len())..range.end.min(state.ro_data.len());
            buffer[..src_range.len()].copy_from_slice(&state.ro_data[src_range]);
            instance.on_load_ok::<T, DEBUG>(compiled_offset, dst, address, T::from_slice(buffer.as_ref()))
        }
    }

    fn load_stack_slow<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        dst: Reg,
        address: u32,
        offset: usize,
    ) -> Target {
        let state = Self::memory_state(instance);
        let offset_end = offset + core::mem::size_of::<T>();
        if offset_end > state.stack_size {
            instance.on_load_trap::<T, DEBUG>(address)
        } else {
            let resident_offset = state.stack_size - state.stack.len();
            let non_resident_range = offset.min(resident_offset)..offset_end.min(resident_offset);
            let resident_range = offset.max(resident_offset) - resident_offset..offset_end.max(resident_offset) - resident_offset;
            let mut buffer = T::Slice::default();
            buffer[non_resident_range.len()..].copy_from_slice(&state.stack[resident_range]);
            instance.on_load_ok::<T, DEBUG>(compiled_offset, dst, address, T::from_slice(buffer.as_ref()))
        }
    }

    fn load_aux_slow<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        dst: Reg,
        address: u32,
        range: Range<usize>,
    ) -> Target {
        let state = Self::memory_state(instance);
        if range.end > state.accessible_aux_size {
            instance.on_load_trap::<T, DEBUG>(address)
        } else {
            let mut buffer = T::Slice::default();
            let src_range = range.start.min(state.aux.len())..range.end.min(state.aux.len());
            buffer[..src_range.len()].copy_from_slice(&state.aux[src_range]);
            instance.on_load_ok::<T, DEBUG>(compiled_offset, dst, address, T::from_slice(buffer.as_ref()))
        }
    }

    #[cold]
    #[inline(never)]
    fn load_impl_slow<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        dst: Reg,
        address: u32,
    ) -> Target {
        macro_rules! range {
            ($base_address:expr) => {{
                let offset = cast(address - $base_address).to_usize();
                let offset_end = offset + core::mem::size_of::<T>();
                offset..offset_end
            }};
        }

        let state = Self::memory_state(instance);
        if address >= state.aux_data_address {
            let range = range!(state.aux_data_address);
            Self::load_aux_slow::<T, DEBUG>(instance, compiled_offset, dst, address, range)
        } else if address >= state.stack_address_low {
            Self::load_stack_slow::<T, DEBUG>(
                instance,
                compiled_offset,
                dst,
                address,
                cast(address - state.stack_address_low).to_usize(),
            )
        } else if address >= state.rw_data_address {
            let range = range!(state.rw_data_address);
            Self::load_rw_data_slow::<T, DEBUG>(instance, compiled_offset, dst, address, range)
        } else if address >= state.ro_data_address {
            let range = range!(state.ro_data_address);
            Self::load_ro_data_slow::<T, DEBUG>(instance, compiled_offset, dst, address, range)
        } else {
            instance.on_load_trap::<T, DEBUG>(address)
        }
    }

    // Dynamic memory-only methods.
    fn is_memory_accessible(&self, _address: u32, _size: u32, _minimum_protection: MemoryProtection) -> bool {
        unimplemented!()
    }

    fn change_memory_protection(&mut self, _address: u32, _length: u32, _protection: MemoryProtection) -> Result<(), MemoryAccessError> {
        unimplemented!();
    }

    fn free_pages(&mut self, _address: u32, _length: u32) {
        unimplemented!()
    }
}

impl Memory for StandardMemory {
    #[inline(always)]
    fn memory_state(instance: &InterpretedInstance) -> &Self {
        &instance.standard_memory
    }

    #[inline(always)]
    fn memory_state_mut(instance: &mut InterpretedInstance) -> &mut Self {
        &mut instance.standard_memory
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn load_impl<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        dst: Reg,
        address: u32,
    ) -> Target {
        let state = Self::memory_state(instance);
        let (offset, slice) = if address >= state.aux_data_address {
            (cast(address - state.aux_data_address).to_usize(), &state.aux[..])
        } else if address >= state.stack_address_low_resident {
            (cast(address - state.stack_address_low_resident).to_usize(), &state.stack[..])
        } else if address >= state.rw_data_address {
            (cast(address - state.rw_data_address).to_usize(), &state.rw_data[..])
        } else if address >= state.ro_data_address {
            (cast(address - state.ro_data_address).to_usize(), &state.ro_data[..])
        } else {
            return Self::load_impl_slow::<T, DEBUG>(instance, compiled_offset, dst, address);
        };

        let range = offset..offset + core::mem::size_of::<T>();
        if let Some(subslice) = slice.get(range) {
            instance.on_load_ok::<T, DEBUG>(compiled_offset, dst, address, T::from_slice(subslice))
        } else {
            Self::load_impl_slow::<T, DEBUG>(instance, compiled_offset, dst, address)
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn store_impl<T: StoreTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        address: u32,
        value: i64,
    ) -> Target {
        let (offset, slice) = if address >= Self::memory_state(instance).stack_address_low_resident {
            (
                cast(address - Self::memory_state(instance).stack_address_low_resident).to_usize(),
                &mut Self::memory_state_mut(instance).stack[..],
            )
        } else if address >= Self::memory_state(instance).rw_data_address {
            (
                cast(address - Self::memory_state(instance).rw_data_address).to_usize(),
                &mut Self::memory_state_mut(instance).rw_data[..],
            )
        } else {
            return Self::store_impl_slow::<T, DEBUG>(instance, compiled_offset, address, value);
        };

        let range = offset..offset + core::mem::size_of::<T>();
        if let Some(subslice) = slice.get_mut(range) {
            let value = T::into_bytes(value);
            subslice.copy_from_slice(value.as_ref());
            instance.on_store_ok::<T, DEBUG>(compiled_offset)
        } else {
            Self::store_impl_slow::<T, DEBUG>(instance, compiled_offset, address, value)
        }
    }
}

struct Page {
    data: Box<[u8]>,
    is_read_only: bool,
}

impl Page {
    fn empty(page_size: u32) -> Self {
        let mut page = Vec::new();
        page.reserve_exact(cast(page_size).to_usize());
        page.resize(cast(page_size).to_usize(), 0);
        Page {
            data: page.into(),
            is_read_only: false,
        }
    }
}

impl core::ops::Deref for Page {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl core::ops::DerefMut for Page {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

pub(crate) struct DynamicMemory {
    pages: BTreeMap<u32, Page>,
    page_size: u32,
    page_size_mask: u32,
}

impl DynamicMemory {
    #[inline]
    fn round_to_page_size_down(&self, value: u32) -> u32 {
        value & !self.page_size_mask
    }

    #[inline]
    fn is_multiple_of_page_size(&self, value: u32) -> bool {
        (value & self.page_size_mask) == 0
    }

    #[inline]
    fn to_page_address(&self, address: u32, length: u32) -> (u32, u32, u32) {
        let page_address_lo = self.round_to_page_size_down(address);
        let page_address_hi = self.round_to_page_size_down(address + (length - 1));
        (self.page_size, page_address_lo, page_address_hi)
    }

    fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            page_size: 0,
            page_size_mask: 0,
        }
    }

    fn clear(&mut self) {
        self.pages.clear()
    }

    fn is_memory_accessible(&self, address: u32, size: u32, minimum_protection: MemoryProtection) -> bool {
        // TODO: This is very slow.
        let result = each_page(self.to_page_address(address, size), address, size, |page_address, _, _, _| {
            if let Some(page) = self.pages.get(&page_address) {
                match minimum_protection {
                    MemoryProtection::ReadWrite => {
                        if page.is_read_only {
                            Err(())
                        } else {
                            Ok(())
                        }
                    }
                    MemoryProtection::Read => Ok(()),
                }
            } else {
                Err(())
            }
        });

        result.is_ok()
    }

    fn read_memory_into<'slice>(&self, address: u32, buffer: &'slice mut [MaybeUninit<u8>]) -> Result<&'slice mut [u8], MemoryAccessError> {
        each_page(
            self.to_page_address(address, cast(buffer.len()).to_u32_or_debug_panic()),
            address,
            cast(buffer.len()).to_u32_or_debug_panic(),
            |page_address, page_offset, buffer_offset, length| {
                assert!(buffer_offset + length <= buffer.len());
                assert!(page_offset + length <= cast(self.page_size).to_usize());
                let page = self.pages.get(&page_address);

                // SAFETY: Buffers are non-overlapping and the ranges are in-bounds.
                unsafe {
                    let dst = buffer.as_mut_ptr().cast::<u8>().add(buffer_offset);
                    if let Some(page) = page {
                        let src = page.as_ptr().add(page_offset);
                        core::ptr::copy_nonoverlapping(src, dst, length);
                        Ok(())
                    } else {
                        Err(MemoryAccessError::OutOfRangeAccess {
                            address: page_address + cast(page_offset).to_u32_or_debug_panic(),
                            length: cast(length).to_u64(),
                        })
                    }
                }
            },
        )?;

        // SAFETY: The buffer was initialized.
        Ok(unsafe { slice_assume_init_mut(buffer) })
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryAccessError> {
        if !self.is_memory_accessible(address, cast(data.len()).to_u32_or_debug_panic(), MemoryProtection::ReadWrite) {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: cast(data.len()).to_u64(),
            });
        }

        let dynamic_memory = self;
        let page_size = dynamic_memory.page_size;
        each_page::<()>(
            dynamic_memory.to_page_address(address, cast(data.len()).to_u32_or_debug_panic()),
            address,
            cast(data.len()).to_u32_or_debug_panic(),
            move |page_address, page_offset, buffer_offset, length| {
                let page = dynamic_memory.pages.entry(page_address).or_insert_with(|| Page::empty(page_size));
                page[page_offset..page_offset + length].copy_from_slice(&data[buffer_offset..buffer_offset + length]);
                Ok(())
            },
        )
        .unwrap();

        Ok(())
    }

    fn zero_memory(&mut self, address: u32, length: u32, memory_protection: Option<MemoryProtection>) -> Result<(), MemoryAccessError> {
        if memory_protection.is_some() {
            debug_assert!(self.is_multiple_of_page_size(address));
            debug_assert!(self.is_multiple_of_page_size(length));
        } else if !self.is_memory_accessible(address, length, MemoryProtection::ReadWrite) {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: u64::from(length),
            });
        }

        let is_read_only = memory_protection.map(|prot| match prot {
            MemoryProtection::Read => true,
            MemoryProtection::ReadWrite => false,
        });

        let dynamic_memory = self;
        let page_size = dynamic_memory.page_size;

        each_page::<()>(
            dynamic_memory.to_page_address(address, length),
            address,
            length,
            move |page_address, page_offset, _, length| match dynamic_memory.pages.entry(page_address) {
                Entry::Occupied(mut entry) => {
                    let page = entry.get_mut();
                    page[page_offset..page_offset + length].fill(0);
                    if let Some(is_read_only) = is_read_only {
                        page.is_read_only = is_read_only;
                    }
                    Ok(())
                }
                Entry::Vacant(entry) => {
                    let mut page = Page::empty(page_size);
                    if let Some(is_read_only) = is_read_only {
                        page.is_read_only = is_read_only;
                    }
                    entry.insert(page);
                    Ok(())
                }
            },
        )
        .unwrap();

        Ok(())
    }

    fn change_memory_protection(&mut self, address: u32, length: u32, protection: MemoryProtection) -> Result<(), MemoryAccessError> {
        each_page(
            self.to_page_address(address, length),
            address,
            length,
            |page_address, page_offset, _buffer_offset, length| {
                if let Some(page) = self.pages.get_mut(&page_address) {
                    page.is_read_only = match protection {
                        MemoryProtection::Read => true,
                        MemoryProtection::ReadWrite => false,
                    };
                    Ok(())
                } else {
                    Err(MemoryAccessError::OutOfRangeAccess {
                        address: page_address + cast(page_offset).to_u32_or_debug_panic(),
                        length: cast(length).to_u64(),
                    })
                }
            },
        )?;

        Ok(())
    }

    fn free_pages(&mut self, address: u32, length: u32) {
        debug_assert!(self.is_multiple_of_page_size(address));
        debug_assert_ne!(length, 0);

        let dynamic_memory = self;
        each_page::<()>(
            dynamic_memory.to_page_address(address, length),
            address,
            length,
            move |page_address, _, _, _| {
                dynamic_memory.pages.remove(&page_address);
                Ok(())
            },
        )
        .unwrap();
    }

    fn mark_dirty(&self) {}

    fn reset_memory(&mut self, module: &Module) {
        self.clear();
        self.page_size = module.memory_map().page_size();

        let page_shift = self.page_size.ilog2();
        self.page_size_mask = (1 << page_shift) - 1;
    }

    fn accessible_aux_size(&self) -> u32 {
        unimplemented!();
    }

    fn set_accessible_aux_size(&mut self, _size: u32) {
        unimplemented!();
    }

    fn heap_size(&self) -> u32 {
        unimplemented!();
    }

    fn sbrk(&mut self, _module: &Module, _size: u32) -> Option<u32> {
        unimplemented!();
    }
}

impl Memory for DynamicMemory {
    fn memory_state(instance: &InterpretedInstance) -> &Self {
        &instance.dynamic_memory
    }

    fn memory_state_mut(instance: &mut InterpretedInstance) -> &mut Self {
        &mut instance.dynamic_memory
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn load_impl<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        dst: Reg,
        address: u32,
    ) -> Target {
        let length = const { cast(core::mem::size_of::<T>()).to_u32_or_panic() };
        let Some(address_end) = address.checked_add(length) else {
            let page_address = Self::memory_state(instance).round_to_page_size_down(0xffffffff);
            if Self::memory_state(instance).pages.contains_key(&page_address) {
                return instance.on_load_trap::<T, DEBUG>(address);
            } else {
                return instance.on_load_segfault::<T, DEBUG>(compiled_offset, address, page_address, false);
            }
        };

        let page_address_lo = Self::memory_state(instance).round_to_page_size_down(address);
        let page_address_hi = Self::memory_state(instance).round_to_page_size_down(address_end - 1);
        if page_address_lo == page_address_hi {
            if let Some(page) = Self::memory_state_mut(instance).pages.get_mut(&page_address_lo) {
                let offset = cast(address).to_usize() - cast(page_address_lo).to_usize();
                let value = T::from_slice(&page[offset..offset + core::mem::size_of::<T>()]);
                instance.on_load_ok::<T, DEBUG>(compiled_offset, dst, address, value)
            } else {
                instance.on_load_segfault::<T, DEBUG>(compiled_offset, address, page_address_lo, false)
            }
        } else {
            let mut iter = Self::memory_state(instance).pages.range(page_address_lo..=page_address_hi);
            let lo = iter.next();
            let hi = iter.next();

            match (lo, hi) {
                (Some((_, lo)), Some((_, hi))) => {
                    let page_size = cast(Self::memory_state(instance).page_size).to_usize();
                    let lo_len = cast(page_address_hi).to_usize() - cast(address).to_usize();
                    let hi_len = core::mem::size_of::<T>() - lo_len;
                    let mut buffer = [0; 8];
                    let buffer = &mut buffer[..core::mem::size_of::<T>()];
                    buffer[..lo_len].copy_from_slice(&lo[page_size - lo_len..]);
                    buffer[lo_len..].copy_from_slice(&hi[..hi_len]);
                    instance.on_load_ok::<T, DEBUG>(compiled_offset, dst, address, T::from_slice(buffer))
                }
                (None, _) => instance.on_load_segfault::<T, DEBUG>(compiled_offset, address, page_address_lo, false),
                (Some((page_address, _)), _) => {
                    let missing_page_address = if *page_address == page_address_lo {
                        page_address_hi
                    } else {
                        page_address_lo
                    };

                    instance.on_load_segfault::<T, DEBUG>(compiled_offset, address, missing_page_address, false)
                }
            }
        }
    }

    fn store_impl<T: StoreTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        compiled_offset: Target,
        address: u32,
        value: i64,
    ) -> Target {
        let length = const { cast(core::mem::size_of::<T>()).to_u32_or_panic() };
        let Some(address_end) = address.checked_add(length) else {
            let page_address = Self::memory_state(instance).round_to_page_size_down(0xffffffff);
            if Self::memory_state(instance).pages.contains_key(&page_address) {
                return instance.on_store_trap::<T, DEBUG>(address);
            } else {
                return instance.on_store_segfault::<T, DEBUG>(compiled_offset, address, page_address, false);
            }
        };

        let page_address_lo = Self::memory_state(instance).round_to_page_size_down(address);
        let page_address_hi = Self::memory_state(instance).round_to_page_size_down(address_end - 1);
        if page_address_lo == page_address_hi {
            if let Some(page) = Self::memory_state_mut(instance).pages.get_mut(&page_address_lo) {
                if page.is_read_only {
                    return instance.on_store_segfault::<T, DEBUG>(compiled_offset, address, page_address_lo, true);
                }

                let offset = cast(address).to_usize() - cast(page_address_lo).to_usize();
                let value = T::into_bytes(value);
                let value = value.as_ref();
                page[offset..offset + value.len()].copy_from_slice(value);
                instance.on_store_ok::<T, DEBUG>(compiled_offset)
            } else {
                instance.on_store_segfault::<T, DEBUG>(compiled_offset, address, page_address_lo, false)
            }
        } else {
            let page_size = cast(Self::memory_state(instance).page_size).to_usize();
            let mut iter = Self::memory_state_mut(instance).pages.range_mut(page_address_lo..=page_address_hi);
            let lo = iter.next();
            let hi = iter.next();

            match (lo, hi) {
                (Some((_, lo)), Some((_, hi))) => {
                    if lo.is_read_only || hi.is_read_only {
                        let page_address = if lo.is_read_only { page_address_lo } else { page_address_hi };
                        return instance.on_store_segfault::<T, DEBUG>(compiled_offset, address, page_address, true);
                    }

                    let value = T::into_bytes(value);
                    let value = value.as_ref();
                    let lo_len = cast(page_address_hi).to_usize() - cast(address).to_usize();
                    let hi_len = value.len() - lo_len;
                    lo[page_size - lo_len..].copy_from_slice(&value[..lo_len]);
                    hi[..hi_len].copy_from_slice(&value[lo_len..]);
                    instance.on_store_ok::<T, DEBUG>(compiled_offset)
                }
                (None, _) => instance.on_store_segfault::<T, DEBUG>(compiled_offset, address, page_address_lo, false),
                (Some((page_address, _)), _) => {
                    let missing_page_address = if *page_address == page_address_lo {
                        page_address_hi
                    } else {
                        page_address_lo
                    };

                    instance.on_store_segfault::<T, DEBUG>(compiled_offset, address, missing_page_address, false)
                }
            }
        }
    }
}

macro_rules! cast_handler {
    ($e:expr) => {{
        #[allow(clippy::as_conversions)]
        let handler = $e as Handler;
        handler
    }};
}

macro_rules! emit_raw {
    ($self:ident, $handler_name:ident::<$($generic:tt),+>($($args:tt)*)) => {
        $self.compiled_handlers.push(cast_handler!(raw_handlers::$handler_name::<$($generic),+>));
        $self.compiled_args.push(Args::$handler_name($($args)*));
    };
}

macro_rules! emit {
    ($self:ident, $handler_name:ident($($args:tt)*)) => {
        emit_raw!($self, $handler_name::<DEBUG>($($args)*));
    };
}

macro_rules! emit_load_store {
    ($self:ident, $handler_name:ident($($args:tt)*)) => {
        let handler = if $self.memory_kind == MEMORY_STANDARD {
            raw_handlers::$handler_name::<StandardMemory, DEBUG>
        } else {
            debug_assert_eq!($self.memory_kind, MEMORY_DYNAMIC);
            raw_handlers::$handler_name::<DynamicMemory, DEBUG>
        };

        $self.compiled_handlers.push(cast_handler!(handler));
        $self.compiled_args.push(Args::$handler_name($($args)*));
    };
}

macro_rules! emit_consistent_address {
    ($self:ident, $handler_name:ident($($args:tt)*)) => {
        $self.compiled_handlers.push($self.handlers::<DEBUG>().$handler_name);
        $self.compiled_args.push(Args::$handler_name($($args)*));
    };
}

macro_rules! emit_branch {
    ($self:ident, $name:ident, $s1:ident, $s2:ident, $i:ident) => {
        let target_true = ProgramCounter($i);
        let target_false = $self.next_program_counter();
        let is_legacy = $self.module.blob().isa().is_legacy();
        if $self.is_jump_target_valid(target_true)
            && ((is_legacy && $self.is_jump_target_valid(target_false)) || (!is_legacy && target_false.0 < $self.module.code_len()))
        {
            emit!($self, $name($s1, $s2, target_true, target_false));
        } else {
            emit!($self, invalid_branch_trap($self.program_counter));
        }
    };
}

fn each_page<E>(
    (page_size, page_address_lo, page_address_hi): (u32, u32, u32),
    address: u32,
    length: u32,
    callback: impl FnMut(u32, usize, usize, usize) -> Result<(), E>,
) -> Result<(), E> {
    each_page_impl(page_size, page_address_lo, page_address_hi, address, length, callback)
}

fn each_page_impl<E>(
    page_size: u32,
    page_address_lo: u32,
    page_address_hi: u32,
    address: u32,
    length: u32,
    mut callback: impl FnMut(u32, usize, usize, usize) -> Result<(), E>,
) -> Result<(), E> {
    let page_size = cast(page_size).to_usize();
    let length = cast(length).to_usize();

    let initial_page_offset = cast(address).to_usize() - cast(page_address_lo).to_usize();
    let initial_chunk_length = core::cmp::min(length, page_size - initial_page_offset);
    callback(page_address_lo, initial_page_offset, 0, initial_chunk_length)?;

    if page_address_lo == page_address_hi {
        return Ok(());
    }

    let mut page_address_lo = cast(page_address_lo).to_u64();
    let page_address_hi = cast(page_address_hi).to_u64();
    page_address_lo += cast(page_size).to_u64();
    let mut buffer_offset = initial_chunk_length;
    while page_address_lo < page_address_hi {
        callback(cast(page_address_lo).to_u32_or_debug_panic(), 0, buffer_offset, page_size)?;
        buffer_offset += page_size;
        page_address_lo += cast(page_size).to_u64();
    }

    callback(
        cast(page_address_lo).to_u32_or_debug_panic(),
        0,
        buffer_offset,
        length - buffer_offset,
    )
}

#[test]
fn test_each_page() {
    fn run(address: u32, length: u32) -> Vec<(u32, usize, usize, usize)> {
        let page_size = 4096;
        let page_address_lo = address / page_size * page_size;
        let page_address_hi = (address + (length - 1)) / page_size * page_size;
        let mut output = Vec::new();
        each_page_impl::<()>(
            page_size,
            page_address_lo,
            page_address_hi,
            address,
            length,
            |page_address, page_offset, buffer_offset, length| {
                output.push((page_address, page_offset, buffer_offset, length));
                Ok(())
            },
        )
        .unwrap();
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

    #[rustfmt::skip]
    assert_eq!(run(0xffffffff - 4095, 4096), alloc::vec![
        (0xfffff000, 0, 0, 4096)
    ]);

    #[rustfmt::skip]
    assert_eq!(run(0xffffffff - 4096, 4095), alloc::vec![
        (0xffffe000, 4095, 0, 1),
        (0xfffff000, 0, 1, 4094)
    ]);
}

use NonZeroU32 as CompiledOffset;

polkavm_common::static_assert!(
    core::mem::size_of::<Handler>() + core::mem::size_of::<Args>() == cast(INTERPRETER_CACHE_ENTRY_SIZE).to_usize()
);

polkavm_common::static_assert!(core::mem::size_of::<CompiledOffset>() == cast(INTERPRETER_FLATMAP_ENTRY_SIZE).to_usize());

struct Handlers {
    charge_gas: Handler,
    step: Handler,
    trace_pc: Handler,
}

const MEMORY_STANDARD: usize = 0;
const MEMORY_DYNAMIC: usize = 1;

macro_rules! access_memory {
    ($self:expr, $kind:expr, |$memory:ident| $block:block) => {
        if $kind == MEMORY_STANDARD {
            let $memory = &$self.standard_memory;
            $block
        } else {
            debug_assert_eq!($kind, MEMORY_DYNAMIC);
            let $memory = &$self.dynamic_memory;
            $block
        }
    };
}

macro_rules! access_memory_mut {
    ($self:expr, $kind:expr, |$memory:ident| $block:block) => {
        if $kind == MEMORY_STANDARD {
            let $memory = &mut $self.standard_memory;
            $block
        } else {
            debug_assert_eq!($kind, MEMORY_DYNAMIC);
            let $memory = &mut $self.dynamic_memory;
            $block
        }
    };
}

fn get_or_build_jump_target_cache<'a>(
    module: &Module,
    cache: &'a mut Vec<Option<CodeBlockBitmapBox>>,
    program_counter: ProgramCounter,
) -> Option<&'a CodeBlockBitmapBox> {
    let blob = module.blob();
    debug_assert!(!blob.isa().is_legacy());

    let offset = cast(program_counter.0).to_usize();
    if offset >= blob.code().len() {
        return None;
    }

    let block = offset / CODE_BLOCK_SIZE;
    if cache.len() <= block {
        cache.resize(blob.code().len().div_ceil(CODE_BLOCK_SIZE), None);
    }

    Some(cache[block].get_or_insert_with(|| {
        let mut bitmap = CodeBlockBitmap::new_boxed();
        bitmap.build(blob.isa(), blob.code(), program_counter.0);
        bitmap
    }))
}

fn is_jump_target_valid_cached(module: &Module, cache: &mut Vec<Option<CodeBlockBitmapBox>>, program_counter: ProgramCounter) -> bool {
    if module.blob().isa().is_legacy() {
        // The legacy check is O(1) already.
        return module.scan_is_jump_target_valid(program_counter);
    }

    let Some(bitmap) = get_or_build_jump_target_cache(module, cache, program_counter) else {
        return false;
    };

    bitmap.get(program_counter)
}

/// Finds the start of the basic block which contains `program_counter`.
///
/// For the extended ISA `program_counter` is only guaranteed to be *inside* of that block; it can
/// point into the middle of an instruction, so this is not a substitute for validating the entry.
fn find_start_of_enclosing_basic_block(
    module: &Module,
    cache: &mut Vec<Option<CodeBlockBitmapBox>>,
    program_counter: ProgramCounter,
) -> Option<ProgramCounter> {
    if module.blob().isa().is_legacy() {
        module.scan_find_start_of_basic_block(program_counter)
    } else {
        get_or_build_jump_target_cache(module, cache, program_counter)?.find_start_of_basic_block(program_counter)
    }
}

pub(crate) struct InterpretedInstance {
    module: Module,
    standard_memory: StandardMemory,
    dynamic_memory: DynamicMemory,
    regs: [i64; Reg::ALL.len()],
    program_counter: ProgramCounter,
    program_counter_valid: bool,
    charge_gas_on_entry: bool,
    next_program_counter: Option<ProgramCounter>,
    next_program_counter_changed: bool,
    cycle_counter: u64,
    gas: i64,
    compiled_offset_for_block: FlatMap<CompiledOffset, true>,
    valid_jump_targets_for_block: Vec<Option<CodeBlockBitmapBox>>,
    compiled_handlers: Vec<Handler>,
    compiled_args: Vec<Args>,
    next_compiled_offset: Target,
    interrupt: InterruptKind,
    step_tracing: bool,
    unresolved_program_counter: Option<ProgramCounter>,
    max_compiled_handlers: Option<usize>,
    debug_mode: bool,
    handlers_debug: Handlers,
    handlers_non_debug: Handlers,
}

impl InterpretedInstance {
    pub fn new_from_module(module: Module, force_step_tracing: bool, imperfect_logger_filtering_workaround: bool) -> Self {
        let step_tracing = module.is_step_tracing() || force_step_tracing;
        let mut instance = Self {
            compiled_offset_for_block: FlatMap::new(module.code_len() + 1), // + 1 for one implicit out-of-bounds trap.
            valid_jump_targets_for_block: Default::default(),
            compiled_handlers: Default::default(),
            compiled_args: Default::default(),
            module,
            standard_memory: StandardMemory::new(),
            dynamic_memory: DynamicMemory::new(),
            regs: [0; Reg::ALL.len()],
            program_counter: ProgramCounter(!0),
            program_counter_valid: false,
            charge_gas_on_entry: true,
            next_program_counter: None,
            next_program_counter_changed: true,
            cycle_counter: 0,
            gas: 0,
            next_compiled_offset: 0,
            interrupt: InterruptKind::Finished,
            step_tracing,
            unresolved_program_counter: None,
            max_compiled_handlers: None,
            debug_mode: cfg!(test)
                || (!imperfect_logger_filtering_workaround
                    && (log::log_enabled!(target: "polkavm", log::Level::Debug)
                        || log::log_enabled!(target: "polkavm::interpreter", log::Level::Debug))),

            // This might seem silly, but Rust doesn't guarantee function pointer equality
            // if a given piece of code is instantiated across different codegen units.
            //
            // In general it's probably unlikely we'll hit this in practice, but I don't
            // particularly like the idea of having to debug this *if* we do, so this
            // here should work around the issue and make sure the pointers are always
            // the same for a given interpreter instance.
            handlers_debug: Handlers {
                charge_gas: cast_handler!(raw_handlers::charge_gas::<true>),
                step: cast_handler!(raw_handlers::step::<true>),
                trace_pc: cast_handler!(raw_handlers::trace_pc::<true>),
            },
            handlers_non_debug: Handlers {
                charge_gas: cast_handler!(raw_handlers::charge_gas::<false>),
                step: cast_handler!(raw_handlers::step::<false>),
                trace_pc: cast_handler!(raw_handlers::trace_pc::<false>),
            },
        };

        instance.initialize_module();
        instance
    }

    #[inline]
    fn memory_kind(&self) -> usize {
        if self.module.is_dynamic_paging() {
            MEMORY_DYNAMIC
        } else {
            MEMORY_STANDARD
        }
    }

    pub fn reg(&self, reg: Reg) -> RegValue {
        let mut value = self.regs[reg.to_usize()];
        if !self.module.blob().is_64_bit() {
            value &= 0xffffffff;
        }

        cast(value).bitwise_as_u64()
    }

    pub fn set_reg(&mut self, reg: Reg, value: RegValue) {
        self.regs[reg.to_usize()] = if !self.module.blob().is_64_bit() {
            let value = cast(value).truncate_to_u32();
            let value = cast(value).bitwise_as_i32();
            cast(value).to_i64_sign_extend()
        } else {
            cast(value).bitwise_as_i64()
        };
    }

    pub fn gas(&self) -> Gas {
        self.gas
    }

    pub fn set_gas(&mut self, gas: Gas) {
        self.gas = gas;
    }

    pub fn set_interpreter_cache_size_limit(&mut self, cache_info: Option<SetCacheSizeLimitArgs>) -> Result<(), Error> {
        let Some(SetCacheSizeLimitArgs {
            max_block_size,
            max_cache_size_bytes,
        }) = cache_info
        else {
            self.max_compiled_handlers = None;
            return Ok(());
        };

        let compiled_handlers_hard_limit = interpreter_calculate_cache_num_entries(max_cache_size_bytes);

        // Calculate the minimum number of compiled handlers required to guarantee a tight upper bound.
        // We must be able to hold at least two basic blocks (including gas metering) and we should also account for precompiled stubs.
        let minimum_compiled_handlers = (cast(max_block_size).to_usize() + 1) * 2;

        if compiled_handlers_hard_limit < minimum_compiled_handlers {
            log::debug!(
                "interpreter cache size is too small to gurantee a tight upper bound: {} < {}; max_block_size={}, max_cache_size_bytes={}",
                compiled_handlers_hard_limit,
                minimum_compiled_handlers,
                max_block_size,
                max_cache_size_bytes
            );
            return Err(Error::from(
                "given maximum cache size is too small to guarantee a tight upper bound",
            ));
        }

        let compiled_handlers_soft_limit = compiled_handlers_hard_limit - (cast(max_block_size).to_usize() + 1);
        self.max_compiled_handlers = Some(compiled_handlers_soft_limit);
        Ok(())
    }

    pub fn set_interpreter_max_allocation_size(&mut self, value: Option<usize>) {
        self.standard_memory.max_allocation_size = value.unwrap_or(usize::MAX);
    }

    pub fn set_interpreter_guest_memory_limit(&mut self, value: Option<usize>) {
        self.standard_memory.guest_memory_limit = value.unwrap_or(usize::MAX);
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
        self.charge_gas_on_entry = true;
    }

    pub fn accessible_aux_size(&self) -> u32 {
        access_memory!(self, self.memory_kind(), |memory| { memory.accessible_aux_size() })
    }

    pub fn set_accessible_aux_size(&mut self, size: u32) {
        access_memory_mut!(self, self.memory_kind(), |memory| { memory.set_accessible_aux_size(size) })
    }

    #[allow(clippy::unused_self)]
    pub fn next_native_program_counter(&self) -> Option<usize> {
        None
    }

    pub fn is_memory_accessible(&self, address: u32, size: u32, minimum_protection: MemoryProtection) -> bool {
        access_memory!(self, self.memory_kind(), |memory| {
            memory.is_memory_accessible(address, size, minimum_protection)
        })
    }

    pub fn read_memory_into<'slice>(
        &mut self,
        address: u32,
        buffer: &'slice mut [MaybeUninit<u8>],
    ) -> Result<&'slice mut [u8], MemoryAccessError> {
        access_memory_mut!(self, self.memory_kind(), |memory| { memory.read_memory_into(address, buffer) })
    }

    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryAccessError> {
        access_memory_mut!(self, self.memory_kind(), |memory| { memory.write_memory(address, data) })
    }

    pub fn zero_memory(&mut self, address: u32, length: u32, memory_protection: Option<MemoryProtection>) -> Result<(), MemoryAccessError> {
        access_memory_mut!(self, self.memory_kind(), |memory| {
            memory.zero_memory(address, length, memory_protection)
        })
    }

    pub fn change_memory_protection(&mut self, address: u32, length: u32, protection: MemoryProtection) -> Result<(), MemoryAccessError> {
        access_memory_mut!(self, self.memory_kind(), |memory| {
            memory.change_memory_protection(address, length, protection)
        })
    }

    pub fn free_pages(&mut self, address: u32, length: u32) {
        access_memory_mut!(self, self.memory_kind(), |memory| { memory.free_pages(address, length) })
    }

    pub fn heap_size(&self) -> u32 {
        access_memory!(self, self.memory_kind(), |memory| { memory.heap_size() })
    }

    pub fn sbrk(&mut self, size: u32) -> Option<u32> {
        access_memory_mut!(self, self.memory_kind(), |memory| { memory.sbrk(&self.module, size) })
    }

    #[allow(clippy::unused_self)]
    pub fn pid(&self) -> Option<u32> {
        None
    }

    pub fn run(&mut self) -> Result<InterruptKind, Error> {
        #[allow(clippy::collapsible_else_if)]
        if self.debug_mode {
            Ok(self.run_impl::<true>())
        } else {
            Ok(self.run_impl::<false>())
        }
    }

    #[inline(never)]
    fn run_impl<const DEBUG: bool>(&mut self) -> InterruptKind {
        access_memory_mut!(self, self.memory_kind(), |memory| {
            memory.mark_dirty();
        });

        if self.next_program_counter_changed {
            let Some(program_counter) = self.next_program_counter else {
                panic!("failed to run: next program counter is not set");
            };

            if let Some((offset, gas_cost)) = self.resolve_arbitrary_jump::<DEBUG>(program_counter) {
                if gas_cost > self.gas {
                    if DEBUG {
                        log::debug!(
                            "Not enough gas to start execution at {program_counter}: required={}, got={}",
                            gas_cost,
                            self.gas,
                        )
                    }

                    return InterruptKind::NotEnoughGas;
                }

                if DEBUG && gas_cost > 0 {
                    log::debug!(
                        "Charging gas on entry at {program_counter}: {} -> {}",
                        self.gas,
                        self.gas - gas_cost
                    );
                }

                self.gas -= gas_cost;
                self.next_compiled_offset = offset;
            } else {
                self.program_counter_valid = true;
                self.program_counter = program_counter;
                return InterruptKind::Trap;
            }

            self.program_counter = program_counter;
            self.next_program_counter = None;
            self.next_program_counter_changed = false;
            self.charge_gas_on_entry = false;

            if DEBUG {
                log::debug!("Starting execution at: {} [{}]", program_counter, self.next_compiled_offset);
            }
        } else if DEBUG {
            log::trace!("Implicitly resuming at: [{}]", self.next_compiled_offset);
        }

        #[cfg(feature = "interpreter-musttail-dispatch")]
        {
            // Ordinary call: `run_impl`'s signature can't join the handlers' `become` chain. Each
            // handler counts its own cycle, so none here.
            let off = self.next_compiled_offset;
            if let Some(&handler) = self.compiled_handlers.get(cast(off).to_usize()) {
                handler(self, off)
            } else {
                self.interrupt.clone()
            }
        }
        #[cfg(not(feature = "interpreter-musttail-dispatch"))]
        {
            let mut offset = self.next_compiled_offset;
            loop {
                let Some(handler) = self.compiled_handlers.get(cast(offset).to_usize()) else {
                    return self.interrupt.clone();
                };

                // Count the instruction about to execute (the no-handler case isn't one).
                if DEBUG {
                    self.cycle_counter += 1;
                }
                offset = handler(self, offset);
            }
        }
    }

    pub fn reset_memory(&mut self) {
        access_memory_mut!(self, self.memory_kind(), |memory| {
            memory.reset_memory(&self.module);
        });
    }

    pub fn reset_interpreter_cache(&mut self) {
        self.compiled_handlers.clear();
        self.compiled_args.clear();
        self.valid_jump_targets_for_block.clear();

        self.compiled_handlers.shrink_to_fit();
        self.compiled_args.shrink_to_fit();
        self.valid_jump_targets_for_block.shrink_to_fit();

        self.compiled_offset_for_block.reset();
        self.next_compiled_offset = 0;
    }

    fn initialize_module(&mut self) {
        if self.module.gas_metering().is_some() {
            self.gas = 0;
        }

        access_memory_mut!(self, self.memory_kind(), |memory| {
            memory.mark_dirty();
            memory.reset_memory(&self.module);
        });
    }

    #[inline(always)]
    fn pack_target(index: usize, is_jump_target_valid: bool) -> NonZeroU32 {
        let mut index = cast(index).to_u32_or_debug_panic();
        if is_jump_target_valid {
            index |= 1 << 31;
        }

        NonZeroU32::new(index + 1).unwrap()
    }

    #[inline(always)]
    fn unpack_target(value: NonZeroU32) -> (bool, Target) {
        let value = value.get() - 1;
        ((value >> 31) == 1, (value << 1) >> 1)
    }

    /// Resolve a jump from *within* the program.
    fn resolve_jump<const DEBUG: bool>(&mut self, program_counter: ProgramCounter) -> Option<Target> {
        if let Some(compiled_offset) = self.compiled_offset_for_block.get(program_counter.0) {
            let (is_jump_target_valid, target) = Self::unpack_target(compiled_offset);
            if !is_jump_target_valid {
                return None;
            }

            return Some(target);
        }

        if !is_jump_target_valid_cached(&self.module, &mut self.valid_jump_targets_for_block, program_counter) {
            return None;
        }

        self.compile_block::<DEBUG>(program_counter, !self.module.blob().isa().is_legacy())
    }

    #[inline(always)]
    fn handlers<const DEBUG: bool>(&self) -> &Handlers {
        if DEBUG {
            &self.handlers_debug
        } else {
            &self.handlers_non_debug
        }
    }

    #[allow(unpredictable_function_pointer_comparisons)]
    fn extract_target_and_gas<const DEBUG: bool>(&self, compiled_offset: NonZeroU32) -> (Target, i64) {
        let (is_jump_target_valid, target) = Self::unpack_target(compiled_offset);
        if is_jump_target_valid
            || self.module.gas_metering().is_none()
            || self.module.is_per_instruction_metering()
            || !self.charge_gas_on_entry
        {
            return (target, 0);
        }

        let mut start = cast(target).to_usize();
        if self.compiled_handlers[start] == self.handlers::<DEBUG>().step
            && self.compiled_handlers[start + 1] == self.handlers::<DEBUG>().charge_gas
        {
            start += 1;
        } else {
            while start > 0 && self.compiled_handlers[start] != self.handlers::<DEBUG>().charge_gas {
                start -= 1;
            }
        }

        assert_eq!(
            self.compiled_handlers[start],
            self.handlers::<DEBUG>().charge_gas,
            "internal error: failed to find the 'charge_gas' handler when jumping into the middle of a basic block"
        );

        let args = self.compiled_args[start];
        let gas_cost = cast(args.a1).to_i64();
        (target, gas_cost)
    }

    /// Resolve a jump from *outside* of the program.
    ///
    /// Unlike jumps from within the program these can start execution anywhere to support suspend/resume of the VM.
    fn resolve_arbitrary_jump<const DEBUG: bool>(&mut self, program_counter: ProgramCounter) -> Option<(Target, i64)> {
        if let Some(compiled_offset) = self.compiled_offset_for_block.get(program_counter.0) {
            return Some(self.extract_target_and_gas::<DEBUG>(compiled_offset));
        }

        if DEBUG {
            log::trace!("Resolving arbitrary jump: {program_counter}");
        }

        let Some(basic_block_offset) =
            find_start_of_enclosing_basic_block(&self.module, &mut self.valid_jump_targets_for_block, program_counter)
        else {
            if DEBUG {
                log::trace!("  -> There's no instruction here!");
            }

            return None;
        };

        if DEBUG {
            log::trace!("  -> Found start of a basic block at: {basic_block_offset}");
        }

        self.compile_block::<DEBUG>(basic_block_offset, false)?;

        // Reject a program counter pointing into the middle of an instruction.
        let Some(compiled_offset) = self.compiled_offset_for_block.get(program_counter.0) else {
            debug_assert_eq!(self.module.scan_find_start_of_basic_block(program_counter), None);
            return None;
        };

        if basic_block_offset == program_counter {
            Some((Self::unpack_target(compiled_offset).1, 0))
        } else {
            Some(self.extract_target_and_gas::<DEBUG>(compiled_offset))
        }
    }

    /// Resolve a fallthrough.
    fn resolve_fallthrough<const DEBUG: bool>(&mut self, program_counter: ProgramCounter) -> Option<Target> {
        if let Some(compiled_offset) = self.compiled_offset_for_block.get(program_counter.0) {
            let (is_jump_target_valid, target) = Self::unpack_target(compiled_offset);
            if !is_jump_target_valid {
                return None;
            }

            return Some(target);
        }

        self.compile_block::<DEBUG>(program_counter, !self.module.blob().isa().is_legacy())
    }

    #[inline(never)]
    fn compile_block<const DEBUG: bool>(&mut self, program_counter: ProgramCounter, known_valid_jump_target: bool) -> Option<Target> {
        if program_counter.0 >= self.module.code_len() {
            return None;
        }

        if DEBUG {
            log::debug!("Compiling block:");
        }

        match self.module.cost_model() {
            CostModelKind::Simple(cost_model) => {
                if self.module.is_per_instruction_metering() {
                    // TODO: Remove this.
                    self.compile_block_impl::<_, DEBUG, true>(program_counter, known_valid_jump_target, GasVisitor::new(cost_model.clone()))
                } else {
                    self.compile_block_impl::<_, DEBUG, false>(
                        program_counter,
                        known_valid_jump_target,
                        GasVisitor::new(cost_model.clone()),
                    )
                }
            }
            CostModelKind::Full(cost_model) => {
                use polkavm_common::simulator::Simulator;
                use polkavm_common::utils::{B32, B64};

                let blob = self.module.blob().clone(); // TODO: Unnecessary clone.
                let code = blob.code();

                if self.module.blob().is_64_bit() {
                    let gas_visitor = Simulator::<B64, ()>::new(code, blob.isa(), *cost_model, ());
                    self.compile_block_impl::<_, DEBUG, false>(program_counter, known_valid_jump_target, gas_visitor)
                } else {
                    let gas_visitor = Simulator::<B32, ()>::new(code, blob.isa(), *cost_model, ());
                    self.compile_block_impl::<_, DEBUG, false>(program_counter, known_valid_jump_target, gas_visitor)
                }
            }
        }
    }

    fn compile_block_impl<G, const DEBUG: bool, const PER_INSTRUCTION_METERING: bool>(
        &mut self,
        program_counter: ProgramCounter,
        known_valid_jump_target: bool,
        mut gas_visitor: G,
    ) -> Option<Target>
    where
        G: GasVisitorT,
    {
        let Ok(origin) = u32::try_from(self.compiled_handlers.len()) else {
            panic!("internal compiled program counter overflow: the program is too big!");
        };

        if cfg!(debug_assertions) && known_valid_jump_target {
            assert!(is_jump_target_valid_cached(
                &self.module,
                &mut self.valid_jump_targets_for_block,
                program_counter
            ));
        }

        let mut charge_gas_index = None;
        let mut is_jump_target_valid =
            known_valid_jump_target || is_jump_target_valid_cached(&self.module, &mut self.valid_jump_targets_for_block, program_counter);

        let instructions = if is_jump_target_valid {
            // A valid jump target always lies on an instruction boundary.
            self.module.instructions_bounded_at_known_boundary(program_counter)
        } else {
            self.module.instructions_bounded_at(program_counter)
        };

        for instruction in instructions {
            self.compiled_offset_for_block.insert(
                instruction.offset.0,
                Self::pack_target(self.compiled_handlers.len(), is_jump_target_valid),
            );

            is_jump_target_valid = false;

            if self.step_tracing {
                if DEBUG {
                    log::debug!("  [{}]: {}: step", self.compiled_handlers.len(), instruction.offset);
                }
                emit_consistent_address!(self, step(instruction.offset));
            }

            if self.module.gas_metering().is_some() {
                if !PER_INSTRUCTION_METERING {
                    if charge_gas_index.is_none() {
                        if DEBUG {
                            log::debug!("  [{}]: {}: charge_gas", self.compiled_handlers.len(), instruction.offset);
                        }

                        charge_gas_index = Some((instruction.offset, self.compiled_handlers.len()));
                        emit_consistent_address!(self, charge_gas(instruction.offset, 0));
                    }
                    instruction.visit_parsing(&mut gas_visitor);
                } else {
                    if DEBUG {
                        log::debug!("  [{}]: {}: charge_gas", self.compiled_handlers.len(), instruction.offset);
                    }

                    emit_consistent_address!(self, charge_gas(instruction.offset, 1));
                }
            }

            if DEBUG {
                log::debug!("  [{}]: {}: {}", self.compiled_handlers.len(), instruction.offset, instruction.kind);
                emit_consistent_address!(self, trace_pc(instruction.offset));
            }

            #[cfg(debug_assertions)]
            let original_length = self.compiled_handlers.len();
            let memory_kind = self.memory_kind();

            instruction.visit(&mut Compiler::<DEBUG> {
                program_counter: instruction.offset,
                next_program_counter: instruction.next_offset,
                compiled_handlers: &mut self.compiled_handlers,
                compiled_args: &mut self.compiled_args,
                valid_jump_targets_for_block: &mut self.valid_jump_targets_for_block,
                module: &self.module,
                memory_kind,
            });

            #[cfg(debug_assertions)]
            debug_assert!(
                instruction.opcode() == polkavm_common::program::Opcode::unlikely || self.compiled_handlers.len() > original_length
            );

            if instruction.opcode().starts_new_basic_block() {
                break;
            }
        }

        if let Some(max_compiled_handlers) = self.max_compiled_handlers {
            let handlers_added = self.compiled_handlers.len() - cast(origin).to_usize();
            if handlers_added > max_compiled_handlers {
                let compiled_handlers_new_limit = handlers_added;

                log::warn!(
                    "interpreter: compiled handlers cache is too small: {} > {}; setting new limit to {} and resetting the cache",
                    handlers_added,
                    max_compiled_handlers,
                    compiled_handlers_new_limit
                );

                self.max_compiled_handlers = Some(compiled_handlers_new_limit);
                self.compiled_handlers[cast(origin).to_usize()] = cast_handler!(raw_handlers::reset_cache::<DEBUG>);
                self.compiled_args[cast(origin).to_usize()] = Args::reset_cache(program_counter);
            } else if self.compiled_handlers.len() > max_compiled_handlers {
                log::debug!(
                    "interpreter: compiled handlers cache size exceeded at {}: {} > {}; will reset the cache",
                    origin,
                    self.compiled_handlers.len(),
                    max_compiled_handlers
                );

                self.compiled_handlers[cast(origin).to_usize()] = cast_handler!(raw_handlers::reset_cache::<DEBUG>);
                self.compiled_args[cast(origin).to_usize()] = Args::reset_cache(program_counter);
            } else if self.compiled_handlers.capacity() > max_compiled_handlers {
                self.compiled_handlers.shrink_to(max_compiled_handlers);
                self.compiled_args.shrink_to(max_compiled_handlers);
            }
        }

        if let Some((program_counter, index)) = charge_gas_index {
            let gas_cost = gas_visitor.take_block_cost().unwrap();
            self.compiled_args[index] = Args::charge_gas(program_counter, gas_cost);
        }

        if self.compiled_handlers.len() == cast(origin).to_usize() {
            return None;
        }

        Some(origin)
    }

    #[inline(always)]
    fn get_i32<const DEBUG: bool>(&self, regimm: impl IntoRegImm) -> i32 {
        match regimm.into() {
            RegImm::Reg(reg) => {
                let value = self.regs[reg.to_usize()];
                if DEBUG {
                    if self.module.blob().is_64_bit() {
                        log::trace!("  get: {reg} = 0x{value:x}");
                    } else {
                        log::trace!("  get: {reg} = 0x{:x}", cast(cast(value).bitwise_as_u64()).truncate_to_u32());
                    }
                }

                debug_assert!(self.module.blob().is_64_bit() || i32::try_from(value).is_ok());
                let value = cast(value).bitwise_as_u64();
                let value = cast(value).truncate_to_u32();
                cast(value).bitwise_as_i32()
            }
            RegImm::Imm(value) => value,
        }
    }

    #[inline(always)]
    fn get_u32<const DEBUG: bool>(&self, regimm: impl IntoRegImm) -> u32 {
        cast(self.get_i32::<DEBUG>(regimm)).bitwise_as_u32()
    }

    #[inline(always)]
    fn get_i64<const DEBUG: bool>(&self, regimm: impl IntoRegImm) -> i64 {
        match regimm.into() {
            RegImm::Reg(reg) => {
                let value = self.regs[reg.to_usize()];
                if DEBUG {
                    if self.module.blob().is_64_bit() {
                        log::trace!("  get: {reg} = 0x{value:x}");
                    } else {
                        log::trace!("  get: {reg} = 0x{:x}", cast(cast(value).bitwise_as_u64()).truncate_to_u32());
                    }
                }
                value
            }
            RegImm::Imm(value) => cast(value).to_i64_sign_extend(),
        }
    }

    #[inline(always)]
    fn get_u64<const DEBUG: bool>(&self, regimm: impl IntoRegImm) -> u64 {
        cast(self.get_i64::<DEBUG>(regimm)).bitwise_as_u64()
    }

    #[inline(always)]
    fn go_to_next_instruction(&mut self, current: Target) -> Target {
        current + 1
    }

    #[inline(always)]
    fn go_to_target(&mut self, target: Target) -> Target {
        target
    }

    #[inline(always)]
    fn trigger_interrupt(&mut self, interrupt: InterruptKind) -> Target {
        self.interrupt = interrupt;
        Target::MAX
    }

    #[inline(always)]
    fn set_i32<const DEBUG: bool>(&mut self, dst: Reg, value: i32) {
        let value = cast(value).to_i64_sign_extend();
        if DEBUG {
            if self.module.blob().is_64_bit() {
                log::trace!("  set: {dst} = 0x{value:x}");
            } else {
                log::trace!("  set: {dst} = 0x{:x}", cast(cast(value).bitwise_as_u64()).truncate_to_u32());
            }
        }

        self.regs[dst.to_usize()] = value;
    }

    #[inline(always)]
    fn set_u32<const DEBUG: bool>(&mut self, dst: Reg, value: u32) {
        self.set_i32::<DEBUG>(dst, cast(value).bitwise_as_i32())
    }

    #[inline(always)]
    fn set_i64<const DEBUG: bool>(&mut self, dst: Reg, value: i64) {
        if DEBUG {
            if self.module.blob().is_64_bit() {
                log::trace!("  set: {dst} = 0x{value:x}");
            } else {
                log::trace!("  set: {dst} = 0x{:x}", cast(cast(value).bitwise_as_u64()).truncate_to_u32());
            }
        }

        debug_assert!(self.module.blob().is_64_bit() || i32::try_from(value).is_ok());
        self.regs[dst.to_usize()] = value;
    }

    #[inline(always)]
    fn set_u64<const DEBUG: bool>(&mut self, dst: Reg, value: u64) {
        self.set_i64::<DEBUG>(dst, cast(value).bitwise_as_i64())
    }

    #[inline(always)]
    fn set3_i32<const DEBUG: bool>(
        &mut self,
        compiled_offset: Target,
        dst: Reg,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        callback: impl Fn(i32, i32) -> i32,
    ) -> Target {
        let s1 = self.get_i32::<DEBUG>(s1);
        let s2 = self.get_i32::<DEBUG>(s2);
        self.set_i32::<DEBUG>(dst, callback(s1, s2));
        self.go_to_next_instruction(compiled_offset)
    }

    #[inline(always)]
    fn set3_u32<const DEBUG: bool>(
        &mut self,
        compiled_offset: Target,
        dst: Reg,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        callback: impl Fn(u32, u32) -> u32,
    ) -> Target {
        self.set3_i32::<DEBUG>(compiled_offset, dst, s1, s2, move |s1, s2| {
            cast(callback(cast(s1).bitwise_as_u32(), cast(s2).bitwise_as_u32())).bitwise_as_i32()
        })
    }

    #[inline(always)]
    fn set3_i64<const DEBUG: bool>(
        &mut self,
        compiled_offset: Target,
        dst: Reg,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        callback: impl Fn(i64, i64) -> i64,
    ) -> Target {
        let s1 = self.get_i64::<DEBUG>(s1);
        let s2 = self.get_i64::<DEBUG>(s2);
        self.set_i64::<DEBUG>(dst, callback(s1, s2));
        self.go_to_next_instruction(compiled_offset)
    }

    #[inline(always)]
    fn set3_u64<const DEBUG: bool>(
        &mut self,
        compiled_offset: Target,
        dst: Reg,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        callback: impl Fn(u64, u64) -> u64,
    ) -> Target {
        self.set3_i64::<DEBUG>(compiled_offset, dst, s1, s2, move |s1, s2| {
            cast(callback(cast(s1).bitwise_as_u64(), cast(s2).bitwise_as_u64())).bitwise_as_i64()
        })
    }

    fn branch_i<const DEBUG: bool>(
        &mut self,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        target_true: Target,
        target_false: Target,
        callback: impl Fn(i64, i64) -> bool,
    ) -> Target {
        let s1 = self.get_i64::<DEBUG>(s1);
        let s2 = self.get_i64::<DEBUG>(s2);

        #[allow(clippy::collapsible_else_if)]
        let target = if callback(s1, s2) { target_true } else { target_false };

        self.go_to_target(target)
    }

    fn branch_u<const DEBUG: bool>(
        &mut self,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        target_true: Target,
        target_false: Target,
        callback: impl Fn(u64, u64) -> bool,
    ) -> Target {
        let s1 = self.get_u64::<DEBUG>(s1);
        let s2 = self.get_u64::<DEBUG>(s2);

        #[allow(clippy::collapsible_else_if)]
        let target = if callback(s1, s2) { target_true } else { target_false };

        self.go_to_target(target)
    }

    fn segfault_impl(
        &mut self,
        compiled_offset: Target,
        program_counter: ProgramCounter,
        page_address: u32,
        is_write_protected: bool,
    ) -> Target {
        // The lowest 64KB of the address space is inaccessible and always traps,
        // matching the recompiler backends. (See #390.)
        if page_address < 0x10000 {
            return trap_impl::<false>(self, program_counter);
        }

        self.program_counter = program_counter;
        self.program_counter_valid = true;
        self.next_program_counter = Some(program_counter);
        self.next_compiled_offset = compiled_offset;
        self.trigger_interrupt(InterruptKind::Segfault(Segfault {
            page_address,
            page_size: self.module.memory_map().page_size(),
            is_write_protected,
        }))
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn load<M: Memory, T: LoadTy, const DEBUG: bool>(
        &mut self,
        compiled_offset: Target,
        program_counter: ProgramCounter,
        dst: Reg,
        base: Option<Reg>,
        offset: i32,
    ) -> Target {
        self.program_counter = program_counter;

        assert!(core::mem::size_of::<T>() >= 1);

        let address = base
            .map_or(0, |base| self.regs[base.to_usize()])
            .wrapping_add(cast(offset).to_i64_sign_extend());

        let address = cast(cast(address).bitwise_as_u64()).truncate_to_u32();
        M::load_impl::<T, DEBUG>(self, compiled_offset, dst, address)
    }

    #[inline(never)]
    fn on_load_ok_trace<T: LoadTy>(dst: Reg, address: u32, value: i64) {
        log::trace!("  {dst} = {kind} [0x{address:x}] = 0x{value:x}", kind = core::any::type_name::<T>());
    }

    #[must_use]
    #[inline(always)]
    fn on_load_ok<T: LoadTy, const DEBUG: bool>(&mut self, compiled_offset: Target, dst: Reg, address: u32, value: i64) -> Target {
        if DEBUG {
            Self::on_load_ok_trace::<T>(dst, address, value);
        }

        self.set_i64::<false>(dst, value);
        self.go_to_next_instruction(compiled_offset)
    }

    #[must_use]
    #[cold]
    #[inline(never)]
    fn on_load_trap<T: LoadTy, const DEBUG: bool>(&mut self, address: u32) -> Target {
        if DEBUG {
            log::debug!(
                "Load of {length} bytes from 0x{address:x} failed: trap! (pc = {program_counter}, cycle = {cycle})",
                length = core::mem::size_of::<T>(),
                program_counter = self.program_counter,
                cycle = self.cycle_counter
            );
        }

        trap_impl::<DEBUG>(self, self.program_counter)
    }

    #[must_use]
    #[cold]
    #[inline(never)]
    fn on_load_segfault<T: LoadTy, const DEBUG: bool>(
        &mut self,
        compiled_offset: Target,
        address: u32,
        page_address: u32,
        is_write_protected: bool,
    ) -> Target {
        if DEBUG {
            log::debug!(
                "Load of {length} bytes from 0x{address:x} failed: segfault! (pc = {program_counter}, cycle = {cycle})",
                length = core::mem::size_of::<T>(),
                program_counter = self.program_counter,
                cycle = self.cycle_counter
            );
        }

        self.segfault_impl(compiled_offset, self.program_counter, page_address, is_write_protected)
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn store<M: Memory, T: StoreTy, const DEBUG: bool>(
        &mut self,
        compiled_offset: Target,
        program_counter: ProgramCounter,
        src: impl IntoRegImm,
        base: Option<Reg>,
        offset: i32,
    ) -> Target {
        self.program_counter = program_counter;

        assert!(core::mem::size_of::<T>() >= 1);

        let address = base
            .map_or(0, |base| self.regs[base.to_usize()])
            .wrapping_add(cast(offset).to_i64_sign_extend());

        let address = cast(cast(address).bitwise_as_u64()).truncate_to_u32();
        let value = match src.into() {
            RegImm::Reg(src) => {
                let value = self.regs[src.to_usize()];
                if DEBUG {
                    log::trace!("  {kind} [0x{address:x}] = {src} = 0x{value:x}", kind = core::any::type_name::<T>());
                }

                value
            }
            RegImm::Imm(value) => {
                if DEBUG {
                    log::trace!("  {kind} [0x{address:x}] = 0x{value:x}", kind = core::any::type_name::<T>());
                }

                cast(value).to_i64_sign_extend()
            }
        };

        M::store_impl::<T, DEBUG>(self, compiled_offset, address, value)
    }

    #[must_use]
    #[inline(always)]
    fn on_store_ok<T: StoreTy, const DEBUG: bool>(&mut self, compiled_offset: Target) -> Target {
        self.go_to_next_instruction(compiled_offset)
    }

    #[must_use]
    #[cold]
    #[inline(never)]
    fn on_store_trap<T: StoreTy, const DEBUG: bool>(&mut self, address: u32) -> Target {
        if DEBUG {
            log::debug!(
                "Store of {length} bytes to 0x{address:x} failed: trap! (pc = {program_counter}, cycle = {cycle})",
                length = core::mem::size_of::<T>(),
                program_counter = self.program_counter,
                cycle = self.cycle_counter
            );
        }

        trap_impl::<DEBUG>(self, self.program_counter)
    }

    #[must_use]
    #[cold]
    #[inline(never)]
    fn on_store_trap_due_to_memory_limit<T: StoreTy, const DEBUG: bool>(&mut self, address: u32) -> Target {
        if DEBUG {
            log::debug!(
                "Store of {length} bytes to 0x{address:x} failed: trap due to memory limits! (pc = {program_counter}, cycle = {cycle})",
                length = core::mem::size_of::<T>(),
                program_counter = self.program_counter,
                cycle = self.cycle_counter
            );
        }

        trap_impl::<DEBUG>(self, self.program_counter)
    }

    #[cold]
    #[inline(never)]
    fn on_store_segfault<T: StoreTy, const DEBUG: bool>(
        &mut self,
        compiled_offset: Target,
        address: u32,
        page_address: u32,
        is_write_protected: bool,
    ) -> Target {
        if DEBUG {
            log::debug!(
                "Store of {length} bytes to 0x{address:x} failed: segfault! (pc = {program_counter}, cycle = {cycle})",
                length = core::mem::size_of::<T>(),
                program_counter = self.program_counter,
                cycle = self.cycle_counter
            );
        }

        self.segfault_impl(compiled_offset, self.program_counter, page_address, is_write_protected)
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn jump_indirect_impl<const DEBUG: bool>(&mut self, program_counter: ProgramCounter, dynamic_address: u32) -> Target {
        if dynamic_address == VM_ADDR_RETURN_TO_HOST {
            self.program_counter = ProgramCounter(!0);
            self.program_counter_valid = false;
            self.next_program_counter = None;
            self.next_program_counter_changed = true;
            return self.trigger_interrupt(InterruptKind::Finished);
        }

        let Some(target) = self.module.jump_table().get_by_address(dynamic_address) else {
            if DEBUG {
                log::trace!("Indirect jump to dynamic address {dynamic_address}: invalid (bad jump table index)");
            }

            return trap_impl::<DEBUG>(self, program_counter);
        };

        if let Some(target) = self.resolve_jump::<DEBUG>(target) {
            if DEBUG {
                log::trace!("Indirect jump to dynamic address {dynamic_address}: {target}");
            }

            self.go_to_target(target)
        } else {
            if DEBUG {
                log::trace!("Indirect jump to dynamic address {dynamic_address}: invalid (bad target)");
            }

            trap_impl::<DEBUG>(self, program_counter)
        }
    }
}

trait LoadTy {
    type Slice: Default
        + core::ops::Index<core::ops::Range<usize>, Output = [u8]>
        + core::ops::IndexMut<core::ops::Range<usize>, Output = [u8]>
        + core::ops::Index<core::ops::RangeFrom<usize>, Output = [u8]>
        + core::ops::IndexMut<core::ops::RangeFrom<usize>, Output = [u8]>
        + core::ops::Index<core::ops::RangeTo<usize>, Output = [u8]>
        + core::ops::IndexMut<core::ops::RangeTo<usize>, Output = [u8]>
        + core::convert::AsRef<[u8]>;
    fn from_slice(xs: &[u8]) -> i64;
}

impl LoadTy for u8 {
    type Slice = [u8; 1];
    fn from_slice(xs: &[u8]) -> i64 {
        cast(u64::from(xs[0])).bitwise_as_i64()
    }
}

impl LoadTy for i8 {
    type Slice = [u8; 1];
    fn from_slice(xs: &[u8]) -> i64 {
        let value = cast(xs[0]).bitwise_as_i8();
        cast(value).to_i64_sign_extend()
    }
}

impl LoadTy for u16 {
    type Slice = [u8; 2];
    fn from_slice(xs: &[u8]) -> i64 {
        cast(u64::from(u16::from_le_bytes([xs[0], xs[1]]))).bitwise_as_i64()
    }
}

impl LoadTy for i16 {
    type Slice = [u8; 2];
    fn from_slice(xs: &[u8]) -> i64 {
        let value = i16::from_le_bytes([xs[0], xs[1]]);
        cast(value).to_i64_sign_extend()
    }
}

impl LoadTy for u32 {
    type Slice = [u8; 4];
    fn from_slice(xs: &[u8]) -> i64 {
        cast(u64::from(u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]))).bitwise_as_i64()
    }
}

impl LoadTy for i32 {
    type Slice = [u8; 4];
    fn from_slice(xs: &[u8]) -> i64 {
        let value = i32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
        cast(value).to_i64_sign_extend()
    }
}

impl LoadTy for u64 {
    type Slice = [u8; 8];
    fn from_slice(xs: &[u8]) -> i64 {
        i64::from_le_bytes([xs[0], xs[1], xs[2], xs[3], xs[4], xs[5], xs[6], xs[7]])
    }
}

trait StoreTy: Sized {
    type Array: AsRef<[u8]>;
    fn into_bytes(value: i64) -> Self::Array;
}

impl StoreTy for u8 {
    type Array = [u8; 1];

    #[inline(always)]
    fn into_bytes(value: i64) -> Self::Array {
        cast(cast(value).bitwise_as_u64()).truncate_to_u8().to_le_bytes()
    }
}

impl StoreTy for u16 {
    type Array = [u8; 2];

    #[inline(always)]
    fn into_bytes(value: i64) -> Self::Array {
        cast(cast(value).bitwise_as_u64()).truncate_to_u16().to_le_bytes()
    }
}

impl StoreTy for u32 {
    type Array = [u8; 4];

    #[inline(always)]
    fn into_bytes(value: i64) -> Self::Array {
        cast(cast(value).bitwise_as_u64()).truncate_to_u32().to_le_bytes()
    }
}

impl StoreTy for u64 {
    type Array = [u8; 8];

    #[inline(always)]
    fn into_bytes(value: i64) -> Self::Array {
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

type Handler = for<'a> fn(visitor: &'a mut InterpretedInstance, compiled_offset: Target) -> HandlerResult;

macro_rules! define_interpreter {
    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident) => {{
        impl Args {
            pub fn $handler_name() -> Args {
                Args::default()
            }
        }

        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: i32) => {{
        impl Args {
            pub fn $handler_name(a0: i32) -> Args {
                Args {
                    a0: cast(a0).bitwise_as_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = args.a0;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: ProgramCounter) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter) -> Args {
                Args {
                    a0: a0.0,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = ProgramCounter(args.a0);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: ProgramCounter, $a1:ident: u32) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter, a1: u32) -> Args {
                Args {
                    a0: a0.0,
                    a1,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = args.a1;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: ProgramCounter, $a1:ident: i32) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter, a1: i32) -> Args {
                Args {
                    a0: a0.0,
                    a1: cast(a1).bitwise_as_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = args.a1;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: ProgramCounter, $a1:ident: ProgramCounter) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter, a1: ProgramCounter) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.0,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = ProgramCounter(args.a1);

        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: ProgramCounter, $a1:ident: i32, $a2:ident: i32) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter, a1: i32, a2: i32) -> Args {
                Args {
                    a0: a0.0,
                    a1: cast(a1).bitwise_as_u32(),
                    a2: cast(a2).bitwise_as_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = cast(args.a1).bitwise_as_i32();
        let $a2 = cast(args.a2).bitwise_as_i32();
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: i32) => {{
        impl Args {
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: i32) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.into().to_u32(),
                    a2: cast(a2).bitwise_as_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = cast(args.a2).bitwise_as_i32();
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: i32, $a3:ident: i32) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: i32, a3: i32) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.into().to_u32(),
                    a2: cast(a2).bitwise_as_u32(),
                    a3: cast(a3).bitwise_as_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = cast(args.a2).bitwise_as_i32();
        let $a3 = cast(args.a3).bitwise_as_i32();
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: i32, $a3:ident: u32) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: i32, a3: u32) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.into().to_u32(),
                    a2: cast(a2).bitwise_as_u32(),
                    a3,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = cast(args.a2).bitwise_as_i32();
        let $a3 = args.a3;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: Reg, $a3:ident: i32) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: impl Into<Reg>, a3: i32) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.into().to_u32(),
                    a2: a2.into().to_u32(),
                    a3: cast(a3).bitwise_as_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = transmute_reg(args.a2);
        let $a3 = cast(args.a3).bitwise_as_i32();
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: Reg, $a3:ident: i32, $a4:ident: i32) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: impl Into<Reg>, a3: i32, a4: i32) -> Args {
                Args {
                    a0: a0.0,
                    a1: a1.into().to_u32() | ((a2.into().to_u32()) << 4),
                    a2: cast(a3).bitwise_as_u32(),
                    a3: cast(a4).bitwise_as_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = ProgramCounter(args.a0);
        let $a1 = transmute_reg(args.a1 & 0b1111);
        let $a2 = transmute_reg(args.a1 >> 4);
        let $a3 = cast(args.a2).bitwise_as_i32();
        let $a4 = cast(args.a3).bitwise_as_i32();
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: Reg) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: a1.into().to_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: Reg) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: impl Into<Reg>) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: a1.into().to_u32(),
                    a2: a2.into().to_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = transmute_reg(args.a2);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: i32) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: i32) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: a1.into().to_u32(),
                    a2: cast(a2).bitwise_as_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = cast(args.a2).bitwise_as_i32();
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: i32) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: i32) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: cast(a1).bitwise_as_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = cast(args.a1).bitwise_as_i32();
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: i32, $a2:ident: i32) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: i32, a2: i32) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: cast(a1).bitwise_as_u32(),
                    a2: cast(a2).bitwise_as_u32(),
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = cast(args.a1).bitwise_as_i32();
        let $a2 = cast(args.a2).bitwise_as_i32();
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: u32, $a2:ident: u32) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: u32, a2: u32) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1,
                    a2,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = args.a1;
        let $a2 = args.a2;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Target) => {{
        impl Args {
            pub fn $handler_name(a0: Target) -> Args {
                Args {
                    a0,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = args.a0;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: i32, $a2:ident: Target) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: i32, a2: Target) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: cast(a1).bitwise_as_u32(),
                    a2,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = cast(args.a1).bitwise_as_i32();
        let $a2 = args.a2;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: Target) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: Target) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: a1.into().to_u32(),
                    a2,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = args.a2;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: Target, $a3:ident: Target) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: Target, a3: Target) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: a1.into().to_u32(),
                    a2,
                    a3,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = args.a2;
        let $a3 = args.a3;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: i32, $a2:ident: Target, $a3:ident: Target) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: impl Into<Reg>, a1: i32, a2: Target, a3: Target) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: cast(a1).bitwise_as_u32(),
                    a2,
                    a3,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = cast(args.a1).bitwise_as_i32();
        let $a2 = args.a2;
        let $a3 = args.a3;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: ProgramCounter) => {{
        impl Args {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: ProgramCounter) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: a1.into().to_u32(),
                    a2: a2.0,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = ProgramCounter(args.a2);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: ProgramCounter, $a3:ident: ProgramCounter) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: ProgramCounter, a3: ProgramCounter) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: a1.into().to_u32(),
                    a2: a2.0,
                    a3: a3.0,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = transmute_reg(args.a1);
        let $a2 = ProgramCounter(args.a2);
        let $a3 = ProgramCounter(args.a3);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident $compiled_offset:ident, $a0:ident: Reg, $a1:ident: i32, $a2:ident: ProgramCounter, $a3:ident: ProgramCounter) => {{
        impl Args {
            #[allow(clippy::needless_update)]
            pub fn $handler_name(a0: impl Into<Reg>, a1: i32, a2: ProgramCounter, a3: ProgramCounter) -> Args {
                Args {
                    a0: a0.into().to_u32(),
                    a1: cast(a1).bitwise_as_u32(),
                    a2: a2.0,
                    a3: a3.0,
                    ..Args::default()
                }
            }
        }

        let args = $self.compiled_args[cast($compiled_offset).to_usize()];
        let $a0 = transmute_reg(args.a0);
        let $a1 = cast(args.a1).bitwise_as_i32();
        let $a2 = ProgramCounter(args.a2);
        let $a3 = ProgramCounter(args.a3);
        $body
    }};

    (@arg_names $handler_name:ident, $a0:ident: $a0_ty:ty, $a1:ident: $a1_ty:ty, $a2:ident: $a2_ty:ty) => {
        asm::$handler_name($a0, $a1, $a2)
    };

    ($(
        fn $handler_name:ident<$(M: $M_ty:ident,)? $(const $const:ident: $const_ty:ty),+>($self:ident: &mut InterpretedInstance, $compiled_offset:ident: Target $($arg:tt)*) -> Target $body:block
    )+) => {
        mod raw_handlers {
            use super::*;
            $(
                #[allow(clippy::needless_lifetimes)]
                pub fn $handler_name<'a, $(M: $M_ty,)? $(const $const: $const_ty),+>($self: &'a mut InterpretedInstance, compiled_offset: Target) -> HandlerResult {
                    let $compiled_offset = compiled_offset;
                    // Count this instruction before executing it (like the non-tail dispatch loop).
                    #[cfg(feature = "interpreter-musttail-dispatch")]
                    if DEBUG {
                        $self.cycle_counter += 1;
                    }
                    let next_off: Target = define_interpreter!(@define $handler_name $body $self $compiled_offset $($arg)*);
                    #[cfg(feature = "interpreter-musttail-dispatch")]
                    {
                        if let Some(&handler) = $self.compiled_handlers.get(cast(next_off).to_usize()) {
                            tail_call!(handler($self, next_off))
                        } else {
                            $self.interrupt.clone()
                        }
                    }
                    #[cfg(not(feature = "interpreter-musttail-dispatch"))]
                    {
                        next_off
                    }
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

fn trap_impl<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter) -> Target {
    visitor.program_counter = program_counter;
    visitor.program_counter_valid = true;
    visitor.next_program_counter = None;
    visitor.next_program_counter_changed = true;
    visitor.unresolved_program_counter = None;
    visitor.trigger_interrupt(InterruptKind::Trap)
}

fn not_enough_gas_impl<const DEBUG: bool>(
    visitor: &mut InterpretedInstance,
    compiled_offset: Target,
    program_counter: ProgramCounter,
    new_gas: i64,
) -> Target {
    match visitor.module.gas_metering().unwrap() {
        GasMeteringKind::Async => {
            visitor.gas = new_gas;
            visitor.program_counter_valid = false;
            visitor.next_program_counter = None;
            visitor.next_program_counter_changed = true;
        }
        GasMeteringKind::Sync => {
            visitor.program_counter = program_counter;
            visitor.program_counter_valid = true;
            visitor.next_program_counter = Some(program_counter);
            visitor.next_program_counter_changed = false;
        }
    }

    visitor.next_compiled_offset = compiled_offset;
    visitor.trigger_interrupt(InterruptKind::NotEnoughGas)
}

macro_rules! handle_unresolved_branch {
    ($debug:expr, $visitor:ident, $compiled_offset:ident, $s1:ident, $s2:ident, $tt:ident, $tf:ident, $name:ident) => {{
        if DEBUG {
            log::trace!("[{}]: jump {} if {} {} {}", $compiled_offset, $tt, $s1, $debug, $s2);
        }

        let offset = $compiled_offset;

        let target_true = $visitor.resolve_jump::<DEBUG>($tt);
        let target_false = $visitor.resolve_jump::<DEBUG>($tf);
        if let (Some(target_true), Some(target_false)) = (target_true, target_false) {
            $visitor.compiled_handlers[cast(offset).to_usize()] = cast_handler!(raw_handlers::$name::<DEBUG>);
            $visitor.compiled_args[cast(offset).to_usize()] = Args::$name($s1, $s2, target_true, target_false);
        } else {
            // This should never happen since we've already prevalidated the targets.
            if cfg!(debug_assertions) {
                panic!("internal error: failed to resolve a branch");
            }

            $visitor.compiled_handlers[cast(offset).to_usize()] = cast_handler!(raw_handlers::invalid_branch_trap::<DEBUG>);
            $visitor.compiled_args[cast(offset).to_usize()] = Args::invalid_branch_trap($tf);
        }

        $visitor.go_to_target(offset)
    }};
}

define_interpreter! {
    fn charge_gas<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, gas_cost: u32) -> Target {
        let new_gas = visitor.gas - i64::from(gas_cost);

        if DEBUG {
            log::trace!("[{}]: charge_gas: {gas_cost} ({} -> {})", compiled_offset, visitor.gas, new_gas);
        }

        if new_gas < 0 {
            not_enough_gas_impl::<DEBUG>(visitor, compiled_offset, program_counter, new_gas)
        } else {
            visitor.gas = new_gas;
            visitor.go_to_next_instruction(compiled_offset)
        }
    }

    fn step<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter) -> Target {
        if DEBUG {
            log::trace!("[{}]: step", compiled_offset);
        }

        visitor.program_counter = program_counter;
        visitor.program_counter_valid = true;
        visitor.next_program_counter = Some(program_counter);
        visitor.next_program_counter_changed = false;
        visitor.next_compiled_offset = compiled_offset + 1;
        visitor.trigger_interrupt(InterruptKind::Step)
    }

    fn trace_pc<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter) -> Target {
        if DEBUG {
            struct TracePc<'a> {
                module: &'a Module,
                compiled_offset: Target,
                program_counter: ProgramCounter,
            }

            impl<'a> core::fmt::Display for TracePc<'a> {
                fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    write!(f, "[{:#x}]: @{:#x}", self.compiled_offset, self.program_counter.0)?;
                    let mut displayed_name = false;
                    let mut displayed_loc = false;
                    for frame in self.module.blob().get_frame_info_for(self.program_counter, Some(1000)) {
                        if !displayed_name {
                            if let Ok(Some(_)) = frame.function_name_without_namespace() {
                                if let Ok(name) = frame.full_name() {
                                    write!(f, " {}", name)?;
                                    displayed_name = true;
                                }
                            }
                        }
                        if !displayed_loc {
                            if let Ok(Some(loc)) = frame.location() {
                                write!(f, " @ {}", loc)?;
                                displayed_loc = true;
                            }
                        }
                        if displayed_name && displayed_loc {
                            break;
                        }
                    }
                    Ok(())
                }
            }

            log::trace!("{}", TracePc { module: &visitor.module, compiled_offset, program_counter });
        }
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn reset_cache<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter) -> Target {
        if DEBUG {
            log::trace!("[{}]: reset_cache", compiled_offset);
        }

        visitor.reset_interpreter_cache();
        if let Some(target) = visitor.compile_block::<DEBUG>(program_counter, false) {
            visitor.go_to_target(target)
        } else {
            visitor.trigger_interrupt(InterruptKind::Trap)
        }
    }

    fn fallthrough<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: fallthrough", compiled_offset);
        }

        visitor.go_to_next_instruction(compiled_offset)
    }

    fn trap<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter) -> Target {
        if DEBUG {
            log::trace!("[{}]: trap", compiled_offset);
        }

        log::debug!("Trap at {}: explicit trap", program_counter);
        trap_impl::<DEBUG>(visitor, program_counter)
    }

    fn invalid_branch_trap<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter) -> Target {
        if DEBUG {
            log::trace!("[{}]: trap (invalid branch)", compiled_offset);
        }

        log::debug!("Trap at {}: invalid branch", program_counter);
        trap_impl::<DEBUG>(visitor, program_counter)
    }

    fn sbrk<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, dst: Reg, size: Reg) -> Target {
        let size = visitor.get_i64::<DEBUG>(size);
        let size = if visitor.module.blob().is_64_bit() {
            u32::try_from(size).ok().unwrap_or(0)
        } else {
            cast(cast(size).bitwise_as_u64()).truncate_to_u32()
        };

        let result = visitor.sbrk(size).unwrap_or(0);
        visitor.set_u64::<DEBUG>(dst, cast(result).to_u64_sign_extend());
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn memset<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter) -> Target {
        if DEBUG {
            log::trace!("[{}]: memset", compiled_offset);
        }

        let gas_metering_enabled = visitor.module.gas_metering().is_some();

        // TODO: This is very inefficient.
        let next_instruction = visitor.go_to_next_instruction(compiled_offset);
        let mut result = next_instruction;

        let value = visitor.get_i32::<DEBUG>(Reg::A1);
        let mut dst = visitor.get_u32::<DEBUG>(Reg::A0);
        let mut count = u64::from(visitor.get_u32::<DEBUG>(Reg::A2));
        while count > 0 {
            if gas_metering_enabled && visitor.gas == 0 {
                result = not_enough_gas_impl::<DEBUG>(visitor, compiled_offset, program_counter, 0);
                break;
            }

            result = visitor.store::<M, u8, DEBUG>(compiled_offset, program_counter, value, None, cast(dst).bitwise_as_i32());
            if result != next_instruction {
                break;
            }

            if gas_metering_enabled {
                visitor.gas -= 1;
            }

            dst += 1;
            count -= 1;
        }

        visitor.set_u64::<DEBUG>(Reg::A0, u64::from(dst));
        visitor.set_u64::<DEBUG>(Reg::A2, count);

        result
    }

    fn ecalli<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, hostcall_number: u32) -> Target {
        if DEBUG {
            log::trace!("[{}]: ecalli {hostcall_number}", compiled_offset);
        }

        let next_offset = visitor
            .module
            .instructions_bounded_at_known_boundary(program_counter)
            .next()
            .unwrap()
            .next_offset;
        visitor.program_counter = program_counter;
        visitor.program_counter_valid = true;
        visitor.next_program_counter = Some(next_offset);
        visitor.next_program_counter_changed = true;
        visitor.next_compiled_offset = compiled_offset + 1;
        visitor.trigger_interrupt(InterruptKind::Ecalli(hostcall_number))
    }

    fn set_less_than_unsigned<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::set_less_than_unsigned(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::from(s1 < s2))
    }

    fn set_less_than_signed<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::set_less_than_signed(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| i64::from(s1 < s2))
    }

    fn shift_logical_right_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_right_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_shr)
    }

    fn shift_logical_right_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_right_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::wrapping_shr(s1, cast(s2).truncate_to_u32()))
    }

    fn shift_arithmetic_right_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_arithmetic_right_32(d, s1, s2));
        }

        visitor.set3_i32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1.wrapping_shr(cast(s2).bitwise_as_u32()))
    }

    fn shift_arithmetic_right_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_arithmetic_right_64(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1.wrapping_shr(cast(cast(s2).bitwise_as_u64()).truncate_to_u32()))
    }

    fn shift_logical_left_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_left_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_shl)
    }

    fn shift_logical_left_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_left_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::wrapping_shl(s1, cast(s2).truncate_to_u32()))
    }

    fn xor<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::xor(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1 ^ s2)
    }

    fn and<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::and(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1 & s2)
    }

    fn or<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::or(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1 | s2)
    }

    fn add_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::add_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_add)
    }

    fn add_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::add_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, u64::wrapping_add)
    }

    fn sub_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::sub_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_sub)
    }

    fn sub_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::sub_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, u64::wrapping_sub)
    }

    fn negate_and_add_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::negate_and_add_imm_32(d, s1, s2));
        }

        visitor.set3_i32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s2.wrapping_sub(s1))
    }

    fn negate_and_add_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::negate_and_add_imm_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s2.wrapping_sub(s1))
    }

    fn mul_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::mul_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_mul)
    }

    fn mul_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::mul_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, u64::wrapping_mul)
    }

    fn mul_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::mul_imm_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_mul)
    }

    fn mul_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::mul_imm_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, u64::wrapping_mul)
    }

    fn mul_upper_signed_signed_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::mul_upper_signed_signed(d, s1, s2));
        }

        visitor.set3_i32::<DEBUG>(compiled_offset, d, s1, s2, mulh)
    }

    fn mul_upper_signed_signed_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::mul_upper_signed_signed(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, mulh64)
    }

    fn mul_upper_unsigned_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::mul_upper_unsigned_unsigned(d, s1, s2));
        }


        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, mulhu)
    }

    fn mul_upper_unsigned_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::mul_upper_unsigned_unsigned(d, s1, s2));
        }


        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, mulhu64)
    }

    fn mul_upper_signed_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::mul_upper_signed_unsigned(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| cast(mulhsu(cast(s1).bitwise_as_i32(), s2)).bitwise_as_u32())
    }

    fn mul_upper_signed_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::mul_upper_signed_unsigned(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| mulhsu64(s1, cast(s2).bitwise_as_u64()))
    }

    fn div_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::div_unsigned_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, divu)
    }

    fn div_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::div_unsigned_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, divu64)
    }

    fn div_signed_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::div_signed_32(d, s1, s2));
        }

        visitor.set3_i32::<DEBUG>(compiled_offset, d, s1, s2, div)
    }

    fn div_signed_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::div_signed_64(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, div64)
    }

    fn rem_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rem_unsigned_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, remu)
    }

    fn rem_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rem_unsigned_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, remu64)
    }

    fn rem_signed_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rem_signed_32(d, s1, s2));
        }

        visitor.set3_i32::<DEBUG>(compiled_offset, d, s1, s2, rem)
    }

    fn rem_signed_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rem_signed_64(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, rem64)
    }

    fn and_inverted_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::and_inverted(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1 & !s2)
    }

    fn and_inverted_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::and_inverted(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1 & !s2)
    }

    fn or_inverted_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::or_inverted(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1 | !s2)
    }

    fn or_inverted_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::or_inverted(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1 | !s2)
    }

    fn xnor_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::xnor(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| !(s1 ^ s2))
    }

    fn xnor_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::xnor(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| !(s1 ^ s2))
    }

    fn maximum_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::maximum(d, s1, s2));
        }

        visitor.set3_i32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1.max(s2))
    }

    fn maximum_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::maximum(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1.max(s2))
    }

    fn maximum_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::maximum_unsigned(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1.max(s2))
    }

    fn maximum_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::maximum_unsigned(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1.max(s2))
    }

    fn minimum_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::minimum(d, s1, s2));
        }

        visitor.set3_i32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1.min(s2))
    }

    fn minimum_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::minimum(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1.min(s2))
    }

    fn minimum_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::minimum_unsigned(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1.min(s2))
    }

    fn minimum_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::minimum_unsigned(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1.min(s2))
    }

    fn rotate_left_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rotate_left_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::rotate_left)
    }

    fn rotate_left_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rotate_left_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::rotate_left(s1, cast(s2).truncate_to_u32()))
    }

    fn rotate_right_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rotate_right_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::rotate_right)
    }

    fn rotate_right_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rotate_right_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::rotate_right(s1, cast(s2).truncate_to_u32()))
    }

    fn set_less_than_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::set_less_than_unsigned_imm(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::from(s1 < s2))
    }

    fn set_greater_than_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::set_greater_than_unsigned_imm(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::from(s1 > s2))
    }

    fn set_less_than_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::set_less_than_signed_imm(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| i64::from(s1 < s2))
    }

    fn set_greater_than_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::set_greater_than_signed_imm(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| i64::from(s1 > s2))
    }

    fn shift_logical_right_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_right_imm_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_shr)
    }

    fn shift_logical_right_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_right_imm_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::wrapping_shr(s1, cast(s2).truncate_to_u32()))
    }

    fn shift_logical_right_imm_alt_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s2: Reg, s1: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_right_imm_alt_32(d, s2, s1));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_shr)
    }

    fn shift_logical_right_imm_alt_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s2: Reg, s1: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_right_imm_alt_64(d, s2, s1));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::wrapping_shr(s1, cast(s2).truncate_to_u32()))
    }

    fn shift_arithmetic_right_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_arithmetic_right_imm_32(d, s1, s2));
        }

        visitor.set3_i32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| i32::wrapping_shr(s1, cast(s2).bitwise_as_u32()))
    }

    fn shift_arithmetic_right_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_arithmetic_right_imm_64(d, s1, s2));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| i64::wrapping_shr(s1, cast(cast(s2).bitwise_as_u64()).truncate_to_u32()))
    }

    fn shift_arithmetic_right_imm_alt_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s2: Reg, s1: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_arithmetic_right_imm_alt_32(d, s2, s1));
        }

        visitor.set3_i32::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| i32::wrapping_shr(s1, cast(s2).bitwise_as_u32()))
    }

    fn shift_arithmetic_right_imm_alt_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s2: Reg, s1: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_arithmetic_right_imm_alt_64(d, s2, s1));
        }

        visitor.set3_i64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| i64::wrapping_shr(s1, cast(cast(s2).bitwise_as_u64()).truncate_to_u32()))
    }

    fn shift_logical_left_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_left_imm_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_shl)
    }

    fn shift_logical_left_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_left_imm_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::wrapping_shl(s1, cast(s2).truncate_to_u32()))
    }

    fn shift_logical_left_imm_alt_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s2: Reg, s1: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_left_imm_alt_32(d, s2, s1));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_shl)
    }

    fn shift_logical_left_imm_alt_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s2: Reg, s1: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::shift_logical_left_imm_alt_64(d, s2, s1));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::wrapping_shl(s1, cast(s2).truncate_to_u32()))
    }

    fn or_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::or_imm(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1 | s2)
    }

    fn and_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::and_imm(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1 & s2)
    }

    fn xor_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::xor_imm(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| s1 ^ s2)
    }

    fn load_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, dst: Reg, imm: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_imm(dst, imm));
        }

        visitor.set_i32::<DEBUG>(dst, imm);
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn load_imm64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, dst: Reg, imm_lo: u32, imm_hi: u32) -> Target {
        let imm = cast(imm_lo).to_u64() | (cast(imm_hi).to_u64() << 32);
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_imm64(dst, imm));
        }

        visitor.set_u64::<DEBUG>(dst, imm);
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn move_reg<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::move_reg(d, s));
        }

        let imm = visitor.get_i64::<DEBUG>(s);
        visitor.set_i64::<DEBUG>(d, imm);
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn count_leading_zero_bits_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::count_leading_zero_bits_32(d, s));
        }

        visitor.set_u32::<DEBUG>(d, u32::leading_zeros(visitor.get_u32::<DEBUG>(s)));
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn count_leading_zero_bits_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::count_leading_zero_bits_64(d, s));
        }

        visitor.set_u64::<DEBUG>(d, cast(u64::leading_zeros(visitor.get_u64::<DEBUG>(s))).to_u64());
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn count_trailing_zero_bits_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::count_trailing_zero_bits_32(d, s));
        }

        visitor.set_u32::<DEBUG>(d, u32::trailing_zeros(visitor.get_u32::<DEBUG>(s)));
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn count_trailing_zero_bits_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::count_trailing_zero_bits_64(d, s));
        }

        visitor.set_u64::<DEBUG>(d, cast(u64::trailing_zeros(visitor.get_u64::<DEBUG>(s))).to_u64());
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn count_set_bits_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::count_set_bits_32(d, s));
        }

        visitor.set_u32::<DEBUG>(d, u32::count_ones(visitor.get_u32::<DEBUG>(s)));
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn count_set_bits_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::count_set_bits_64(d, s));
        }

        visitor.set_u64::<DEBUG>(d, cast(u64::count_ones(visitor.get_u64::<DEBUG>(s))).to_u64());
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn sign_extend_8_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::sign_extend_8(d, s));
        }

        let byte = cast(cast(visitor.get_u32::<DEBUG>(s)).truncate_to_u8()).bitwise_as_i8();
        visitor.set_u32::<DEBUG>(d, cast(cast(byte).to_i32_sign_extend()).bitwise_as_u32());
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn sign_extend_8_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::sign_extend_8(d, s));
        }

        let byte = cast(cast(visitor.get_u64::<DEBUG>(s)).truncate_to_u8()).bitwise_as_i8();
        visitor.set_i64::<DEBUG>(d, cast(byte).to_i64_sign_extend());
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn sign_extend_16_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::sign_extend_16(d, s));
        }

        let hword = cast(cast(visitor.get_u32::<DEBUG>(s)).truncate_to_u16()).bitwise_as_i16();
        visitor.set_u32::<DEBUG>(d, cast(cast(hword).to_i32_sign_extend()).bitwise_as_u32());
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn sign_extend_16_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::sign_extend_16(d, s));
        }

        let hword = cast(cast(visitor.get_u64::<DEBUG>(s)).truncate_to_u16()).bitwise_as_i16();
        visitor.set_u64::<DEBUG>(d, cast(cast(hword).to_i64_sign_extend()).bitwise_as_u64());
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn zero_extend_16_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::zero_extend_16(d, s));
        }

        let hword = cast(visitor.get_u32::<DEBUG>(s)).truncate_to_u16();
        visitor.set_u32::<DEBUG>(d, cast(hword).to_u32());
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn zero_extend_16_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::zero_extend_16(d, s));
        }

        let hword = cast(visitor.get_u64::<DEBUG>(s)).truncate_to_u16();
        visitor.set_u64::<DEBUG>(d, cast(hword).to_u64());
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn reverse_byte_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::reverse_byte(d, s));
        }

        visitor.set_u32::<DEBUG>(d, u32::swap_bytes(visitor.get_u32::<DEBUG>(s)));
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn reverse_byte_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::reverse_byte(d, s));
        }

        visitor.set_u64::<DEBUG>(d, u64::swap_bytes(visitor.get_u64::<DEBUG>(s)));
        visitor.go_to_next_instruction(compiled_offset)
    }

    fn cmov_if_zero<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg, c: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::cmov_if_zero(d, s, c));
        }

        if visitor.get_u64::<DEBUG>(c) == 0 {
            let value = visitor.get_u64::<DEBUG>(s);
            visitor.set_u64::<DEBUG>(d, value);
        }

        visitor.go_to_next_instruction(compiled_offset)
    }

    fn cmov_if_zero_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, c: Reg, s: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::cmov_if_zero_imm(d, c, s));
        }

        if visitor.get_u64::<DEBUG>(c) == 0 {
            visitor.set_i32::<DEBUG>(d, s);
        }

        visitor.go_to_next_instruction(compiled_offset)
    }

    fn cmov_if_not_zero<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s: Reg, c: Reg) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::cmov_if_not_zero(d, s, c));
        }

        if visitor.get_u64::<DEBUG>(c) != 0 {
            let value = visitor.get_u64::<DEBUG>(s);
            visitor.set_u64::<DEBUG>(d, value);
        }

        visitor.go_to_next_instruction(compiled_offset)
    }

    fn cmov_if_not_zero_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, c: Reg, s: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::cmov_if_not_zero_imm(d, c, s));
        }

        if visitor.get_u64::<DEBUG>(c) != 0 {
            visitor.set_i32::<DEBUG>(d, s);
        }

        visitor.go_to_next_instruction(compiled_offset)
    }

    fn rotate_right_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rotate_right_imm_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::rotate_right)
    }

    fn rotate_right_imm_alt_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rotate_right_imm_alt_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s2, s1, u32::rotate_right)
    }

    fn rotate_right_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rotate_right_imm_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, |s1, s2| u64::rotate_right(s1, cast(s2).truncate_to_u32()))
    }

    fn rotate_right_imm_alt_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::rotate_right_imm_alt_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s2, s1, |s2, s1| u64::rotate_right(s2, cast(s1).truncate_to_u32()))
    }

    fn add_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::add_imm_32(d, s1, s2));
        }

        visitor.set3_u32::<DEBUG>(compiled_offset, d, s1, s2, u32::wrapping_add)
    }

    fn add_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, d: Reg, s1: Reg, s2: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::add_imm_64(d, s1, s2));
        }

        visitor.set3_u64::<DEBUG>(compiled_offset, d, s1, s2, u64::wrapping_add)
    }

    fn store_imm_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, offset: i32, value: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_imm_u8(offset, value));
        }

        visitor.store::<M, u8, DEBUG>(compiled_offset, program_counter, value, None, offset)
    }

    fn store_imm_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, offset: i32, value: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_imm_u16(offset, value));
        }

        visitor.store::<M, u16, DEBUG>(compiled_offset, program_counter, value, None, offset)
    }

    fn store_imm_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, offset: i32, value: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_imm_u32(offset, value));
        }

        visitor.store::<M, u32, DEBUG>(compiled_offset, program_counter, value, None, offset)
    }

    fn store_imm_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, offset: i32, value: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_imm_u64(offset, value));
        }

        visitor.store::<M, u64, DEBUG>(compiled_offset, program_counter, value, None, offset)
    }

    fn store_imm_indirect_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, base: Reg, offset: i32, value: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_imm_indirect_u8(base, offset, value));
        }

        visitor.store::<M, u8, DEBUG>(compiled_offset, program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, base: Reg, offset: i32, value: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_imm_indirect_u16(base, offset, value));
        }

        visitor.store::<M, u16, DEBUG>(compiled_offset, program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, base: Reg, offset: i32, value: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_imm_indirect_u32(base, offset, value));
        }

        visitor.store::<M, u32, DEBUG>(compiled_offset, program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, base: Reg, offset: i32, value: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_imm_indirect_u64(base, offset, value));
        }

        visitor.store::<M, u64, DEBUG>(compiled_offset, program_counter, value, Some(base), offset)
    }

    fn store_indirect_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, src: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_indirect_u8(src, base, offset));
        }

        visitor.store::<M, u8, DEBUG>(compiled_offset, program_counter, src, Some(base), offset)
    }

    fn store_indirect_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, src: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_indirect_u16(src, base, offset));
        }

        visitor.store::<M, u16, DEBUG>(compiled_offset, program_counter, src, Some(base), offset)
    }

    fn store_indirect_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, src: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_indirect_u32(src, base, offset));
        }

        visitor.store::<M, u32, DEBUG>(compiled_offset, program_counter, src, Some(base), offset)
    }

    fn store_indirect_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, src: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_indirect_u64(src, base, offset));
        }

        visitor.store::<M, u64, DEBUG>(compiled_offset, program_counter, src, Some(base), offset)
    }

    fn store_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, src: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_u8(src, offset));
        }

        visitor.store::<M, u8, DEBUG>(compiled_offset, program_counter, src, None, offset)
    }

    fn store_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, src: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_u16(src, offset));
        }

        visitor.store::<M, u16, DEBUG>(compiled_offset, program_counter, src, None, offset)
    }

    fn store_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, src: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_u32(src, offset));
        }

        visitor.store::<M, u32, DEBUG>(compiled_offset, program_counter, src, None, offset)
    }

    fn store_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, src: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::store_u64(src, offset));
        }

        visitor.store::<M, u64, DEBUG>(compiled_offset, program_counter, src, None, offset)
    }

    fn load_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_u8(dst, offset));
        }

        visitor.load::<M, u8, DEBUG>(compiled_offset, program_counter, dst, None, offset)
    }

    fn load_i8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_i8(dst, offset));
        }

        visitor.load::<M, i8, DEBUG>(compiled_offset, program_counter, dst, None, offset)
    }

    fn load_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_u16(dst, offset));
        }

        visitor.load::<M, u16, DEBUG>(compiled_offset, program_counter, dst, None, offset)
    }

    fn load_i16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_i16(dst, offset));
        }

        visitor.load::<M, i16, DEBUG>(compiled_offset, program_counter, dst, None, offset)
    }

    fn load_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_u32(dst, offset));
        }

        visitor.load::<M, u32, DEBUG>(compiled_offset, program_counter, dst, None, offset)
    }

    fn load_i32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_i32(dst, offset));
        }

        visitor.load::<M, i32, DEBUG>(compiled_offset, program_counter, dst, None, offset)
    }

    fn load_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_u64(dst, offset));
        }

        visitor.load::<M, u64, DEBUG>(compiled_offset, program_counter, dst, None, offset)
    }

    fn load_indirect_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_indirect_u8(dst, base, offset));
        }

        visitor.load::<M, u8, DEBUG>(compiled_offset, program_counter, dst, Some(base), offset)
    }

    fn load_indirect_i8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_indirect_i8(dst, base, offset));
        }

        visitor.load::<M, i8, DEBUG>(compiled_offset, program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_indirect_u16(dst, base, offset));
        }

        visitor.load::<M, u16, DEBUG>(compiled_offset, program_counter, dst, Some(base), offset)
    }

    fn load_indirect_i16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_indirect_i16(dst, base, offset));
        }

        visitor.load::<M, i16, DEBUG>(compiled_offset, program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_indirect_u32(dst, base, offset));
        }

        visitor.load::<M, u32, DEBUG>(compiled_offset, program_counter, dst, Some(base), offset)
    }

    fn load_indirect_i32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_indirect_i32(dst, base, offset));
        }

        visitor.load::<M, i32, DEBUG>(compiled_offset, program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_indirect_u64(dst, base, offset));
        }

        visitor.load::<M, u64, DEBUG>(compiled_offset, program_counter, dst, Some(base), offset)
    }

    fn branch_less_unsigned<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <u {s2}", compiled_offset);
        }

        visitor.branch_u::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 < s2)
    }

    fn branch_less_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <u {s2}", compiled_offset);
        }

        visitor.branch_u::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 < s2)
    }

    fn branch_less_signed<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <s {s2}", compiled_offset);
        }

        visitor.branch_i::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 < s2)
    }

    fn branch_less_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <s {s2}", compiled_offset);
        }

        visitor.branch_i::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 < s2)
    }

    fn branch_eq<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} == {s2}", compiled_offset);
        }

        visitor.branch_u::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 == s2)
    }

    fn branch_eq_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} == {s2}", compiled_offset);
        }

        visitor.branch_u::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 == s2)
    }

    fn branch_not_eq<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} != {s2}", compiled_offset);
        }

        visitor.branch_u::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 != s2)
    }

    fn branch_not_eq_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} != {s2}", compiled_offset);
        }

        visitor.branch_u::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 != s2)
    }

    fn branch_greater_or_equal_unsigned<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=u {s2}", compiled_offset);
        }

        visitor.branch_u::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 >= s2)
    }

    fn branch_greater_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=u {s2}", compiled_offset);
        }

        visitor.branch_u::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 >= s2)
    }

    fn branch_greater_or_equal_signed<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=s {s2}", compiled_offset);
        }

        visitor.branch_i::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 >= s2)
    }

    fn branch_greater_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=s {s2}", compiled_offset);
        }

        visitor.branch_i::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 >= s2)
    }

    fn branch_less_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <=u {s2}", compiled_offset);
        }

        visitor.branch_u::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 <= s2)
    }

    fn branch_less_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <=s {s2}", compiled_offset);
        }

        visitor.branch_i::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 <= s2)
    }

    fn branch_greater_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >u {s2}", compiled_offset);
        }

        visitor.branch_u::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 > s2)
    }

    fn branch_greater_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: Target, tf: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >s {s2}", compiled_offset);
        }

        visitor.branch_i::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 > s2)
    }

    fn jump<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, target: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: jump ~{target}", compiled_offset);
        }

        visitor.go_to_target(target)
    }

    fn jump_indirect<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, base: Reg, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::jump_indirect(base, offset));
        }

        let dynamic_address = visitor.get_i64::<DEBUG>(base).wrapping_add(cast(offset).to_i64_sign_extend());
        let dynamic_address = cast(cast(dynamic_address).bitwise_as_u64()).truncate_to_u32();
        visitor.jump_indirect_impl::<DEBUG>(program_counter, dynamic_address)
    }

    fn load_imm_and_jump_indirect<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, ra: Reg, base: Reg, value: i32, offset: i32) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_imm_and_jump_indirect(ra, base, value, offset));
        }

        let dynamic_address = visitor.get_i64::<DEBUG>(base).wrapping_add(cast(offset).to_i64_sign_extend());
        let dynamic_address = cast(cast(dynamic_address).bitwise_as_u64()).truncate_to_u32();
        visitor.set_i32::<DEBUG>(ra, value);
        visitor.jump_indirect_impl::<DEBUG>(program_counter, dynamic_address)
    }

    fn load_imm_and_jump<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, ra: Reg, value: i32, target: Target) -> Target {
        if DEBUG {
            log::trace!("[{}]: {}", compiled_offset, asm::load_imm_and_jump(ra, value, target));
        }

        visitor.set_i32::<DEBUG>(ra, value);
        visitor.go_to_target(target)
    }

    fn unresolved_branch_less_unsigned<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!("<u", visitor, compiled_offset, s1, s2, tt, tf, branch_less_unsigned)
    }

    fn unresolved_branch_less_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!("<u", visitor, compiled_offset, s1, s2, tt, tf, branch_less_unsigned_imm)
    }

    fn unresolved_branch_less_signed<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!("<s", visitor, compiled_offset, s1, s2, tt, tf, branch_less_signed)
    }

    fn unresolved_branch_less_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!("<s", visitor, compiled_offset, s1, s2, tt, tf, branch_less_signed_imm)
    }

    fn unresolved_branch_eq<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!("==", visitor, compiled_offset, s1, s2, tt, tf, branch_eq)
    }

    fn unresolved_branch_eq_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!("==", visitor, compiled_offset, s1, s2, tt, tf, branch_eq_imm)
    }

    fn unresolved_branch_not_eq<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!("!=", visitor, compiled_offset, s1, s2, tt, tf, branch_not_eq)
    }

    fn unresolved_branch_not_eq_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!("!=", visitor, compiled_offset, s1, s2, tt, tf, branch_not_eq_imm)
    }

    fn unresolved_branch_greater_or_equal_unsigned<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!(">=u", visitor, compiled_offset, s1, s2, tt, tf, branch_greater_or_equal_unsigned)
    }

    fn unresolved_branch_greater_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!(">=u", visitor, compiled_offset, s1, s2, tt, tf, branch_greater_or_equal_unsigned_imm)
    }

    fn unresolved_branch_greater_or_equal_signed<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!(">=s", visitor, compiled_offset, s1, s2, tt, tf, branch_greater_or_equal_signed)
    }

    fn unresolved_branch_greater_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!(">=s", visitor, compiled_offset, s1, s2, tt, tf, branch_greater_or_equal_signed_imm)
    }

    fn unresolved_branch_greater_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!(">u", visitor, compiled_offset, s1, s2, tt, tf, branch_greater_unsigned_imm)
    }

    fn unresolved_branch_greater_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!(">s", visitor, compiled_offset, s1, s2, tt, tf, branch_greater_signed_imm)
    }

    fn unresolved_branch_less_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!("<=u", visitor, compiled_offset, s1, s2, tt, tf, branch_less_or_equal_unsigned_imm)
    }

    fn unresolved_branch_less_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, s1: Reg, s2: i32, tt: ProgramCounter, tf: ProgramCounter) -> Target {
        handle_unresolved_branch!("<=s", visitor, compiled_offset, s1, s2, tt, tf, branch_less_or_equal_signed_imm)
    }

    fn unresolved_jump<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, jump_to: ProgramCounter) -> Target {
        if DEBUG {
            log::trace!("[{}]: unresolved jump {jump_to}", compiled_offset);
        }

        if let Some(target) = visitor.resolve_jump::<DEBUG>(jump_to) {
            let offset = compiled_offset;
            if offset + 1 == target {
                if DEBUG {
                    log::trace!("  -> resolved to fallthrough");
                }
                visitor.compiled_handlers[cast(offset).to_usize()] = cast_handler!(raw_handlers::fallthrough::<DEBUG>);
                visitor.compiled_args[cast(offset).to_usize()] = Args::fallthrough();
            } else {
                if DEBUG {
                    log::trace!("  -> resolved to jump");
                }
                visitor.compiled_handlers[cast(offset).to_usize()] = cast_handler!(raw_handlers::jump::<DEBUG>);
                visitor.compiled_args[cast(offset).to_usize()] = Args::jump(target);
            }

            visitor.go_to_target(target)
        } else {
            if DEBUG {
                log::trace!("  -> resolved to trap");
            }
            trap_impl::<DEBUG>(visitor, program_counter)
        }
    }

    fn unresolved_load_imm_and_jump<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, ra: Reg, value: i32, jump_to: u32) -> Target {
        if DEBUG {
            log::trace!("[{}]: unresolved {}", compiled_offset, asm::load_imm_and_jump(ra, value, jump_to));
        }

        visitor.set_i32::<DEBUG>(ra, value);

        let offset = compiled_offset;
        if let Some(target) = visitor.resolve_jump::<DEBUG>(ProgramCounter(jump_to)) {
            if DEBUG {
                log::trace!("  -> resolved to jump");
            }
            visitor.compiled_handlers[cast(offset).to_usize()] = cast_handler!(raw_handlers::load_imm_and_jump::<DEBUG>);
            visitor.compiled_args[cast(offset).to_usize()] = Args::load_imm_and_jump(ra, value, target);
            visitor.go_to_target(target)
        } else {
            if DEBUG {
                log::trace!("  -> resolved to trap");
            }
            trap_impl::<DEBUG>(visitor, program_counter)
        }
    }

    fn unresolved_fallthrough<const DEBUG: bool>(visitor: &mut InterpretedInstance, compiled_offset: Target, program_counter: ProgramCounter, jump_to: ProgramCounter) -> Target {
        if DEBUG {
            log::trace!("[{}]: unresolved fallthrough {jump_to}", compiled_offset);
        }

        let offset = compiled_offset;
        if let Some(target) = visitor.resolve_fallthrough::<DEBUG>(jump_to) {
            if offset + 1 == target {
                if DEBUG {
                    log::trace!("  -> resolved to fallthrough");
                }
                visitor.compiled_handlers[cast(offset).to_usize()] = cast_handler!(raw_handlers::fallthrough::<DEBUG>);
                visitor.compiled_args[cast(offset).to_usize()] = Args::fallthrough();
            } else {
                if DEBUG {
                    log::trace!("  -> resolved to jump");
                }
                visitor.compiled_handlers[cast(offset).to_usize()] = cast_handler!(raw_handlers::jump::<DEBUG>);
                visitor.compiled_args[cast(offset).to_usize()] = Args::jump(target);
            }

            visitor.go_to_target(target)
        } else {
            if DEBUG {
                log::trace!("  -> resolved to trap");
            }
            trap_impl::<DEBUG>(visitor, program_counter)
        }
    }
}

struct Compiler<'a, const DEBUG: bool> {
    program_counter: ProgramCounter,
    next_program_counter: ProgramCounter,
    compiled_handlers: &'a mut Vec<Handler>,
    compiled_args: &'a mut Vec<Args>,
    valid_jump_targets_for_block: &'a mut Vec<Option<CodeBlockBitmapBox>>,
    module: &'a Module,
    memory_kind: usize,
}

impl<'a, const DEBUG: bool> Compiler<'a, DEBUG> {
    fn next_program_counter(&self) -> ProgramCounter {
        self.next_program_counter
    }

    fn is_jump_target_valid(&mut self, program_counter: ProgramCounter) -> bool {
        is_jump_target_valid_cached(self.module, self.valid_jump_targets_for_block, program_counter)
    }

    #[track_caller]
    fn assert_64_bit(&self) {
        debug_assert!(self.module.blob().is_64_bit());
    }
}

impl<'a, const DEBUG: bool> InstructionVisitor for Compiler<'a, DEBUG> {
    type ReturnTy = ();

    #[cold]
    fn invalid(&mut self) -> Self::ReturnTy {
        self.trap();
    }

    fn trap(&mut self) -> Self::ReturnTy {
        emit!(self, trap(self.program_counter));
    }

    fn fallthrough(&mut self) -> Self::ReturnTy {
        let target = self.next_program_counter();
        emit!(self, unresolved_fallthrough(self.program_counter, target));
    }

    fn unlikely(&mut self) -> Self::ReturnTy {}

    fn sbrk(&mut self, dst: RawReg, size: RawReg) -> Self::ReturnTy {
        emit!(self, sbrk(dst, size));
    }

    fn memset(&mut self) -> Self::ReturnTy {
        #[allow(clippy::branches_sharing_code)]
        if self.memory_kind == MEMORY_STANDARD {
            emit_raw!(self, memset::<StandardMemory, DEBUG>(self.program_counter));
        } else {
            debug_assert_eq!(self.memory_kind, MEMORY_DYNAMIC);
            emit_raw!(self, memset::<DynamicMemory, DEBUG>(self.program_counter));
        }
    }

    fn ecalli(&mut self, imm: i32) -> Self::ReturnTy {
        emit!(self, ecalli(self.program_counter, cast(imm).bitwise_as_u32()));
    }

    fn set_less_than_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, set_less_than_unsigned(d, s1, s2));
    }

    fn set_less_than_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, set_less_than_signed(d, s1, s2));
    }

    fn shift_logical_right_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, shift_logical_right_32(d, s1, s2));
    }

    fn shift_arithmetic_right_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_32(d, s1, s2));
    }

    fn shift_logical_left_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, shift_logical_left_32(d, s1, s2));
    }

    fn shift_logical_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, shift_logical_right_64(d, s1, s2));
    }

    fn shift_arithmetic_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, shift_arithmetic_right_64(d, s1, s2));
    }

    fn shift_logical_left_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, shift_logical_left_64(d, s1, s2));
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

    fn add_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, add_32(d, s1, s2));
    }

    fn add_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, add_64(d, s1, s2));
    }

    fn sub_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, sub_32(d, s1, s2));
    }

    fn sub_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, sub_64(d, s1, s2));
    }

    fn negate_and_add_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, negate_and_add_imm_32(d, s1, s2));
    }

    fn negate_and_add_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, negate_and_add_imm_64(d, s1, s2));
    }

    fn mul_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, mul_32(d, s1, s2));
    }

    fn mul_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, mul_64(d, s1, s2));
    }

    fn mul_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, mul_imm_32(d, s1, s2));
    }

    fn mul_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, mul_imm_64(d, s1, s2));
    }

    fn mul_upper_signed_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, mul_upper_signed_signed_64(d, s1, s2));
        } else {
            emit!(self, mul_upper_signed_signed_32(d, s1, s2));
        }
    }

    fn mul_upper_unsigned_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, mul_upper_unsigned_unsigned_64(d, s1, s2));
        } else {
            emit!(self, mul_upper_unsigned_unsigned_32(d, s1, s2));
        }
    }

    fn mul_upper_signed_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, mul_upper_signed_unsigned_64(d, s1, s2));
        } else {
            emit!(self, mul_upper_signed_unsigned_32(d, s1, s2));
        }
    }

    fn div_unsigned_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, div_unsigned_32(d, s1, s2));
    }

    fn div_signed_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, div_signed_32(d, s1, s2));
    }

    fn rem_unsigned_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, rem_unsigned_32(d, s1, s2));
    }

    fn rem_signed_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, rem_signed_32(d, s1, s2));
    }

    fn div_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, div_unsigned_64(d, s1, s2));
    }

    fn div_signed_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, div_signed_64(d, s1, s2));
    }

    fn rem_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rem_unsigned_64(d, s1, s2));
    }

    fn rem_signed_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rem_signed_64(d, s1, s2));
    }

    fn and_inverted(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, and_inverted_64(d, s1, s2));
        } else {
            emit!(self, and_inverted_32(d, s1, s2));
        }
    }

    fn or_inverted(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, or_inverted_64(d, s1, s2));
        } else {
            emit!(self, or_inverted_32(d, s1, s2));
        }
    }

    fn xnor(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, xnor_64(d, s1, s2));
        } else {
            emit!(self, xnor_32(d, s1, s2));
        }
    }

    fn maximum(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, maximum_64(d, s1, s2));
        } else {
            emit!(self, maximum_32(d, s1, s2));
        }
    }

    fn maximum_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, maximum_unsigned_64(d, s1, s2));
        } else {
            emit!(self, maximum_unsigned_32(d, s1, s2));
        }
    }

    fn minimum(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, minimum_64(d, s1, s2));
        } else {
            emit!(self, minimum_32(d, s1, s2));
        }
    }

    fn minimum_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, minimum_unsigned_64(d, s1, s2));
        } else {
            emit!(self, minimum_unsigned_32(d, s1, s2));
        }
    }

    fn rotate_left_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, rotate_left_32(d, s1, s2));
    }

    fn rotate_left_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rotate_left_64(d, s1, s2));
    }

    fn rotate_right_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, rotate_right_32(d, s1, s2));
    }

    fn rotate_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rotate_right_64(d, s1, s2));
    }

    fn set_less_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, set_less_than_unsigned_imm(d, s1, s2));
    }

    fn set_greater_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, set_greater_than_unsigned_imm(d, s1, s2));
    }

    fn set_less_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, set_less_than_signed_imm(d, s1, s2));
    }

    fn set_greater_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, set_greater_than_signed_imm(d, s1, s2));
    }

    fn shift_logical_right_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, shift_logical_right_imm_32(d, s1, s2));
    }

    fn shift_logical_right_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        emit!(self, shift_logical_right_imm_alt_32(d, s2, s1));
    }

    fn shift_arithmetic_right_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_imm_32(d, s1, s2));
    }

    fn shift_arithmetic_right_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_imm_alt_32(d, s2, s1));
    }

    fn shift_logical_left_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, shift_logical_left_imm_32(d, s1, s2));
    }

    fn shift_logical_left_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        emit!(self, shift_logical_left_imm_alt_32(d, s2, s1));
    }

    fn shift_logical_right_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, shift_logical_right_imm_64(d, s1, s2));
    }

    fn shift_logical_right_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        emit!(self, shift_logical_right_imm_alt_64(d, s2, s1));
    }

    fn shift_arithmetic_right_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_imm_64(d, s1, s2));
    }

    fn shift_arithmetic_right_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_imm_alt_64(d, s2, s1));
    }

    fn shift_logical_left_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, shift_logical_left_imm_64(d, s1, s2));
    }

    fn shift_logical_left_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        emit!(self, shift_logical_left_imm_alt_64(d, s2, s1));
    }

    fn or_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, or_imm(d, s1, s2));
    }

    fn and_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, and_imm(d, s1, s2));
    }

    fn xor_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, xor_imm(d, s1, s2));
    }

    fn load_imm(&mut self, dst: RawReg, imm: i32) -> Self::ReturnTy {
        emit!(self, load_imm(dst, imm));
    }

    fn load_imm64(&mut self, dst: RawReg, imm: u64) -> Self::ReturnTy {
        emit!(
            self,
            load_imm64(dst, cast(imm).truncate_to_u32(), cast(imm >> 32).truncate_to_u32())
        );
    }

    fn move_reg(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        emit!(self, move_reg(d, s));
    }

    fn count_leading_zero_bits_32(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        emit!(self, count_leading_zero_bits_32(d, s));
    }

    fn count_leading_zero_bits_64(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, count_leading_zero_bits_64(d, s));
    }

    fn count_trailing_zero_bits_32(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        emit!(self, count_trailing_zero_bits_32(d, s));
    }

    fn count_trailing_zero_bits_64(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, count_trailing_zero_bits_64(d, s));
    }

    fn count_set_bits_32(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        emit!(self, count_set_bits_32(d, s));
    }

    fn count_set_bits_64(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, count_set_bits_64(d, s));
    }

    fn sign_extend_8(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, sign_extend_8_64(d, s));
        } else {
            emit!(self, sign_extend_8_32(d, s));
        }
    }

    fn sign_extend_16(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, sign_extend_16_64(d, s));
        } else {
            emit!(self, sign_extend_16_32(d, s));
        }
    }

    fn zero_extend_16(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, zero_extend_16_64(d, s));
        } else {
            emit!(self, zero_extend_16_32(d, s));
        }
    }

    fn reverse_byte(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, reverse_byte_64(d, s));
        } else {
            emit!(self, reverse_byte_32(d, s));
        }
    }

    fn cmov_if_zero(&mut self, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        emit!(self, cmov_if_zero(d, s, c));
    }

    fn cmov_if_zero_imm(&mut self, d: RawReg, c: RawReg, s: i32) -> Self::ReturnTy {
        emit!(self, cmov_if_zero_imm(d, c, s));
    }

    fn cmov_if_not_zero(&mut self, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        emit!(self, cmov_if_not_zero(d, s, c));
    }

    fn cmov_if_not_zero_imm(&mut self, d: RawReg, c: RawReg, s: i32) -> Self::ReturnTy {
        emit!(self, cmov_if_not_zero_imm(d, c, s));
    }

    fn rotate_right_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, rotate_right_imm_32(d, s1, s2));
    }

    fn rotate_right_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        emit!(self, rotate_right_imm_alt_32(d, s2, s1));
    }

    fn rotate_right_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rotate_right_imm_64(d, s1, s2));
    }

    fn rotate_right_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rotate_right_imm_alt_64(d, s2, s1));
    }

    fn add_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, add_imm_64(d, s1, s2));
    }

    fn add_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        emit!(self, add_imm_32(d, s1, s2));
    }

    fn store_imm_u8(&mut self, offset: i32, value: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_u8(self.program_counter, offset, value));
    }

    fn store_imm_u16(&mut self, offset: i32, value: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_u16(self.program_counter, offset, value));
    }

    fn store_imm_u32(&mut self, offset: i32, value: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_u32(self.program_counter, offset, value));
    }

    fn store_imm_u64(&mut self, offset: i32, value: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, store_imm_u64(self.program_counter, offset, value));
    }

    fn store_imm_indirect_u8(&mut self, base: RawReg, offset: i32, value: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_indirect_u8(self.program_counter, base, offset, value));
    }

    fn store_imm_indirect_u16(&mut self, base: RawReg, offset: i32, value: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_indirect_u16(self.program_counter, base, offset, value));
    }

    fn store_imm_indirect_u32(&mut self, base: RawReg, offset: i32, value: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_indirect_u32(self.program_counter, base, offset, value));
    }

    fn store_imm_indirect_u64(&mut self, base: RawReg, offset: i32, value: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, store_imm_indirect_u64(self.program_counter, base, offset, value));
    }

    fn store_indirect_u8(&mut self, src: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_indirect_u8(self.program_counter, src, base, offset));
    }

    fn store_indirect_u16(&mut self, src: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_indirect_u16(self.program_counter, src, base, offset));
    }

    fn store_indirect_u32(&mut self, src: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_indirect_u32(self.program_counter, src, base, offset));
    }

    fn store_indirect_u64(&mut self, src: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, store_indirect_u64(self.program_counter, src, base, offset));
    }

    fn store_u8(&mut self, src: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_u8(self.program_counter, src, offset));
    }

    fn store_u16(&mut self, src: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_u16(self.program_counter, src, offset));
    }

    fn store_u32(&mut self, src: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, store_u32(self.program_counter, src, offset));
    }

    fn store_u64(&mut self, src: RawReg, offset: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, store_u64(self.program_counter, src, offset));
    }

    fn load_u8(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, load_u8(self.program_counter, dst, offset));
    }

    fn load_i8(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, load_i8(self.program_counter, dst, offset));
    }

    fn load_u16(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, load_u16(self.program_counter, dst, offset));
    }

    fn load_i16(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, load_i16(self.program_counter, dst, offset));
    }

    fn load_i32(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, load_i32(self.program_counter, dst, offset));
    }

    fn load_u32(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, load_u32(self.program_counter, dst, offset));
    }

    fn load_u64(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, load_u64(self.program_counter, dst, offset));
    }

    fn load_indirect_u8(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, load_indirect_u8(self.program_counter, dst, base, offset));
    }

    fn load_indirect_i8(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, load_indirect_i8(self.program_counter, dst, base, offset));
    }

    fn load_indirect_u16(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, load_indirect_u16(self.program_counter, dst, base, offset));
    }

    fn load_indirect_i16(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, load_indirect_i16(self.program_counter, dst, base, offset));
    }

    fn load_indirect_i32(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        emit_load_store!(self, load_indirect_i32(self.program_counter, dst, base, offset));
    }

    fn load_indirect_u32(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, load_indirect_u32(self.program_counter, dst, base, offset));
    }

    fn load_indirect_u64(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, load_indirect_u64(self.program_counter, dst, base, offset));
    }

    fn branch_less_unsigned(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_unsigned, s1, s2, i);
    }

    fn branch_less_unsigned_imm(&mut self, s1: RawReg, s2: i32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_unsigned_imm, s1, s2, i);
    }

    fn branch_less_signed(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_signed, s1, s2, i);
    }

    fn branch_less_signed_imm(&mut self, s1: RawReg, s2: i32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_signed_imm, s1, s2, i);
    }

    fn branch_eq(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_eq, s1, s2, i);
    }

    fn branch_eq_imm(&mut self, s1: RawReg, s2: i32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_eq_imm, s1, s2, i);
    }

    fn branch_not_eq(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_not_eq, s1, s2, i);
    }

    fn branch_not_eq_imm(&mut self, s1: RawReg, s2: i32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_not_eq_imm, s1, s2, i);
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_unsigned, s1, s2, i);
    }

    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: i32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_unsigned_imm, s1, s2, i);
    }

    fn branch_greater_or_equal_signed(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_signed, s1, s2, i);
    }

    fn branch_greater_or_equal_signed_imm(&mut self, s1: RawReg, s2: i32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_signed_imm, s1, s2, i);
    }

    fn branch_less_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: i32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_or_equal_unsigned_imm, s1, s2, i);
    }

    fn branch_less_or_equal_signed_imm(&mut self, s1: RawReg, s2: i32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_or_equal_signed_imm, s1, s2, i);
    }

    fn branch_greater_unsigned_imm(&mut self, s1: RawReg, s2: i32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_unsigned_imm, s1, s2, i);
    }

    fn branch_greater_signed_imm(&mut self, s1: RawReg, s2: i32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_signed_imm, s1, s2, i);
    }

    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        emit!(self, unresolved_jump(self.program_counter, ProgramCounter(target)));
    }

    fn jump_indirect(&mut self, base: RawReg, offset: i32) -> Self::ReturnTy {
        emit!(self, jump_indirect(self.program_counter, base, offset));
    }

    fn load_imm_and_jump(&mut self, dst: RawReg, imm: i32, target: u32) -> Self::ReturnTy {
        emit!(self, unresolved_load_imm_and_jump(self.program_counter, dst, imm, target));
    }

    fn load_imm_and_jump_indirect(&mut self, ra: RawReg, base: RawReg, value: i32, offset: i32) -> Self::ReturnTy {
        emit!(self, load_imm_and_jump_indirect(self.program_counter, ra, base, value, offset));
    }
}
