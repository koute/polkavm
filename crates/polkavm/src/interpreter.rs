use crate::api::{BackendAccess, ExecutionConfig, MemoryAccessError, Module, OnHostcall};
use crate::error::{bail, Error};
use core::mem::MaybeUninit;
use polkavm_common::abi::VM_ADDR_RETURN_TO_HOST;
use polkavm_common::error::Trap;
use polkavm_common::init::GuestProgramInit;
use polkavm_common::program::{InstructionVisitor, Opcode, Reg};
use polkavm_common::utils::{byte_slice_init, Access, AsUninitSliceMut};

type ExecutionError<E = core::convert::Infallible> = polkavm_common::error::ExecutionError<E>;

pub(crate) struct InterpretedModule {
    ro_data: Vec<u8>,
    rw_data: Vec<u8>,
}

impl InterpretedModule {
    pub fn new(init: GuestProgramInit) -> Result<Self, Error> {
        let memory_config = init.memory_config().map_err(Error::from_static_str)?;
        let mut ro_data: Vec<_> = init.ro_data().into();
        ro_data.resize(memory_config.ro_data_size() as usize, 0);

        Ok(InterpretedModule {
            ro_data,
            rw_data: init.rw_data().into(),
        })
    }
}

pub(crate) type OnSetReg<'a> = &'a mut dyn FnMut(Reg, u32) -> Result<(), Trap>;
pub(crate) type OnStore<'a> = &'a mut dyn for<'r> FnMut(u32, &'r [u8]) -> Result<(), Trap>;

#[derive(Default)]
pub(crate) struct InterpreterContext<'a> {
    on_hostcall: Option<OnHostcall<'a>>,
    on_set_reg: Option<OnSetReg<'a>>,
    on_store: Option<OnStore<'a>>,
}

impl<'a> InterpreterContext<'a> {
    pub fn set_on_hostcall(&mut self, on_hostcall: OnHostcall<'a>) {
        self.on_hostcall = Some(on_hostcall);
    }

    pub fn set_on_set_reg(&mut self, on_set_reg: OnSetReg<'a>) {
        self.on_set_reg = Some(on_set_reg);
    }

    pub fn set_on_store(&mut self, on_store: OnStore<'a>) {
        self.on_store = Some(on_store);
    }
}

pub(crate) struct InterpretedInstance {
    module: Module,
    heap: Vec<u8>,
    stack: Vec<u8>,
    regs: [u32; Reg::ALL_NON_ZERO.len() + 1],
    pc: u32,
    return_to_host: bool,
    cycle_counter: u64,
}

impl InterpretedInstance {
    pub fn new(module: Module) -> Result<Self, Error> {
        if module.interpreted_module().is_none() {
            bail!("an interpreter cannot be created from the given module")
        }

        let mut heap = Vec::new();
        let mut stack = Vec::new();

        heap.reserve_exact(module.memory_config().heap_size() as usize);
        stack.reserve_exact(module.memory_config().stack_size() as usize);

        let mut interpreter = Self {
            heap,
            stack,
            module,
            regs: [0; Reg::ALL_NON_ZERO.len() + 1],
            pc: VM_ADDR_RETURN_TO_HOST,
            return_to_host: true,
            cycle_counter: 0,
        };

        interpreter.reset_memory();
        Ok(interpreter)
    }

    pub fn call(&mut self, export_index: usize, on_hostcall: OnHostcall, config: &ExecutionConfig) -> Result<(), ExecutionError<Error>> {
        let mut ctx = InterpreterContext::default();
        ctx.set_on_hostcall(on_hostcall);
        self.prepare_for_call(export_index, config);

        let result = self.run(ctx);
        if config.reset_memory_after_execution {
            self.reset_memory();
        }

        result
    }

    pub fn run(&mut self, ctx: InterpreterContext) -> Result<(), ExecutionError<Error>> {
        let mut visitor = Visitor { inner: self, ctx };
        loop {
            visitor.inner.cycle_counter += 1;
            let Some(instruction) = visitor.inner.module.instructions().get(visitor.inner.pc as usize).copied() else {
                return Err(ExecutionError::Trap(Default::default()));
            };

            let result: Result<(), ExecutionError<core::convert::Infallible>> = instruction.visit(&mut visitor);
            if let Err(error) = result {
                match error {
                    ExecutionError::Trap(trap) => return Err(ExecutionError::Trap(trap)),
                    ExecutionError::Error(_) => unreachable!(),
                }
            }

            if visitor.inner.return_to_host {
                break;
            }
        }

        Ok(())
    }

    pub fn reset_memory(&mut self) {
        let interpreted_module = self.module.interpreted_module().unwrap();
        self.heap.clear();
        self.heap.extend_from_slice(&interpreted_module.rw_data);
        self.heap.resize(self.module.memory_config().heap_size() as usize, 0);
        self.stack.clear();
        self.stack.resize(self.module.memory_config().stack_size() as usize, 0);
    }

    pub fn prepare_for_call(&mut self, export_index: usize, config: &ExecutionConfig) {
        // TODO: If this function becomes public then this needs to return an error.
        let address = self
            .module
            .get_export(export_index)
            .expect("internal error: invalid export index")
            .address();
        let target_pc = self
            .module
            .instruction_by_jump_target(address)
            .expect("internal error: invalid export address");

        self.return_to_host = false;
        self.regs[1..].copy_from_slice(&config.initial_regs);
        self.pc = target_pc;
    }

    pub fn step_once(&mut self, ctx: InterpreterContext) -> Result<(), ExecutionError> {
        self.cycle_counter += 1;
        let Some(instruction) = self.module.instructions().get(self.pc as usize).copied() else {
            return Err(ExecutionError::Trap(Default::default()));
        };

        let mut visitor = Visitor { inner: self, ctx };

        instruction.visit(&mut visitor)
    }

    pub fn access(&mut self) -> InterpretedAccess {
        InterpretedAccess { instance: self }
    }

    fn get_memory_slice(&self, address: u32, length: u32) -> Option<&[u8]> {
        let memory_config = self.module.memory_config();
        let (range, memory) = if memory_config.ro_data_range().contains(&address) {
            let module = self.module.interpreted_module().unwrap();
            (memory_config.ro_data_range(), &module.ro_data)
        } else if memory_config.heap_range().contains(&address) {
            (memory_config.heap_range(), &self.heap)
        } else if memory_config.stack_range().contains(&address) {
            (memory_config.stack_range(), &self.stack)
        } else {
            return None;
        };

        let offset = address - range.start;
        memory.get(offset as usize..offset as usize + length as usize)
    }

    fn get_memory_slice_mut(&mut self, address: u32, length: u32) -> Option<&mut [u8]> {
        let memory_config = self.module.memory_config();
        let (range, memory_slice) = if memory_config.heap_range().contains(&address) {
            (memory_config.heap_range(), &mut self.heap)
        } else if memory_config.stack_range().contains(&address) {
            (memory_config.stack_range(), &mut self.stack)
        } else {
            return None;
        };

        let offset = (address - range.start) as usize;
        memory_slice.get_mut(offset..offset + length as usize)
    }

    fn next_instruction_jump_target(&self) -> Option<u32> {
        let inst = self.module.instructions().get(self.pc as usize + 1).copied()?;
        if inst.raw_op() == Opcode::jump_target as u8 {
            Some(inst.raw_imm_or_reg().checked_mul(4)?)
        } else {
            None
        }
    }
}

pub struct InterpretedAccess<'a> {
    instance: &'a mut InterpretedInstance,
}

impl<'a> Access<'a> for InterpretedAccess<'a> {
    type Error = MemoryAccessError<&'static str>;

    fn get_reg(&self, reg: Reg) -> u32 {
        if reg == Reg::Zero {
            return 0;
        }

        self.instance.regs[reg as usize]
    }

    fn set_reg(&mut self, reg: Reg, value: u32) {
        if reg == Reg::Zero {
            return;
        }

        self.instance.regs[reg as usize] = value;
    }

    fn read_memory_into_slice<'slice, T>(&self, address: u32, buffer: &'slice mut T) -> Result<&'slice mut [u8], Self::Error>
    where
        T: ?Sized + AsUninitSliceMut,
    {
        let buffer: &mut [MaybeUninit<u8>] = buffer.as_uninit_slice_mut();
        let Some(slice) = self.instance.get_memory_slice(address, buffer.len() as u32) else {
            return Err(MemoryAccessError {
                address,
                length: buffer.len() as u64,
                error: "out of range read",
            });
        };

        Ok(byte_slice_init(buffer, slice))
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
        let Some(slice) = self.instance.get_memory_slice_mut(address, data.len() as u32) else {
            return Err(MemoryAccessError {
                address,
                length: data.len() as u64,
                error: "out of range write",
            });
        };

        slice.copy_from_slice(data);
        Ok(())
    }

    fn program_counter(&self) -> Option<u32> {
        Some(self.instance.pc)
    }

    fn native_program_counter(&self) -> Option<u64> {
        None
    }
}

struct Visitor<'a, 'b> {
    inner: &'a mut InterpretedInstance,
    ctx: InterpreterContext<'b>,
}

impl<'a, 'b> Visitor<'a, 'b> {
    fn set(&mut self, dst: Reg, value: u32) -> Result<(), ExecutionError> {
        if dst == Reg::Zero {
            return Ok(());
        }

        self.inner.regs[dst as usize] = value;
        log::trace!("{dst} = 0x{value:x}");

        if let Some(on_set_reg) = self.ctx.on_set_reg.as_mut() {
            let result = (on_set_reg)(dst, value);
            Ok(result.map_err(ExecutionError::Trap)?)
        } else {
            Ok(())
        }
    }

    fn set3(&mut self, dst: Reg, s1: Reg, s2: Reg, callback: impl Fn(u32, u32) -> u32) -> Result<(), ExecutionError> {
        let s1 = self.inner.regs[s1 as usize];
        let s2 = self.inner.regs[s2 as usize];
        self.set(dst, callback(s1, s2))?;
        self.inner.pc += 1;
        Ok(())
    }

    fn set2(&mut self, dst: Reg, src: Reg, callback: impl Fn(u32) -> u32) -> Result<(), ExecutionError> {
        let src = self.inner.regs[src as usize];
        self.set(dst, callback(src))?;
        self.inner.pc += 1;
        Ok(())
    }

    fn branch(&mut self, s1: Reg, s2: Reg, target: u32, callback: impl Fn(u32, u32) -> bool) -> Result<(), ExecutionError> {
        let s1 = self.inner.regs[s1 as usize];
        let s2 = self.inner.regs[s2 as usize];
        if callback(s1, s2) {
            self.inner.pc = self.inner.module.instruction_by_jump_target(target).unwrap();
        // TODO
        } else {
            self.inner.pc += 1;
        }

        Ok(())
    }

    fn load<T: LoadTy>(&mut self, dst: Reg, base: Reg, offset: u32) -> Result<(), ExecutionError> {
        assert!(core::mem::size_of::<T>() >= 1);

        let address = self.inner.regs[base as usize].wrapping_add(offset);
        let length = core::mem::size_of::<T>() as u32;
        let Some(slice) = self.inner.get_memory_slice(address, length) else {
            log::debug!(
                "Load of {length} bytes from 0x{address:x} failed! (pc = #{pc}, cycle = {cycle})",
                pc = self.inner.pc,
                cycle = self.inner.cycle_counter
            );
            self.inner.module.debug_print_location(log::Level::Debug, self.inner.pc);
            return Err(ExecutionError::Trap(Default::default()));
        };

        log::trace!("{dst} = {kind} [0x{address:x}]", kind = std::any::type_name::<T>());

        let value = T::from_slice(slice);
        self.set(dst, value)?;
        self.inner.pc += 1;
        Ok(())
    }

    fn store<T: StoreTy>(&mut self, src: Reg, base: Reg, offset: u32) -> Result<(), ExecutionError> {
        assert!(core::mem::size_of::<T>() >= 1);

        let value = self.inner.regs[src as usize];
        let address = self.inner.regs[base as usize].wrapping_add(offset);
        let length = core::mem::size_of::<T>() as u32;
        let Some(slice) = self.inner.get_memory_slice_mut(address, length) else {
            log::debug!(
                "Store of {length} bytes to 0x{address:x} failed! (pc = #{pc}, cycle = {cycle})",
                pc = self.inner.pc,
                cycle = self.inner.cycle_counter
            );
            self.inner.module.debug_print_location(log::Level::Debug, self.inner.pc);
            return Err(ExecutionError::Trap(Default::default()));
        };

        log::trace!("{kind} [0x{address:x}] = {src} = 0x{value:x}", kind = std::any::type_name::<T>());

        let value = T::into_bytes(value);
        slice.copy_from_slice(value.as_ref());

        if let Some(on_store) = self.ctx.on_store.as_mut() {
            (on_store)(address, value.as_ref()).map_err(ExecutionError::Trap)?;
        }

        self.inner.pc += 1;
        Ok(())
    }
}

trait LoadTy {
    fn from_slice(xs: &[u8]) -> u32;
}

impl LoadTy for u8 {
    fn from_slice(xs: &[u8]) -> u32 {
        xs[0] as u32
    }
}

impl LoadTy for i8 {
    fn from_slice(xs: &[u8]) -> u32 {
        xs[0] as i8 as i32 as u32
    }
}

impl LoadTy for u16 {
    fn from_slice(xs: &[u8]) -> u32 {
        u16::from_le_bytes([xs[0], xs[1]]) as u32
    }
}

impl LoadTy for i16 {
    fn from_slice(xs: &[u8]) -> u32 {
        i16::from_le_bytes([xs[0], xs[1]]) as i32 as u32
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
    fn into_bytes(value: u32) -> Self::Array {
        (value as u8).to_le_bytes()
    }
}

impl StoreTy for u16 {
    type Array = [u8; 2];
    fn into_bytes(value: u32) -> Self::Array {
        (value as u16).to_le_bytes()
    }
}

impl StoreTy for u32 {
    type Array = [u8; 4];
    fn into_bytes(value: u32) -> Self::Array {
        value.to_le_bytes()
    }
}

fn divu(s1: u32, s2: u32) -> u32 {
    if s2 == 0 {
        u32::MAX
    } else {
        s1 / s2
    }
}

fn remu(s1: u32, s2: u32) -> u32 {
    if s2 == 0 {
        s1
    } else {
        s1 % s2
    }
}

fn div(s1: i32, s2: i32) -> i32 {
    if s2 == 0 {
        -1
    } else if s1 == i32::MIN && s2 == -1 {
        s1
    } else {
        s1 / s2
    }
}

fn rem(s1: i32, s2: i32) -> i32 {
    if s2 == 0 {
        s1
    } else if s1 == i32::MIN && s2 == -1 {
        0
    } else {
        s1 % s2
    }
}

impl<'a, 'b> InstructionVisitor for Visitor<'a, 'b> {
    type ReturnTy = Result<(), ExecutionError>;

    fn trap(&mut self) -> Self::ReturnTy {
        Err(ExecutionError::Trap(Default::default()))
    }

    fn jump_target(&mut self, _: u32) -> Self::ReturnTy {
        self.inner.pc += 1;
        Ok(())
    }

    fn ecalli(&mut self, imm: u32) -> Self::ReturnTy {
        if let Some(on_hostcall) = self.ctx.on_hostcall.as_mut() {
            let access = BackendAccess::Interpreted(self.inner.access());
            (on_hostcall)(imm as u64, access).map_err(ExecutionError::Trap)?;
            self.inner.pc += 1;
            Ok(())
        } else {
            log::debug!("Hostcall called without any hostcall handler set!");
            Err(ExecutionError::Trap(Default::default()))
        }
    }

    fn set_less_than_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| (s1 < s2) as u32)
    }

    fn set_less_than_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| ((s1 as i32) < (s2 as i32)) as u32)
    }

    fn shift_logical_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1.wrapping_shr(s2))
    }

    fn shift_arithmetic_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| ((s1 as i32) >> s2) as u32)
    }

    fn shift_logical_left(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1.wrapping_shl(s2))
    }

    fn xor(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1 ^ s2)
    }

    fn and(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1 & s2)
    }

    fn or(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1 | s2)
    }

    fn add(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1.wrapping_add(s2))
    }

    fn sub(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1.wrapping_sub(s2))
    }

    fn mul(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| s1.wrapping_mul(s2))
    }

    fn mul_upper_signed_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| {
            let s1: i32 = s1 as i32;
            let s2: i32 = s2 as i32;
            let s1: i64 = s1 as i64;
            let s2: i64 = s2 as i64;
            ((s1 * s2) >> 32) as u64 as u32
        })
    }

    #[allow(clippy::unnecessary_cast)]
    fn mul_upper_unsigned_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| {
            let s1: u32 = s1;
            let s2: u32 = s2;
            let s1: u64 = s1 as u64;
            let s2: u64 = s2 as u64;
            ((s1 * s2) >> 32) as u64 as u32
        })
    }

    fn mul_upper_signed_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| {
            let s1: i32 = s1 as i32;
            let s2: u32 = s2;
            let s1: i64 = s1 as i64;
            let s2: i64 = s2 as u64 as i64;
            ((s1 * s2) >> 32) as u64 as u32
        })
    }

    fn div_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, divu)
    }

    fn div_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| div(s1 as i32, s2 as i32) as u32)
    }

    fn rem_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, remu)
    }

    fn rem_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set3(d, s1, s2, |s1, s2| rem(s1 as i32, s2 as i32) as u32)
    }

    fn set_less_than_unsigned_imm(&mut self, d: Reg, s: Reg, i: u32) -> Self::ReturnTy {
        self.set2(d, s, |s| (s < i) as u32)
    }

    fn set_less_than_signed_imm(&mut self, d: Reg, s: Reg, i: u32) -> Self::ReturnTy {
        self.set2(d, s, |s| ((s as i32) < (i as i32)) as u32)
    }

    fn shift_logical_right_imm(&mut self, d: Reg, s: Reg, i: u32) -> Self::ReturnTy {
        self.set2(d, s, |s| s.wrapping_shr(i))
    }

    fn shift_arithmetic_right_imm(&mut self, d: Reg, s: Reg, i: u32) -> Self::ReturnTy {
        self.set2(d, s, |s| ((s as i32) >> i) as u32)
    }

    fn shift_logical_left_imm(&mut self, d: Reg, s: Reg, i: u32) -> Self::ReturnTy {
        self.set2(d, s, |s| s.wrapping_shl(i))
    }

    fn or_imm(&mut self, d: Reg, s: Reg, i: u32) -> Self::ReturnTy {
        self.set2(d, s, |s| s | i)
    }

    fn and_imm(&mut self, d: Reg, s: Reg, i: u32) -> Self::ReturnTy {
        self.set2(d, s, |s| s & i)
    }

    fn xor_imm(&mut self, d: Reg, s: Reg, i: u32) -> Self::ReturnTy {
        self.set2(d, s, |s| s ^ i)
    }

    fn add_imm(&mut self, d: Reg, s: Reg, i: u32) -> Self::ReturnTy {
        self.set2(d, s, |s| s.wrapping_add(i))
    }

    fn store_u8(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store::<u8>(src, base, offset)
    }

    fn store_u16(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store::<u16>(src, base, offset)
    }

    fn store_u32(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store::<u32>(src, base, offset)
    }

    fn load_u8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load::<u8>(dst, base, offset)
    }

    fn load_i8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load::<i8>(dst, base, offset)
    }

    fn load_u16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load::<u16>(dst, base, offset)
    }

    fn load_i16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load::<i16>(dst, base, offset)
    }

    fn load_u32(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load::<u32>(dst, base, offset)
    }

    fn branch_less_unsigned(&mut self, s1: Reg, s2: Reg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 < s2)
    }

    fn branch_less_signed(&mut self, s1: Reg, s2: Reg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| (s1 as i32) < (s2 as i32))
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: Reg, s2: Reg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 >= s2)
    }

    fn branch_greater_or_equal_signed(&mut self, s1: Reg, s2: Reg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| (s1 as i32) >= (s2 as i32))
    }

    fn branch_eq(&mut self, s1: Reg, s2: Reg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 == s2)
    }

    fn branch_not_eq(&mut self, s1: Reg, s2: Reg, i: u32) -> Self::ReturnTy {
        self.branch(s1, s2, i, |s1, s2| s1 != s2)
    }

    fn jump_and_link_register(&mut self, ra: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        let offset = offset.wrapping_mul(4);
        let target = self.inner.regs[base as usize].wrapping_add(offset);

        if ra != Reg::Zero {
            if let Some(return_target) = self.inner.next_instruction_jump_target() {
                self.set(ra, return_target)?;
            } else {
                log::error!("Found a jump instruction which is not followed by a jump target instruction!");
                return Err(ExecutionError::Trap(Default::default()));
            }
        }

        if target % 4 != 0 {
            log::error!("Found a jump with a misaligned target: target = {target}");
            return Err(ExecutionError::Trap(Default::default()));
        }

        if target == VM_ADDR_RETURN_TO_HOST {
            self.inner.return_to_host = true;
            return Ok(());
        }

        let Some(next_pc) = self.inner.module.instruction_by_jump_target(target / 4) else {
            log::debug!("Return to 0x{target:x} failed: no such jump target");
            return Err(ExecutionError::Trap(Default::default()));
        };

        self.inner.pc = next_pc;
        Ok(())
    }
}

#[test]
fn test_div_rem() {
    assert_eq!(divu(10, 2), 5);
    assert_eq!(divu(10, 0), u32::MAX);

    assert_eq!(div(10, 2), 5);
    assert_eq!(div(10, 0), -1);
    assert_eq!(div(i32::MIN, -1), i32::MIN);

    assert_eq!(remu(10, 9), 1);
    assert_eq!(remu(10, 5), 0);
    assert_eq!(remu(10, 0), 10);

    assert_eq!(rem(10, 9), 1);
    assert_eq!(rem(10, 5), 0);
    assert_eq!(rem(10, 0), 10);
    assert_eq!(rem(i32::MIN, -1), 0);
}
