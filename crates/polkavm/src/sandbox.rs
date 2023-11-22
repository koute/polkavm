use std::borrow::Cow;

use polkavm_common::{
    abi::VM_PAGE_SIZE,
    error::{ExecutionError, Trap},
    init::GuestProgramInit,
    program::Reg,
    zygote::{
        AddressTable,
        SandboxMemoryConfig,
        VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION,
        VM_RPC_FLAG_RECONFIGURE, VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION,
    },
    utils::{Access, Gas}
};

use crate::api::BackendAccess;
use crate::config::{GasMeteringKind, SandboxKind};

macro_rules! get_field_offset {
    ($struct:expr, |$struct_ident:ident| $get_field:expr) => {{
        let $struct_ident = $struct;
        let struct_ref = &$struct_ident;
        let field_ref = $get_field;
        let struct_addr = struct_ref as *const _ as usize;
        let field_addr = field_ref as *const _ as usize;
        field_addr - struct_addr
    }}
}

pub mod generic;

#[cfg(target_os = "linux")]
pub mod linux;

// This is literally the only thing we need from `libc` on Linux, so instead of including
// the whole crate let's just define these ourselves.
#[cfg(target_os = "linux")]
const _SC_PAGESIZE: core::ffi::c_int = 30;

#[cfg(target_os = "linux")]
extern "C" {
    fn sysconf(name: core::ffi::c_int) -> core::ffi::c_long;
}

#[cfg(not(target_os = "linux"))]
use libc::{sysconf, _SC_PAGESIZE};

pub(crate) fn get_native_page_size() -> usize {
    // TODO: Cache this?

    // SAFETY: This function has no safety invariants and should be always safe to call.
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

pub(crate) fn assert_native_page_size() {
    let native_page_size = get_native_page_size();
    assert!(
        native_page_size <= VM_PAGE_SIZE as usize && VM_PAGE_SIZE as usize % native_page_size == 0,
        "unsupported native page size: {}",
        native_page_size
    );
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct OutOfGas;

fn get_gas_remaining(raw_gas: u64) -> Result<Gas, OutOfGas> {
    Gas::new(raw_gas).ok_or(OutOfGas)
}

#[test]
fn test_get_gas_remaining() {
    assert_eq!(get_gas_remaining(0), Ok(Gas::new(0).unwrap()));
    assert_eq!(get_gas_remaining(1), Ok(Gas::new(1).unwrap()));
    assert_eq!(get_gas_remaining((-1_i64) as u64), Err(OutOfGas));
    assert_eq!(get_gas_remaining(Gas::MIN.get()), Ok(Gas::MIN));
    assert_eq!(get_gas_remaining(Gas::MAX.get()), Ok(Gas::MAX));

    // We should never have such gas values, but test it anyway.
    assert_eq!(get_gas_remaining(Gas::MAX.get() + 1), Err(OutOfGas));
}

pub trait SandboxConfig: Default {
    fn enable_logger(&mut self, value: bool);
}

pub trait SandboxAddressSpace {
    fn native_code_address(&self) -> u64;
}

pub trait SandboxProgram: Clone {
    fn machine_code(&self) -> Cow<[u8]>;
}

pub(crate) trait Sandbox: Sized {
    const KIND: SandboxKind;

    type Access<'r>: Access<'r> + Into<BackendAccess<'r>> where Self: 'r;
    type Config: SandboxConfig;
    type Error: core::fmt::Debug + core::fmt::Display;
    type Program: SandboxProgram;
    type AddressSpace: SandboxAddressSpace;

    fn reserve_address_space() -> Result<Self::AddressSpace, Self::Error>;
    fn prepare_program(init: SandboxProgramInit, address_space: Self::AddressSpace, gas_metering: Option<GasMeteringKind>) -> Result<Self::Program, Self::Error>;
    fn spawn(config: &Self::Config) -> Result<Self, Self::Error>;
    fn execute(&mut self, args: ExecuteArgs<Self>) -> Result<(), ExecutionError<Self::Error>>;
    fn access(&'_ mut self) -> Self::Access<'_>;
    fn pid(&self) -> Option<u32>;
    fn address_table() -> AddressTable;
    fn vmctx_regs_offset() -> usize;
    fn vmctx_gas_offset() -> usize;
    fn gas_remaining_impl(&self) -> Result<Option<Gas>, OutOfGas>;
}

pub(crate) type OnHostcall<'a, T> = &'a mut dyn for<'r> FnMut(u32, <T as Sandbox>::Access<'r>) -> Result<(), Trap>;

#[derive(Copy, Clone)]
pub struct SandboxProgramInit<'a> {
    guest_init: GuestProgramInit<'a>,
    code: &'a [u8],
    jump_table: &'a [u8],
    sysreturn_address: u64,
}

impl<'a> Default for SandboxProgramInit<'a> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<'a> core::ops::Deref for SandboxProgramInit<'a> {
    type Target = GuestProgramInit<'a>;
    fn deref(&self) -> &Self::Target {
        &self.guest_init
    }
}

impl<'a> SandboxProgramInit<'a> {
    pub fn new(guest_init: GuestProgramInit<'a>) -> Self {
        Self {
            guest_init,
            code: &[],
            jump_table: &[],
            sysreturn_address: 0,
        }
    }

    pub fn with_code(mut self, code: &'a [u8]) -> Self {
        self.code = code;
        self
    }

    pub fn with_jump_table(mut self, jump_table: &'a [u8]) -> Self {
        self.jump_table = jump_table;
        self
    }

    pub fn with_sysreturn_address(mut self, address: u64) -> Self {
        self.sysreturn_address = address;
        self
    }

    fn memory_config(&self, native_page_size: usize) -> Result<SandboxMemoryConfig, &'static str> {
        let mut config = SandboxMemoryConfig::empty();
        config.set_guest_config(self.guest_init.memory_config()?);
        config.set_code_size(native_page_size, self.code.len())?;
        config.set_jump_table_size(native_page_size, self.jump_table.len())?;

        Ok(config)
    }
}

pub(crate) struct ExecuteArgs<'a, T> where T: Sandbox + 'a {
    rpc_address: u64,
    rpc_flags: u32,
    program: Option<&'a T::Program>,
    on_hostcall: Option<OnHostcall<'a, T>>,
    initial_regs: &'a [u32],
    gas: Option<Gas>,
}

impl<'a, T> Default for ExecuteArgs<'a, T> where T: Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T> ExecuteArgs<'a, T> where T: Sandbox {
    #[inline]
    pub fn new() -> Self {
        static EMPTY_REGS: &[u32; Reg::ALL_NON_ZERO.len()] = &[0; Reg::ALL_NON_ZERO.len()];
        ExecuteArgs {
            rpc_address: 0,
            rpc_flags: 0,
            program: None,
            on_hostcall: None,
            initial_regs: EMPTY_REGS,
            gas: None,
        }
    }

    #[inline]
    pub fn set_program(&mut self, program: &'a T::Program) {
        self.rpc_flags |= VM_RPC_FLAG_RECONFIGURE;
        self.program = Some(program);
    }

    #[inline]
    pub fn set_reset_memory_after_execution(&mut self) {
        self.rpc_flags |= VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION;
    }

    #[inline]
    pub fn set_clear_program_after_execution(&mut self) {
        self.rpc_flags |= VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION;
    }

    #[inline]
    pub fn set_call(&mut self, address: u64) {
        self.rpc_address = address;
    }

    #[inline]
    pub fn set_on_hostcall(&mut self, callback: OnHostcall<'a, T>) {
        self.on_hostcall = Some(callback);
    }

    #[inline]
    pub fn set_initial_regs(&mut self, regs: &'a [u32]) {
        assert_eq!(regs.len(), Reg::ALL_NON_ZERO.len());
        self.initial_regs = regs;
    }

    #[inline]
    pub fn set_gas(&mut self, gas: Gas) {
        self.gas = Some(gas);
    }

    fn get_gas(&self, gas_metering: Option<GasMeteringKind>) -> Option<u64> {
        if self.program.is_none() && self.gas.is_none() && gas_metering.is_some() {
            // Keep whatever value was set there previously.
            return None;
        }

        let gas = self.gas.unwrap_or(Gas::MIN);
        if gas_metering.is_some() {
            Some(gas.get())
        } else {
            Some(0)
        }
    }
}

#[cfg(test)]
macro_rules! sandbox_tests {
    ($sandbox_kind:ident) => {
        mod $sandbox_kind {
            use crate::sandbox::Sandbox as _;
            use crate::sandbox::SandboxConfig as _;
            use crate::sandbox::SandboxAddressSpace as _;
            use crate::sandbox::{SandboxKind, SandboxProgramInit, ExecuteArgs, get_native_page_size};
            use polkavm_assembler::amd64::addr::*;
            use polkavm_assembler::amd64::inst::*;
            use polkavm_assembler::amd64::Reg::*;
            use polkavm_assembler::amd64::{LoadKind, RegSize, Size};
            use polkavm_assembler::Assembler;
            use polkavm_common::init::GuestProgramInit;
            use polkavm_common::utils::Access;
            use polkavm_common::error::ExecutionError;

            use crate::sandbox::$sandbox_kind::{Sandbox, SandboxConfig};

            fn emit_sysreturn(asm: &mut Assembler) {
                asm.push(mov_imm64(rcx, Sandbox::address_table().syscall_return));
                asm.push(jmp(rcx));
            }

            #[test]
            fn spawn_stress_test() {
                let _ = env_logger::try_init();
                let init = GuestProgramInit::new().with_ro_data(&[0x00]).with_bss(1);
                let init = SandboxProgramInit::new(init);

                let mut asm = Assembler::new();
                emit_sysreturn(&mut asm);

                let code = asm.finalize();
                let address_space = Sandbox::reserve_address_space().unwrap();
                let native_code_address = address_space.native_code_address();
                let program = Sandbox::prepare_program(init.with_code(code), address_space, None).unwrap();

                const THREAD_COUNT: usize = 32;
                let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREAD_COUNT));

                let mut threads = Vec::new();
                for _ in 0..THREAD_COUNT {
                    let program = program.clone();
                    let barrier = barrier.clone();
                    let thread = std::thread::spawn(move || {
                        barrier.wait();
                        for _ in 0..32 {
                            let mut args = ExecuteArgs::new();
                            args.set_program(&program);
                            args.set_call(native_code_address);

                            let mut config = SandboxConfig::default();
                            config.enable_logger(true);

                            let mut sandbox = Sandbox::spawn(&config).unwrap();
                            sandbox.execute(args).unwrap();
                        }
                    });
                    threads.push(thread);
                }

                let mut results = Vec::new();
                for thread in threads {
                    results.push(thread.join());
                }

                for result in results {
                    result.unwrap();
                }
            }

            #[test]
            fn basic_execution_works() {
                let _ = env_logger::try_init();

                let init = GuestProgramInit::new().with_ro_data(&[0xaa, 0xbb]).with_bss(1);
                let init = SandboxProgramInit::new(init);

                let mem = init.memory_config(get_native_page_size()).unwrap();
                let mut asm = Assembler::new();
                if Sandbox::KIND != SandboxKind::Generic {
                    asm.push(mov_imm(r15, imm32(0)));
                }

                asm
                    .push(load(LoadKind::U32, rax, reg_indirect(RegSize::R64, r15 + mem.ro_data_address().try_into().unwrap())))
                    .push(store(Size::U8, reg_indirect(RegSize::R64, r15 + i32::try_from(mem.rw_data_address()).unwrap()), rax))
                    .push(store(Size::U16, reg_indirect(RegSize::R64, r15 + (i32::try_from(mem.rw_data_address()).unwrap() + 4)), rax));

                emit_sysreturn(&mut asm);
                let code = asm.finalize();
                let address_space = Sandbox::reserve_address_space().unwrap();
                let native_code_address = address_space.native_code_address();
                let program = Sandbox::prepare_program(init.with_code(code), address_space, None).unwrap();
                let mut args = ExecuteArgs::new();
                args.set_program(&program);
                args.set_call(native_code_address);

                let mut config = SandboxConfig::default();
                config.enable_logger(true);

                let mut sandbox = Sandbox::spawn(&config).unwrap();
                sandbox.execute(args).unwrap();

                assert_eq!(
                    sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 8).unwrap(),
                    [0xaa, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0x00, 0x00,]
                );
            }

            #[test]
            fn program_memory_can_be_reused_and_cleared() {
                let _ = env_logger::try_init();

                let init = GuestProgramInit::new().with_bss(1);
                let init = SandboxProgramInit::new(init);
                let mem = init.memory_config(get_native_page_size()).unwrap();
                let mut asm = Assembler::new();
                if Sandbox::KIND != SandboxKind::Generic {
                    asm.push(mov_imm(r15, imm32(0)));
                }

                asm
                    .push(load(LoadKind::U32, rax, reg_indirect(RegSize::R64, r15 + mem.rw_data_address().try_into().unwrap())))
                    .push(add((rax, imm64(1))))
                    .push(store(Size::U32, reg_indirect(RegSize::R64, r15 + i32::try_from(mem.rw_data_address()).unwrap()), rax));

                emit_sysreturn(&mut asm);
                let code = asm.finalize();
                let address_space = Sandbox::reserve_address_space().unwrap();
                let native_code_address = address_space.native_code_address();
                let program = Sandbox::prepare_program(init.with_code(code), address_space, None).unwrap();

                let mut sandbox = Sandbox::spawn(&Default::default()).unwrap();
                assert!(sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 4).is_err());

                {
                    let mut args = ExecuteArgs::new();
                    args.set_program(&program);
                    sandbox.execute(args).unwrap();
                    assert_eq!(
                        sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 4).unwrap(),
                        [0x00, 0x00, 0x00, 0x00]
                    );
                }

                {
                    let mut args = ExecuteArgs::new();
                    args.set_call(native_code_address);
                    sandbox.execute(args).unwrap();
                    assert_eq!(
                        sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 4).unwrap(),
                        [0x01, 0x00, 0x00, 0x00]
                    );
                }

                {
                    let mut args = ExecuteArgs::new();
                    args.set_call(native_code_address);
                    sandbox.execute(args).unwrap();
                    assert_eq!(
                        sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 4).unwrap(),
                        [0x02, 0x00, 0x00, 0x00]
                    );
                }

                {
                    let mut args = ExecuteArgs::new();
                    args.set_call(native_code_address);
                    args.set_reset_memory_after_execution();
                    sandbox.execute(args).unwrap();
                    assert_eq!(
                        sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 4).unwrap(),
                        [0x00, 0x00, 0x00, 0x00]
                    );
                }

                {
                    let mut args = ExecuteArgs::new();
                    args.set_call(native_code_address);
                    sandbox.execute(args).unwrap();
                    assert_eq!(
                        sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 4).unwrap(),
                        [0x01, 0x00, 0x00, 0x00]
                    );
                }

                {
                    let mut args = ExecuteArgs::new();
                    args.set_clear_program_after_execution();
                    sandbox.execute(args).unwrap();
                    assert!(sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 4).is_err());
                }
            }

            #[test]
            fn out_of_bounds_memory_access_generates_a_trap() {
                let _ = env_logger::try_init();

                let init = GuestProgramInit::new().with_bss(1);
                let init = SandboxProgramInit::new(init);
                let mem = init.memory_config(get_native_page_size()).unwrap();
                let mut asm = Assembler::new();
                if Sandbox::KIND != SandboxKind::Generic {
                    asm.push(mov_imm(r15, imm32(0)));
                }

                asm
                    .push(load(LoadKind::U32, rax, reg_indirect(RegSize::R64, r15 + mem.rw_data_address().try_into().unwrap())))
                    .push(add((rax, imm64(1))))
                    .push(store(Size::U32, reg_indirect(RegSize::R64, r15 + i32::try_from(mem.rw_data_address()).unwrap()), rax))
                    .push(load(LoadKind::U32, rax, reg_indirect(RegSize::R64, r15)));

                emit_sysreturn(&mut asm);
                let code = asm.finalize();
                let address_space = Sandbox::reserve_address_space().unwrap();
                let native_code_address = address_space.native_code_address();
                let program = Sandbox::prepare_program(init.with_code(code), address_space, None).unwrap();

                let mut sandbox = Sandbox::spawn(&Default::default()).unwrap();
                {
                    let mut args = ExecuteArgs::new();
                    args.set_program(&program);
                    args.set_call(native_code_address);
                    match sandbox.execute(args) {
                        Err(ExecutionError::Trap(_)) => {}
                        _ => panic!(),
                    }

                    assert_eq!(
                        sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 4).unwrap(),
                        [0x01, 0x00, 0x00, 0x00]
                    );
                }

                // The VM still works even though it got hit with a SIGSEGV.
                {
                    let mut args = ExecuteArgs::new();
                    args.set_call(native_code_address);
                    match sandbox.execute(args) {
                        Err(ExecutionError::Trap(_)) => {}
                        _ => panic!(),
                    }

                    assert_eq!(
                        sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 4).unwrap(),
                        [0x02, 0x00, 0x00, 0x00]
                    );
                }
            }

            #[test]
            fn divide_by_zero_generates_a_trap() {
                if Sandbox::KIND == SandboxKind::Generic {
                    return;
                }

                let _ = env_logger::try_init();

                let init = GuestProgramInit::new().with_bss(4);
                let init = SandboxProgramInit::new(init);
                let mem = init.memory_config(get_native_page_size()).unwrap();
                let mut asm = Assembler::new();
                asm
                    .push(mov_imm(rdx, imm32(0)))
                    .push(mov_imm(rax, imm32(1)))
                    .push(mov_imm(rcx, imm32(0)))
                    .push(mov_imm(r8, imm32(0x11223344)))
                    .push(store(Size::U32, abs(RegSize::R32, i32::try_from(mem.rw_data_address()).unwrap()), r8))
                    .push(idiv(RegSize::R32, rcx))
                    .push(mov_imm(r8, imm32(0x12345678)))
                    .push(store(Size::U32, abs(RegSize::R32, i32::try_from(mem.rw_data_address()).unwrap()), r8));

                emit_sysreturn(&mut asm);
                let code = asm.finalize();
                let address_space = Sandbox::reserve_address_space().unwrap();
                let native_code_address = address_space.native_code_address();
                let program = Sandbox::prepare_program(init.with_code(code), address_space, None).unwrap();
                let mut sandbox = Sandbox::spawn(&Default::default()).unwrap();

                {
                    let mut args = ExecuteArgs::new();
                    args.set_program(&program);
                    args.set_call(native_code_address);
                    match sandbox.execute(args) {
                        Err(ExecutionError::Trap(_)) => {}
                        _ => panic!(),
                    }

                    assert_eq!(
                        sandbox.access().read_memory_into_new_vec(mem.rw_data_address(), 4).unwrap(),
                        [0x44, 0x33, 0x22, 0x11]
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    sandbox_tests!(linux);
    sandbox_tests!(generic);
}
