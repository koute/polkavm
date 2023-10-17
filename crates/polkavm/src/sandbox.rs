use polkavm_common::{
    abi::VM_PAGE_SIZE,
    error::{ExecutionError, Trap},
    init::GuestProgramInit,
    program::Reg,
    zygote::{
        SandboxMemoryConfig,
        VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION,
        VM_RPC_FLAG_RECONFIGURE, VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION,
    },
    utils::Access
};

use crate::api::BackendAccess;
use crate::config::SandboxKind;

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

pub trait SandboxConfig: Default {
    fn enable_logger(&mut self, value: bool);
}

pub trait SandboxAddressSpace {
    fn native_code_address(&self) -> u64;
}

pub trait Sandbox: Sized {
    const KIND: SandboxKind;

    type Access<'r>: Access<'r> + Into<BackendAccess<'r>> where Self: 'r;
    type Config: SandboxConfig;
    type Error: core::fmt::Debug + core::fmt::Display;
    type Program;
    type AddressSpace: SandboxAddressSpace;

    fn reserve_address_space() -> Result<Self::AddressSpace, Self::Error>;
    fn prepare_program(init: SandboxProgramInit, address_space: Self::AddressSpace) -> Result<Self::Program, Self::Error>;
    fn spawn(config: &Self::Config) -> Result<Self, Self::Error>;
    fn execute(&mut self, args: ExecuteArgs<Self>) -> Result<(), ExecutionError<Self::Error>>;
    fn access(&'_ mut self) -> Self::Access<'_>;
}

pub type OnHostcall<'a, T> = &'a mut dyn for<'r> FnMut(u64, <T as Sandbox>::Access<'r>) -> Result<(), Trap>;

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

pub struct ExecuteArgs<'a, T> where T: Sandbox + 'a {
    rpc_address: u64,
    rpc_flags: u32,
    program: Option<&'a T::Program>,
    on_hostcall: Option<OnHostcall<'a, T>>,
    initial_regs: &'a [u32],
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
}

#[cfg(test)]
macro_rules! sandbox_tests {
    ($sandbox_kind:ident) => {
        mod $sandbox_kind {
            use crate::sandbox::Sandbox as _;
            use crate::sandbox::SandboxConfig as _;
            use crate::sandbox::SandboxAddressSpace as _;
            use crate::sandbox::{SandboxKind, SandboxProgramInit, ExecuteArgs, get_native_page_size};
            use polkavm_assembler::amd64::inst::*;
            use polkavm_assembler::amd64::Reg::*;
            use polkavm_assembler::amd64::{LoadKind, RegSize, StoreKind};
            use polkavm_assembler::Assembler;
            use polkavm_common::init::GuestProgramInit;
            use polkavm_common::utils::Access;
            use polkavm_common::error::ExecutionError;

            use crate::sandbox::$sandbox_kind::{Sandbox, SandboxConfig};

            #[test]
            fn basic_execution_works() {
                let _ = env_logger::try_init();

                let init = GuestProgramInit::new().with_ro_data(&[0xaa, 0xbb]).with_bss(1);
                let init = SandboxProgramInit::new(init);

                let mem = init.memory_config(get_native_page_size()).unwrap();
                let mut asm = Assembler::new();
                if Sandbox::KIND != SandboxKind::Generic {
                    asm.push(load32_imm(r15, 0));
                }

                asm
                    .push(load_indirect(rax, RegSize::R64, r15, mem.ro_data_address().try_into().unwrap(), LoadKind::U32))
                    .push(store_indirect(RegSize::R64, r15, i32::try_from(mem.rw_data_address()).unwrap(), rax, StoreKind::U8))
                    .push(store_indirect(RegSize::R64, r15, i32::try_from(mem.rw_data_address()).unwrap() + 4, rax, StoreKind::U16))
                    .push(ret());

                let code = asm.finalize();
                let address_space = Sandbox::reserve_address_space().unwrap();
                let native_code_address = address_space.native_code_address();
                let program = Sandbox::prepare_program(init.with_code(code), address_space).unwrap();
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
                    asm.push(load32_imm(r15, 0));
                }

                asm
                    .push(load_indirect(rax, RegSize::R64, r15, mem.rw_data_address().try_into().unwrap(), LoadKind::U32))
                    .push(add_imm(RegSize::R64, rax, 1))
                    .push(store_indirect(RegSize::R64, r15, i32::try_from(mem.rw_data_address()).unwrap(), rax, StoreKind::U32))
                    .push(ret());

                let code = asm.finalize();
                let address_space = Sandbox::reserve_address_space().unwrap();
                let native_code_address = address_space.native_code_address();
                let program = Sandbox::prepare_program(init.with_code(code), address_space).unwrap();

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
                    asm.push(load32_imm(r15, 0));
                }

                asm
                    .push(load_indirect(rax, RegSize::R64, r15, mem.rw_data_address().try_into().unwrap(), LoadKind::U32))
                    .push(add_imm(RegSize::R64, rax, 1))
                    .push(store_indirect(RegSize::R64, r15, i32::try_from(mem.rw_data_address()).unwrap(), rax, StoreKind::U32))
                    .push(load_indirect(rax, RegSize::R64, r15, 0, LoadKind::U32))
                    .push(ret());

                let code = asm.finalize();
                let address_space = Sandbox::reserve_address_space().unwrap();
                let native_code_address = address_space.native_code_address();
                let program = Sandbox::prepare_program(init.with_code(code), address_space).unwrap();

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
                let code = asm
                    .push(load32_imm(rdx, 0))
                    .push(load32_imm(rax, 1))
                    .push(load32_imm(rcx, 0))
                    .push(load32_imm(r8, 0x11223344))
                    .push(store_abs(i32::try_from(mem.rw_data_address()).unwrap(), r8, StoreKind::U32))
                    .push(idiv(RegSize::R32, rcx))
                    .push(load32_imm(r8, 0x12345678))
                    .push(store_abs(i32::try_from(mem.rw_data_address()).unwrap(), r8, StoreKind::U32))
                    .push(ret())
                    .finalize();

                let address_space = Sandbox::reserve_address_space().unwrap();
                let native_code_address = address_space.native_code_address();
                let program = Sandbox::prepare_program(init.with_code(code), address_space).unwrap();
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
