//! This module defines the ABI boundary between the host and the zygote.
//!
//! In general everything here can be modified at will, provided the zygote
//! is recompiled.

use crate::abi::GuestMemoryConfig;
use crate::utils::align_to_next_page_usize;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64};

/// The address where the native code starts inside of the VM.
///
/// This is not directly accessible by the program running inside of the VM.
pub const VM_ADDR_NATIVE_CODE: u64 = 0x100000000;

/// The address where the indirect jump table starts inside of the VM.
///
/// This is not directly accessible by the program running inside of the VM.
pub const VM_ADDR_JUMP_TABLE: u64 = 0x800000000;

/// The address where the return-to-host jump table vector physically resides.
pub const VM_ADDR_JUMP_TABLE_RETURN_TO_HOST: u64 = 0x9ffff8000;

/// The address of the native entry point used for triggering syscalls.
pub const VM_ADDR_SYSCALL: u64 = 0x3ffffc000;

// Constants used by the syscall handler in zygote to figure out what exact
// kind of a syscall should be executed.
//
// TODO: Remove these. All of these should be separate functions.
pub const SYSCALL_HOSTCALL: u32 = 1;
pub const SYSCALL_TRAP: u32 = 2;
pub const SYSCALL_RETURN: u32 = 3;
pub const SYSCALL_TRACE: u32 = 4;

/// A special hostcall number set by the *guest* to trigger a trace.
pub const HOSTCALL_TRACE: u64 = 0x100000000;

/// A special hostcall number set by the *host* to signal that the guest should stop executing the program.
pub const HOSTCALL_ABORT_EXECUTION: u64 = !0;

/// A sentinel value to indicate that the instruction counter is not available.
pub const SANDBOX_EMPTY_NTH_INSTRUCTION: u32 = !0;

/// A sentinel value to indicate that the native program counter is not available.
pub const SANDBOX_EMPTY_NATIVE_PROGRAM_COUNTER: u64 = 0;

/// The address of the global per-VM context struct.
pub const VM_ADDR_VMCTX: u64 = 0x400000000;

/// The address of the signal stack.
pub const VM_ADDR_SIGSTACK: u64 = 0x500000000;

/// The address of the native stack.
pub const VM_ADDR_NATIVE_STACK_LOW: u64 = 0x600000000;

/// The size of the native stack.
pub const VM_ADDR_NATIVE_STACK_SIZE: u64 = 0x4000;

/// The address of the top of the native stack.
pub const VM_ADDR_NATIVE_STACK_HIGH: u64 = VM_ADDR_NATIVE_STACK_LOW + VM_ADDR_NATIVE_STACK_SIZE;

/// The maximum number of native code bytes that can be emitted by a single VM instruction.
///
/// This does *not* affect the VM ABI and can be changed at will,
/// but should be high enough that it's never hit.
pub const VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH: u32 = 32;

/// The maximum number of native code bytes that can be emitted as an epilogue.
///
/// This does *not* affect the VM ABI and can be changed at will,
/// but should be high enough that it's never hit.
pub const VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH: u32 = 1024 * 1024;

/// The maximum number of bytes the jump table can be.
pub const VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE: u32 = (crate::abi::VM_MAXIMUM_JUMP_TARGET + 1) * core::mem::size_of::<u64>() as u32;

/// The maximum number of bytes the native code can be.
pub const VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE: u32 = 512 * 1024 * 1024 - 1;

/// The memory configuration used by a given program and/or sandbox instance.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct SandboxMemoryConfig {
    guest_config: GuestMemoryConfig,
    code_size: u32,
    jump_table_size: u32,
}

impl core::ops::Deref for SandboxMemoryConfig {
    type Target = GuestMemoryConfig;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.guest_config
    }
}

impl core::ops::DerefMut for SandboxMemoryConfig {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guest_config
    }
}

impl SandboxMemoryConfig {
    #[inline]
    pub const fn empty() -> Self {
        Self {
            guest_config: GuestMemoryConfig::empty(),
            code_size: 0,
            jump_table_size: 0,
        }
    }

    #[inline]
    pub fn set_guest_config(&mut self, guest_config: GuestMemoryConfig) {
        self.guest_config = guest_config;
    }

    #[inline]
    pub const fn code_size(&self) -> usize {
        self.code_size as usize
    }

    #[inline]
    pub fn clear_code_size(&mut self) {
        self.code_size = 0;
    }

    pub fn set_code_size(&mut self, native_page_size: usize, code_size: usize) -> Result<(), &'static str> {
        if code_size > VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE as usize {
            return Err("size of the native code exceeded the maximum code size");
        }

        let code_size = match align_to_next_page_usize(native_page_size, code_size) {
            Some(value) => value,
            None => unreachable!(),
        };

        self.code_size = code_size as u32;
        Ok(())
    }

    #[inline]
    pub const fn jump_table_size(&self) -> usize {
        self.jump_table_size as usize
    }

    #[inline]
    pub fn clear_jump_table_size(&mut self) {
        self.jump_table_size = 0;
    }

    pub fn set_jump_table_size(&mut self, native_page_size: usize, jump_table_size: usize) -> Result<(), &'static str> {
        if jump_table_size > VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE as usize {
            return Err("size of the jump table exceeded te maximum size");
        }

        let jump_table_size = match align_to_next_page_usize(native_page_size, jump_table_size) {
            Some(value) => value,
            None => unreachable!(),
        };

        self.jump_table_size = jump_table_size as u32;
        Ok(())
    }
}

/// A flag which will trigger the sandbox to reload its program before execution.
pub const VM_RPC_FLAG_RECONFIGURE: u32 = 1 << 0;

/// A flag which will trigger the sandbox to reset its memory after execution.
pub const VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION: u32 = 1 << 1;

/// A flag which will trigger the sandbox to unload its program after execution.
pub const VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION: u32 = 1 << 2;

/// A flag which will trigger the sandbox to send a SIGSTOP to itself before execution.
///
/// Mostly useful for debugging.
pub const VM_RPC_FLAG_SIGSTOP_BEFORE_EXECUTION: u32 = 1 << 3;

#[repr(C)]
pub struct VmInit {
    pub stack_address: AtomicU64,
    pub stack_length: AtomicU64,
    pub vdso_address: AtomicU64,
    pub vdso_length: AtomicU64,
    pub vvar_address: AtomicU64,
    pub vvar_length: AtomicU64,
}

const MESSAGE_BUFFER_SIZE: usize = 512;

#[repr(align(64))]
pub struct CacheAligned<T>(T);

impl<T> core::ops::Deref for CacheAligned<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> core::ops::DerefMut for CacheAligned<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(C)]
pub struct VmCtxSyscall {
    // NOTE: The order of fields here can matter for performance!
    /// The hostcall number that was triggered.
    pub hostcall: UnsafeCell<u64>,
    /// A dump of all of the registers of the VM.
    pub regs: UnsafeCell<[u32; 13]>,
    /// The number of the instruction just about to be executed.
    ///
    /// Should be treated as empty if equal to `SANDBOX_EMPTY_NTH_INSTRUCTION`.
    pub nth_instruction: UnsafeCell<u32>,

    /// The current RIP. Filled out in case of a trap or during tracing.
    ///
    /// Should be treated as empty if equal to `SANDBOX_EMPTY_NATIVE_PROGRAM_COUNTER`.
    pub rip: UnsafeCell<u64>,
}

#[repr(C)]
pub struct VmCtxCounters {
    pub syscall_wait_loop_start: UnsafeCell<u64>,
    pub syscall_futex_wait: UnsafeCell<u64>,
}

/// The virtual machine context.
///
/// This is mapped in shared memory and used by the sandbox to keep its state in,
/// as well as by the host to communicate with the sandbox.
#[repr(C)]
pub struct VmCtx {
    /// The futex used to synchronize the sandbox with the host process.
    pub futex: CacheAligned<AtomicU32>,

    /// The address of the native code to call inside of the VM, if non-zero.
    pub rpc_address: UnsafeCell<u64>,
    /// Flags specifying what exactly the sandbox should do.
    pub rpc_flags: UnsafeCell<u32>,
    /// The current memory configuration of the sandbox.
    pub memory_config: UnsafeCell<SandboxMemoryConfig>,
    /// The new memory configuration of the sandbox. Will be applied if the appropriate flag is set.
    pub new_memory_config: UnsafeCell<SandboxMemoryConfig>,
    /// The new sysreturn trampoline address. Will be applied if the appropriate flag is set.
    pub new_sysreturn_address: UnsafeCell<u64>,

    /// Fields used when making syscalls from the VM into the host.
    syscall_ffi: CacheAligned<VmCtxSyscall>,

    /// Performance counters. Only for debugging.
    pub counters: CacheAligned<VmCtxCounters>,

    /// One-time args used during initialization.
    pub init: VmInit,

    /// Length of the message in the message buffer.
    pub message_length: UnsafeCell<u32>,
    /// A buffer used to marshal error messages.
    pub message_buffer: UnsafeCell<[u8; MESSAGE_BUFFER_SIZE]>,
}

// Make sure it fits within a single page on amd64.
static_assert!(core::mem::size_of::<VmCtx>() <= 4096);

/// The VM is busy.
pub const VMCTX_FUTEX_BUSY: u32 = 0;

/// The VM is ready to be initialized.
pub const VMCTX_FUTEX_INIT: u32 = 1;

/// The VM is idle and is waiting for work.
pub const VMCTX_FUTEX_IDLE: u32 = 2;

/// The VM has triggered a host call.
pub const VMCTX_FUTEX_HOSTCALL: u32 = 3;

/// The VM has triggered a trap.
pub const VMCTX_FUTEX_TRAP: u32 = 4;

impl VmCtx {
    /// Creates a fresh VM context.
    pub const fn new() -> Self {
        VmCtx {
            futex: CacheAligned(AtomicU32::new(VMCTX_FUTEX_BUSY)),

            rpc_address: UnsafeCell::new(0),
            rpc_flags: UnsafeCell::new(0),
            memory_config: UnsafeCell::new(SandboxMemoryConfig::empty()),
            new_memory_config: UnsafeCell::new(SandboxMemoryConfig::empty()),
            new_sysreturn_address: UnsafeCell::new(0),

            syscall_ffi: CacheAligned(VmCtxSyscall {
                hostcall: UnsafeCell::new(0),
                regs: UnsafeCell::new([0; 13]),
                rip: UnsafeCell::new(0),
                nth_instruction: UnsafeCell::new(0),
            }),

            counters: CacheAligned(VmCtxCounters {
                syscall_wait_loop_start: UnsafeCell::new(0),
                syscall_futex_wait: UnsafeCell::new(0),
            }),

            init: VmInit {
                stack_address: AtomicU64::new(0),
                stack_length: AtomicU64::new(0),
                vdso_address: AtomicU64::new(0),
                vdso_length: AtomicU64::new(0),
                vvar_address: AtomicU64::new(0),
                vvar_length: AtomicU64::new(0),
            },

            message_length: UnsafeCell::new(0),
            message_buffer: UnsafeCell::new([0; MESSAGE_BUFFER_SIZE]),
        }
    }

    // Define some accessor methods so that we don't have to update the rest of the codebase
    // when we shuffle things around in the structure.

    #[inline(always)]
    pub const fn hostcall(&self) -> &UnsafeCell<u64> {
        &self.syscall_ffi.0.hostcall
    }

    #[inline(always)]
    pub const fn regs(&self) -> &UnsafeCell<[u32; 13]> {
        &self.syscall_ffi.0.regs
    }

    #[inline(always)]
    pub const fn rip(&self) -> &UnsafeCell<u64> {
        &self.syscall_ffi.0.rip
    }

    #[inline(always)]
    pub const fn nth_instruction(&self) -> &UnsafeCell<u32> {
        &self.syscall_ffi.0.nth_instruction
    }
}

static_assert!(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST == VM_ADDR_JUMP_TABLE + ((crate::abi::VM_ADDR_RETURN_TO_HOST as u64) << 1));
static_assert!((VM_ADDR_JUMP_TABLE + 0x100000000 - crate::abi::VM_ADDR_RETURN_TO_HOST as u64) % 0x4000 == 0);
static_assert!(VM_ADDR_JUMP_TABLE + (VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE as u64) < VM_ADDR_JUMP_TABLE_RETURN_TO_HOST);
static_assert!(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST < VM_ADDR_JUMP_TABLE + 0x200000000);
static_assert!(VM_ADDR_JUMP_TABLE.count_ones() == 1);
static_assert!((1 << VM_ADDR_JUMP_TABLE.trailing_zeros()) == VM_ADDR_JUMP_TABLE);

static_assert!(
    VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE
        >= crate::abi::VM_MAXIMUM_INSTRUCTION_COUNT * VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH + VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH
);
static_assert!(VM_ADDR_NATIVE_CODE > 0xffffffff);
static_assert!(VM_ADDR_VMCTX > 0xffffffff);
static_assert!(VM_ADDR_NATIVE_STACK_LOW > 0xffffffff);
