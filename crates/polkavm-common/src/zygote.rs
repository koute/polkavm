//! This module defines the ABI boundary between the host and the zygote.
//!
//! In general everything here can be modified at will, provided the zygote
//! is recompiled.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

// Due to the limitations of Rust's compile time constant evaluation machinery
// we need to define this struct multiple times.
macro_rules! define_address_table {
    ($($name:ident: $type:ty,)+) => {
        #[repr(C)]
        pub struct AddressTableRaw {
            $(pub $name: $type),+
        }

        #[derive(Copy, Clone)]
        #[repr(packed)]
        pub struct AddressTablePacked {
            $(pub $name: u64),+
        }

        #[derive(Copy, Clone)]
        pub struct AddressTable {
            $(pub $name: u64),+
        }

        impl AddressTable {
            #[inline]
            pub fn from_raw(table: AddressTableRaw) -> Self {
                Self {
                    $(
                        $name: table.$name as u64
                    ),+
                }
            }

            pub const fn from_packed(table: &AddressTablePacked) -> Self {
                Self {
                    $(
                        $name: table.$name
                    ),+
                }
            }
        }

        static_assert!(core::mem::size_of::<AddressTableRaw>() == core::mem::size_of::<AddressTablePacked>());
        static_assert!(core::mem::size_of::<AddressTableRaw>() == core::mem::size_of::<AddressTable>());
    }
}

// These are the addresses exported from the zygote.
define_address_table! {
    syscall_hostcall: unsafe extern "C" fn(u32),
    syscall_trap: unsafe extern "C" fn() -> !,
    syscall_return: unsafe extern "C" fn() -> !,
    syscall_trace: unsafe extern "C" fn(u32, u64),
    syscall_sbrk: unsafe extern "C" fn(u64) -> u32,
}

/// The address where the native code starts inside of the VM.
///
/// This is not directly accessible by the program running inside of the VM.
pub const VM_ADDR_NATIVE_CODE: u64 = 0x100000000;

/// The address where the indirect jump table starts inside of the VM.
///
/// This is not directly accessible by the program running inside of the VM.
pub const VM_ADDR_JUMP_TABLE: u64 = 0x800000000;

/// The address where the return-to-host jump table vector physically resides.
pub const VM_ADDR_JUMP_TABLE_RETURN_TO_HOST: u64 = VM_ADDR_JUMP_TABLE + ((crate::abi::VM_ADDR_RETURN_TO_HOST as u64) << 3);

/// A special hostcall number set by the *host* to signal that the guest should stop executing the program.
pub const HOSTCALL_ABORT_EXECUTION: u32 = !0;

/// A special hostcall number set by the *host* to signal that the guest should execute `sbrk`.
pub const HOSTCALL_SBRK: u32 = !0 - 1;

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

/// Address where the shared memory is mapped.
pub const VM_ADDR_SHARED_MEMORY: u64 = 0x700000000;

/// The size of the shared memory region.
pub const VM_SHARED_MEMORY_SIZE: u64 = u32::MAX as u64;

/// The maximum number of native code bytes that can be emitted by a single VM instruction.
///
/// This does *not* affect the VM ABI and can be changed at will,
/// but should be high enough that it's never hit.
pub const VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH: u32 = 53;

/// The maximum number of native code bytes that can be emitted as an epilogue.
///
/// This does *not* affect the VM ABI and can be changed at will,
/// but should be high enough that it's never hit.
pub const VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH: u32 = 1024 * 1024;

/// The maximum number of bytes the jump table can be.
pub const VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE: u64 = (crate::abi::VM_MAXIMUM_JUMP_TABLE_ENTRIES as u64 + 1)
    * core::mem::size_of::<u64>() as u64
    * crate::abi::VM_CODE_ADDRESS_ALIGNMENT as u64;

/// The maximum number of bytes the jump table can span in virtual memory.
pub const VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE: u64 = 0x100000000 * core::mem::size_of::<u64>() as u64;

// TODO: Make this smaller.
/// The maximum number of bytes the native code can be.
pub const VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE: u32 = 2048 * 1024 * 1024 - 1;

/// A flag which will trigger the sandbox to reload its program before execution.
pub const VM_RPC_FLAG_RECONFIGURE: u32 = 1 << 0;

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
pub struct CacheAligned<T>(pub T);

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
pub struct VmCtxHeapInfo {
    pub heap_top: UnsafeCell<u64>,
    pub heap_threshold: UnsafeCell<u64>,
}

const REG_COUNT: usize = crate::program::Reg::ALL.len();

#[repr(C)]
pub struct VmCtxSyscall {
    // NOTE: The order of fields here can matter for performance!
    /// The current gas counter.
    pub gas: UnsafeCell<i64>,
    /// The hostcall number that was triggered.
    pub hostcall: UnsafeCell<u32>,
    /// A dump of all of the registers of the VM.
    pub regs: UnsafeCell<[u32; REG_COUNT]>,
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

#[repr(C)]
pub struct VmMap {
    pub address: u64,
    pub length: u64,
    pub shm_offset: u64,
    pub is_writable: bool,
}

/// The virtual machine context.
///
/// This is mapped in shared memory and used by the sandbox to keep its state in,
/// as well as by the host to communicate with the sandbox.
#[allow(clippy::partial_pub_fields)]
#[repr(C)]
pub struct VmCtx {
    /// Fields used when making syscalls from the VM into the host.
    syscall_ffi: CacheAligned<VmCtxSyscall>,

    /// The state of the program's heap.
    pub heap_info: VmCtxHeapInfo,

    /// The futex used to synchronize the sandbox with the host process.
    pub futex: CacheAligned<AtomicU32>,

    /// The address of the native code to call inside of the VM, if non-zero.
    pub rpc_address: UnsafeCell<u64>,
    /// Flags specifying what exactly the sandbox should do.
    pub rpc_flags: UnsafeCell<u32>,
    /// The amount of memory to allocate.
    pub rpc_sbrk: UnsafeCell<u32>,
    /// Whether the memory of the sandbox is dirty.
    pub is_memory_dirty: AtomicBool,
    /// Offset in shared memory to this sandbox's memory map.
    pub shm_memory_map_offset: UnsafeCell<u64>,
    /// Number of maps to map.
    pub shm_memory_map_count: UnsafeCell<u64>,
    /// Offset in shared memory to this sandbox's code.
    pub shm_code_offset: UnsafeCell<u64>,
    /// Length this sandbox's code.
    pub shm_code_length: UnsafeCell<u64>,
    /// Offset in shared memory to this sandbox's jump table.
    pub shm_jump_table_offset: UnsafeCell<u64>,
    /// Length of sandbox's jump table, in bytes.
    pub shm_jump_table_length: UnsafeCell<u64>,
    /// Address of the sysreturn routine.
    pub sysreturn_address: UnsafeCell<u64>,

    /// Address to the base of the heap.
    pub heap_base: UnsafeCell<u32>,

    /// The initial heap growth threshold.
    pub heap_initial_threshold: UnsafeCell<u32>,

    /// The maximum heap size.
    pub heap_max_size: UnsafeCell<u32>,

    /// The page size.
    pub page_size: UnsafeCell<u32>,

    /// Whether userfaultfd-based memory management is enabled.
    pub uffd_enabled: UnsafeCell<bool>,

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

#[allow(clippy::new_without_default)]
impl VmCtx {
    /// Creates a zeroed VM context.
    pub const fn zeroed() -> Self {
        VmCtx {
            futex: CacheAligned(AtomicU32::new(VMCTX_FUTEX_BUSY)),

            rpc_address: UnsafeCell::new(0),
            rpc_flags: UnsafeCell::new(0),
            rpc_sbrk: UnsafeCell::new(0),
            is_memory_dirty: AtomicBool::new(false),
            shm_memory_map_offset: UnsafeCell::new(0),
            shm_memory_map_count: UnsafeCell::new(0),
            shm_code_offset: UnsafeCell::new(0),
            shm_code_length: UnsafeCell::new(0),
            shm_jump_table_offset: UnsafeCell::new(0),
            shm_jump_table_length: UnsafeCell::new(0),
            sysreturn_address: UnsafeCell::new(0),
            heap_base: UnsafeCell::new(0),
            heap_initial_threshold: UnsafeCell::new(0),
            heap_max_size: UnsafeCell::new(0),
            page_size: UnsafeCell::new(0),
            uffd_enabled: UnsafeCell::new(false),

            syscall_ffi: CacheAligned(VmCtxSyscall {
                gas: UnsafeCell::new(0),
                hostcall: UnsafeCell::new(0),
                regs: UnsafeCell::new([0; REG_COUNT]),
                rip: UnsafeCell::new(0),
                nth_instruction: UnsafeCell::new(0),
            }),

            heap_info: VmCtxHeapInfo {
                heap_top: UnsafeCell::new(0),
                heap_threshold: UnsafeCell::new(0),
            },

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

    /// Creates a fresh VM context.
    pub const fn new() -> Self {
        let mut vmctx = Self::zeroed();
        vmctx.syscall_ffi.0.nth_instruction = UnsafeCell::new(SANDBOX_EMPTY_NTH_INSTRUCTION);
        vmctx
    }

    // Define some accessor methods so that we don't have to update the rest of the codebase
    // when we shuffle things around in the structure.

    #[inline(always)]
    pub const fn gas(&self) -> &UnsafeCell<i64> {
        &self.syscall_ffi.0.gas
    }

    #[inline(always)]
    pub const fn heap_info(&self) -> &VmCtxHeapInfo {
        &self.heap_info
    }

    #[inline(always)]
    pub const fn hostcall(&self) -> &UnsafeCell<u32> {
        &self.syscall_ffi.0.hostcall
    }

    #[inline(always)]
    pub const fn regs(&self) -> &UnsafeCell<[u32; REG_COUNT]> {
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

static_assert!(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST > VM_ADDR_JUMP_TABLE);
static_assert!(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST % 0x4000 == 0);
static_assert!(VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE <= VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE);
static_assert!(VM_ADDR_JUMP_TABLE + VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE < VM_ADDR_JUMP_TABLE_RETURN_TO_HOST);
static_assert!(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST < VM_ADDR_JUMP_TABLE + VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE);
static_assert!(VM_ADDR_JUMP_TABLE.count_ones() == 1);
static_assert!((1 << VM_ADDR_JUMP_TABLE.trailing_zeros()) == VM_ADDR_JUMP_TABLE);

static_assert!(
    VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE
        >= crate::abi::VM_MAXIMUM_CODE_SIZE * VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH + VM_COMPILER_MAXIMUM_EPILOGUE_LENGTH
);
static_assert!(VM_ADDR_NATIVE_CODE > 0xffffffff);
static_assert!(VM_ADDR_VMCTX > 0xffffffff);
static_assert!(VM_ADDR_NATIVE_STACK_LOW > 0xffffffff);
