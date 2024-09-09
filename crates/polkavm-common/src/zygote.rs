//! This module defines the ABI boundary between the host and the zygote.
//!
//! In general everything here can be modified at will, provided the zygote
//! is recompiled.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64};

// Due to the limitations of Rust's compile time constant evaluation machinery
// we need to define this struct multiple times.
macro_rules! define_address_table {
    (
        $name_raw:ident, $name_packed:ident, $name_table:ident,
        $($name:ident: $type:ty,)+
    ) => {
        #[repr(C)]
        pub struct $name_raw {
            $(pub $name: $type),+
        }

        #[derive(Copy, Clone)]
        #[repr(packed)]
        pub struct $name_packed {
            $(pub $name: u64),+
        }

        #[derive(Copy, Clone)]
        pub struct $name_table {
            $(pub $name: u64),+
        }

        impl $name_table {
            #[inline]
            pub fn from_raw(table: $name_raw) -> Self {
                Self {
                    $(
                        $name: table.$name as u64
                    ),+
                }
            }

            pub const fn from_packed(table: &$name_packed) -> Self {
                Self {
                    $(
                        $name: table.$name
                    ),+
                }
            }
        }

        static_assert!(core::mem::size_of::<$name_raw>() == core::mem::size_of::<$name_packed>());
        static_assert!(core::mem::size_of::<$name_raw>() == core::mem::size_of::<$name_table>());
    }
}

// These are the addresses exported from the zygote.
define_address_table! {
    AddressTableRaw, AddressTablePacked, AddressTable,
    syscall_hostcall: unsafe extern "C" fn() -> !,
    syscall_trap: unsafe extern "C" fn() -> !,
    syscall_return: unsafe extern "C" fn() -> !,
    syscall_step: unsafe extern "C" fn() -> !,
    syscall_sbrk: unsafe extern "C" fn(u64) -> u32,
}

define_address_table! {
    ExtTableRaw, ExtTablePacked, ExtTable,
    ext_sbrk: unsafe extern "C" fn() -> !,
    ext_reset_memory: unsafe extern "C" fn() -> !,
    ext_zero_memory_chunk: unsafe extern "C" fn() -> !,
    ext_load_program: unsafe extern "C" fn() -> !,
    ext_recycle: unsafe extern "C" fn() -> !,
    ext_fetch_idle_regs: unsafe extern "C" fn() -> !,
}

pub const FD_DUMMY_STDIN: i32 = 0;
pub const FD_LOGGER_STDOUT: i32 = 1;
pub const FD_LOGGER_STDERR: i32 = 2;
pub const FD_SHM: i32 = 3;
pub const FD_MEM: i32 = 4;
pub const FD_SOCKET: i32 = 5;
pub const FD_VMCTX: i32 = 6;
pub const FD_LIFETIME_PIPE: i32 = 7;
pub const LAST_USED_FD: i32 = FD_LIFETIME_PIPE;

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

/// The maximum number of bytes the jump table can be.
pub const VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE: u64 = (crate::abi::VM_MAXIMUM_JUMP_TABLE_ENTRIES as u64 + 1)
    * core::mem::size_of::<u64>() as u64
    * crate::abi::VM_CODE_ADDRESS_ALIGNMENT as u64;

/// The maximum number of bytes the jump table can span in virtual memory.
pub const VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE: u64 = 0x100000000 * core::mem::size_of::<u64>() as u64;

// TODO: Make this smaller.
/// The maximum number of bytes the native code can be.
pub const VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE: u32 = 2048 * 1024 * 1024 - 1;

#[repr(C)]
pub struct JmpBuf {
    pub rip: AtomicU64,
    pub rbx: AtomicU64,
    pub rsp: AtomicU64,
    pub rbp: AtomicU64,
    pub r12: AtomicU64,
    pub r13: AtomicU64,
    pub r14: AtomicU64,
    pub r15: AtomicU64,
}

#[repr(C)]
pub struct VmInit {
    pub stack_address: AtomicU64,
    pub stack_length: AtomicU64,
    pub vdso_address: AtomicU64,
    pub vdso_length: AtomicU64,
    pub vvar_address: AtomicU64,
    pub vvar_length: AtomicU64,

    /// Whether userfaultfd-based memory management is available.
    pub uffd_available: AtomicBool,

    /// Whether sandboxing is disabled.
    pub sandbox_disabled: AtomicBool,

    /// Whether the logger is enabled.
    pub logging_enabled: AtomicBool,

    pub idle_regs: JmpBuf,
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
pub struct VmCtxCounters {
    pub syscall_wait_loop_start: UnsafeCell<u64>,
    pub syscall_futex_wait: UnsafeCell<u64>,
}

#[repr(C)]
pub enum VmFd {
    None,
    Shm,
    Mem,
}

#[repr(C)]
pub struct VmMap {
    pub address: u64,
    pub length: u64,
    pub protection: u32,
    pub flags: u32,
    pub fd: VmFd,
    pub fd_offset: u64,
}

/// The virtual machine context.
///
/// This is mapped in shared memory and used by the sandbox to keep its state in,
/// as well as by the host to communicate with the sandbox.
#[allow(clippy::partial_pub_fields)]
#[repr(C)]
pub struct VmCtx {
    // NOTE: The order of fields here can matter for performance!
    _align_1: CacheAligned<()>,

    /// The current gas counter.
    pub gas: AtomicI64,

    _align_2: CacheAligned<()>,

    /// The futex used to synchronize the sandbox with the host process.
    pub futex: AtomicU32,

    /// Address to which to jump to.
    pub jump_into: AtomicU64,

    /// The address of the instruction currently being executed.
    pub program_counter: AtomicU32,

    /// The address of the next instruction to be executed.
    pub next_program_counter: AtomicU32,

    /// A multipurpose field:
    ///   - the hostcall number that was triggered,
    ///   - the sbrk argument,
    ///   - the sbrk return value,
    pub arg: AtomicU32,

    /// A dump of all of the registers of the VM.
    pub regs: [AtomicU32; REG_COUNT],

    /// The address of the native code to call inside of the VM process, if non-zero.
    pub next_native_program_counter: AtomicU64,

    /// The state of the program's heap.
    pub heap_info: VmCtxHeapInfo,

    pub arg2: AtomicU32,

    /// Offset in shared memory to this sandbox's memory map.
    pub shm_memory_map_offset: AtomicU64,
    /// Number of maps to map.
    pub shm_memory_map_count: AtomicU64,
    /// Offset in shared memory to this sandbox's code.
    pub shm_code_offset: AtomicU64,
    /// Length this sandbox's code.
    pub shm_code_length: AtomicU64,
    /// Offset in shared memory to this sandbox's jump table.
    pub shm_jump_table_offset: AtomicU64,
    /// Length of sandbox's jump table, in bytes.
    pub shm_jump_table_length: AtomicU64,

    /// Address of the sysreturn routine.
    pub sysreturn_address: AtomicU64,

    /// Whether userfaultfd-based memory management is enabled.
    pub uffd_enabled: AtomicBool,

    /// Address to the base of the heap.
    pub heap_base: UnsafeCell<u32>,

    /// The initial heap growth threshold.
    pub heap_initial_threshold: UnsafeCell<u32>,

    /// The maximum heap size.
    pub heap_max_size: UnsafeCell<u32>,

    /// The page size.
    pub page_size: UnsafeCell<u32>,

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

/// The VM is idle.
pub const VMCTX_FUTEX_IDLE: u32 = 1;

/// The VM has triggered a host call and is idle.
pub const VMCTX_FUTEX_GUEST_ECALLI: u32 = VMCTX_FUTEX_IDLE | (1 << 1);

/// The VM has triggered a trap and is idle.
pub const VMCTX_FUTEX_GUEST_TRAP: u32 = VMCTX_FUTEX_IDLE | (2 << 1);

/// The VM's signal handler was triggered.
pub const VMCTX_FUTEX_GUEST_SIGNAL: u32 = VMCTX_FUTEX_IDLE | (3 << 1);

/// The VM has went through a single instruction is idle.
pub const VMCTX_FUTEX_GUEST_STEP: u32 = VMCTX_FUTEX_IDLE | (4 << 1);

#[allow(clippy::declare_interior_mutable_const)]
const ATOMIC_U32_ZERO: AtomicU32 = AtomicU32::new(0);

#[allow(clippy::new_without_default)]
impl VmCtx {
    /// Creates a zeroed VM context.
    pub const fn zeroed() -> Self {
        VmCtx {
            _align_1: CacheAligned(()),
            _align_2: CacheAligned(()),

            gas: AtomicI64::new(0),
            program_counter: AtomicU32::new(0),
            next_program_counter: AtomicU32::new(0),
            arg: AtomicU32::new(0),
            arg2: AtomicU32::new(0),
            regs: [ATOMIC_U32_ZERO; REG_COUNT],
            jump_into: AtomicU64::new(0),
            next_native_program_counter: AtomicU64::new(0),

            futex: AtomicU32::new(VMCTX_FUTEX_BUSY),

            shm_memory_map_offset: AtomicU64::new(0),
            shm_memory_map_count: AtomicU64::new(0),
            shm_code_offset: AtomicU64::new(0),
            shm_code_length: AtomicU64::new(0),
            shm_jump_table_offset: AtomicU64::new(0),
            shm_jump_table_length: AtomicU64::new(0),
            uffd_enabled: AtomicBool::new(false),
            sysreturn_address: AtomicU64::new(0),
            heap_base: UnsafeCell::new(0),
            heap_initial_threshold: UnsafeCell::new(0),
            heap_max_size: UnsafeCell::new(0),
            page_size: UnsafeCell::new(0),

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
                uffd_available: AtomicBool::new(false),
                sandbox_disabled: AtomicBool::new(false),
                logging_enabled: AtomicBool::new(false),
                idle_regs: JmpBuf {
                    rip: AtomicU64::new(0),
                    rbx: AtomicU64::new(0),
                    rsp: AtomicU64::new(0),
                    rbp: AtomicU64::new(0),
                    r12: AtomicU64::new(0),
                    r13: AtomicU64::new(0),
                    r14: AtomicU64::new(0),
                    r15: AtomicU64::new(0),
                },
            },

            message_length: UnsafeCell::new(0),
            message_buffer: UnsafeCell::new([0; MESSAGE_BUFFER_SIZE]),
        }
    }

    /// Creates a fresh VM context.
    pub const fn new() -> Self {
        Self::zeroed()
    }
}

static_assert!(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST > VM_ADDR_JUMP_TABLE);
static_assert!(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST % 0x4000 == 0);
static_assert!(VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE <= VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE);
static_assert!(VM_ADDR_JUMP_TABLE + VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE < VM_ADDR_JUMP_TABLE_RETURN_TO_HOST);
static_assert!(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST < VM_ADDR_JUMP_TABLE + VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE);
static_assert!(VM_ADDR_JUMP_TABLE.count_ones() == 1);
static_assert!((1 << VM_ADDR_JUMP_TABLE.trailing_zeros()) == VM_ADDR_JUMP_TABLE);

static_assert!(VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE >= crate::abi::VM_MAXIMUM_CODE_SIZE * VM_COMPILER_MAXIMUM_INSTRUCTION_LENGTH);
static_assert!(VM_ADDR_NATIVE_CODE > 0xffffffff);
static_assert!(VM_ADDR_VMCTX > 0xffffffff);
static_assert!(VM_ADDR_NATIVE_STACK_LOW > 0xffffffff);
