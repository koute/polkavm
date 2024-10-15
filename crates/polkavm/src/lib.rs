#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unused_must_use)]
#![forbid(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::exhaustive_structs)]

#[cfg(all(
    not(miri),
    target_arch = "x86_64",
    any(
        target_os = "linux",
        all(feature = "generic-sandbox", any(target_os = "macos", target_os = "freebsd"))
    ),
    feature = "std",
))]
macro_rules! if_compiler_is_supported {
    ({
        $($if_true:tt)*
    } else {
        $($if_false:tt)*
    }) => {
        $($if_true)*
    };

    ($($if_true:tt)*) => {
        $($if_true)*
    }
}

#[cfg(not(all(
    not(miri),
    target_arch = "x86_64",
    any(
        target_os = "linux",
        all(feature = "generic-sandbox", any(target_os = "macos", target_os = "freebsd"))
    ),
    feature = "std",
)))]
macro_rules! if_compiler_is_supported {
    ({
        $($if_true:tt)*
    } else {
        $($if_false:tt)*
    }) => {
        $($if_false)*
    };

    ($($if_true:tt)*) => {}
}

extern crate alloc;

mod error;

mod api;
mod config;
mod gas;
mod interpreter;
mod linker;
mod page_set;
#[cfg(feature = "std")]
mod source_cache;
mod utils;

#[cfg(feature = "std")]
mod mutex_std;

#[cfg(feature = "std")]
pub(crate) use mutex_std as mutex;

#[cfg(not(feature = "std"))]
mod mutex_no_std;

#[cfg(not(feature = "std"))]
pub(crate) use mutex_no_std as mutex;

impl<T> Default for crate::mutex::Mutex<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(feature = "module-cache")]
mod module_cache;

if_compiler_is_supported! {
    mod compiler;
    mod sandbox;

    #[cfg(all(target_os = "linux", not(feature = "export-internals-for-testing")))]
    mod generic_allocator;

    #[cfg(all(target_os = "linux", not(feature = "export-internals-for-testing")))]
    mod bit_mask;

    #[cfg(target_os = "linux")]
    mod shm_allocator;
}

// These are needed due to: https://github.com/rust-lang/rustfmt/issues/3253
#[cfg(rustfmt)]
mod bit_mask;
#[cfg(rustfmt)]
mod compiler;
#[cfg(rustfmt)]
mod generic_allocator;
#[cfg(rustfmt)]
mod sandbox;
#[cfg(rustfmt)]
mod shm_allocator;

pub use polkavm_common::{
    abi::MemoryMap,
    program::{ProgramBlob, ProgramCounter, ProgramParts, Reg},
    utils::{ArcBytes, AsUninitSliceMut},
};

/// Miscellaneous types related to debug info.
pub mod debug_info {
    pub use polkavm_common::program::{FrameInfo, FrameKind, LineProgram, RegionInfo, SourceLocation};

    #[cfg(feature = "std")]
    pub use crate::source_cache::SourceCache;
}

/// Miscellaneous types related to program blobs.
pub mod program {
    pub use polkavm_common::program::{
        ISA32_V1_NoSbrk, Imports, ImportsIter, Instruction, InstructionSet, Instructions, JumpTable, JumpTableIter, Opcode,
        ParsedInstruction, ProgramExport, ProgramParseError, ProgramSymbol, RawReg, ISA32_V1, ISA64_V1,
    };
}

pub type Gas = i64;

pub use crate::api::{Engine, MemoryAccessError, Module, RawInstance, RegValue};
pub use crate::config::{BackendKind, Config, GasMeteringKind, ModuleConfig, SandboxKind};
pub use crate::error::Error;
pub use crate::linker::{CallError, Caller, Instance, InstancePre, Linker};
pub use crate::utils::{InterruptKind, Segfault};

pub const RETURN_TO_HOST: u32 = polkavm_common::abi::VM_ADDR_RETURN_TO_HOST;

#[cfg(test)]
mod tests;

// These need to be toplevel for the macros to work.
#[cfg(feature = "export-internals-for-testing")]
pub mod generic_allocator;

#[cfg(feature = "export-internals-for-testing")]
pub mod bit_mask;

#[cfg(feature = "export-internals-for-testing")]
#[doc(hidden)]
pub mod _for_testing {
    #[cfg(target_os = "linux")]
    if_compiler_is_supported! {
        pub use crate::shm_allocator::{ShmAllocation, ShmAllocator};
        pub fn create_shm_allocator() -> Result<crate::shm_allocator::ShmAllocator, polkavm_linux_raw::Error> {
            crate::sandbox::init_native_page_size();
            crate::shm_allocator::ShmAllocator::new()
        }
    }
}
