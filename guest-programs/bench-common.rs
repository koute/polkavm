extern crate alloc;

#[allow(unused_imports)]
use alloc::boxed::Box;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_family = "wasm")]
    {
        core::arch::wasm32::unreachable();
    }

    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        core::arch::asm!("unimp", options(noreturn));
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }

    #[cfg(target_os = "solana")]
    unsafe {
        core::hint::unreachable_unchecked();
    }
}

#[cfg(not(any(target_os = "solana", target_ckb_vm)))]
#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn initialize() {
    benchmark_initialize(unsafe { &mut STATE });
}

#[cfg(not(any(target_os = "solana", target_ckb_vm)))]
#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn run() {
    benchmark_run(unsafe { &mut STATE });
}

#[cfg(target_ckb_vm)]
#[no_mangle]
unsafe extern "C" fn __entry_point(arg: usize) {
    if arg == 0 {
        benchmark_initialize(unsafe { &mut STATE });
    } else if arg == 1 {
        benchmark_run(unsafe { &mut STATE });
    }
}

#[cfg(target_ckb_vm)]
core::arch::global_asm!(
    ".global _start",
    "_start:",
    "call __entry_point",
    "ecall",
);

#[cfg(not(target_os = "solana"))]
macro_rules! define_benchmark {
    (
        heap_size = $heap_size:expr,
        state = $state:expr,
    ) => {
        #[global_allocator]
        static mut GLOBAL_ALLOC: simplealloc::SimpleAlloc<{ $heap_size }> = simplealloc::SimpleAlloc::new();
        static mut STATE: State = $state;
    };
}

#[cfg(target_os = "solana")]
#[no_mangle]
extern "C" fn sol_memcpy_(dst: *mut u8, src: *const u8, n: usize) {
    unsafe {
        for _ in 0..n {
            *dst.add(n) = *src.add(n);
        }
    }
}

#[cfg(target_os = "solana")]
#[no_mangle]
extern "C" fn sol_memset_(dst: *mut u8, value: u8, n: usize) {
    unsafe {
        for _ in 0..n {
            *dst.add(n) = value;
        }
    }
}

#[cfg(target_os = "solana")]
#[repr(C)]
struct SolanaHeap<const N: usize> {
    state: State,
    allocator: simplealloc::SimpleAlloc<N>
}

#[cfg(target_os = "solana")]
macro_rules! define_benchmark {
    (
        heap_size = $heap_size:expr,
        state = $state:expr,
    ) => {
        struct SolanaAlloc;

        unsafe impl alloc::alloc::GlobalAlloc for SolanaAlloc {
            #[inline]
            unsafe fn alloc(&self, layout: alloc::alloc::Layout) -> *mut u8 {
                let heap = 0x300000000 as *mut SolanaHeap<{$heap_size}>;
                alloc::alloc::GlobalAlloc::alloc(&(*heap).allocator, layout)
            }

            #[inline]
            unsafe fn dealloc(&self, pointer: *mut u8, layout: alloc::alloc::Layout) {
                let heap = 0x300000000 as *mut SolanaHeap<{$heap_size}>;
                alloc::alloc::GlobalAlloc::dealloc(&(*heap).allocator, pointer, layout)
            }
        }

        #[global_allocator]
        static GLOBAL_ALLOC: SolanaAlloc = SolanaAlloc;

        #[link_section = ".heap_size"]
        #[no_mangle]
        static HEAP_SIZE: usize = core::mem::size_of::<SolanaHeap<{$heap_size}>>();

        #[cfg(target_os = "solana")]
        #[no_mangle]
        pub unsafe extern "C" fn __solana_entry_point() {
            let heap = 0x300000000 as *mut SolanaHeap<{$heap_size}>;
            let arg = *(0x400000000 as *const u8);
            if arg == 0 {
                // NOTE: This assumes that the allocator doesn't need to be initialized.
                core::ptr::write(heap as *mut State, $state);
                benchmark_initialize(&mut (*heap).state);
            } else if arg == 1 {
                benchmark_run(&mut (*heap).state);
            }
        }
    };
}
