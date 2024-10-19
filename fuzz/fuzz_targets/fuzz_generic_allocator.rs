#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

struct TestConfig;

polkavm::generic_allocator::allocator_config! {
    impl AllocatorConfig for TestConfig {
        const MAX_ALLOCATION_SIZE: u64 = 6291456;
        const MAX_BINS: u32 = 4096;
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    size: u64,
    ops: Vec<Op>,
}

#[derive(Arbitrary, Debug)]
enum Op {
    Alloc { size: u64 },
    Free { index: usize },
}

fuzz_target!(|input: Input| {
    let mut allocator = polkavm::generic_allocator::tests::TestAllocator::<TestConfig>::new(input.size);
    let mut allocations: Vec<u64> = vec![];

    for method in input.ops {
        match method {
            Op::Alloc { size } => {
                if let Some(allocation) = allocator.alloc(size) {
                    allocations.push(allocation);
                }
            }
            Op::Free { index } => {
                if !allocations.is_empty() {
                    let index = index % allocations.len();
                    allocations.swap_remove(index);
                }
            }
        }
    }
});
