#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Alloc { page_count: u32 },
    Free { index: usize },
}

fuzz_target!(|ops: Vec<Op>| {
    let allocator = polkavm::_for_testing::create_shm_allocator().unwrap();
    let mut allocations: Vec<(polkavm::_for_testing::ShmAllocation, u32)> = vec![];

    const MAX_PAGES: u64 = 1024 * 1024 * 1024 / 4096;
    let mut count_pages = 0;

    for method in ops {
        match method {
            Op::Alloc { page_count } => {
                if (count_pages + page_count as u64) < MAX_PAGES {
                    let allocation = allocator.alloc((page_count * 4096) as usize).unwrap();
                    for (old_allocation, _) in &allocations {
                        let old_address = old_allocation.as_ptr() as usize;
                        let old_size = old_allocation.len();
                        let new_address = allocation.as_ptr() as usize;
                        let new_size = allocation.len();

                        if old_size == 0 || new_size == 0 {
                            continue;
                        }

                        let is_overlapping = (new_address >= old_address && new_address < (old_address + old_size))
                            || (new_address + new_size > old_address && new_address + new_size <= (old_address + old_size));

                        assert!(
                            !is_overlapping,
                            "overlapping allocation: original = 0x{:08x}-0x{:08x}, new = 0x{:08x}-0x{:08x}",
                            old_address,
                            old_address + old_size,
                            new_address,
                            new_address + new_size,
                        );
                    }
                    count_pages += page_count as u64;
                    allocations.push((allocation, page_count));
                }
            }
            Op::Free { index } => {
                if !allocations.is_empty() {
                    let index = index % allocations.len();
                    let (_, page_count) = allocations.swap_remove(index);
                    count_pages -= page_count as u64;
                }
            }
        }
    }
});
