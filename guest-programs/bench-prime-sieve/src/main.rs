#![no_std]
#![no_main]

include!("../../bench-common.rs");

struct State;
define_benchmark! {
    heap_size = 1024 * 1024,
    state = State,
}

use primes::PrimeSieve;

use crate::unrolled_extreme::FlagStorageExtremeHybrid;

mod unrolled;
mod unrolled_extreme;

pub mod primes {
    use alloc::vec;
    use alloc::vec::Vec;

    /// Shorthand for the `u8` bit count to avoid additional conversions.
    const U8_BITS: usize = u8::BITS as usize;

    /// Shorthand for the `u32` bit count to avoid additional conversions.
    const U32_BITS: usize = u32::BITS as usize;

    /// Validator to compare against known primes.
    #[derive(Default)]
    pub struct PrimeValidator;

    static PRIME_VALIDATOR_DATA: &[(usize, usize)] = &[
        (10, 4),   // Historical data for validating our results - the number of primes
        (100, 25), // to be found under some limit, such as 168 primes under 1000
        (1000, 168),
        (10000, 1229),
        (100000, 9592),
        (1000000, 78498),
        (10000000, 664579),
        (100000000, 5761455),
    ];

    impl PrimeValidator {
        // Return Some(true) or Some(false) if we know the answer, or None if we don't have
        // an entry for the given sieve_size.
        pub fn is_valid(&self, sieve_size: usize, result: usize) -> Option<bool> {
            if let Some(&(_, expected)) = PRIME_VALIDATOR_DATA.iter().find(|(size, _)| sieve_size == *size) {
                Some(result == expected)
            } else {
                None
            }
        }

        #[cfg(test)]
        pub fn known_results_iter(&self) -> impl Iterator<Item = (&usize, &usize)> {
            self.0.iter()
        }
    }

    /// Trait defining the interface to different kinds of storage, e.g.
    /// bits within bytes, a vector of bytes, etc.
    pub trait FlagStorage {
        /// create new storage for given number of flags pre-initialised to all true
        fn create_true(size: usize) -> Self;

        /// reset all flags for the given `skip` factor (prime); start is implied
        /// from the factor, and handled by the specific storage implementation
        fn reset_flags(&mut self, skip: usize);

        /// get a specific flag
        fn get(&self, index: usize) -> bool;
    }

    /// Recommended start for resetting bits -- at the square of the factor
    pub const fn square_start(skip_factor: usize) -> usize {
        skip_factor * skip_factor / 2
    }

    /// Minimum start for resetting bits -- this is the earliest reset
    /// we can apply without clobbering the factor itself
    pub const fn minimum_start(skip_factor: usize) -> usize {
        skip_factor / 2 + skip_factor
    }

    /// Storage using a simple vector of bytes.
    /// Doing the same with bools is equivalent, as bools are currently
    /// represented as bytes in Rust. However, this is not guaranteed to
    /// remain so for all time. To ensure consistent memory use in the future,
    /// we're explicitly using bytes (u8) here.
    pub struct FlagStorageByteVector(Vec<u8>);

    impl FlagStorage for FlagStorageByteVector {
        fn create_true(size: usize) -> Self {
            FlagStorageByteVector(vec![1; size])
        }

        #[inline(always)]
        fn reset_flags(&mut self, skip: usize) {
            let mut i = square_start(skip);

            // unrolled loop - there's a small benefit
            let end_unrolled = self.0.len().saturating_sub(skip * 3);
            while i < end_unrolled {
                // Safety: We have ensured that (i+skip*3) < self.0.len().
                // The compiler will not elide these bounds checks,
                // so there is a performance benefit to using get_unchecked_mut here.
                unsafe {
                    *self.0.get_unchecked_mut(i) = 0;
                    *self.0.get_unchecked_mut(i + skip) = 0;
                    *self.0.get_unchecked_mut(i + skip * 2) = 0;
                    *self.0.get_unchecked_mut(i + skip * 3) = 0;
                }
                i += skip * 4;
            }

            // bounds checks are elided
            while i < self.0.len() {
                self.0[i] = 0;
                i += skip;
            }
        }

        #[inline(always)]
        fn get(&self, index: usize) -> bool {
            if let Some(val) = self.0.get(index) {
                *val == 1
            } else {
                false
            }
        }
    }

    /// Storage using a vector of 32-bit words, but addressing individual bits within each. Bits are
    /// reset by applying a mask created by a shift on every iteration, similar to the C++ implementation.
    pub struct FlagStorageBitVector {
        words: Vec<u32>,
        length_bits: usize,
    }

    impl FlagStorage for FlagStorageBitVector {
        fn create_true(size: usize) -> Self {
            let num_words = size / U32_BITS + (size % U32_BITS).min(1);
            FlagStorageBitVector {
                words: vec![u32::MAX; num_words],
                length_bits: size,
            }
        }

        #[inline(always)]
        fn reset_flags(&mut self, skip: usize) {
            let mut i = square_start(skip);
            while i < self.words.len() * U32_BITS {
                let word_idx = i / U32_BITS;
                let bit_idx = i % U32_BITS;
                // Note: Unsafe usage to ensure that we elide the bounds check reliably.
                //       We have ensured that word_index < self.words.len().
                unsafe {
                    *self.words.get_unchecked_mut(word_idx) &= !(1 << bit_idx);
                }
                i += skip;
            }
        }

        #[inline(always)]
        fn get(&self, index: usize) -> bool {
            if index >= self.length_bits {
                return false;
            }
            let word = self.words.get(index / U32_BITS).unwrap();
            *word & (1 << (index % U32_BITS)) != 0
        }
    }

    /// Storage using a vector of 32-bit words, but addressing individual bits within each. Bits are
    /// reset by rotating the mask left instead of modulo+shift.
    pub struct FlagStorageBitVectorRotate {
        words: Vec<u32>,
        length_bits: usize,
    }

    impl FlagStorage for FlagStorageBitVectorRotate {
        fn create_true(size: usize) -> Self {
            let num_words = size / U32_BITS + (size % U32_BITS).min(1);
            FlagStorageBitVectorRotate {
                words: vec![u32::MAX; num_words],
                length_bits: size,
            }
        }

        #[inline(always)]
        fn reset_flags(&mut self, skip: usize) {
            let start = square_start(skip);
            let mut i = start;
            let roll_bits = skip as u32;
            let mut rolling_mask1 = !(1 << (start % U32_BITS));
            let mut rolling_mask2 = !(1 << ((start + skip) % U32_BITS));

            // if the skip is larger than the word size, we're clearing bits in different
            // words each time: we can unroll the loop
            if skip > U32_BITS {
                let roll_bits_double = roll_bits * 2;
                let unrolled_end = (self.words.len() * U32_BITS).saturating_sub(skip);
                while i < unrolled_end {
                    let word_idx1 = i / U32_BITS;
                    let word_idx2 = (i + skip) / U32_BITS;
                    // Safety: We have ensured that (i+skip) < self.words.len() * U32_BITS.
                    // The compiler will not elide these bounds checks,
                    // so there is a performance benefit to using get_unchecked_mut here.
                    unsafe {
                        *self.words.get_unchecked_mut(word_idx1) &= rolling_mask1;
                        *self.words.get_unchecked_mut(word_idx2) &= rolling_mask2;
                    }
                    rolling_mask1 = rolling_mask1.rotate_left(roll_bits_double);
                    rolling_mask2 = rolling_mask2.rotate_left(roll_bits_double);
                    i += skip * 2;
                }
            }

            while i < self.words.len() * U32_BITS {
                let word_idx = i / U32_BITS;
                // Safety: We have ensured that word_index < self.words.len().
                // Unsafe required to ensure that we elide the bounds check reliably.
                unsafe {
                    *self.words.get_unchecked_mut(word_idx) &= rolling_mask1;
                }
                i += skip;
                rolling_mask1 = rolling_mask1.rotate_left(roll_bits);
            }
        }

        #[inline(always)]
        fn get(&self, index: usize) -> bool {
            if index >= self.length_bits {
                return false;
            }
            let word = self.words.get(index / U32_BITS).unwrap();
            *word & (1 << (index % U32_BITS)) != 0
        }
    }

    /// Storage using a vector of (8-bit) bytes, but individually addressing bits within
    /// each byte for bit-level storage. This is a fun variation I made up myself, but
    /// I'm pretty sure it's not original: someone must have done this before, and it
    /// probably has a name. If you happen to know, let me know :)
    ///
    /// The idea here is to store bits in a different order. First we make use of all the
    /// _first_ bits in each word. Then we come back to the start of the array and
    /// proceed to use the _second_ bit in each word, and so on.
    ///
    /// There is a computation / memory bandwidth tradeoff here. This works well
    /// only for sieves that fit inside the processor cache. For processors with
    /// smaller caches or larger sieves, this algorithm will result in a lot of
    /// cache thrashing due to multiple passes. It really doesn't work well on something
    /// like a raspberry pi.
    ///
    /// [`FlagStorageBitVectorStripedBlocks`] takes a more cache-friendly approach.
    pub struct FlagStorageBitVectorStriped {
        words: Vec<u8>,
        length_bits: usize,
    }

    impl FlagStorage for FlagStorageBitVectorStriped {
        fn create_true(size: usize) -> Self {
            let num_words = size / U8_BITS + (size % U8_BITS).min(1);
            Self {
                words: vec![u8::MAX; num_words],
                length_bits: size,
            }
        }

        #[inline(always)]
        fn reset_flags(&mut self, skip: usize) {
            // determine start bit, and first word
            let start = square_start(skip);
            let words_len = self.words.len();
            let mut bit_idx = start / words_len;
            let mut word_idx = start % words_len;

            while bit_idx < U8_BITS {
                // calculate effective end position: we might have a shorter stripe on the last iteration
                let stripe_start_position = bit_idx * words_len;
                let effective_len = words_len.min(self.length_bits - stripe_start_position);

                // get mask for this bit position
                let mask = !(1 << bit_idx);

                // unrolled loop
                while word_idx < effective_len.saturating_sub(skip) {
                    // Safety: we have ensured that (word_idx + skip*N) < length
                    unsafe {
                        *self.words.get_unchecked_mut(word_idx) &= mask;
                        *self.words.get_unchecked_mut(word_idx + skip) &= mask;
                    }
                    word_idx += skip * 2;
                }

                // remainder
                while word_idx < effective_len {
                    // safety: we have ensured that word_idx < length
                    unsafe {
                        *self.words.get_unchecked_mut(word_idx) &= mask;
                    }
                    word_idx += skip;
                }

                // early termination: this is the last stripe
                if effective_len != words_len {
                    return;
                }

                // bit/stripe complete; advance to next bit
                bit_idx += 1;
                word_idx -= words_len;
            }
        }

        #[inline(always)]
        fn get(&self, index: usize) -> bool {
            if index > self.length_bits {
                return false;
            }
            let word_index = index % self.words.len();
            let bit_index = index / self.words.len();
            let word = self.words.get(word_index).unwrap();
            *word & (1 << bit_index) != 0
        }
    }

    /// This is a variation of [`FlagStorageBitVectorStriped`] that has better locality.
    /// The striped storage is divided up into smaller blocks, and we do multiple
    /// passes over the smaller block rather than the entire sieve.
    ///
    /// The implementation is generic over two parameters, making use of Rust's new
    /// const generics.
    /// - `BLOCK_SIZE` is the size of the blocks, in words (bytes seem to work best)
    /// - `HYBRID` is a boolean specifying whether to enable a slightly different
    ///   algorithm for resetting smaller factors.
    ///   - `false` disables the algorithm, falling back on only the original striped block resets
    ///   - `true` enables the new algorithm for smaller skip factors (under 8)
    ///
    /// Since there are a lot of bits to reset for smaller factors, there is a moderate
    /// performance gain from using the `HYBRID` approach.
    pub struct FlagStorageBitVectorStripedBlocks<const BLOCK_SIZE: usize, const HYBRID: bool> {
        blocks: Vec<[u8; BLOCK_SIZE]>,
        length_bits: usize,
    }

    /// This is the optimal block size for [`FlagStorageBitVectorStriped`] for CPUs
    /// with a fair amount of L1 cache, and works well on AMD Ryzen.
    pub const BLOCK_SIZE_DEFAULT: usize = 16 * 1024;

    /// This is a good block size for [`FlagStorageBitVectorStriped`] for CPUs with
    /// less L1 cache available. It's also useful when running many sieves
    /// in parallel.
    pub const BLOCK_SIZE_SMALL: usize = 4 * 1024;

    impl<const BLOCK_SIZE: usize, const HYBRID: bool> FlagStorageBitVectorStripedBlocks<BLOCK_SIZE, HYBRID> {
        const BLOCK_SIZE_BITS: usize = BLOCK_SIZE * U8_BITS;

        /// Returns `1` if the `index` for a given `start`, and `skip`
        /// should be reset; `0` otherwise.
        fn should_reset(index: usize, start: usize, skip: usize) -> u8 {
            let rel = index as isize - start as isize;
            if rel % skip as isize == 0 {
                1
            } else {
                0
            }
        }

        /// This is the new algorithm for resetting words in a different
        /// order from the original `reset_flags_general` algorithm below.
        ///
        /// In the original algorithm, we reset all the first bits in the block,
        /// then all the second bits, and so on. This works really well in the
        /// general case, when we have a large skip factor, as we don't touch
        /// most words.
        ///
        /// We use this algorithm when the skip factors are small, say less
        /// than 8. In this case, we're typically touching every word in the block,
        /// and we can expect each word to have multiple bits that need to be reset.
        /// So we proceed in a different order, one word at a time. And for each
        /// word, we reset the bits one by one.
        ///
        /// Note that the algorithm is generic over the `SKIP` factor, which
        /// allows the compiler to do some extra optimisation. Each skip factor
        /// we specify will result in specific code.
        #[inline(always)]
        fn reset_flags_dense<const SKIP: usize>(&mut self) {
            // earliest start to avoid resetting the factor itself
            let start = SKIP / 2 + SKIP;
            debug_assert!(start < BLOCK_SIZE, "algorithm only correct for small skip factors");
            for (block_idx, block) in self.blocks.iter_mut().enumerate() {
                // Preserve the first bit of one word we know we're going to overwrite
                // with the masks. Its cheaper to put it back afterwards than break the loop
                // into two sections with different rules. Only applicable on the first block:
                // this is the factor itself, and we don't want to reset that flag.
                let preserved_word_mask = if block_idx == 0 { block[SKIP / 2] & 1 } else { 0 };

                // Calculate the masks we're going to apply first. Note that each mask
                // will reset only a single bit, which is why we have 8 separate masks.
                // Note that we _could_ calculate a single mask word and apply it in a
                // single operation, but I believe that would be against the rules as
                // we would be resetting multiple bits in one operation if we did that.
                let mut mask_set = [[0u8; U8_BITS]; SKIP];
                #[allow(clippy::needless_range_loop)]
                for word_idx in 0..SKIP {
                    for bit in 0..8 {
                        let block_index_offset = block_idx * BLOCK_SIZE * U8_BITS;
                        let bit_index_offset = bit * BLOCK_SIZE;
                        let index = block_index_offset + bit_index_offset + word_idx;
                        mask_set[word_idx][bit] = !(Self::should_reset(index, start, SKIP) << bit);
                    }
                }
                // rebind as immutable
                let mask_set = mask_set;

                /// apply all 8 masks - one for each bit - using a fold, mostly
                /// because folds are fun
                fn apply_masks(word: &mut u8, masks: &[u8; U8_BITS]) {
                    *word = masks.iter().fold(*word, |w, mask| w & mask);
                }

                // run through all exact `SKIP` size chunks - the compiler is able to
                // optimise known sizes quite well.
                block.chunks_exact_mut(SKIP).for_each(|words| {
                    words.iter_mut().zip(mask_set.iter().copied()).for_each(|(word, masks)| {
                        apply_masks(word, &masks);
                    });
                });

                // run through the remaining stub of fewer than SKIP items
                block
                    .chunks_exact_mut(SKIP)
                    .into_remainder()
                    .iter_mut()
                    .zip(mask_set.iter().copied())
                    .for_each(|(word, masks)| {
                        apply_masks(word, &masks);
                    });

                // restore the first bit on the preserved word in the first block,
                // as noted above
                if block_idx == 0 {
                    block[SKIP / 2] |= preserved_word_mask;
                }
            }
        }

        /// This is the original striped-blocks algorithm, and proceeds to
        /// set the first bit in every applicable word, then the second bit
        /// and so on. This works really well for larger skip sizes, as the
        /// words we need to reset are generally quite far apart.
        #[inline(always)]
        fn reset_flags_general(&mut self, skip: usize) {
            // determine first block, start bit, and first word
            let start = square_start(skip);
            let block_idx_start = start / Self::BLOCK_SIZE_BITS;
            let offset_idx = start % Self::BLOCK_SIZE_BITS;
            let mut bit_idx = offset_idx / BLOCK_SIZE;
            let mut word_idx = offset_idx % BLOCK_SIZE;

            for block_idx in block_idx_start..self.blocks.len() {
                // Safety: we have ensured the block_idx < length
                let block = unsafe { self.blocks.get_unchecked_mut(block_idx) };
                while bit_idx < U8_BITS {
                    // calculate effective end position: we might have a shorter stripe on the last iteration
                    let stripe_start_position = block_idx * Self::BLOCK_SIZE_BITS + bit_idx * BLOCK_SIZE;
                    let effective_len = BLOCK_SIZE.min(self.length_bits - stripe_start_position);

                    // get mask for this bit position
                    let mask = !(1 << bit_idx);

                    // unrolled loop
                    while word_idx < effective_len.saturating_sub(skip * 3) {
                        // Safety: we have ensured that (word_idx + skip*N) < length
                        unsafe {
                            *block.get_unchecked_mut(word_idx) &= mask;
                            *block.get_unchecked_mut(word_idx + skip) &= mask;
                            *block.get_unchecked_mut(word_idx + skip * 2) &= mask;
                            *block.get_unchecked_mut(word_idx + skip * 3) &= mask;
                        }
                        word_idx += skip * 4;
                    }

                    // remainder
                    while word_idx < effective_len {
                        // safety: we have ensured that word_idx < length
                        unsafe {
                            *block.get_unchecked_mut(word_idx) &= mask;
                        }
                        word_idx += skip;
                    }

                    // early termination: this is the last stripe
                    if effective_len != BLOCK_SIZE {
                        return;
                    }

                    // bit/stripe complete; advance to next bit
                    bit_idx += 1;
                    word_idx -= BLOCK_SIZE;
                }

                // block complete; reset bit index and proceed with the next block
                bit_idx = 0;
            }
        }
    }

    impl<const BLOCK_SIZE: usize, const HYBRID: bool> FlagStorage for FlagStorageBitVectorStripedBlocks<BLOCK_SIZE, HYBRID> {
        fn create_true(size: usize) -> Self {
            let num_blocks = size / Self::BLOCK_SIZE_BITS + (size % Self::BLOCK_SIZE_BITS).min(1);
            Self {
                length_bits: size,
                blocks: vec![[u8::MAX; BLOCK_SIZE]; num_blocks],
            }
        }

        /// Reset flags specified by the sieve. We use the optional
        /// hybrid/dense reset methods for small factors if the
        /// `HYBRID` type parameter is true, with the general
        /// algorithm for higher skip factors. If `HYBRID` is false,
        /// we rely only on the general approach for all skip factors.
        #[inline(always)]
        fn reset_flags(&mut self, skip: usize) {
            if HYBRID {
                match skip {
                    // We only really gain an advantage from dense
                    // resetting up to skip factors under 8, as after
                    // that, we're expecting the resets to be sparse.
                    // We only get called for odd skip factors, so there's
                    // no point adding cases for even numbers.
                    1 => self.reset_flags_dense::<1>(),
                    3 => self.reset_flags_dense::<3>(),
                    5 => self.reset_flags_dense::<5>(),
                    7 => self.reset_flags_dense::<7>(),
                    _ => self.reset_flags_general(skip),
                }
            } else {
                self.reset_flags_general(skip);
            }
        }

        #[inline(always)]
        fn get(&self, index: usize) -> bool {
            if index > self.length_bits {
                return false;
            }
            let block = index / Self::BLOCK_SIZE_BITS;
            let offset = index % Self::BLOCK_SIZE_BITS;
            let bit_index = offset / BLOCK_SIZE;
            let word_index = offset % BLOCK_SIZE;
            let word = self.blocks.get(block).unwrap().get(word_index).unwrap();
            *word & (1 << bit_index) != 0
        }
    }

    /// The actual sieve implementation, generic over the storage. This allows us to
    /// include the storage type we want without re-writing the algorithm each time.
    pub struct PrimeSieve<T: FlagStorage> {
        pub sieve_size: usize,
        flags: T,
    }

    impl<T> PrimeSieve<T>
    where
        T: FlagStorage,
    {
        #[inline(always)]
        pub fn new(sieve_size: usize) -> Self {
            let num_flags = sieve_size / 2 + 1;
            PrimeSieve {
                sieve_size,
                flags: T::create_true(num_flags),
            }
        }

        fn is_num_flagged(&self, number: usize) -> bool {
            if number % 2 == 0 {
                return false;
            }
            let index = number / 2;
            self.flags.get(index)
        }

        // count number of primes (not optimal, but doesn't need to be)
        pub fn count_primes(&self) -> usize {
            (1..self.sieve_size).filter(|v| self.is_num_flagged(*v)).count()
        }

        // calculate the primes up to the specified limit
        #[inline(always)]
        pub fn run_sieve(&mut self) {
            let mut factor = 3;
            let q = softfloat::F32::from_u32(self.sieve_size as u32).sqrt().to_u32() as usize;

            loop {
                // find next factor - next still-flagged number
                factor = (factor / 2..self.sieve_size / 2).find(|n| self.flags.get(*n)).unwrap() * 2 + 1;

                // check for termination _before_ resetting flags;
                // note: need to check up to and including q, otherwise we
                // fail to catch cases like sieve_size = 1000
                if factor > q {
                    break;
                }

                // reset flags starting at `start`, every `factor`'th flag
                let skip = factor;
                self.flags.reset_flags(skip);

                factor += 2;
            }
        }
    }
}

fn run_sieve(limit: usize) -> PrimeSieve<FlagStorageExtremeHybrid> {
    let mut sieve: PrimeSieve<FlagStorageExtremeHybrid> = primes::PrimeSieve::new(limit);
    sieve.run_sieve();
    sieve
}

fn benchmark_initialize(_state: &mut State) {
    for limit in [100, 1000, 10000, 100000, 1000000, 10000000] {
        let prime_sieve = run_sieve(limit);
        assert_eq!(
            crate::primes::PrimeValidator.is_valid(prime_sieve.sieve_size, prime_sieve.count_primes()),
            Some(true)
        );
    }
}

fn benchmark_run(_state: &mut State) {
    core::hint::black_box(run_sieve(10000000));
}
