use crate::abi::{VM_CODE_ADDRESS_ALIGNMENT, VM_MAXIMUM_CODE_SIZE, VM_MAXIMUM_IMPORT_COUNT, VM_MAXIMUM_JUMP_TABLE_ENTRIES};
use crate::cast::cast;
use crate::utils::ArcBytes;
use crate::varint::{read_simple_varint, read_varint, simple_varint_length, write_simple_varint_with_length, MAX_VARINT_LENGTH};
use core::fmt::Write;
use core::ops::Range;

#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct RawReg(u32);

#[cfg(feature = "alloc")]
use crate::abi::MemoryMapBuilder;

impl Eq for RawReg {}
impl PartialEq for RawReg {
    fn eq(&self, rhs: &Self) -> bool {
        self.get() == rhs.get()
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for RawReg {
    fn arbitrary(unstructured: &mut arbitrary::Unstructured) -> Result<Self, arbitrary::Error> {
        Reg::arbitrary(unstructured).map(|reg| reg.into())
    }
}

impl RawReg {
    #[inline]
    pub const fn get(self) -> Reg {
        let mut value = self.0 & 0b1111;
        if value > 12 {
            value = 12;
        }

        let Some(reg) = Reg::from_raw(value) else { unreachable!() };
        reg
    }

    #[inline]
    pub const fn raw_unparsed(self) -> u32 {
        self.0
    }
}

impl From<Reg> for RawReg {
    fn from(reg: Reg) -> Self {
        Self(reg as u32)
    }
}

impl From<RawReg> for Reg {
    fn from(reg: RawReg) -> Self {
        reg.get()
    }
}

impl core::fmt::Debug for RawReg {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "{} (0x{:x})", self.get(), self.0)
    }
}

impl core::fmt::Display for RawReg {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.get().fmt(fmt)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u32)]
pub enum Reg {
    RA = 0,
    SP = 1,
    T0 = 2,
    T1 = 3,
    T2 = 4,
    S0 = 5,
    S1 = 6,
    A0 = 7,
    A1 = 8,
    A2 = 9,
    A3 = 10,
    A4 = 11,
    A5 = 12,
}

impl Reg {
    #[inline]
    pub const fn to_usize(self) -> usize {
        self as usize
    }

    #[inline]
    pub const fn to_u32(self) -> u32 {
        self as u32
    }

    #[inline]
    pub const fn raw(self) -> RawReg {
        RawReg(self as u32)
    }

    #[inline]
    pub const fn from_raw(value: u32) -> Option<Reg> {
        Some(match value {
            0 => Reg::RA,
            1 => Reg::SP,
            2 => Reg::T0,
            3 => Reg::T1,
            4 => Reg::T2,
            5 => Reg::S0,
            6 => Reg::S1,
            7 => Reg::A0,
            8 => Reg::A1,
            9 => Reg::A2,
            10 => Reg::A3,
            11 => Reg::A4,
            12 => Reg::A5,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        use Reg::*;
        match self {
            RA => "ra",
            SP => "sp",
            T0 => "t0",
            T1 => "t1",
            T2 => "t2",
            S0 => "s0",
            S1 => "s1",
            A0 => "a0",
            A1 => "a1",
            A2 => "a2",
            A3 => "a3",
            A4 => "a4",
            A5 => "a5",
        }
    }

    pub const fn name_non_abi(self) -> &'static str {
        use Reg::*;
        match self {
            RA => "r0",
            SP => "r1",
            T0 => "r2",
            T1 => "r3",
            T2 => "r4",
            S0 => "r5",
            S1 => "r6",
            A0 => "r7",
            A1 => "r8",
            A2 => "r9",
            A3 => "r10",
            A4 => "r11",
            A5 => "r12",
        }
    }

    /// List of all of the VM's registers.
    pub const ALL: [Reg; 13] = {
        use Reg::*;
        [RA, SP, T0, T1, T2, S0, S1, A0, A1, A2, A3, A4, A5]
    };

    /// List of all input/output argument registers.
    pub const ARG_REGS: [Reg; 9] = [Reg::A0, Reg::A1, Reg::A2, Reg::A3, Reg::A4, Reg::A5, Reg::T0, Reg::T1, Reg::T2];

    pub const MAXIMUM_INPUT_REGS: usize = 9;
    pub const MAXIMUM_OUTPUT_REGS: usize = 2;
}

impl core::fmt::Display for Reg {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self.name())
    }
}

#[inline(never)]
#[cold]
fn find_next_offset_legacy_unbounded(bitmask: &[u8], code_len: u32, mut offset: u32) -> u32 {
    while let Some(&byte) = bitmask.get(offset as usize >> 3) {
        let shift = offset & 7;
        let mask = byte >> shift;
        if mask == 0 {
            offset += 8 - shift;
        } else {
            offset += mask.trailing_zeros();
            break;
        }
    }

    core::cmp::min(code_len, offset)
}

#[inline(never)]
fn visitor_step_slow_legacy<T>(
    state: &mut <T as OpcodeVisitor>::State,
    code: &[u8],
    bitmask: &[u8],
    offset: u32,
    opcode_visitor: T,
) -> (u32, <T as OpcodeVisitor>::ReturnTy, bool)
where
    T: OpcodeVisitor,
{
    if offset as usize >= code.len() {
        return (offset + 1, visitor_step_invalid_instruction(state, offset, 1, opcode_visitor), true);
    }

    debug_assert!(code.len() <= u32::MAX as usize);
    debug_assert_eq!(bitmask.len(), code.len().div_ceil(8));
    debug_assert!(offset as usize <= code.len());
    debug_assert!(get_bit_for_offset(bitmask, code.len(), offset), "bit at {offset} is zero");

    let (skip, mut is_next_instruction_invalid) = parse_bitmask_slow(bitmask, code.len(), offset);
    let chunk = load_chunk(code, offset as usize);
    let opcode = chunk as u8;

    if is_next_instruction_invalid && offset as usize + skip as usize + 1 >= code.len() {
        // This is the last instruction.
        if !opcode_visitor
            .instruction_set()
            .opcode_from_raw(u32::from(opcode))
            .unwrap_or(Opcode::trap)
            .can_fallthrough()
        {
            // We can't fallthrough, so there's no need to inject a trap after this instruction.
            is_next_instruction_invalid = false;
        }
    }

    (
        offset + skip + 1,
        opcode_visitor.dispatch(state, usize::from(opcode), chunk, offset, skip + 1),
        is_next_instruction_invalid,
    )
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn visitor_step_fast_legacy<T>(
    state: &mut <T as OpcodeVisitor>::State,
    code: &[u8],
    bitmask: &[u8],
    offset: u32,
    opcode_visitor: T,
) -> (u32, <T as OpcodeVisitor>::ReturnTy, bool)
where
    T: OpcodeVisitor,
{
    debug_assert!(code.len() <= u32::MAX as usize);
    debug_assert_eq!(bitmask.len(), code.len().div_ceil(8));
    debug_assert!(offset as usize <= code.len());
    debug_assert!(get_bit_for_offset(bitmask, code.len(), offset), "bit at {offset} is zero");
    debug_assert!(offset as usize + 32 <= code.len());

    let Some(skip) = parse_bitmask_fast(bitmask, offset) else {
        unreachable!()
    };

    let chunk = load_chunk(code, offset as usize);
    let opcode = usize::from(chunk as u8);

    debug_assert!(skip <= BITMASK_MAX);
    let result = opcode_visitor.dispatch(state, opcode, chunk, offset, skip + 1);

    let next_offset = offset + skip + 1;
    let is_next_instruction_invalid = skip == 24 && !get_bit_for_offset(bitmask, code.len(), next_offset);
    (next_offset, result, is_next_instruction_invalid)
}

#[cfg_attr(not(debug_assertions), inline(always))]
#[cold]
fn visitor_step_invalid_instruction<T>(state: &mut <T as OpcodeVisitor>::State, offset: u32, length: u32, opcode_visitor: T) -> T::ReturnTy
where
    T: OpcodeVisitor,
{
    opcode_visitor.dispatch(state, LEGACY_INVALID_RAW_OPCODE as usize, 0, offset, length)
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn visitor_step_runner_legacy<T, const FAST_PATH: bool>(
    state: &mut <T as OpcodeVisitor>::State,
    code: &[u8],
    bitmask: &[u8],
    mut offset: u32,
    opcode_visitor: T,
) -> u32
where
    T: OpcodeVisitor<ReturnTy = ()>,
{
    let (next_offset, (), is_next_instruction_invalid) = if FAST_PATH {
        visitor_step_fast_legacy(state, code, bitmask, offset, opcode_visitor)
    } else {
        visitor_step_slow_legacy(state, code, bitmask, offset, opcode_visitor)
    };

    offset = next_offset;
    if is_next_instruction_invalid {
        // The invalid instruction covers everything up until the next real instruction.
        let next_offset = if (offset as usize) < code.len() {
            let next_offset = find_next_offset_legacy_unbounded(bitmask, code.len() as u32, offset);
            debug_assert!(next_offset > offset);
            next_offset
        } else {
            offset
        };

        visitor_step_invalid_instruction(state, offset, next_offset - offset, opcode_visitor);
        offset = next_offset;
    }

    offset
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn visitor_run<T>(state: &mut <T as OpcodeVisitor>::State, blob: &ProgramBlob, opcode_visitor: T)
where
    T: OpcodeVisitor<ReturnTy = ()>,
{
    if opcode_visitor.instruction_set().is_legacy() {
        visitor_run_legacy(state, blob.code(), blob.bitmask(), opcode_visitor)
    } else {
        visitor_run_extended(state, blob.code(), opcode_visitor)
    }
}

// Having this be never inlined makes it easier to analyze the resulting assembly/machine code,
// and it also seems to make the code mariginally faster for some reason.
#[inline(never)]
fn visitor_run_legacy<T>(state: &mut <T as OpcodeVisitor>::State, code: &[u8], bitmask: &[u8], opcode_visitor: T)
where
    T: OpcodeVisitor<ReturnTy = ()>,
{
    let mut offset = 0;
    if !get_bit_for_offset(bitmask, code.len(), 0) {
        offset = find_next_offset_legacy_unbounded(bitmask, code.len() as u32, 0);
        visitor_step_invalid_instruction(state, 0, offset, opcode_visitor);
    }

    while cast(offset).to_usize() + 32 <= code.len() {
        offset = visitor_step_runner_legacy::<T, true>(state, code, bitmask, offset, opcode_visitor);
    }

    while cast(offset).to_usize() < code.len() {
        offset = visitor_step_runner_legacy::<T, false>(state, code, bitmask, offset, opcode_visitor);
    }
}

#[inline(never)]
fn visitor_run_extended<T>(state: &mut <T as OpcodeVisitor>::State, code: &[u8], opcode_visitor: T)
where
    T: OpcodeVisitor<ReturnTy = ()>,
{
    let table = opcode_visitor.instruction_set().raw_opcode_table();
    let mut offset: usize = 0;

    if code.len() >= CODE_BLOCK_SIZE {
        offset = visitor_run_extended_full_blocks::<T>(state, code, opcode_visitor, table);
    }

    if offset < code.len() {
        offset = visitor_run_extended_last_block::<T>(state, code, opcode_visitor, table, offset);
    }

    debug_assert_eq!(offset, code.len());
}

#[must_use]
#[inline(never)]
fn visitor_run_extended_full_blocks<T>(
    state: &mut <T as OpcodeVisitor>::State,
    code: &[u8],
    opcode_visitor: T,
    table: &'static RawOpcodeTable,
) -> usize
where
    T: OpcodeVisitor<ReturnTy = ()>,
{
    let loop_boundary = (code.len() / CODE_BLOCK_SIZE) * CODE_BLOCK_SIZE;
    let mut offset = 0;
    while offset < loop_boundary {
        debug_assert!(is_on_a_block_boundary(offset));

        let block_boundary = offset + CODE_BLOCK_SIZE;
        while offset < block_boundary {
            offset = visitor_step_extended::<T>(state, code, offset, block_boundary, opcode_visitor, table);
        }

        debug_assert_eq!(offset, block_boundary);
    }

    offset
}

#[must_use]
#[inline(never)]
fn visitor_run_extended_last_block<T>(
    state: &mut <T as OpcodeVisitor>::State,
    code: &[u8],
    opcode_visitor: T,
    table: &'static RawOpcodeTable,
    mut offset: usize,
) -> usize
where
    T: OpcodeVisitor<ReturnTy = ()>,
{
    debug_assert!(is_on_a_block_boundary(offset));
    debug_assert!(code.len() - offset < CODE_BLOCK_SIZE);

    let block_boundary = code.len();
    let bulk_boundary = (code.len() / 16) * 16;
    while offset < bulk_boundary {
        // Fast path.
        offset = visitor_step_extended::<T>(state, code, offset, block_boundary, opcode_visitor, table);
    }

    while offset < code.len() {
        // Slow path.
        offset = visitor_step_extended::<T>(state, code, offset, block_boundary, opcode_visitor, table);
    }

    offset
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn load_chunk(code: &[u8], offset: usize) -> u128 {
    let chunk = code.get(offset..offset + 16);
    if let Some(chunk) = chunk {
        // NOTE: This should produce the same assembly as the unsafe `read_unaligned`.
        u128::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7], chunk[8], chunk[9], chunk[10], chunk[11],
            chunk[12], chunk[13], chunk[14], chunk[15],
        ])
    } else {
        let code = &code[core::cmp::min(offset, code.len())..];
        let mut t: [u8; 16] = [0; 16];
        t[..code.len()].copy_from_slice(code);
        u128::from_le_bytes([
            t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], t[9], t[10], t[11], t[12], t[13], t[14], t[15],
        ])
    }
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn extract_opcode(chunk: u32) -> u32 {
    let raw_opcode = chunk & 0xffff;
    let mut opcode = raw_opcode & 0xff;
    if opcode == u32::from(EXTENDED_OPCODE_PREFIX) {
        opcode += raw_opcode >> 8;
    }

    opcode
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn visitor_step_extended<T>(
    state: &mut <T as OpcodeVisitor>::State,
    code: &[u8],
    offset: usize,
    block_boundary: usize,
    opcode_visitor: T,
    table: &'static RawOpcodeTable,
) -> usize
where
    T: OpcodeVisitor<ReturnTy = ()>,
{
    let ((), next_offset) = parse_raw_extended(code, offset, block_boundary, table, move |raw_opcode, chunk, offset, length| {
        debug_assert!(offset + cast(length).to_usize() <= block_boundary);
        opcode_visitor.dispatch(
            state,
            cast(raw_opcode).to_usize(),
            chunk,
            cast(offset).to_u32_or_debug_panic(),
            length,
        );
    });

    next_offset
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn parse_raw_extended<F, R>(code: &[u8], offset: usize, block_boundary: usize, table: &'static RawOpcodeTable, callback: F) -> (R, usize)
where
    F: FnOnce(u32, u128, usize, u32) -> R,
{
    debug_assert!(code.len() <= u32::MAX as usize);
    debug_assert!(offset <= code.len());

    let chunk: u128 = load_chunk(code, offset);
    let mut raw_opcode = extract_opcode(chunk as u32);
    let Some(length) = table.length_table.get(cast(raw_opcode).to_usize()) else {
        unreachable!();
    };

    let mut length = length.get();
    let mut next_offset = offset + cast(length).to_usize();
    if next_offset >= block_boundary {
        // The last instruction of a macro block has to fit in it and has to end a basic block, otherwise it becomes a trap.
        if next_offset > block_boundary || !table.ends_basic_block(cast(raw_opcode).to_usize()) {
            raw_opcode = cast(EXTENDED_INVALID_RAW_OPCODE).to_u32_or_debug_panic();
        }

        length = cast(block_boundary - offset).to_u32_or_debug_panic();
        next_offset = block_boundary;
    }

    let result = callback(raw_opcode, chunk, offset, length);
    debug_assert!(next_offset > offset);
    (result, next_offset)
}

#[derive(Copy, Clone, Debug)]
struct ExtendedStep {
    raw_opcode: usize,
    next_offset: usize,
    #[allow(dead_code)]
    length: u32,
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn parse_simple_extended<I>(instruction_set: I, code: &[u8], offset: usize) -> ExtendedStep
where
    I: InstructionSet,
{
    let ((raw_opcode, length), next_offset) = parse_raw_extended(
        code,
        offset,
        end_of_macro_block(offset, code.len()),
        instruction_set.raw_opcode_table(),
        |raw_opcode, _, _, length| (raw_opcode, length),
    );

    ExtendedStep {
        raw_opcode: cast(raw_opcode).to_usize(),
        next_offset,
        length,
    }
}

#[inline(always)]
fn sign_extend_at(value: u32, bits_to_cut: u32) -> u32 {
    (((u64::from(value) << bits_to_cut) as u32 as i32).wrapping_shr(bits_to_cut)) as u32
}

type LookupEntry = u32;
const EMPTY_LOOKUP_ENTRY: LookupEntry = 0;

#[repr(transparent)]
struct LookupTable([LookupEntry; 256]);

impl LookupTable {
    const fn pack(imm1_bits: u32, imm1_skip: u32, imm2_bits: u32) -> LookupEntry {
        assert!(imm1_bits <= 0b111111);
        assert!(imm2_bits <= 0b111111);
        assert!(imm1_skip <= 0b111111);
        (imm1_bits) | ((imm1_skip) << 6) | ((imm2_bits) << 12)
    }

    #[inline(always)]
    fn unpack(entry: LookupEntry) -> (u32, u32, u32) {
        (entry & 0b111111, (entry >> 6) & 0b111111, (entry >> 12) & 0b111111)
    }

    const fn build(offset: i32) -> Self {
        const fn min_u32(a: u32, b: u32) -> u32 {
            if a < b {
                a
            } else {
                b
            }
        }

        const fn clamp_i32(range: core::ops::RangeInclusive<i32>, value: i32) -> i32 {
            if value < *range.start() {
                *range.start()
            } else if value > *range.end() {
                *range.end()
            } else {
                value
            }
        }

        const fn sign_extend_cutoff_for_length(length: u32) -> u32 {
            match length {
                0 => 32,
                1 => 24,
                2 => 16,
                3 => 8,
                4 => 0,
                _ => unreachable!(),
            }
        }

        let mut output = [EMPTY_LOOKUP_ENTRY; 256];
        let mut skip = 0;
        while skip <= 0b11111 {
            let mut aux = 0;
            while aux <= 0b111 {
                let imm1_length = min_u32(4, aux);
                let imm2_length = clamp_i32(0..=4, skip as i32 - imm1_length as i32 - offset) as u32;
                let imm1_bits = sign_extend_cutoff_for_length(imm1_length);
                let imm2_bits = sign_extend_cutoff_for_length(imm2_length);
                let imm1_skip = imm1_length * 8;

                let index = Self::get_lookup_index(skip, aux);
                output[index as usize] = Self::pack(imm1_bits, imm1_skip, imm2_bits);
                aux += 1;
            }
            skip += 1;
        }

        LookupTable(output)
    }

    #[inline(always)]
    const fn get_lookup_index(skip: u32, aux: u32) -> u32 {
        debug_assert!(skip <= 0b11111);
        let skip = skip & 0b11111;
        let index = skip | ((aux & 0b111) << 5);
        debug_assert!(index <= 0xff);
        index
    }

    #[inline(always)]
    fn get(&self, skip: u32, aux: u32) -> (u32, u32, u32) {
        let index = Self::get_lookup_index(skip, aux);
        debug_assert!((index as usize) < self.0.len());

        #[allow(unsafe_code)]
        // SAFETY: `index` is composed of a 5-bit `skip` and 3-bit `aux`,
        // which gives us 8 bits in total, and the table's length is 256,
        // so out of bounds access in impossible.
        Self::unpack(*unsafe { self.0.get_unchecked(index as usize) })
    }
}

pub const INTERPRETER_CACHE_ENTRY_SIZE: u32 = {
    if cfg!(target_pointer_width = "32") {
        20
    } else if cfg!(target_pointer_width = "64") {
        24
    } else {
        panic!("unsupported target pointer width")
    }
};

pub const INTERPRETER_FLATMAP_ENTRY_SIZE: u32 = 4;

pub fn interpreter_calculate_cache_size(count: usize) -> usize {
    count * INTERPRETER_CACHE_ENTRY_SIZE as usize
}

pub fn interpreter_calculate_cache_num_entries(bytes: usize) -> usize {
    bytes / INTERPRETER_CACHE_ENTRY_SIZE as usize
}

static TABLE_2: LookupTable = LookupTable::build(2);
static TABLE_3: LookupTable = LookupTable::build(3);
static TABLE_4: LookupTable = LookupTable::build(4);

#[inline(always)]
fn fixup_length<const EXT: bool>(length: u32) -> u32 {
    if EXT {
        length - 2
    } else {
        length - 1
    }
}

#[inline(always)]
const fn fixup_shift<const EXT: bool>() -> u32 {
    if EXT {
        16
    } else {
        8
    }
}

#[inline(always)]
fn chunk_into_u64<const EXT: bool, const EXTRA_SHIFT: u32>(chunk: u128) -> u64 {
    let shift = const { fixup_shift::<EXT>() + EXTRA_SHIFT };
    (chunk >> shift) as u64
}

#[inline(always)]
fn chunk_into_u32<const EXT: bool, const EXTRA_SHIFT: u32>(chunk: u128) -> u32 {
    let shift = const {
        let shift = fixup_shift::<EXT>() + EXTRA_SHIFT;
        assert!(shift <= 32);
        shift
    };
    ((chunk as u64) >> shift) as u32
}

#[inline(always)]
fn fixup_chunk64<const EXT: bool>(chunk: u128) -> u64 {
    (chunk as u64) >> fixup_shift::<EXT>()
}

#[inline(always)]
const fn fixup_table_1<const EXT: bool>() -> &'static LookupTable {
    if EXT {
        &TABLE_3
    } else {
        &TABLE_2
    }
}

#[inline(always)]
const fn fixup_table_2<const EXT: bool>() -> &'static LookupTable {
    if EXT {
        &TABLE_4
    } else {
        &TABLE_3
    }
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_imm<const EXT: bool>(chunk: u128, length: u32) -> i32 {
    let length = fixup_length::<EXT>(length);
    let chunk = chunk_into_u32::<EXT, 0>(chunk);
    cast(read_simple_varint(chunk, length)).bitwise_as_i32()
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_offset<const EXT: bool>(chunk: u128, instruction_offset: u32, length: u32) -> u32 {
    instruction_offset.wrapping_add(cast(read_args_imm::<EXT>(chunk, length)).bitwise_as_u32())
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_imm2<const EXT: bool>(chunk: u128, length: u32) -> (i32, i32) {
    let (imm1_bits, imm1_skip, imm2_bits) = fixup_table_1::<EXT>().get(length, chunk_into_u32::<EXT, 0>(chunk));
    let chunk = chunk_into_u64::<EXT, 8>(chunk);
    let imm1 = sign_extend_at(chunk as u32, imm1_bits);
    let chunk = chunk >> imm1_skip;
    let imm2 = sign_extend_at(chunk as u32, imm2_bits);
    (cast(imm1).bitwise_as_i32(), cast(imm2).bitwise_as_i32())
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_reg_imm<const EXT: bool>(chunk: u128, length: u32) -> (RawReg, i32) {
    let chunk = fixup_chunk64::<EXT>(chunk);
    let reg = RawReg(chunk as u32);
    let chunk = chunk >> 8;
    let (_, _, imm_bits) = fixup_table_1::<EXT>().get(length, 0);
    let imm = sign_extend_at(chunk as u32, imm_bits);
    (reg, cast(imm).bitwise_as_i32())
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_reg_imm2<const EXT: bool>(chunk: u128, length: u32) -> (RawReg, i32, i32) {
    let reg = RawReg(chunk_into_u32::<EXT, 0>(chunk));
    let (imm1_bits, imm1_skip, imm2_bits) = fixup_table_1::<EXT>().get(length, chunk_into_u32::<EXT, 4>(chunk));
    let chunk = chunk_into_u64::<EXT, 8>(chunk);
    let imm1 = sign_extend_at(chunk as u32, imm1_bits);
    let chunk = chunk >> imm1_skip;
    let imm2 = sign_extend_at(chunk as u32, imm2_bits);
    (reg, cast(imm1).bitwise_as_i32(), cast(imm2).bitwise_as_i32())
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_reg_imm_offset<const EXT: bool>(chunk: u128, instruction_offset: u32, length: u32) -> (RawReg, i32, u32) {
    let (reg, imm1, imm2) = read_args_reg_imm2::<EXT>(chunk, length);
    let imm2 = instruction_offset.wrapping_add(cast(imm2).bitwise_as_u32());
    (reg, imm1, imm2)
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_regs2_imm2<const EXT: bool>(chunk: u128, length: u32) -> (RawReg, RawReg, i32, i32) {
    let (reg1, reg2, imm1_aux) = {
        let value = chunk_into_u32::<EXT, 0>(chunk);
        (RawReg(value), RawReg(value >> 4), value >> 8)
    };

    let (imm1_bits, imm1_skip, imm2_bits) = fixup_table_2::<EXT>().get(length, imm1_aux);
    let chunk = chunk_into_u64::<EXT, 16>(chunk);
    let imm1 = sign_extend_at(chunk as u32, imm1_bits);
    let chunk = chunk >> imm1_skip;
    let imm2 = sign_extend_at(chunk as u32, imm2_bits);
    (reg1, reg2, cast(imm1).bitwise_as_i32(), cast(imm2).bitwise_as_i32())
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_reg_imm64<const EXT: bool>(chunk: u128) -> (RawReg, u64) {
    let reg = RawReg(chunk_into_u32::<EXT, 0>(chunk));
    let imm = chunk_into_u64::<EXT, 8>(chunk);
    (reg, imm)
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_regs2_imm<const EXT: bool>(chunk: u128, length: u32) -> (RawReg, RawReg, i32) {
    let chunk = fixup_chunk64::<EXT>(chunk);
    let (reg1, reg2) = {
        let value = chunk as u32;
        (RawReg(value), RawReg(value >> 4))
    };
    let chunk = chunk >> 8;
    let (_, _, imm_bits) = fixup_table_1::<EXT>().get(length, 0);
    let imm = sign_extend_at(chunk as u32, imm_bits);
    (reg1, reg2, cast(imm).bitwise_as_i32())
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_regs2_offset<const EXT: bool>(chunk: u128, instruction_offset: u32, length: u32) -> (RawReg, RawReg, u32) {
    let (reg1, reg2, imm) = read_args_regs2_imm::<EXT>(chunk, length);
    let imm = instruction_offset.wrapping_add(cast(imm).bitwise_as_u32());
    (reg1, reg2, imm)
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_regs3<const EXT: bool>(chunk: u128) -> (RawReg, RawReg, RawReg) {
    let chunk = chunk_into_u32::<EXT, 0>(chunk);
    let (reg2, reg3, reg1) = (RawReg(chunk), RawReg(chunk >> 4), RawReg(chunk >> 8));
    (reg1, reg2, reg3)
}

#[doc(hidden)]
#[inline(always)]
pub fn read_args_regs2<const EXT: bool>(chunk: u128) -> (RawReg, RawReg) {
    let chunk = chunk_into_u32::<EXT, 0>(chunk);
    let (reg1, reg2) = (RawReg(chunk), RawReg(chunk >> 4));
    (reg1, reg2)
}

#[cfg(kani)]
mod kani {
    use crate::cast::cast;
    use core::cmp::min;

    fn clamp<T>(range: core::ops::RangeInclusive<T>, value: T) -> T
    where
        T: PartialOrd + Copy,
    {
        if value < *range.start() {
            *range.start()
        } else if value > *range.end() {
            *range.end()
        } else {
            value
        }
    }

    fn read<O, L>(slice: &[u8], offset: O, length: L) -> u32
    where
        O: TryInto<usize>,
        L: TryInto<usize>,
    {
        let offset = offset.try_into().unwrap_or_else(|_| unreachable!());
        let length = length.try_into().unwrap_or_else(|_| unreachable!());
        let slice = &slice[offset..offset + length];
        match length {
            0 => 0,
            1 => slice[0] as u32,
            2 => u16::from_le_bytes([slice[0], slice[1]]) as u32,
            3 => u32::from_le_bytes([slice[0], slice[1], slice[2], 0]),
            4 => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
            _ => unreachable!(),
        }
    }

    fn sext<L>(value: u32, length: L) -> u32
    where
        L: Into<i64>,
    {
        match length.into() {
            0 => 0,
            1 => value as u8 as i8 as i32 as u32,
            2 => value as u16 as i16 as i32 as u32,
            3 => (((value << 8) as i32) >> 8) as u32,
            4 => value,
            _ => unreachable!(),
        }
    }

    macro_rules! args {
        ($opcode_bytes:expr) => {{
            let code: [u8; 16] = kani::any();
            let chunk = u128::from_le_bytes(code);
            let length: u32 = kani::any_where(|x| *x >= $opcode_bytes && *x - $opcode_bytes <= super::BITMASK_MAX);

            (code, chunk, length)
        }};
    }

    macro_rules! for_both_ext {
        (|$code:ident, $chunk:ident, $length:ident, $args:ident, $read_args:ident| $body:expr) => {{
            {
                let (code, $chunk, $length) = args!(1);
                let $code = &code[1..];
                let $args = $length - 1;
                let $read_args = super::$read_args::<false>;
                $body
            }
            {
                let (code, $chunk, $length) = args!(2);
                let $code = &code[2..];
                let $args = $length - 2;
                let $read_args = super::$read_args::<true>;
                $body
            }
        }};
    }

    #[kani::proof]
    fn verify_read_args_imm() {
        fn simple_read_args_imm(code: &[u8], args_length: u32) -> i32 {
            let imm_length = min(4, args_length);
            cast(sext(read(code, 0, imm_length), imm_length)).bitwise_as_i32()
        }

        for_both_ext!(|code, chunk, length, args_length, read_args_imm| {
            assert_eq!(read_args_imm(chunk, length), simple_read_args_imm(code, args_length));
        });
    }

    #[kani::proof]
    fn verify_read_args_imm2() {
        fn simple_read_args_imm2(code: &[u8], args_length: i32) -> (i32, i32) {
            let imm1_length = min(4, i32::from(code[0]) & 0b111);
            let imm2_length = clamp(0..=4, args_length - imm1_length - 1);
            let imm1 = sext(read(code, 1, imm1_length), imm1_length);
            let imm2 = sext(read(code, 1 + imm1_length, imm2_length), imm2_length);
            let imm1 = cast(imm1).bitwise_as_i32();
            let imm2 = cast(imm2).bitwise_as_i32();
            (imm1, imm2)
        }

        for_both_ext!(|code, chunk, length, args_length, read_args_imm2| {
            assert_eq!(read_args_imm2(chunk, length), simple_read_args_imm2(code, args_length as i32));
        });
    }

    #[kani::proof]
    fn verify_read_args_reg_imm() {
        fn simple_read_args_reg_imm(code: &[u8], args_length: i32) -> (u8, i32) {
            let reg = min(12, code[0] & 0b1111);
            let imm_length = clamp(0..=4, args_length - 1);
            let imm = sext(read(code, 1, imm_length), imm_length);
            let imm = cast(imm).bitwise_as_i32();
            (reg, imm)
        }

        for_both_ext!(|code, chunk, length, args_length, read_args_reg_imm| {
            let (reg, imm) = read_args_reg_imm(chunk, length);
            let reg = reg.get() as u8;
            assert_eq!((reg, imm), simple_read_args_reg_imm(code, args_length as i32));
        });
    }

    #[kani::proof]
    fn verify_read_args_reg_imm2() {
        fn simple_read_args_reg_imm2(code: &[u8], args_length: i32) -> (u8, i32, i32) {
            let reg = min(12, code[0] & 0b1111);
            let imm1_length = min(4, i32::from(code[0] >> 4) & 0b111);
            let imm2_length = clamp(0..=4, args_length - imm1_length - 1);
            let imm1 = sext(read(code, 1, imm1_length), imm1_length);
            let imm2 = sext(read(code, 1 + imm1_length, imm2_length), imm2_length);
            let imm1 = cast(imm1).bitwise_as_i32();
            let imm2 = cast(imm2).bitwise_as_i32();
            (reg, imm1, imm2)
        }

        for_both_ext!(|code, chunk, length, args_length, read_args_reg_imm2| {
            let (reg, imm1, imm2) = read_args_reg_imm2(chunk, length);
            let reg = reg.get() as u8;
            assert_eq!((reg, imm1, imm2), simple_read_args_reg_imm2(code, args_length as i32));
        });
    }

    #[kani::proof]
    fn verify_read_args_regs2_imm2() {
        fn simple_read_args_regs2_imm2(code: &[u8], args_length: i32) -> (u8, u8, i32, i32) {
            let reg1 = min(12, code[0] & 0b1111);
            let reg2 = min(12, code[0] >> 4);
            let imm1_length = min(4, i32::from(code[1]) & 0b111);
            let imm2_length = clamp(0..=4, args_length - imm1_length - 2);
            let imm1 = sext(read(code, 2, imm1_length), imm1_length);
            let imm2 = sext(read(code, 2 + imm1_length, imm2_length), imm2_length);
            let imm1 = cast(imm1).bitwise_as_i32();
            let imm2 = cast(imm2).bitwise_as_i32();
            (reg1, reg2, imm1, imm2)
        }

        for_both_ext!(|code, chunk, length, args_length, read_args_regs2_imm2| {
            let (reg1, reg2, imm1, imm2) = read_args_regs2_imm2(chunk, length);
            let reg1 = reg1.get() as u8;
            let reg2 = reg2.get() as u8;
            assert_eq!((reg1, reg2, imm1, imm2), simple_read_args_regs2_imm2(code, args_length as i32));
        });
    }

    #[kani::proof]
    fn verify_read_args_regs2_imm() {
        fn simple_read_args_regs2_imm(code: &[u8], args_length: u32) -> (u8, u8, i32) {
            let reg1 = min(12, code[0] & 0b1111);
            let reg2 = min(12, code[0] >> 4);
            let imm_length = clamp(0..=4, args_length as i32 - 1);
            let imm = sext(read(code, 1, imm_length), imm_length);
            let imm = cast(imm).bitwise_as_i32();
            (reg1, reg2, imm)
        }

        for_both_ext!(|code, chunk, length, args_length, read_args_regs2_imm| {
            let (reg1, reg2, imm) = read_args_regs2_imm(chunk, length);
            let reg1 = reg1.get() as u8;
            let reg2 = reg2.get() as u8;
            assert_eq!((reg1, reg2, imm), simple_read_args_regs2_imm(code, args_length));
        });
    }

    #[kani::proof]
    fn verify_read_args_regs3() {
        fn simple_read_args_regs3(code: &[u8]) -> (u8, u8, u8) {
            let reg2 = min(12, code[0] & 0b1111);
            let reg3 = min(12, code[0] >> 4);
            let reg1 = min(12, code[1] & 0b1111);
            (reg1, reg2, reg3)
        }

        {
            let (code, chunk, _) = args!(1);
            let (reg1, reg2, reg3) = super::read_args_regs3::<false>(chunk);
            assert_eq!(
                (reg1.get() as u8, reg2.get() as u8, reg3.get() as u8),
                simple_read_args_regs3(&code[1..])
            );
        }
        {
            let (code, chunk, _) = args!(2);
            let (reg1, reg2, reg3) = super::read_args_regs3::<true>(chunk);
            assert_eq!(
                (reg1.get() as u8, reg2.get() as u8, reg3.get() as u8),
                simple_read_args_regs3(&code[2..])
            );
        }
    }

    #[kani::proof]
    fn verify_read_args_regs2() {
        fn simple_read_args_regs2(code: &[u8]) -> (u8, u8) {
            let reg1 = min(12, code[0] & 0b1111);
            let reg2 = min(12, code[0] >> 4);
            (reg1, reg2)
        }

        {
            let (code, chunk, _) = args!(1);
            let (reg1, reg2) = super::read_args_regs2::<false>(chunk);
            assert_eq!((reg1.get() as u8, reg2.get() as u8), simple_read_args_regs2(&code[1..]));
        }
        {
            let (code, chunk, _) = args!(2);
            let (reg1, reg2) = super::read_args_regs2::<true>(chunk);
            assert_eq!((reg1.get() as u8, reg2.get() as u8), simple_read_args_regs2(&code[2..]));
        }
    }

    #[kani::proof]
    fn verify_interpreter_cache_size() {
        let x: usize = kani::any_where(|x| *x <= super::cast(u32::MAX).to_usize());
        let bytes: usize = super::interpreter_calculate_cache_size(x);
        let calculate_count = super::interpreter_calculate_cache_num_entries(bytes);
        assert_eq!(calculate_count, x);

        let count = super::interpreter_calculate_cache_num_entries(x);
        let calculated_bytes = super::interpreter_calculate_cache_size(count);
        assert!(calculated_bytes <= x);
        assert!(x - calculated_bytes <= super::interpreter_calculate_cache_size(1));
    }

    #[kani::proof]
    fn verify_extended_parse_simple() {
        let isa = super::ISA_Latest64;
        let mut code = [0_u8; super::CODE_BLOCK_SIZE + 6];
        let offset: usize = kani::any_where(|x| *x < super::CODE_BLOCK_SIZE + 6);
        code[offset] = kani::any();
        if offset + 1 < code.len() {
            code[offset + 1] = kani::any();
        }

        let block_end = super::end_of_macro_block(offset, code.len());
        let step = super::parse_simple_extended(isa, &code, offset);
        assert!(step.next_offset > offset);
        assert!(step.next_offset <= block_end);
        assert!(offset + step.length as usize == step.next_offset);

        if step.raw_opcode != super::EXTENDED_INVALID_RAW_OPCODE {
            let length = super::InstructionSet::raw_opcode_table(isa).length_table[step.raw_opcode].get();
            assert!(step.next_offset == min(offset + length as usize, block_end));

            // The last instruction of a macro block always ends a basic block.
            assert!(step.next_offset < block_end || super::ends_basic_block_extended(isa, step.raw_opcode));
        }
    }

    #[kani::proof]
    fn verify_extended_parse_instruction() {
        let isa = super::ISA_Latest64;
        let raw_opcode: usize = kani::any_where(|x| *x <= super::EXTENDED_INVALID_RAW_OPCODE);
        let chunk: u128 = kani::any();
        let offset: u32 = kani::any();
        let length = if raw_opcode == super::EXTENDED_INVALID_RAW_OPCODE {
            // A truncated instruction is decoded as `invalid` with the length it covers.
            kani::any()
        } else {
            super::InstructionSet::raw_opcode_table(isa).length_table[raw_opcode].get()
        };

        let _ = super::InstructionSet::parse_instruction(isa, raw_opcode, chunk, offset, length);
    }
}

/// The lowest level visitor; dispatches directly on opcode numbers.
pub trait OpcodeVisitor: Copy {
    type State;
    type ReturnTy;
    type InstructionSet: InstructionSet;

    fn instruction_set(self) -> Self::InstructionSet;
    fn dispatch(self, state: &mut Self::State, opcode: usize, chunk: u128, offset: u32, length: u32) -> Self::ReturnTy;
}

macro_rules! define_all_instructions {
    (@impl_shared $($name:ident,)+) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
        #[repr(u8)]
        pub enum Opcode {
            $(
                $name,
            )+

            // This is here to prevent `as` casts.
            #[doc(hidden)]
            _NonExhaustive(()),
        }

        impl Opcode {
            pub const ALL: &[Opcode] = &[
                $(Opcode::$name,)+
            ];

            pub fn name(self) -> &'static str {
                match self {
                    $(
                        Opcode::$name => stringify!($name),
                    )+

                    Opcode::_NonExhaustive(()) => {
                        #[cfg(debug_assertions)]
                        unreachable!();

                        #[cfg(not(debug_assertions))]
                        ""
                    },
                }
            }

            #[inline]
            const fn discriminant(&self) -> u8 {
                #[allow(unsafe_code)]
                // SAFETY: Reading a discriminant into a primitive when we have a #[repr] on the enum is safe,
                //         since Rust guarantees it has a union-like layout.
                unsafe {
                    *(self as *const Opcode).cast::<u8>()
                }
            }
        }

        impl core::fmt::Display for Opcode {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                fmt.write_str(self.name())
            }
        }

        impl core::str::FromStr for Opcode {
            type Err = &'static str;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(match s {
                    $(
                        stringify!($name) => Opcode::$name,
                    )+
                    _ => return Err("unknown opcode")
                })
            }
        }
    };

    (
        [$($name_argless:ident,)+]
        [$($name_reg_imm:ident,)+]
        [$($name_reg_imm_offset:ident,)+]
        [$($name_reg_imm_imm:ident,)+]
        [$($name_reg_reg_imm:ident,)+]
        [$($name_reg_reg_offset:ident,)+]
        [$($name_reg_reg_reg:ident,)+]
        [$($name_offset:ident,)+]
        [$($name_imm:ident,)+]
        [$($name_imm_imm:ident,)+]
        [$($name_reg_reg:ident,)+]
        [$($name_reg_reg_imm_imm:ident,)+]
        [$($name_reg_imm64:ident,)+]
    ) => {
        define_all_instructions!(
            @impl_shared
            $($name_argless,)+
            $($name_reg_imm,)+
            $($name_reg_imm_offset,)+
            $($name_reg_imm_imm,)+
            $($name_reg_reg_imm,)+
            $($name_reg_reg_offset,)+
            $($name_reg_reg_reg,)+
            $($name_offset,)+
            $($name_imm,)+
            $($name_imm_imm,)+
            $($name_reg_reg,)+
            $($name_reg_reg_imm_imm,)+
            $($name_reg_imm64,)+
        );

        #[macro_export]
        macro_rules! impl_parsing_visitor_for_instruction_visitor {
            ($visitor_ty:ident) => {
                impl ParsingVisitor for $visitor_ty {
                    type ReturnTy = <$visitor_ty as $crate::program::InstructionVisitor>::ReturnTy;

                    $(fn $name_argless(&mut self, _offset: u32, _length: u32) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_argless(self) })+
                    $(fn $name_reg_imm(&mut self, _offset: u32, _length: u32, reg: RawReg, imm: i32) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_reg_imm(self, reg, imm) })+
                    $(fn $name_reg_imm_offset(&mut self, _offset: u32, _length: u32, reg: RawReg, imm1: i32, imm2: u32) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_reg_imm_offset(self, reg, imm1, imm2) })+
                    $(fn $name_reg_imm_imm(&mut self, _offset: u32, _length: u32, reg: RawReg, imm1: i32, imm2: i32) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_reg_imm_imm(self, reg, imm1, imm2) })+
                    $(fn $name_reg_reg_imm(&mut self, _offset: u32, _length: u32, reg1: RawReg, reg2: RawReg, imm: i32) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_reg_reg_imm(self, reg1, reg2, imm) })+
                    $(fn $name_reg_reg_offset(&mut self, _offset: u32, _length: u32, reg1: RawReg, reg2: RawReg, imm: u32) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_reg_reg_offset(self, reg1, reg2, imm) })+
                    $(fn $name_reg_reg_reg(&mut self, _offset: u32, _length: u32, reg1: RawReg, reg2: RawReg, reg3: RawReg) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_reg_reg_reg(self, reg1, reg2, reg3) })+
                    $(fn $name_offset(&mut self, _offset: u32, _length: u32, imm: u32) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_offset(self, imm) })+
                    $(fn $name_imm(&mut self, _offset: u32, _length: u32, imm: i32) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_imm(self, imm) })+
                    $(fn $name_imm_imm(&mut self, _offset: u32, _length: u32, imm1: i32, imm2: i32) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_imm_imm(self, imm1, imm2) })+
                    $(fn $name_reg_reg(&mut self, _offset: u32, _length: u32, reg1: RawReg, reg2: RawReg) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_reg_reg(self, reg1, reg2) })+
                    $(fn $name_reg_reg_imm_imm(&mut self, _offset: u32, _length: u32, reg1: RawReg, reg2: RawReg, imm1: i32, imm2: i32) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_reg_reg_imm_imm(self, reg1, reg2, imm1, imm2) })+
                    $(fn $name_reg_imm64(&mut self, _offset: u32, _length: u32, reg: RawReg, imm: u64) -> Self::ReturnTy { $crate::program::InstructionVisitor::$name_reg_imm64(self, reg, imm) })+

                    fn invalid(&mut self, _offset: u32, _length: u32) -> Self::ReturnTy { $crate::program::InstructionVisitor::invalid(self) }
                }
            };
        }

        pub trait ParsingVisitor {
            type ReturnTy;

            $(fn $name_argless(&mut self, offset: u32, length: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm(&mut self, offset: u32, length: u32, reg: RawReg, imm: i32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_offset(&mut self, offset: u32, length: u32, reg: RawReg, imm1: i32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_imm(&mut self, offset: u32, length: u32, reg: RawReg, imm1: i32, imm2: i32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm(&mut self, offset: u32, length: u32, reg1: RawReg, reg2: RawReg, imm: i32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_offset(&mut self, offset: u32, length: u32, reg1: RawReg, reg2: RawReg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_reg(&mut self, offset: u32, length: u32, reg1: RawReg, reg2: RawReg, reg3: RawReg) -> Self::ReturnTy;)+
            $(fn $name_offset(&mut self, offset: u32, length: u32, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_imm(&mut self, offset: u32, length: u32, imm: i32) -> Self::ReturnTy;)+
            $(fn $name_imm_imm(&mut self, offset: u32, length: u32, imm1: i32, imm2: i32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg(&mut self, offset: u32, length: u32, reg1: RawReg, reg2: RawReg) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm_imm(&mut self, offset: u32, length: u32, reg1: RawReg, reg2: RawReg, imm1: i32, imm2: i32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm64(&mut self, offset: u32, length: u32, reg: RawReg, imm: u64) -> Self::ReturnTy;)+

            fn invalid(&mut self, offset: u32, length: u32) -> Self::ReturnTy;
        }

        pub trait InstructionVisitor {
            type ReturnTy;

            $(fn $name_argless(&mut self) -> Self::ReturnTy;)+
            $(fn $name_reg_imm(&mut self, reg: RawReg, imm: i32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_offset(&mut self, reg: RawReg, imm1: i32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_imm(&mut self, reg: RawReg, imm1: i32, imm2: i32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm(&mut self, reg1: RawReg, reg2: RawReg, imm: i32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_offset(&mut self, reg1: RawReg, reg2: RawReg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_reg(&mut self, reg1: RawReg, reg2: RawReg, reg3: RawReg) -> Self::ReturnTy;)+
            $(fn $name_offset(&mut self, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_imm(&mut self, imm: i32) -> Self::ReturnTy;)+
            $(fn $name_imm_imm(&mut self, imm1: i32, imm2: i32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg(&mut self, reg1: RawReg, reg2: RawReg) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm_imm(&mut self, reg1: RawReg, reg2: RawReg, imm1: i32, imm2: i32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm64(&mut self, reg: RawReg, imm: u64) -> Self::ReturnTy;)+

            fn invalid(&mut self) -> Self::ReturnTy;
        }

        #[derive(Copy, Clone, PartialEq, Eq, Debug)]
        #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
        #[allow(non_camel_case_types)]
        #[repr(u32)]
        pub enum Instruction {
            $($name_argless,)+
            $($name_reg_imm(RawReg, i32),)+
            $($name_reg_imm_offset(RawReg, i32, u32),)+
            $($name_reg_imm_imm(RawReg, i32, i32),)+
            $($name_reg_reg_imm(RawReg, RawReg, i32),)+
            $($name_reg_reg_offset(RawReg, RawReg, u32),)+
            $($name_reg_reg_reg(RawReg, RawReg, RawReg),)+
            $($name_offset(u32),)+
            $($name_imm(i32),)+
            $($name_imm_imm(i32, i32),)+
            $($name_reg_reg(RawReg, RawReg),)+
            $($name_reg_reg_imm_imm(RawReg, RawReg, i32, i32),)+
            $($name_reg_imm64(RawReg, u64),)+
            invalid = LEGACY_INVALID_RAW_OPCODE as u32,
        }

        impl Instruction {
            pub fn visit<T>(self, visitor: &mut T) -> T::ReturnTy where T: InstructionVisitor {
                match self {
                    $(Self::$name_argless => visitor.$name_argless(),)+
                    $(Self::$name_reg_imm(reg, imm) => visitor.$name_reg_imm(reg, imm),)+
                    $(Self::$name_reg_imm_offset(reg, imm1, imm2) => visitor.$name_reg_imm_offset(reg, imm1, imm2),)+
                    $(Self::$name_reg_imm_imm(reg, imm1, imm2) => visitor.$name_reg_imm_imm(reg, imm1, imm2),)+
                    $(Self::$name_reg_reg_imm(reg1, reg2, imm) => visitor.$name_reg_reg_imm(reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_offset(reg1, reg2, imm) => visitor.$name_reg_reg_offset(reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_reg(reg1, reg2, reg3) => visitor.$name_reg_reg_reg(reg1, reg2, reg3),)+
                    $(Self::$name_offset(imm) => visitor.$name_offset(imm),)+
                    $(Self::$name_imm(imm) => visitor.$name_imm(imm),)+
                    $(Self::$name_imm_imm(imm1, imm2) => visitor.$name_imm_imm(imm1, imm2),)+
                    $(Self::$name_reg_reg(reg1, reg2) => visitor.$name_reg_reg(reg1, reg2),)+
                    $(Self::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2) => visitor.$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2),)+
                    $(Self::$name_reg_imm64(reg, imm) => visitor.$name_reg_imm64(reg, imm),)+
                    Self::invalid => visitor.invalid(),
                }
            }

            pub fn visit_parsing<T>(self, offset: u32, length: u32, visitor: &mut T) -> T::ReturnTy where T: ParsingVisitor {
                match self {
                    $(Self::$name_argless => visitor.$name_argless(offset, length),)+
                    $(Self::$name_reg_imm(reg, imm) => visitor.$name_reg_imm(offset, length, reg, imm),)+
                    $(Self::$name_reg_imm_offset(reg, imm1, imm2) => visitor.$name_reg_imm_offset(offset, length, reg, imm1, imm2),)+
                    $(Self::$name_reg_imm_imm(reg, imm1, imm2) => visitor.$name_reg_imm_imm(offset, length, reg, imm1, imm2),)+
                    $(Self::$name_reg_reg_imm(reg1, reg2, imm) => visitor.$name_reg_reg_imm(offset, length, reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_offset(reg1, reg2, imm) => visitor.$name_reg_reg_offset(offset, length, reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_reg(reg1, reg2, reg3) => visitor.$name_reg_reg_reg(offset, length, reg1, reg2, reg3),)+
                    $(Self::$name_offset(imm) => visitor.$name_offset(offset, length, imm),)+
                    $(Self::$name_imm(imm) => visitor.$name_imm(offset, length, imm),)+
                    $(Self::$name_imm_imm(imm1, imm2) => visitor.$name_imm_imm(offset, length, imm1, imm2),)+
                    $(Self::$name_reg_reg(reg1, reg2) => visitor.$name_reg_reg(offset, length, reg1, reg2),)+
                    $(Self::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2) => visitor.$name_reg_reg_imm_imm(offset, length, reg1, reg2, imm1, imm2),)+
                    $(Self::$name_reg_imm64(reg, imm) => visitor.$name_reg_imm64(offset, length, reg, imm),)+
                    Self::invalid => visitor.invalid(offset, length),
                }
            }

            pub fn serialize_into<I>(self, isa: I, position: u32, buffer: &mut [u8]) -> usize where I: InstructionSet {
                match self {
                    $(Self::$name_argless => Self::serialize_argless(isa, buffer, Opcode::$name_argless),)+
                    $(Self::$name_reg_imm(reg, imm) => Self::serialize_reg_imm(isa, buffer, Opcode::$name_reg_imm, reg, imm),)+
                    $(Self::$name_reg_imm_offset(reg, imm1, imm2) => Self::serialize_reg_imm_offset(isa, buffer, position, Opcode::$name_reg_imm_offset, reg, imm1, imm2),)+
                    $(Self::$name_reg_imm_imm(reg, imm1, imm2) => Self::serialize_reg_imm_imm(isa, buffer, Opcode::$name_reg_imm_imm, reg, imm1, imm2),)+
                    $(Self::$name_reg_reg_imm(reg1, reg2, imm) => Self::serialize_reg_reg_imm(isa, buffer, Opcode::$name_reg_reg_imm, reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_offset(reg1, reg2, imm) => Self::serialize_reg_reg_offset(isa, buffer, position, Opcode::$name_reg_reg_offset, reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_reg(reg1, reg2, reg3) => Self::serialize_reg_reg_reg(isa, buffer, Opcode::$name_reg_reg_reg, reg1, reg2, reg3),)+
                    $(Self::$name_offset(imm) => Self::serialize_offset(isa, buffer, position, Opcode::$name_offset, imm),)+
                    $(Self::$name_imm(imm) => Self::serialize_imm(isa, buffer, Opcode::$name_imm, imm),)+
                    $(Self::$name_imm_imm(imm1, imm2) => Self::serialize_imm_imm(isa, buffer, Opcode::$name_imm_imm, imm1, imm2),)+
                    $(Self::$name_reg_reg(reg1, reg2) => Self::serialize_reg_reg(isa, buffer, Opcode::$name_reg_reg, reg1, reg2),)+
                    $(Self::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2) => Self::serialize_reg_reg_imm_imm(isa, buffer, Opcode::$name_reg_reg_imm_imm, reg1, reg2, imm1, imm2),)+
                    $(Self::$name_reg_imm64(reg, imm) => Self::serialize_reg_imm64(isa, buffer, Opcode::$name_reg_imm64, reg, imm),)+
                    Self::invalid => Self::serialize_argless(isa, buffer, Opcode::trap),
                }
            }

            pub fn opcode(self) -> Opcode {
                match self {
                    $(Self::$name_argless => Opcode::$name_argless,)+
                    $(Self::$name_reg_imm(..) => Opcode::$name_reg_imm,)+
                    $(Self::$name_reg_imm_offset(..) => Opcode::$name_reg_imm_offset,)+
                    $(Self::$name_reg_imm_imm(..) => Opcode::$name_reg_imm_imm,)+
                    $(Self::$name_reg_reg_imm(..) => Opcode::$name_reg_reg_imm,)+
                    $(Self::$name_reg_reg_offset(..) => Opcode::$name_reg_reg_offset,)+
                    $(Self::$name_reg_reg_reg(..) => Opcode::$name_reg_reg_reg,)+
                    $(Self::$name_offset(..) => Opcode::$name_offset,)+
                    $(Self::$name_imm(..) => Opcode::$name_imm,)+
                    $(Self::$name_imm_imm(..) => Opcode::$name_imm_imm,)+
                    $(Self::$name_reg_reg(..) => Opcode::$name_reg_reg,)+
                    $(Self::$name_reg_reg_imm_imm(..) => Opcode::$name_reg_reg_imm_imm,)+
                    $(Self::$name_reg_imm64(..) => Opcode::$name_reg_imm64,)+
                    Self::invalid => Opcode::trap,
                }
            }
        }

        pub mod asm {
            use super::{Instruction, Reg};

            $(
                pub fn $name_argless() -> Instruction {
                    Instruction::$name_argless
                }
            )+

            $(
                pub fn $name_reg_imm(reg: Reg, imm: i32) -> Instruction {
                    Instruction::$name_reg_imm(reg.into(), imm)
                }
            )+

            $(
                pub fn $name_reg_imm_offset(reg: Reg, imm1: i32, imm2: u32) -> Instruction {
                    Instruction::$name_reg_imm_offset(reg.into(), imm1, imm2)
                }
            )+

            $(
                pub fn $name_reg_imm_imm(reg: Reg, imm1: i32, imm2: i32) -> Instruction {
                    Instruction::$name_reg_imm_imm(reg.into(), imm1, imm2)
                }
            )+

            $(
                pub fn $name_reg_reg_imm(reg1: Reg, reg2: Reg, imm: i32) -> Instruction {
                    Instruction::$name_reg_reg_imm(reg1.into(), reg2.into(), imm)
                }
            )+

            $(
                pub fn $name_reg_reg_offset(reg1: Reg, reg2: Reg, imm: u32) -> Instruction {
                    Instruction::$name_reg_reg_offset(reg1.into(), reg2.into(), imm)
                }
            )+

            $(
                pub fn $name_reg_reg_reg(reg1: Reg, reg2: Reg, reg3: Reg) -> Instruction {
                    Instruction::$name_reg_reg_reg(reg1.into(), reg2.into(), reg3.into())
                }
            )+

            $(
                pub fn $name_offset(imm: u32) -> Instruction {
                    Instruction::$name_offset(imm)
                }
            )+

            $(
                pub fn $name_imm(imm: i32) -> Instruction {
                    Instruction::$name_imm(imm)
                }
            )+

            $(
                pub fn $name_imm_imm(imm1: i32, imm2: i32) -> Instruction {
                    Instruction::$name_imm_imm(imm1, imm2)
                }
            )+

            $(
                pub fn $name_reg_reg(reg1: Reg, reg2: Reg) -> Instruction {
                    Instruction::$name_reg_reg(reg1.into(), reg2.into())
                }
            )+

            $(
                pub fn $name_reg_reg_imm_imm(reg1: Reg, reg2: Reg, imm1: i32, imm2: i32) -> Instruction {
                    Instruction::$name_reg_reg_imm_imm(reg1.into(), reg2.into(), imm1, imm2)
                }
            )+

            $(
                pub fn $name_reg_imm64(reg: Reg, imm: u64) -> Instruction {
                    Instruction::$name_reg_imm64(reg.into(), imm)
                }
            )+

            pub fn ret() -> Instruction {
                jump_indirect(Reg::RA, 0)
            }
        }

        #[derive(Copy, Clone)]
        struct EnumVisitor<I> {
            instruction_set: I
        }

        impl<'a, I> OpcodeVisitor for EnumVisitor<I> where I: InstructionSet {
            type State = ();
            type ReturnTy = Instruction;
            type InstructionSet = I;

            fn instruction_set(self) -> Self::InstructionSet {
                self.instruction_set
            }

            fn dispatch(self, _state: &mut (), opcode: usize, chunk: u128, offset: u32, length: u32) -> Instruction {
                self.instruction_set().parse_instruction(opcode, chunk, offset, length)
            }
        }
    };
}

const UNUSED_RAW_OPCODE: u32 = 254;

macro_rules! define_legacy_instruction_set {
    (@impl_shared $isa_name:ident, $($name:ident = $value:expr,)+) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone, Debug, Default)]
        pub struct $isa_name;

        impl $isa_name {
            #[doc(hidden)]
            pub const RAW_OPCODE_TO_ENUM_CONST: [Option<Opcode>; 256] = {
                let mut map = [None; 256];
                $(
                    map[$value] = Some(Opcode::$name);
                )+
                map
            };

            pub const OPCODE_DISCRIMINANT_TO_RAW_OPCODE_CONST: [u8; 256] = {
                let mut map = [UNUSED_RAW_OPCODE as u8; 256];
                assert!($isa_name::RAW_OPCODE_TO_ENUM_CONST[UNUSED_RAW_OPCODE as usize].is_none());

                $({
                    let discriminant = Opcode::$name.discriminant() as usize;
                    assert!(map[discriminant] as u32 == UNUSED_RAW_OPCODE);
                    map[discriminant] = $value;
                })+

                map
            };
        }
    };

    (
        ($d:tt)
        $isa_name:ident,
        $build_static_dispatch_table:ident,
        [$($name_argless:ident = $value_argless:expr,)+]
        [$($name_reg_imm:ident = $value_reg_imm:expr,)+]
        [$($name_reg_imm_offset:ident = $value_reg_imm_offset:expr,)+]
        [$($name_reg_imm_imm:ident = $value_reg_imm_imm:expr,)+]
        [$($name_reg_reg_imm:ident = $value_reg_reg_imm:expr,)+]
        [$($name_reg_reg_offset:ident = $value_reg_reg_offset:expr,)+]
        [$($name_reg_reg_reg:ident = $value_reg_reg_reg:expr,)+]
        [$($name_offset:ident = $value_offset:expr,)+]
        [$($name_imm:ident = $value_imm:expr,)+]
        [$($name_imm_imm:ident = $value_imm_imm:expr,)+]
        [$($name_reg_reg:ident = $value_reg_reg:expr,)+]
        [$($name_reg_reg_imm_imm:ident = $value_reg_reg_imm_imm:expr,)+]
        [$($name_reg_imm64:ident = $value_reg_imm64:expr,)*]
    ) => {
        define_legacy_instruction_set!(
            @impl_shared
            $isa_name,
            $($name_argless = $value_argless,)+
            $($name_reg_imm = $value_reg_imm,)+
            $($name_reg_imm_offset = $value_reg_imm_offset,)+
            $($name_reg_imm_imm = $value_reg_imm_imm,)+
            $($name_reg_reg_imm = $value_reg_reg_imm,)+
            $($name_reg_reg_offset = $value_reg_reg_offset,)+
            $($name_reg_reg_reg = $value_reg_reg_reg,)+
            $($name_offset = $value_offset,)+
            $($name_imm = $value_imm,)+
            $($name_imm_imm = $value_imm_imm,)+
            $($name_reg_reg = $value_reg_reg,)+
            $($name_reg_reg_imm_imm = $value_reg_reg_imm_imm,)+
            $($name_reg_imm64 = $value_reg_imm64,)*
        );

        impl InstructionSet for $isa_name {
            #[inline]
            fn is_legacy(self) -> bool {
                true
            }

            #[cfg_attr(feature = "alloc", inline)]
            fn opcode_from_raw(self, raw_opcode: u32) -> Option<Opcode> {
                static RAW_OPCODE_TO_ENUM: [Option<Opcode>; 256] = $isa_name::RAW_OPCODE_TO_ENUM_CONST;
                *RAW_OPCODE_TO_ENUM.get(raw_opcode as usize)?
            }

            #[cfg_attr(feature = "alloc", inline)]
            fn opcode_to_raw(self, opcode: Opcode, args_length: u32) -> Option<(u32, u32)> {
                static OPCODE_DISCRIMINANT_TO_RAW_OPCODE: [u8; 256] = $isa_name::OPCODE_DISCRIMINANT_TO_RAW_OPCODE_CONST;
                let raw_opcode = OPCODE_DISCRIMINANT_TO_RAW_OPCODE[opcode.discriminant() as usize];
                if u32::from(raw_opcode) == UNUSED_RAW_OPCODE {
                    None
                } else {
                    Some((u32::from(raw_opcode), args_length))
                }
            }

            fn supports_opcode(self, opcode: Opcode) -> bool {
                match opcode {
                    $(Opcode::$name_argless => true,)+
                    $(Opcode::$name_reg_imm => true,)+
                    $(Opcode::$name_reg_imm_offset => true,)+
                    $(Opcode::$name_reg_imm_imm => true,)+
                    $(Opcode::$name_reg_reg_imm => true,)+
                    $(Opcode::$name_reg_reg_offset => true,)+
                    $(Opcode::$name_reg_reg_reg => true,)+
                    $(Opcode::$name_offset => true,)+
                    $(Opcode::$name_imm => true,)+
                    $(Opcode::$name_imm_imm => true,)+
                    $(Opcode::$name_reg_reg => true,)+
                    $(Opcode::$name_reg_reg_imm_imm => true,)+
                    $(Opcode::$name_reg_imm64 => true,)*
                    #[allow(unreachable_patterns)]
                    _ => false,
                }
            }

            fn parse_instruction(self, raw_opcode: usize, chunk: u128, offset: u32, length: u32) -> Instruction {
                match raw_opcode {
                    $(
                        $value_argless => Instruction::$name_argless,
                    )+
                    $(
                        $value_reg_imm => {
                            let (reg, imm) = $crate::program::read_args_reg_imm::<false>(chunk, length);
                            Instruction::$name_reg_imm(reg, imm)
                        },
                    )+
                    $(
                        $value_reg_imm_offset => {
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm_offset::<false>(chunk, offset, length);
                            Instruction::$name_reg_imm_offset(reg, imm1, imm2)
                        },
                    )+
                    $(
                        $value_reg_imm_imm => {
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm2::<false>(chunk, length);
                            Instruction::$name_reg_imm_imm(reg, imm1, imm2)
                        },
                    )+
                    $(
                        $value_reg_reg_imm => {
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_imm::<false>(chunk, length);
                            Instruction::$name_reg_reg_imm(reg1, reg2, imm)
                        }
                    )+
                    $(
                        $value_reg_reg_offset => {
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_offset::<false>(chunk, offset, length);
                            Instruction::$name_reg_reg_offset(reg1, reg2, imm)
                        }
                    )+
                    $(
                        $value_reg_reg_reg => {
                            let (reg1, reg2, reg3) = $crate::program::read_args_regs3::<false>(chunk);
                            Instruction::$name_reg_reg_reg(reg1, reg2, reg3)
                        }
                    )+
                    $(
                        $value_offset => {
                            let imm = $crate::program::read_args_offset::<false>(chunk, offset, length);
                            Instruction::$name_offset(imm)
                        }
                    )+
                    $(
                        $value_imm => {
                            let imm = $crate::program::read_args_imm::<false>(chunk, length);
                            Instruction::$name_imm(imm)
                        }
                    )+
                    $(
                        $value_imm_imm => {
                            let (imm1, imm2) = $crate::program::read_args_imm2::<false>(chunk, length);
                            Instruction::$name_imm_imm(imm1, imm2)
                        }
                    )+
                    $(
                        $value_reg_reg => {
                            let (reg1, reg2) = $crate::program::read_args_regs2::<false>(chunk);
                            Instruction::$name_reg_reg(reg1, reg2)
                        }
                    )+
                    $(
                        $value_reg_reg_imm_imm => {
                            let (reg1, reg2, imm1, imm2) = $crate::program::read_args_regs2_imm2::<false>(chunk, length);
                            Instruction::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2)
                        }
                    )+
                    $(
                        $value_reg_imm64 => {
                            let (reg, imm) = $crate::program::read_args_reg_imm64::<false>(chunk);
                            Instruction::$name_reg_imm64(reg, imm)
                        }
                    )*
                    _ => Instruction::invalid,
                }
            }
        }

        #[macro_export]
        macro_rules! $build_static_dispatch_table {
            ($table_name:ident, $visitor_ty:ident<$d($visitor_ty_params:tt),*>) => {{
                use $crate::program::{
                    LEGACY_RAW_OPCODE_COUNT,
                    ParsingVisitor
                };

                type ReturnTy<$d($visitor_ty_params),*> = <$visitor_ty<$d($visitor_ty_params),*> as ParsingVisitor>::ReturnTy;
                type VisitFn<$d($visitor_ty_params),*> = fn(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32);

                #[derive(Copy, Clone)]
                struct DispatchTable<'a>(&'a [VisitFn<'a>; LEGACY_RAW_OPCODE_COUNT]);

                impl<'a> $crate::program::OpcodeVisitor for DispatchTable<'a> {
                    type State = $visitor_ty<'a>;
                    type ReturnTy = ();
                    type InstructionSet = $crate::program::$isa_name;

                    #[inline]
                    fn instruction_set(self) -> Self::InstructionSet {
                        $crate::program::$isa_name
                    }

                    #[inline]
                    fn dispatch(self, state: &mut $visitor_ty<'a>, opcode: usize, chunk: u128, offset: u32, length: u32) {
                        self.0[opcode](state, chunk, offset, length)
                    }
                }

                static $table_name: [VisitFn; LEGACY_RAW_OPCODE_COUNT] = {
                    let mut table = [invalid_instruction as VisitFn; LEGACY_RAW_OPCODE_COUNT];

                    $({
                        // Putting all of the handlers in a single link section can make a big difference
                        // when it comes to performance, even up to 10% in some cases. This will force the
                        // compiler and the linker to put all of this code near each other, minimizing
                        // instruction cache misses.
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_argless<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, _chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            state.$name_argless(offset, length)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_argless].is_some() {
                            table[$value_argless] = $name_argless;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm) = $crate::program::read_args_reg_imm::<false>(chunk, length);
                            state.$name_reg_imm(offset, length, reg, imm)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_reg_imm].is_some() {
                            table[$value_reg_imm] = $name_reg_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_offset<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm_offset::<false>(chunk, offset, length);
                            state.$name_reg_imm_offset(offset, length, reg, imm1, imm2)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_reg_imm_offset].is_some() {
                            table[$value_reg_imm_offset] = $name_reg_imm_offset;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm2::<false>(chunk, length);
                            state.$name_reg_imm_imm(offset, length, reg, imm1, imm2)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_reg_imm_imm].is_some() {
                            table[$value_reg_imm_imm] = $name_reg_imm_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_imm::<false>(chunk, length);
                            state.$name_reg_reg_imm(offset, length, reg1, reg2, imm)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_reg_reg_imm].is_some() {
                            table[$value_reg_reg_imm] = $name_reg_reg_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_offset<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_offset::<false>(chunk, offset, length);
                            state.$name_reg_reg_offset(offset, length, reg1, reg2, imm)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_reg_reg_offset].is_some() {
                            table[$value_reg_reg_offset] = $name_reg_reg_offset;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_reg<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, reg3) = $crate::program::read_args_regs3::<false>(chunk);
                            state.$name_reg_reg_reg(offset, length, reg1, reg2, reg3)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_reg_reg_reg].is_some() {
                            table[$value_reg_reg_reg] = $name_reg_reg_reg;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_offset<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let imm = $crate::program::read_args_offset::<false>(chunk, offset, length);
                            state.$name_offset(offset, length, imm)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_offset].is_some() {
                            table[$value_offset] = $name_offset;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let imm = $crate::program::read_args_imm::<false>(chunk, length);
                            state.$name_imm(offset, length, imm)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_imm].is_some() {
                            table[$value_imm] = $name_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (imm1, imm2) = $crate::program::read_args_imm2::<false>(chunk, length);
                            state.$name_imm_imm(offset, length, imm1, imm2)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_imm_imm].is_some() {
                            table[$value_imm_imm] = $name_imm_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2) = $crate::program::read_args_regs2::<false>(chunk);
                            state.$name_reg_reg(offset, length, reg1, reg2)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_reg_reg].is_some() {
                            table[$value_reg_reg] = $name_reg_reg;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm1, imm2) = $crate::program::read_args_regs2_imm2::<false>(chunk, length);
                            state.$name_reg_reg_imm_imm(offset, length, reg1, reg2, imm1, imm2)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_reg_reg_imm_imm].is_some() {
                            table[$value_reg_reg_imm_imm] = $name_reg_reg_imm_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm64<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm) = $crate::program::read_args_reg_imm64::<false>(chunk);
                            state.$name_reg_imm64(offset, length, reg, imm)
                        }

                        if $crate::program::$isa_name::RAW_OPCODE_TO_ENUM_CONST[$value_reg_imm64].is_some() {
                            table[$value_reg_imm64] = $name_reg_imm64;
                        }
                    })*

                    #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                    #[cold]
                    fn invalid_instruction<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, _chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                        state.invalid(offset, length)
                    }

                    table
                };

                #[inline]
                #[allow(unsafe_code)]
                // SAFETY: Here we transmute the lifetimes which were unnecessarily extended to be 'static due to the table here being a `static`.
                fn transmute_lifetime<'a>(table: DispatchTable<'static>) -> DispatchTable<'a> {
                    unsafe { core::mem::transmute(&$table_name) }
                }

                transmute_lifetime(DispatchTable(&$table_name))
            }};
        }

        pub use $build_static_dispatch_table;
    };
}

macro_rules! define_extended_instruction_set {
    (
        ($d:tt)
        $isa_name:ident,
        $build_static_dispatch_table:ident,

        [$($name_argless:ident = [$($length_argless:literal: $value_argless:expr),+],)+]
        [$($name_reg_imm:ident = [$($length_reg_imm:literal: $value_reg_imm:expr),+],)+]
        [$($name_reg_imm_offset:ident = [$($length_reg_imm_offset:literal: $value_reg_imm_offset:expr),+],)+]
        [$($name_reg_imm_imm:ident = [$($length_reg_imm_imm:literal: $value_reg_imm_imm:expr),+],)+]
        [$($name_reg_reg_imm:ident = [$($length_reg_reg_imm:literal: $value_reg_reg_imm:expr),+],)+]
        [$($name_reg_reg_offset:ident = [$($length_reg_reg_offset:literal: $value_reg_reg_offset:expr),+],)+]
        [$($name_reg_reg_reg:ident = [$($length_reg_reg_reg:literal: $value_reg_reg_reg:expr),+],)+]
        [$($name_offset:ident = [$($length_offset:literal: $value_offset:expr),+],)+]
        [$($name_imm:ident = [$($length_imm:literal: $value_imm:expr),+],)+]
        [$($name_imm_imm:ident = [$($length_imm_imm:literal: $value_imm_imm:expr),+],)+]
        [$($name_reg_reg:ident = [$($length_reg_reg:literal: $value_reg_reg:expr),+],)+]
        [$($name_reg_reg_imm_imm:ident = [$($length_reg_reg_imm_imm:literal: $value_reg_reg_imm_imm:expr),+],)+]
        [$($name_reg_imm64:ident = [$($length_reg_imm64:literal: $value_reg_imm64:expr),*],)*]
    ) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone, Debug, Default)]
        pub struct $isa_name;

        macro_rules! extended_for_each_entry {
            ($d callback:ident) => {
                $($( $d callback!($name_argless, $value_argless, $length_argless); )+)+
                $($( $d callback!($name_reg_imm, $value_reg_imm, $length_reg_imm); )+)+
                $($( $d callback!($name_reg_imm_offset, $value_reg_imm_offset, $length_reg_imm_offset); )+)+
                $($( $d callback!($name_reg_imm_imm, $value_reg_imm_imm, $length_reg_imm_imm); )+)+
                $($( $d callback!($name_reg_reg_imm, $value_reg_reg_imm, $length_reg_reg_imm); )+)+
                $($( $d callback!($name_reg_reg_offset, $value_reg_reg_offset, $length_reg_reg_offset); )+)+
                $($( $d callback!($name_reg_reg_reg, $value_reg_reg_reg, $length_reg_reg_reg); )+)+
                $($( $d callback!($name_offset, $value_offset, $length_offset); )+)+
                $($( $d callback!($name_imm, $value_imm, $length_imm); )+)+
                $($( $d callback!($name_imm_imm, $value_imm_imm, $length_imm_imm); )+)+
                $($( $d callback!($name_reg_reg, $value_reg_reg, $length_reg_reg); )+)+
                $($( $d callback!($name_reg_reg_imm_imm, $value_reg_reg_imm_imm, $length_reg_reg_imm_imm); )+)+
                $($( $d callback!($name_reg_imm64, $value_reg_imm64, $length_reg_imm64); )*)*
            }
        }

        impl $isa_name {
            #[doc(hidden)]
            pub const RAW_OPCODE_TO_ENUM_CONST: [Option<Opcode>; EXTENDED_RAW_OPCODE_COUNT] = {
                let mut map = [None; EXTENDED_RAW_OPCODE_COUNT];
                macro_rules! set {
                    ($entry_name:ident, $value:expr, $args_length:expr) => {
                        assert!($value < EXTENDED_INVALID_RAW_OPCODE);
                        #[allow(unused_comparisons)]
                        {
                            assert!($args_length <= EXTENDED_MAX_ARGS_LENGTH);
                        }
                        assert!(map[$value].is_none(), "duplicate opcode byte value");
                        map[$value] = Some(Opcode::$entry_name);
                    };
                }
                extended_for_each_entry!(set);
                map
            };

            #[doc(hidden)]
            pub const RAW_OPCODE_STARTS_NEW_BASIC_BLOCK_CONST: [bool; EXTENDED_RAW_OPCODE_COUNT] = {
                let mut map = [true; EXTENDED_RAW_OPCODE_COUNT];
                macro_rules! set {
                    ($entry_name:ident, $value:expr, $args_length:expr) => {
                        map[$value] = Opcode::$entry_name.starts_new_basic_block();
                    };
                }
                extended_for_each_entry!(set);
                map
            };

            #[doc(hidden)]
            pub const RAW_OPCODE_TO_LENGTH_CONST: [RawOpcodeLength; EXTENDED_RAW_OPCODE_COUNT] = {
                let mut map = [RawOpcodeLength(0_u8); EXTENDED_RAW_OPCODE_COUNT];
                let mut index = 0;
                while index < map.len() {
                    map[index].0 = 1;
                    if index >= 255 {
                        map[index].0 += 1;
                    }
                    index += 1;
                }

                macro_rules! set {
                    ($entry_name:ident, $raw_opcode:expr, $args_length:expr) => {
                        let mut length = $args_length as u8 + 1;
                        if $raw_opcode >= 255 {
                            length += 1;
                        }
                        map[$raw_opcode].0 = length;
                    };
                }
                extended_for_each_entry!(set);
                map
            };

            #[doc(hidden)]
            pub const OPCODE_AND_LENGTH_TO_RAW_OPCODE_CONST: [[RawOpcodeEntry; EXTENDED_MAX_ARGS_LENGTH + 1]; 256] = {
                let mut map = [[RawOpcodeEntry::empty(); EXTENDED_MAX_ARGS_LENGTH + 1]; 256];
                macro_rules! set {
                    ($entry_name:ident, $raw_opcode:expr, $args_length:expr) => {
                        let args_length: u16 = $args_length;
                        let discriminant = Opcode::$entry_name.discriminant() as usize;
                        let entry = &mut map[discriminant];
                        entry[args_length as usize] = RawOpcodeEntry::new($raw_opcode as u16, args_length);

                        let mut args_length_subset = 0;
                        while args_length_subset < args_length {
                            if entry[args_length_subset as usize].is_empty() {
                                entry[args_length_subset as usize] = RawOpcodeEntry::new($raw_opcode as u16, args_length);
                            }
                            args_length_subset += 1;
                        }
                    };
                }
                extended_for_each_entry!(set);
                map
            };

            #[doc(hidden)]
            pub const OPCODE_IS_SUPPORTED_CONST: [bool; 256] = {
                let mut map = [false; 256];
                macro_rules! set {
                    ($entry_name:ident, $raw_opcode:expr, $args_length:expr) => {
                        map[Opcode::$entry_name.discriminant() as usize] = true;
                    };
                }
                extended_for_each_entry!(set);
                map
            };
        }

        impl InstructionSet for $isa_name {
            #[inline]
            fn is_legacy(self) -> bool {
                false
            }

            #[cfg_attr(feature = "alloc", inline)]
            fn opcode_from_raw(self, raw_opcode: u32) -> Option<Opcode> {
                static RAW_OPCODE_TO_ENUM: [Option<Opcode>; EXTENDED_RAW_OPCODE_COUNT] = $isa_name::RAW_OPCODE_TO_ENUM_CONST;
                *RAW_OPCODE_TO_ENUM.get(raw_opcode as usize)?
            }

            #[cfg_attr(feature = "alloc", inline)]
            fn opcode_to_raw(self, opcode: Opcode, args_length: u32) -> Option<(u32, u32)> {
                static OPCODE_AND_LENGTH_TO_RAW_OPCODE: [[RawOpcodeEntry; EXTENDED_MAX_ARGS_LENGTH + 1]; 256] = $isa_name::OPCODE_AND_LENGTH_TO_RAW_OPCODE_CONST;
                let entry = *OPCODE_AND_LENGTH_TO_RAW_OPCODE[opcode.discriminant() as usize].get(args_length as usize)?;
                if entry.is_empty() {
                    None
                } else {
                    Some((u32::from(entry.raw_opcode()), u32::from(entry.args_length())))
                }
            }

            #[cfg_attr(feature = "alloc", inline)]
            fn supports_opcode(self, opcode: Opcode) -> bool {
                static OPCODE_IS_SUPPORTED: [bool; 256] = $isa_name::OPCODE_IS_SUPPORTED_CONST;
                OPCODE_IS_SUPPORTED[opcode.discriminant() as usize]
            }

            #[cfg_attr(feature = "alloc", inline)]
            fn raw_opcode_table(self) -> &'static RawOpcodeTable {
                static RAW_OPCODE_TABLE: RawOpcodeTable = RawOpcodeTable {
                    length_table: $isa_name::RAW_OPCODE_TO_LENGTH_CONST,
                    starts_new_basic_block_table: $isa_name::RAW_OPCODE_STARTS_NEW_BASIC_BLOCK_CONST,
                };

                &RAW_OPCODE_TABLE
            }

            fn parse_instruction(self, raw_opcode: usize, chunk: u128, offset: u32, length: u32) -> Instruction {
                macro_rules! args {
                    ($name:ident($d($arg:ident),+)) => {
                        if raw_opcode >= 255 {
                            $crate::program::$name::<true>($d($arg),+)
                        } else {
                            $crate::program::$name::<false>($d($arg),+)
                        }
                    }
                }

                match raw_opcode {
                    $(
                        $($value_argless)|+ => Instruction::$name_argless,
                    )+
                    $(
                        $($value_reg_imm)|+ => {
                            let (reg, imm) = args!(read_args_reg_imm(chunk, length));
                            Instruction::$name_reg_imm(reg, imm)
                        },
                    )+
                    $(
                        $($value_reg_imm_offset)|+ => {
                            let (reg, imm1, imm2) = args!(read_args_reg_imm_offset(chunk, offset, length));
                            Instruction::$name_reg_imm_offset(reg, imm1, imm2)
                        },
                    )+
                    $(
                        $($value_reg_imm_imm)|+ => {
                            let (reg, imm1, imm2) = args!(read_args_reg_imm2(chunk, length));
                            Instruction::$name_reg_imm_imm(reg, imm1, imm2)
                        },
                    )+
                    $(
                        $($value_reg_reg_imm)|+ => {
                            let (reg1, reg2, imm) = args!(read_args_regs2_imm(chunk, length));
                            Instruction::$name_reg_reg_imm(reg1, reg2, imm)
                        }
                    )+
                    $(
                        $($value_reg_reg_offset)|+ => {
                            let (reg1, reg2, imm) = args!(read_args_regs2_offset(chunk, offset, length));
                            Instruction::$name_reg_reg_offset(reg1, reg2, imm)
                        }
                    )+
                    $(
                        $($value_reg_reg_reg)|+ => {
                            let (reg1, reg2, reg3) = args!(read_args_regs3(chunk));
                            Instruction::$name_reg_reg_reg(reg1, reg2, reg3)
                        }
                    )+
                    $(
                        $($value_offset)|+ => {
                            let imm = args!(read_args_offset(chunk, offset, length));
                            Instruction::$name_offset(imm)
                        }
                    )+
                    $(
                        $($value_imm)|+ => {
                            let imm = args!(read_args_imm(chunk, length));
                            Instruction::$name_imm(imm)
                        }
                    )+
                    $(
                        $($value_imm_imm)|+ => {
                            let (imm1, imm2) = args!(read_args_imm2(chunk, length));
                            Instruction::$name_imm_imm(imm1, imm2)
                        }
                    )+
                    $(
                        $($value_reg_reg)|+ => {
                            let (reg1, reg2) = args!(read_args_regs2(chunk));
                            Instruction::$name_reg_reg(reg1, reg2)
                        }
                    )+
                    $(
                        $($value_reg_reg_imm_imm)|+ => {
                            let (reg1, reg2, imm1, imm2) = args!(read_args_regs2_imm2(chunk, length));
                            Instruction::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2)
                        }
                    )+
                    $(
                        $($value_reg_imm64)|+ => {
                            let (reg, imm) = args!(read_args_reg_imm64(chunk));
                            Instruction::$name_reg_imm64(reg, imm)
                        }
                    )*
                    _ => Instruction::invalid,
                }
            }
        }

        #[macro_export]
        macro_rules! $build_static_dispatch_table {
            ($table_name:ident, $visitor_ty:ident<$d($visitor_ty_params:tt),*>) => {{
                use $crate::program::{
                    EXTENDED_RAW_OPCODE_COUNT,
                    ParsingVisitor
                };

                type ReturnTy<$d($visitor_ty_params),*> = <$visitor_ty<$d($visitor_ty_params),*> as ParsingVisitor>::ReturnTy;
                type VisitFn<$d($visitor_ty_params),*> = fn(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32);

                #[derive(Copy, Clone)]
                struct DispatchTable<'a>(&'a [VisitFn<'a>; EXTENDED_RAW_OPCODE_COUNT]);

                impl<'a> $crate::program::OpcodeVisitor for DispatchTable<'a> {
                    type State = $visitor_ty<'a>;
                    type ReturnTy = ();
                    type InstructionSet = $crate::program::$isa_name;

                    #[inline]
                    fn instruction_set(self) -> Self::InstructionSet {
                        $crate::program::$isa_name
                    }

                    #[inline]
                    fn dispatch(self, state: &mut $visitor_ty<'a>, opcode: usize, chunk: u128, offset: u32, length: u32) {
                        self.0[opcode](state, chunk, offset, length)
                    }
                }

                static $table_name: [VisitFn; EXTENDED_RAW_OPCODE_COUNT] = {
                    let mut table = [invalid_instruction as VisitFn; EXTENDED_RAW_OPCODE_COUNT];

                    $({
                        // Putting all of the handlers in a single link section can make a big difference
                        // when it comes to performance, even up to 10% in some cases. This will force the
                        // compiler and the linker to put all of this code near each other, minimizing
                        // instruction cache misses.
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_argless<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, _chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            state.$name_argless(offset, length)
                        }

                        $(table[$value_argless] = $name_argless;)+
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm) = $crate::program::read_args_reg_imm::<EXT>(chunk, length);
                            state.$name_reg_imm(offset, length, reg, imm)
                        }

                        $(table[$value_reg_imm] = $name_reg_imm::<{ ($value_reg_imm) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_offset<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm_offset::<EXT>(chunk, offset, length);
                            state.$name_reg_imm_offset(offset, length, reg, imm1, imm2)
                        }

                        $(table[$value_reg_imm_offset] = $name_reg_imm_offset::<{ ($value_reg_imm_offset) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_imm<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm2::<EXT>(chunk, length);
                            state.$name_reg_imm_imm(offset, length, reg, imm1, imm2)
                        }

                        $(table[$value_reg_imm_imm] = $name_reg_imm_imm::<{ ($value_reg_imm_imm) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_imm::<EXT>(chunk, length);
                            state.$name_reg_reg_imm(offset, length, reg1, reg2, imm)
                        }

                        $(table[$value_reg_reg_imm] = $name_reg_reg_imm::<{ ($value_reg_reg_imm) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_offset<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_offset::<EXT>(chunk, offset, length);
                            state.$name_reg_reg_offset(offset, length, reg1, reg2, imm)
                        }

                        $(table[$value_reg_reg_offset] = $name_reg_reg_offset::<{ ($value_reg_reg_offset) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_reg<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, reg3) = $crate::program::read_args_regs3::<EXT>(chunk);
                            state.$name_reg_reg_reg(offset, length, reg1, reg2, reg3)
                        }

                        $(table[$value_reg_reg_reg] = $name_reg_reg_reg::<{ ($value_reg_reg_reg) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_offset<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let imm = $crate::program::read_args_offset::<EXT>(chunk, offset, length);
                            state.$name_offset(offset, length, imm)
                        }

                        $(table[$value_offset] = $name_offset::<{ ($value_offset) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let imm = $crate::program::read_args_imm::<EXT>(chunk, length);
                            state.$name_imm(offset, length, imm)
                        }

                        $(table[$value_imm] = $name_imm::<{ ($value_imm) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm_imm<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (imm1, imm2) = $crate::program::read_args_imm2::<EXT>(chunk, length);
                            state.$name_imm_imm(offset, length, imm1, imm2)
                        }

                        $(table[$value_imm_imm] = $name_imm_imm::<{ ($value_imm_imm) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2) = $crate::program::read_args_regs2::<EXT>(chunk);
                            state.$name_reg_reg(offset, length, reg1, reg2)
                        }

                        $(table[$value_reg_reg] = $name_reg_reg::<{ ($value_reg_reg) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm_imm<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm1, imm2) = $crate::program::read_args_regs2_imm2::<EXT>(chunk, length);
                            state.$name_reg_reg_imm_imm(offset, length, reg1, reg2, imm1, imm2)
                        }

                        $(table[$value_reg_reg_imm_imm] = $name_reg_reg_imm_imm::<{ ($value_reg_reg_imm_imm) >= 255 }>;)+
                    })*


                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm64<$d($visitor_ty_params),*, const EXT: bool>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm) = $crate::program::read_args_reg_imm64::<EXT>(chunk);
                            state.$name_reg_imm64(offset, length, reg, imm)
                        }

                        $(table[$value_reg_imm64] = $name_reg_imm64::<{ ($value_reg_imm64) >= 255 }>;)*
                    })*


                    #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                    #[cold]
                    fn invalid_instruction<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, _chunk: u128, offset: u32, length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                        state.invalid(offset, length)
                    }

                    table
                };

                #[inline]
                #[allow(unsafe_code)]
                // SAFETY: Here we transmute the lifetimes which were unnecessarily extended to be 'static due to the table here being a `static`.
                fn transmute_lifetime<'a>(table: DispatchTable<'static>) -> DispatchTable<'a> {
                    unsafe { core::mem::transmute(&$table_name) }
                }

                transmute_lifetime(DispatchTable(&$table_name))
            }};
        }

        pub use $build_static_dispatch_table;
    };
}

#[inline]
fn parse_instruction_legacy<I>(instruction_set: I, code: &[u8], bitmask: &[u8], offset: u32) -> (u32, Instruction, bool)
where
    I: InstructionSet,
{
    let visitor = EnumVisitor { instruction_set };
    if offset as usize + 32 <= code.len() {
        visitor_step_fast_legacy(&mut (), code, bitmask, offset, visitor)
    } else {
        visitor_step_slow_legacy(&mut (), code, bitmask, offset, visitor)
    }
}

const LEGACY_INVALID_RAW_OPCODE: u32 = 256;

#[doc(hidden)]
pub const LEGACY_RAW_OPCODE_COUNT: usize = 257;

define_all_instructions! {
    // Instructions with args: none
    [
        trap,
        fallthrough,
        memset,
        unlikely,
    ]

    // Instructions with args: reg, imm
    [
        jump_indirect,
        load_imm,
        load_u8,
        load_i8,
        load_u16,
        load_i16,
        load_i32,
        load_u32,
        load_u64,
        store_u8,
        store_u16,
        store_u32,
        store_u64,
    ]

    // Instructions with args: reg, imm, offset
    [
        load_imm_and_jump,
        branch_eq_imm,
        branch_not_eq_imm,
        branch_less_unsigned_imm,
        branch_less_signed_imm,
        branch_greater_or_equal_unsigned_imm,
        branch_greater_or_equal_signed_imm,
        branch_less_or_equal_signed_imm,
        branch_less_or_equal_unsigned_imm,
        branch_greater_signed_imm,
        branch_greater_unsigned_imm,
    ]

    // Instructions with args: reg, imm, imm
    [
        store_imm_indirect_u8,
        store_imm_indirect_u16,
        store_imm_indirect_u32,
        store_imm_indirect_u64,
    ]

    // Instructions with args: reg, reg, imm
    [
        store_indirect_u8,
        store_indirect_u16,
        store_indirect_u32,
        store_indirect_u64,
        load_indirect_u8,
        load_indirect_i8,
        load_indirect_u16,
        load_indirect_i16,
        load_indirect_i32,
        load_indirect_u32,
        load_indirect_u64,
        add_imm_32,
        add_imm_64,
        and_imm,
        xor_imm,
        or_imm,
        mul_imm_32,
        mul_imm_64,
        set_less_than_unsigned_imm,
        set_less_than_signed_imm,
        shift_logical_left_imm_32,
        shift_logical_left_imm_64,
        shift_logical_right_imm_32,
        shift_logical_right_imm_64,
        shift_arithmetic_right_imm_32,
        shift_arithmetic_right_imm_64,
        negate_and_add_imm_32,
        negate_and_add_imm_64,
        set_greater_than_unsigned_imm,
        set_greater_than_signed_imm,
        shift_logical_right_imm_alt_32,
        shift_logical_right_imm_alt_64,
        shift_arithmetic_right_imm_alt_32,
        shift_arithmetic_right_imm_alt_64,
        shift_logical_left_imm_alt_32,
        shift_logical_left_imm_alt_64,

        cmov_if_zero_imm,
        cmov_if_not_zero_imm,

        rotate_right_imm_32,
        rotate_right_imm_alt_32,
        rotate_right_imm_64,
        rotate_right_imm_alt_64,
    ]

    // Instructions with args: reg, reg, offset
    [
        branch_eq,
        branch_not_eq,
        branch_less_unsigned,
        branch_less_signed,
        branch_greater_or_equal_unsigned,
        branch_greater_or_equal_signed,
    ]

    // Instructions with args: reg, reg, reg
    [
        add_32,
        add_64,
        sub_32,
        sub_64,
        and,
        xor,
        or,
        mul_32,
        mul_64,
        mul_upper_signed_signed,
        mul_upper_unsigned_unsigned,
        mul_upper_signed_unsigned,
        set_less_than_unsigned,
        set_less_than_signed,
        shift_logical_left_32,
        shift_logical_left_64,
        shift_logical_right_32,
        shift_logical_right_64,
        shift_arithmetic_right_32,
        shift_arithmetic_right_64,
        div_unsigned_32,
        div_unsigned_64,
        div_signed_32,
        div_signed_64,
        rem_unsigned_32,
        rem_unsigned_64,
        rem_signed_32,
        rem_signed_64,

        cmov_if_zero,
        cmov_if_not_zero,

        and_inverted,
        or_inverted,
        xnor,
        maximum,
        maximum_unsigned,
        minimum,
        minimum_unsigned,
        rotate_left_32,
        rotate_left_64,
        rotate_right_32,
        rotate_right_64,
    ]

    // Instructions with args: offset
    [
        jump,
    ]

    // Instructions with args: imm
    [
        ecalli,
    ]

    // Instructions with args: imm, imm
    [
        store_imm_u8,
        store_imm_u16,
        store_imm_u32,
        store_imm_u64,
    ]

    // Instructions with args: reg, reg
    [
        move_reg,
        sbrk,
        count_leading_zero_bits_32,
        count_leading_zero_bits_64,
        count_trailing_zero_bits_32,
        count_trailing_zero_bits_64,
        count_set_bits_32,
        count_set_bits_64,
        sign_extend_8,
        sign_extend_16,
        zero_extend_16,
        reverse_byte,
    ]

    // Instructions with args: reg, reg, imm, imm
    [
        load_imm_and_jump_indirect,
    ]

    // Instruction with args: reg, imm64
    [
        load_imm64,
    ]
}

define_legacy_instruction_set! {
    ($)

    ISA_ReviveV1,
    build_static_dispatch_table_revive_v1,

    [
        trap                                     = 0,
        fallthrough                              = 1,
        // MISSING: memset
        // MISSING: unlikely
    ]
    [
        jump_indirect                            = 50,
        load_imm                                 = 51,
        load_u8                                  = 52,
        load_i8                                  = 53,
        load_u16                                 = 54,
        load_i16                                 = 55,
        load_i32                                 = 57,
        load_u32                                 = 56,
        load_u64                                 = 58,
        store_u8                                 = 59,
        store_u16                                = 60,
        store_u32                                = 61,
        store_u64                                = 62,
    ]
    [
        load_imm_and_jump                        = 80,
        branch_eq_imm                            = 81,
        branch_not_eq_imm                        = 82,
        branch_less_unsigned_imm                 = 83,
        branch_less_signed_imm                   = 87,
        branch_greater_or_equal_unsigned_imm     = 85,
        branch_greater_or_equal_signed_imm       = 89,
        branch_less_or_equal_signed_imm          = 88,
        branch_less_or_equal_unsigned_imm        = 84,
        branch_greater_signed_imm                = 90,
        branch_greater_unsigned_imm              = 86,
    ]
    [
        store_imm_indirect_u8                    = 70,
        store_imm_indirect_u16                   = 71,
        store_imm_indirect_u32                   = 72,
        store_imm_indirect_u64                   = 73,
    ]
    [
        store_indirect_u8                        = 120,
        store_indirect_u16                       = 121,
        store_indirect_u32                       = 122,
        store_indirect_u64                       = 123,
        load_indirect_u8                         = 124,
        load_indirect_i8                         = 125,
        load_indirect_u16                        = 126,
        load_indirect_i16                        = 127,
        load_indirect_i32                        = 129,
        load_indirect_u32                        = 128,
        load_indirect_u64                        = 130,
        add_imm_32                               = 131,
        add_imm_64                               = 149,
        and_imm                                  = 132,
        xor_imm                                  = 133,
        or_imm                                   = 134,
        mul_imm_32                               = 135,
        mul_imm_64                               = 150,
        set_less_than_unsigned_imm               = 136,
        set_less_than_signed_imm                 = 137,
        shift_logical_left_imm_32                = 138,
        shift_logical_left_imm_64                = 151,
        shift_logical_right_imm_32               = 139,
        shift_logical_right_imm_64               = 152,
        shift_arithmetic_right_imm_32            = 140,
        shift_arithmetic_right_imm_64            = 153,
        negate_and_add_imm_32                    = 141,
        negate_and_add_imm_64                    = 154,
        set_greater_than_unsigned_imm            = 142,
        set_greater_than_signed_imm              = 143,
        shift_logical_right_imm_alt_32           = 145,
        shift_logical_right_imm_alt_64           = 156,
        shift_arithmetic_right_imm_alt_32        = 146,
        shift_arithmetic_right_imm_alt_64        = 157,
        shift_logical_left_imm_alt_32            = 144,
        shift_logical_left_imm_alt_64            = 155,
        cmov_if_zero_imm                         = 147,
        cmov_if_not_zero_imm                     = 148,
        rotate_right_imm_32                      = 160,
        rotate_right_imm_alt_32                  = 161,
        rotate_right_imm_64                      = 158,
        rotate_right_imm_alt_64                  = 159,
    ]
    [
        branch_eq                                = 170,
        branch_not_eq                            = 171,
        branch_less_unsigned                     = 172,
        branch_less_signed                       = 173,
        branch_greater_or_equal_unsigned         = 174,
        branch_greater_or_equal_signed           = 175,
    ]
    [
        add_32                                   = 190,
        add_64                                   = 200,
        sub_32                                   = 191,
        sub_64                                   = 201,
        and                                      = 210,
        xor                                      = 211,
        or                                       = 212,
        mul_32                                   = 192,
        mul_64                                   = 202,
        mul_upper_signed_signed                  = 213,
        mul_upper_unsigned_unsigned              = 214,
        mul_upper_signed_unsigned                = 215,
        set_less_than_unsigned                   = 216,
        set_less_than_signed                     = 217,
        shift_logical_left_32                    = 197,
        shift_logical_left_64                    = 207,
        shift_logical_right_32                   = 198,
        shift_logical_right_64                   = 208,
        shift_arithmetic_right_32                = 199,
        shift_arithmetic_right_64                = 209,
        div_unsigned_32                          = 193,
        div_unsigned_64                          = 203,
        div_signed_32                            = 194,
        div_signed_64                            = 204,
        rem_unsigned_32                          = 195,
        rem_unsigned_64                          = 205,
        rem_signed_32                            = 196,
        rem_signed_64                            = 206,
        cmov_if_zero                             = 218,
        cmov_if_not_zero                         = 219,
        and_inverted                             = 224,
        or_inverted                              = 225,
        xnor                                     = 226,
        maximum                                  = 227,
        maximum_unsigned                         = 228,
        minimum                                  = 229,
        minimum_unsigned                         = 230,
        rotate_left_32                           = 221,
        rotate_left_64                           = 220,
        rotate_right_32                          = 223,
        rotate_right_64                          = 222,
    ]
    [
        jump                                     = 40,
    ]
    [
        ecalli                                   = 10,
    ]
    [
        store_imm_u8                             = 30,
        store_imm_u16                            = 31,
        store_imm_u32                            = 32,
        store_imm_u64                            = 33,
    ]
    [
        move_reg                                 = 100,
        count_leading_zero_bits_32               = 105,
        count_leading_zero_bits_64               = 104,
        count_trailing_zero_bits_32              = 107,
        count_trailing_zero_bits_64              = 106,
        count_set_bits_32                        = 103,
        count_set_bits_64                        = 102,
        sign_extend_8                            = 108,
        sign_extend_16                           = 109,
        zero_extend_16                           = 110,
        reverse_byte                             = 111,
    ]
    [
        load_imm_and_jump_indirect               = 180,
    ]
    [
        load_imm64                               = 20,
    ]
}

define_legacy_instruction_set! {
    ($)

    ISA_Latest32,
    build_static_dispatch_table_latest32,

    [
        trap                                     = 0,
        fallthrough                              = 1,
        memset                                   = 2,
        unlikely                                 = 3,
    ]
    [
        jump_indirect                            = 50,
        load_imm                                 = 51,
        load_u8                                  = 52,
        load_i8                                  = 53,
        load_u16                                 = 54,
        load_i16                                 = 55,
        load_i32                                 = 57,
        store_u8                                 = 59,
        store_u16                                = 60,
        store_u32                                = 61,
    ]
    [
        load_imm_and_jump                        = 80,
        branch_eq_imm                            = 81,
        branch_not_eq_imm                        = 82,
        branch_less_unsigned_imm                 = 83,
        branch_less_signed_imm                   = 87,
        branch_greater_or_equal_unsigned_imm     = 85,
        branch_greater_or_equal_signed_imm       = 89,
        branch_less_or_equal_signed_imm          = 88,
        branch_less_or_equal_unsigned_imm        = 84,
        branch_greater_signed_imm                = 90,
        branch_greater_unsigned_imm              = 86,
    ]
    [
        store_imm_indirect_u8                    = 70,
        store_imm_indirect_u16                   = 71,
        store_imm_indirect_u32                   = 72,
    ]
    [
        store_indirect_u8                        = 120,
        store_indirect_u16                       = 121,
        store_indirect_u32                       = 122,
        load_indirect_u8                         = 124,
        load_indirect_i8                         = 125,
        load_indirect_u16                        = 126,
        load_indirect_i16                        = 127,
        load_indirect_i32                        = 129,
        add_imm_32                               = 131,
        and_imm                                  = 132,
        xor_imm                                  = 133,
        or_imm                                   = 134,
        mul_imm_32                               = 135,
        set_less_than_unsigned_imm               = 136,
        set_less_than_signed_imm                 = 137,
        shift_logical_left_imm_32                = 138,
        shift_logical_right_imm_32               = 139,
        shift_arithmetic_right_imm_32            = 140,
        negate_and_add_imm_32                    = 141,
        set_greater_than_unsigned_imm            = 142,
        set_greater_than_signed_imm              = 143,
        shift_logical_right_imm_alt_32           = 145,
        shift_arithmetic_right_imm_alt_32        = 146,
        shift_logical_left_imm_alt_32            = 144,
        cmov_if_zero_imm                         = 147,
        cmov_if_not_zero_imm                     = 148,
        rotate_right_imm_32                      = 160,
        rotate_right_imm_alt_32                  = 161,
    ]
    [
        branch_eq                                = 170,
        branch_not_eq                            = 171,
        branch_less_unsigned                     = 172,
        branch_less_signed                       = 173,
        branch_greater_or_equal_unsigned         = 174,
        branch_greater_or_equal_signed           = 175,
    ]
    [
        add_32                                   = 190,
        sub_32                                   = 191,
        and                                      = 210,
        xor                                      = 211,
        or                                       = 212,
        mul_32                                   = 192,
        mul_upper_signed_signed                  = 213,
        mul_upper_unsigned_unsigned              = 214,
        mul_upper_signed_unsigned                = 215,
        set_less_than_unsigned                   = 216,
        set_less_than_signed                     = 217,
        shift_logical_left_32                    = 197,
        shift_logical_right_32                   = 198,
        shift_arithmetic_right_32                = 199,
        div_unsigned_32                          = 193,
        div_signed_32                            = 194,
        rem_unsigned_32                          = 195,
        rem_signed_32                            = 196,
        cmov_if_zero                             = 218,
        cmov_if_not_zero                         = 219,
        and_inverted                             = 224,
        or_inverted                              = 225,
        xnor                                     = 226,
        maximum                                  = 227,
        maximum_unsigned                         = 228,
        minimum                                  = 229,
        minimum_unsigned                         = 230,
        rotate_left_32                           = 221,
        rotate_right_32                          = 223,
    ]
    [
        jump                                     = 40,
    ]
    [
        ecalli                                   = 10,
    ]
    [
        store_imm_u8                             = 30,
        store_imm_u16                            = 31,
        store_imm_u32                            = 32,
    ]
    [
        move_reg                                 = 100,
        sbrk                                     = 101,
        count_leading_zero_bits_32               = 105,
        count_trailing_zero_bits_32              = 107,
        count_set_bits_32                        = 103,
        sign_extend_8                            = 108,
        sign_extend_16                           = 109,
        zero_extend_16                           = 110,
        reverse_byte                             = 111,
    ]
    [
        load_imm_and_jump_indirect               = 180,
    ]
    [
    ]
}

define_extended_instruction_set! {
    ($)

    ISA_Latest64,
    build_static_dispatch_table_latest64,

    // argless
    [
        trap                                     = [0: 0],
        fallthrough                              = [0: 1],
        memset                                   = [0: 510],
        unlikely                                 = [0: 2],
    ]
    // reg_imm
    [
        jump_indirect                            = [1: 3, 5: 255],
        load_imm                                 = [1: 4, 2: 5, 3: 6, 4: 7, 5: 8],
        load_u8                                  = [5: 9],
        load_i8                                  = [4: 10, 5: 256],
        load_u16                                 = [5: 11],
        load_i16                                 = [5: 12],
        load_i32                                 = [4: 13, 5: 14],
        load_u32                                 = [5: 15],
        load_u64                                 = [4: 16, 5: 17],
        store_u8                                 = [5: 18],
        store_u16                                = [5: 19],
        store_u32                                = [5: 20],
        store_u64                                = [4: 21, 5: 22],
    ]
    // reg_imm_offset
    [
        load_imm_and_jump                        = [4: 23, 5: 24, 6: 25, 7: 26, 8: 27, 9: 257],
        branch_eq_imm                            = [2: 28, 3: 29, 4: 30, 5: 31, 6: 32, 9: 33],
        branch_not_eq_imm                        = [2: 34, 3: 35, 4: 36, 6: 37, 9: 258],
        branch_less_unsigned_imm                 = [3: 38, 4: 39, 5: 40, 9: 41],
        branch_less_signed_imm                   = [2: 42, 3: 43, 4: 44, 9: 45],
        branch_greater_or_equal_unsigned_imm     = [3: 46, 4: 47, 5: 48, 9: 259],
        branch_greater_or_equal_signed_imm       = [2: 49, 3: 50, 9: 51],
        branch_less_or_equal_signed_imm          = [2: 52, 3: 53, 6: 54, 9: 260],
        branch_less_or_equal_unsigned_imm        = [3: 55, 4: 56, 6: 57, 9: 261],
        branch_greater_signed_imm                = [3: 58, 4: 59, 5: 60, 9: 61],
        branch_greater_unsigned_imm              = [3: 62, 4: 63, 5: 64, 9: 65],
    ]
    // reg_imm_imm
    [
        store_imm_indirect_u8                    = [1: 66, 2: 67, 3: 68, 4: 69, 5: 70, 9: 262],
        store_imm_indirect_u16                   = [2: 71, 3: 72, 4: 73, 5: 74, 9: 263],
        store_imm_indirect_u32                   = [1: 75, 2: 76, 3: 77, 4: 78, 6: 79, 9: 80],
        store_imm_indirect_u64                   = [1: 81, 2: 82, 3: 83, 4: 84, 5: 85, 6: 86, 7: 87, 9: 264],
    ]
    // reg_reg_imm
    [
        store_indirect_u8                        = [1: 88, 2: 89, 3: 90, 5: 265],
        store_indirect_u16                       = [1: 91, 2: 92, 3: 93, 5: 266],
        store_indirect_u32                       = [1: 94, 2: 95, 3: 96, 5: 267],
        store_indirect_u64                       = [1: 97, 2: 98, 3: 99, 5: 268],
        load_indirect_u8                         = [1: 100, 2: 101, 3: 102, 5: 269],
        load_indirect_i8                         = [1: 103, 2: 104, 3: 105, 5: 270],
        load_indirect_u16                        = [1: 106, 2: 107, 3: 108, 5: 271],
        load_indirect_i16                        = [1: 109, 2: 110, 3: 111, 5: 272],
        load_indirect_i32                        = [1: 112, 2: 113, 3: 114, 5: 273],
        load_indirect_u32                        = [1: 115, 2: 116, 3: 117, 5: 274],
        load_indirect_u64                        = [1: 118, 2: 119, 3: 120, 5: 275],
        add_imm_32                               = [1: 121, 2: 122, 3: 123, 5: 124],
        add_imm_64                               = [2: 125, 3: 126, 4: 127, 5: 128],
        and_imm                                  = [2: 129, 3: 130, 5: 131],
        xor_imm                                  = [2: 132, 3: 133, 5: 134],
        or_imm                                   = [2: 135, 3: 136, 5: 137],
        mul_imm_32                               = [5: 138],
        mul_imm_64                               = [2: 139, 3: 140, 5: 141],
        set_less_than_unsigned_imm               = [2: 142, 3: 143, 5: 144],
        set_less_than_signed_imm                 = [1: 145, 2: 146, 5: 276],
        shift_logical_left_imm_32                = [2: 147, 5: 277],
        shift_logical_left_imm_64                = [2: 148, 5: 278],
        shift_logical_right_imm_32               = [2: 149, 5: 279],
        shift_logical_right_imm_64               = [2: 150, 5: 280],
        shift_arithmetic_right_imm_32            = [2: 151, 5: 281],
        shift_arithmetic_right_imm_64            = [2: 152, 5: 282],
        negate_and_add_imm_32                    = [1: 153, 3: 154, 5: 283],
        negate_and_add_imm_64                    = [1: 155, 2: 156, 5: 157],
        set_greater_than_unsigned_imm            = [1: 158, 5: 159],
        set_greater_than_signed_imm              = [1: 160, 5: 284],
        shift_logical_right_imm_alt_32           = [5: 285],
        shift_logical_right_imm_alt_64           = [2: 161, 5: 162],
        shift_arithmetic_right_imm_alt_32        = [5: 286],
        shift_arithmetic_right_imm_alt_64        = [5: 287],
        shift_logical_left_imm_alt_32            = [5: 163],
        shift_logical_left_imm_alt_64            = [2: 164, 5: 288],
        cmov_if_zero_imm                         = [1: 165, 2: 166, 5: 167],
        cmov_if_not_zero_imm                     = [1: 168, 2: 169, 5: 170],
        rotate_right_imm_32                      = [2: 171, 5: 289],
        rotate_right_imm_alt_32                  = [5: 290],
        rotate_right_imm_64                      = [2: 172, 5: 291],
        rotate_right_imm_alt_64                  = [5: 292],
    ]
    // reg_reg_offset
    [
        branch_eq                                = [2: 173, 3: 174, 5: 175],
        branch_not_eq                            = [2: 176, 3: 177, 5: 178],
        branch_less_unsigned                     = [2: 179, 3: 180, 5: 293],
        branch_less_signed                       = [2: 181, 3: 182, 5: 294],
        branch_greater_or_equal_unsigned         = [2: 183, 3: 184, 5: 295],
        branch_greater_or_equal_signed           = [2: 185, 3: 186, 5: 296],
    ]
    // reg_reg_reg
    [
        add_32                                   = [2: 187],
        add_64                                   = [2: 188],
        sub_32                                   = [2: 189],
        sub_64                                   = [2: 190],
        and                                      = [2: 191],
        xor                                      = [2: 192],
        or                                       = [2: 193],
        mul_32                                   = [2: 194],
        mul_64                                   = [2: 195],
        mul_upper_signed_signed                  = [2: 297],
        mul_upper_unsigned_unsigned              = [2: 196],
        mul_upper_signed_unsigned                = [2: 298],
        set_less_than_unsigned                   = [2: 197],
        set_less_than_signed                     = [2: 198],
        shift_logical_left_32                    = [2: 199],
        shift_logical_left_64                    = [2: 200],
        shift_logical_right_32                   = [2: 201],
        shift_logical_right_64                   = [2: 202],
        shift_arithmetic_right_32                = [2: 299],
        shift_arithmetic_right_64                = [2: 300],
        div_unsigned_32                          = [2: 203],
        div_unsigned_64                          = [2: 204],
        div_signed_32                            = [2: 205],
        div_signed_64                            = [2: 301],
        rem_unsigned_32                          = [2: 206],
        rem_unsigned_64                          = [2: 207],
        rem_signed_32                            = [2: 208],
        rem_signed_64                            = [2: 302],
        cmov_if_zero                             = [2: 209],
        cmov_if_not_zero                         = [2: 210],
        and_inverted                             = [2: 211],
        or_inverted                              = [2: 212],
        xnor                                     = [2: 213],
        maximum                                  = [2: 303],
        maximum_unsigned                         = [2: 214],
        minimum                                  = [2: 304],
        minimum_unsigned                         = [2: 215],
        rotate_left_32                           = [2: 305],
        rotate_left_64                           = [2: 216],
        rotate_right_32                          = [2: 306],
        rotate_right_64                          = [2: 307],
    ]
    // offset
    [
        jump                                     = [1: 217, 2: 218, 3: 219, 4: 220],
    ]
    // imm
    [
        ecalli                                   = [1: 221, 4: 308],
    ]
    // imm_imm
    [
        store_imm_u8                             = [6: 222, 9: 309],
        store_imm_u16                            = [9: 310],
        store_imm_u32                            = [5: 223, 6: 224, 9: 225],
        store_imm_u64                            = [5: 226, 9: 311],
    ]
    // reg_reg
    [
        move_reg                                 = [1: 227],
        sbrk                                     = [1: 509],
        count_leading_zero_bits_32               = [1: 228],
        count_leading_zero_bits_64               = [1: 229],
        count_trailing_zero_bits_32              = [1: 312],
        count_trailing_zero_bits_64              = [1: 230],
        count_set_bits_32                        = [1: 231],
        count_set_bits_64                        = [1: 232],
        sign_extend_8                            = [1: 233],
        sign_extend_16                           = [1: 234],
        zero_extend_16                           = [1: 235],
        reverse_byte                             = [1: 236],
    ]
    // reg_reg_imm_imm
    [
        load_imm_and_jump_indirect               = [4: 237, 5: 238, 10: 313],
    ]
    // reg_imm64
    [
        load_imm64                               = [9: 239],
    ]
}

define_legacy_instruction_set! {
    ($)

    ISA_JamV1,
    build_static_dispatch_table_jam_v1,

    [
        trap                                     = 0,
        fallthrough                              = 1,
        unlikely                                 = 2,
    ]
    [
        jump_indirect                            = 50,
        load_imm                                 = 51,
        load_u8                                  = 52,
        load_i8                                  = 53,
        load_u16                                 = 54,
        load_i16                                 = 55,
        load_i32                                 = 57,
        load_u32                                 = 56,
        load_u64                                 = 58,
        store_u8                                 = 59,
        store_u16                                = 60,
        store_u32                                = 61,
        store_u64                                = 62,
    ]
    [
        load_imm_and_jump                        = 80,
        branch_eq_imm                            = 81,
        branch_not_eq_imm                        = 82,
        branch_less_unsigned_imm                 = 83,
        branch_less_signed_imm                   = 87,
        branch_greater_or_equal_unsigned_imm     = 85,
        branch_greater_or_equal_signed_imm       = 89,
        branch_less_or_equal_signed_imm          = 88,
        branch_less_or_equal_unsigned_imm        = 84,
        branch_greater_signed_imm                = 90,
        branch_greater_unsigned_imm              = 86,
    ]
    [
        store_imm_indirect_u8                    = 70,
        store_imm_indirect_u16                   = 71,
        store_imm_indirect_u32                   = 72,
        store_imm_indirect_u64                   = 73,
    ]
    [
        store_indirect_u8                        = 120,
        store_indirect_u16                       = 121,
        store_indirect_u32                       = 122,
        store_indirect_u64                       = 123,
        load_indirect_u8                         = 124,
        load_indirect_i8                         = 125,
        load_indirect_u16                        = 126,
        load_indirect_i16                        = 127,
        load_indirect_i32                        = 129,
        load_indirect_u32                        = 128,
        load_indirect_u64                        = 130,
        add_imm_32                               = 131,
        add_imm_64                               = 149,
        and_imm                                  = 132,
        xor_imm                                  = 133,
        or_imm                                   = 134,
        mul_imm_32                               = 135,
        mul_imm_64                               = 150,
        set_less_than_unsigned_imm               = 136,
        set_less_than_signed_imm                 = 137,
        shift_logical_left_imm_32                = 138,
        shift_logical_left_imm_64                = 151,
        shift_logical_right_imm_32               = 139,
        shift_logical_right_imm_64               = 152,
        shift_arithmetic_right_imm_32            = 140,
        shift_arithmetic_right_imm_64            = 153,
        negate_and_add_imm_32                    = 141,
        negate_and_add_imm_64                    = 154,
        set_greater_than_unsigned_imm            = 142,
        set_greater_than_signed_imm              = 143,
        shift_logical_right_imm_alt_32           = 145,
        shift_logical_right_imm_alt_64           = 156,
        shift_arithmetic_right_imm_alt_32        = 146,
        shift_arithmetic_right_imm_alt_64        = 157,
        shift_logical_left_imm_alt_32            = 144,
        shift_logical_left_imm_alt_64            = 155,
        cmov_if_zero_imm                         = 147,
        cmov_if_not_zero_imm                     = 148,
        rotate_right_imm_32                      = 160,
        rotate_right_imm_alt_32                  = 161,
        rotate_right_imm_64                      = 158,
        rotate_right_imm_alt_64                  = 159,
    ]
    [
        branch_eq                                = 170,
        branch_not_eq                            = 171,
        branch_less_unsigned                     = 172,
        branch_less_signed                       = 173,
        branch_greater_or_equal_unsigned         = 174,
        branch_greater_or_equal_signed           = 175,
    ]
    [
        add_32                                   = 190,
        add_64                                   = 200,
        sub_32                                   = 191,
        sub_64                                   = 201,
        and                                      = 210,
        xor                                      = 211,
        or                                       = 212,
        mul_32                                   = 192,
        mul_64                                   = 202,
        mul_upper_signed_signed                  = 213,
        mul_upper_unsigned_unsigned              = 214,
        mul_upper_signed_unsigned                = 215,
        set_less_than_unsigned                   = 216,
        set_less_than_signed                     = 217,
        shift_logical_left_32                    = 197,
        shift_logical_left_64                    = 207,
        shift_logical_right_32                   = 198,
        shift_logical_right_64                   = 208,
        shift_arithmetic_right_32                = 199,
        shift_arithmetic_right_64                = 209,
        div_unsigned_32                          = 193,
        div_unsigned_64                          = 203,
        div_signed_32                            = 194,
        div_signed_64                            = 204,
        rem_unsigned_32                          = 195,
        rem_unsigned_64                          = 205,
        rem_signed_32                            = 196,
        rem_signed_64                            = 206,
        cmov_if_zero                             = 218,
        cmov_if_not_zero                         = 219,
        and_inverted                             = 224,
        or_inverted                              = 225,
        xnor                                     = 226,
        maximum                                  = 227,
        maximum_unsigned                         = 228,
        minimum                                  = 229,
        minimum_unsigned                         = 230,
        rotate_left_32                           = 221,
        rotate_left_64                           = 220,
        rotate_right_32                          = 223,
        rotate_right_64                          = 222,
    ]
    [
        jump                                     = 40,
    ]
    [
        ecalli                                   = 10,
    ]
    [
        store_imm_u8                             = 30,
        store_imm_u16                            = 31,
        store_imm_u32                            = 32,
        store_imm_u64                            = 33,
    ]
    [
        move_reg                                 = 100,
        count_leading_zero_bits_32               = 104,
        count_leading_zero_bits_64               = 103,
        count_trailing_zero_bits_32              = 106,
        count_trailing_zero_bits_64              = 105,
        count_set_bits_32                        = 102,
        count_set_bits_64                        = 101,
        sign_extend_8                            = 107,
        sign_extend_16                           = 108,
        zero_extend_16                           = 109,
        reverse_byte                             = 110,
    ]
    [
        load_imm_and_jump_indirect               = 180,
    ]
    [
        load_imm64                               = 20,
    ]
}

#[test]
fn test_opcode_from_raw() {
    assert_eq!(ISA_Latest64.opcode_from_raw(0), Some(Opcode::trap));
    assert_eq!(ISA_Latest64.opcode_from_raw(1), Some(Opcode::fallthrough));
    assert_eq!(
        ISA_Latest64.opcode_from_raw(u32::from(EXTENDED_OPCODE_PREFIX)),
        Some(Opcode::jump_indirect)
    );
    assert_eq!(ISA_Latest64.opcode_from_raw(EXTENDED_INVALID_RAW_OPCODE as u32), None);
    assert_eq!(ISA_ReviveV1.opcode_from_raw(LEGACY_INVALID_RAW_OPCODE), None);
    assert_eq!(ISA_ReviveV1.opcode_from_raw(3), None);
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum InstructionSetKind {
    ReviveV1,
    JamV1,
    Latest32,
    Latest64,
}

impl InstructionSetKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::ReviveV1 => "revive_v1",
            Self::JamV1 => "jam_v1",
            Self::Latest32 => "latest32",
            Self::Latest64 => "latest64",
        }
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn blob_version(self) -> u8 {
        match self {
            Self::ReviveV1 => 0,
            Self::Latest32 => 1,
            Self::Latest64 => 2,
            Self::JamV1 => 3,
        }
    }

    pub(crate) fn from_blob_version(version: u8) -> Option<Self> {
        match version {
            0 => Some(Self::ReviveV1),
            1 => Some(Self::Latest32),
            2 => Some(Self::Latest64),
            3 => Some(Self::JamV1),
            _ => None,
        }
    }

    /// Returns whether the ISA is 64-bit.
    pub fn is_64_bit(&self) -> bool {
        match self {
            InstructionSetKind::Latest32 => false,
            InstructionSetKind::ReviveV1 | InstructionSetKind::JamV1 | InstructionSetKind::Latest64 => true,
        }
    }
}

macro_rules! dispatch_isa {
    ($self:ident, $isa:ident => $e:expr) => {
        match $self {
            Self::ReviveV1 => {
                let $isa = ISA_ReviveV1;
                $e
            }
            Self::Latest32 => {
                let $isa = ISA_Latest32;
                $e
            }
            Self::Latest64 => {
                let $isa = ISA_Latest64;
                $e
            }
            Self::JamV1 => {
                let $isa = ISA_JamV1;
                $e
            }
        }
    };
}

impl InstructionSet for InstructionSetKind {
    fn opcode_from_raw(self, raw_opcode: u32) -> Option<Opcode> {
        dispatch_isa!(self, isa => isa.opcode_from_raw(raw_opcode))
    }

    fn opcode_to_raw(self, opcode: Opcode, args_length: u32) -> Option<(u32, u32)> {
        dispatch_isa!(self, isa => isa.opcode_to_raw(opcode, args_length))
    }

    fn supports_opcode(self, opcode: Opcode) -> bool {
        dispatch_isa!(self, isa => isa.supports_opcode(opcode))
    }

    fn parse_instruction(self, raw_opcode: usize, chunk: u128, offset: u32, length: u32) -> Instruction {
        dispatch_isa!(self, isa => isa.parse_instruction(raw_opcode, chunk, offset, length))
    }

    #[inline]
    fn is_legacy(self) -> bool {
        dispatch_isa!(self, isa => isa.is_legacy())
    }

    #[inline]
    fn raw_opcode_table(self) -> &'static RawOpcodeTable {
        dispatch_isa!(self, isa => isa.raw_opcode_table())
    }
}

impl Opcode {
    pub fn can_fallthrough(self) -> bool {
        !matches!(
            self,
            Self::trap | Self::jump | Self::jump_indirect | Self::load_imm_and_jump | Self::load_imm_and_jump_indirect
        )
    }

    pub const fn starts_new_basic_block(self) -> bool {
        matches!(
            self,
            Self::trap
                | Self::fallthrough
                | Self::jump
                | Self::jump_indirect
                | Self::load_imm_and_jump
                | Self::load_imm_and_jump_indirect
                | Self::branch_eq
                | Self::branch_eq_imm
                | Self::branch_greater_or_equal_signed
                | Self::branch_greater_or_equal_signed_imm
                | Self::branch_greater_or_equal_unsigned
                | Self::branch_greater_or_equal_unsigned_imm
                | Self::branch_greater_signed_imm
                | Self::branch_greater_unsigned_imm
                | Self::branch_less_or_equal_signed_imm
                | Self::branch_less_or_equal_unsigned_imm
                | Self::branch_less_signed
                | Self::branch_less_signed_imm
                | Self::branch_less_unsigned
                | Self::branch_less_unsigned_imm
                | Self::branch_not_eq
                | Self::branch_not_eq_imm
        )
    }
}

impl core::fmt::Display for Instruction {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.visit(&mut InstructionFormatter {
            format: &Default::default(),
            fmt,
        })
    }
}

impl Instruction {
    pub fn display<'a>(self, format: &'a InstructionFormat<'a>) -> impl core::fmt::Display + 'a {
        struct Inner<'a, 'b> {
            instruction: Instruction,
            format: &'a InstructionFormat<'b>,
        }

        impl<'a, 'b> core::fmt::Display for Inner<'a, 'b> {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                self.instruction.visit(&mut InstructionFormatter { format: self.format, fmt })
            }
        }

        Inner { instruction: self, format }
    }

    pub fn starts_new_basic_block(self) -> bool {
        self.opcode().starts_new_basic_block()
    }

    #[must_use]
    fn serialize_opcode(isa: impl InstructionSet, buffer: &mut [u8], opcode: Opcode, args_length: u32) -> (usize, u32) {
        if let Some((raw_opcode, actual_args_length)) = isa.opcode_to_raw(opcode, args_length) {
            let length = if raw_opcode < u32::from(EXTENDED_OPCODE_PREFIX) {
                buffer[0] = raw_opcode as u8;
                1
            } else {
                buffer[0] = EXTENDED_OPCODE_PREFIX;
                buffer[1] = (raw_opcode - u32::from(EXTENDED_OPCODE_PREFIX)) as u8;
                2
            };

            (length, actual_args_length - args_length)
        } else {
            buffer[0] = UNUSED_RAW_OPCODE as u8;
            (1, 0)
        }
    }

    fn adjust_length(imm_length: u32, length_delta: u32) -> u32 {
        debug_assert!(imm_length <= 4);
        let imm_length_ext = imm_length + length_delta;
        debug_assert!(imm_length_ext <= 4);
        imm_length_ext
    }

    fn adjust_length2(imm1_length: u32, imm2_length: u32, length_delta: u32) -> (u32, u32) {
        debug_assert!(imm1_length <= 4);
        debug_assert!(imm2_length <= 4);

        let imm1_length_ext = (imm1_length + length_delta).min(4);
        let length_delta = length_delta - (imm1_length_ext - imm1_length);
        let imm2_length_ext = imm2_length + length_delta;

        debug_assert!(imm1_length_ext <= 4);
        debug_assert!(imm2_length_ext <= 4);

        (imm1_length_ext, imm2_length_ext)
    }

    fn serialize_argless(isa: impl InstructionSet, buffer: &mut [u8], opcode: Opcode) -> usize {
        Self::serialize_opcode(isa, buffer, opcode, 0).0
    }

    fn serialize_reg_imm_offset(
        isa: impl InstructionSet,
        buffer: &mut [u8],
        position: u32,
        opcode: Opcode,
        reg: RawReg,
        imm1: i32,
        imm2: u32,
    ) -> usize {
        let imm1 = cast(imm1).bitwise_as_u32();
        let imm2 = imm2.wrapping_sub(position);
        let imm1_length = simple_varint_length(imm1);
        let imm2_length = simple_varint_length(imm2);
        let (mut position, length_delta) = Self::serialize_opcode(isa, buffer, opcode, 1 + imm1_length + imm2_length);
        let (imm1_length, imm2_length) = Self::adjust_length2(imm1_length, imm2_length, length_delta);
        buffer[position] = reg.0 as u8 | (imm1_length << 4) as u8;
        position += 1;
        position += write_simple_varint_with_length(imm1, imm1_length, &mut buffer[position..]);
        position += write_simple_varint_with_length(imm2, imm2_length, &mut buffer[position..]);
        position
    }

    fn serialize_reg_imm_imm(isa: impl InstructionSet, buffer: &mut [u8], opcode: Opcode, reg: RawReg, imm1: i32, imm2: i32) -> usize {
        let imm1 = cast(imm1).bitwise_as_u32();
        let imm2 = cast(imm2).bitwise_as_u32();
        let imm1_length = simple_varint_length(imm1);
        let imm2_length = simple_varint_length(imm2);
        let (mut position, length_delta) = Self::serialize_opcode(isa, buffer, opcode, 1 + imm1_length + imm2_length);
        let (imm1_length, imm2_length) = Self::adjust_length2(imm1_length, imm2_length, length_delta);
        buffer[position] = reg.0 as u8 | (imm1_length << 4) as u8;
        position += 1;
        position += write_simple_varint_with_length(imm1, imm1_length, &mut buffer[position..]);
        position += write_simple_varint_with_length(imm2, imm2_length, &mut buffer[position..]);
        position
    }
    fn serialize_reg_reg_imm_imm(
        isa: impl InstructionSet,
        buffer: &mut [u8],
        opcode: Opcode,
        reg1: RawReg,
        reg2: RawReg,
        imm1: i32,
        imm2: i32,
    ) -> usize {
        let imm1 = cast(imm1).bitwise_as_u32();
        let imm2 = cast(imm2).bitwise_as_u32();
        let imm1_length = simple_varint_length(imm1);
        let imm2_length = simple_varint_length(imm2);
        let (mut position, length_delta) = Self::serialize_opcode(isa, buffer, opcode, 2 + imm1_length + imm2_length);
        let (imm1_length, imm2_length) = Self::adjust_length2(imm1_length, imm2_length, length_delta);
        buffer[position] = reg1.0 as u8 | (reg2.0 as u8) << 4;
        position += 1;
        buffer[position] = imm1_length as u8;
        position += 1;
        position += write_simple_varint_with_length(imm1, imm1_length, &mut buffer[position..]);
        position + write_simple_varint_with_length(imm2, imm2_length, &mut buffer[position..])
    }

    fn serialize_reg_imm64(isa: impl InstructionSet, buffer: &mut [u8], opcode: Opcode, reg: RawReg, imm: u64) -> usize {
        let (mut position, _) = Self::serialize_opcode(isa, buffer, opcode, 9);
        buffer[position] = reg.0 as u8;
        position += 1;
        buffer[position..position + 8].copy_from_slice(&imm.to_le_bytes());
        position + 8
    }

    fn serialize_reg_reg_reg(
        isa: impl InstructionSet,
        buffer: &mut [u8],
        opcode: Opcode,
        reg1: RawReg,
        reg2: RawReg,
        reg3: RawReg,
    ) -> usize {
        let (mut position, _) = Self::serialize_opcode(isa, buffer, opcode, 2);
        buffer[position] = reg2.0 as u8 | (reg3.0 as u8) << 4;
        position += 1;
        buffer[position] = reg1.0 as u8;
        position + 1
    }

    fn serialize_reg_reg_imm(isa: impl InstructionSet, buffer: &mut [u8], opcode: Opcode, reg1: RawReg, reg2: RawReg, imm: i32) -> usize {
        let imm = cast(imm).bitwise_as_u32();
        let imm_length = simple_varint_length(imm);
        let (mut position, length_delta) = Self::serialize_opcode(isa, buffer, opcode, 1 + imm_length);
        let imm_length = Self::adjust_length(imm_length, length_delta);
        buffer[position] = reg1.0 as u8 | (reg2.0 as u8) << 4;
        position += 1;
        position + write_simple_varint_with_length(imm, imm_length, &mut buffer[position..])
    }

    fn serialize_reg_reg_offset(
        isa: impl InstructionSet,
        buffer: &mut [u8],
        position: u32,
        opcode: Opcode,
        reg1: RawReg,
        reg2: RawReg,
        imm: u32,
    ) -> usize {
        let imm = imm.wrapping_sub(position);
        let imm_length = simple_varint_length(imm);
        let (mut position, length_delta) = Self::serialize_opcode(isa, buffer, opcode, 1 + imm_length);
        let imm_length = Self::adjust_length(imm_length, length_delta);
        buffer[position] = reg1.0 as u8 | (reg2.0 as u8) << 4;
        position += 1;
        position + write_simple_varint_with_length(imm, imm_length, &mut buffer[position..])
    }

    fn serialize_reg_imm(isa: impl InstructionSet, buffer: &mut [u8], opcode: Opcode, reg: RawReg, imm: i32) -> usize {
        let imm = cast(imm).bitwise_as_u32();
        let imm_length = simple_varint_length(imm);
        let (mut position, length_delta) = Self::serialize_opcode(isa, buffer, opcode, 1 + imm_length);
        let imm_length = Self::adjust_length(imm_length, length_delta);
        buffer[position] = reg.0 as u8;
        position += 1;
        position + write_simple_varint_with_length(imm, imm_length, &mut buffer[position..])
    }

    fn serialize_offset(isa: impl InstructionSet, buffer: &mut [u8], position: u32, opcode: Opcode, imm: u32) -> usize {
        Self::serialize_offset_with_minimum_imm_length(isa, buffer, position, opcode, imm, 0)
    }

    pub(crate) fn serialize_offset_with_minimum_imm_length(
        isa: impl InstructionSet,
        buffer: &mut [u8],
        position: u32,
        opcode: Opcode,
        imm: u32,
        minimum_imm_length: u32,
    ) -> usize {
        let imm = imm.wrapping_sub(position);
        let imm_length = simple_varint_length(imm).max(minimum_imm_length);
        let (position, length_delta) = Self::serialize_opcode(isa, buffer, opcode, imm_length);
        let imm_length = Self::adjust_length(imm_length, length_delta);
        position + write_simple_varint_with_length(imm, imm_length, &mut buffer[position..])
    }

    fn serialize_imm(isa: impl InstructionSet, buffer: &mut [u8], opcode: Opcode, imm: i32) -> usize {
        let imm = cast(imm).bitwise_as_u32();
        let imm_length = simple_varint_length(imm);
        let (position, length_delta) = Self::serialize_opcode(isa, buffer, opcode, imm_length);
        let imm_length = Self::adjust_length(imm_length, length_delta);
        position + write_simple_varint_with_length(imm, imm_length, &mut buffer[position..])
    }

    fn serialize_imm_imm(isa: impl InstructionSet, buffer: &mut [u8], opcode: Opcode, imm1: i32, imm2: i32) -> usize {
        let imm1 = cast(imm1).bitwise_as_u32();
        let imm2 = cast(imm2).bitwise_as_u32();
        let imm1_length = simple_varint_length(imm1);
        let imm2_length = simple_varint_length(imm2);
        let (mut position, length_delta) = Self::serialize_opcode(isa, buffer, opcode, 1 + imm1_length + imm2_length);
        let (imm1_length, imm2_length) = Self::adjust_length2(imm1_length, imm2_length, length_delta);
        buffer[position] = imm1_length as u8;
        position += 1;
        position += write_simple_varint_with_length(imm1, imm1_length, &mut buffer[position..]);
        position + write_simple_varint_with_length(imm2, imm2_length, &mut buffer[position..])
    }

    fn serialize_reg_reg(isa: impl InstructionSet, buffer: &mut [u8], opcode: Opcode, reg1: RawReg, reg2: RawReg) -> usize {
        let (position, _) = Self::serialize_opcode(isa, buffer, opcode, 1);
        buffer[position] = reg1.0 as u8 | (reg2.0 as u8) << 4;
        position + 1
    }
}

pub const MAX_INSTRUCTION_LENGTH: usize = 2 + MAX_VARINT_LENGTH * 2;

#[derive(Clone)]
#[non_exhaustive]
pub struct InstructionFormat<'a> {
    pub prefer_non_abi_reg_names: bool,
    pub prefer_unaliased: bool,
    pub jump_target_formatter: Option<&'a dyn Fn(u32, &mut core::fmt::Formatter) -> core::fmt::Result>,
    pub is_64_bit: bool,
}

impl<'a> Default for InstructionFormat<'a> {
    fn default() -> Self {
        InstructionFormat {
            prefer_non_abi_reg_names: false,
            prefer_unaliased: false,
            jump_target_formatter: None,
            is_64_bit: true,
        }
    }
}

struct InstructionFormatter<'a, 'b, 'c> {
    format: &'a InstructionFormat<'c>,
    fmt: &'a mut core::fmt::Formatter<'b>,
}

impl<'a, 'b, 'c> InstructionFormatter<'a, 'b, 'c> {
    fn format_reg(&self, reg: RawReg) -> &'static str {
        if self.format.prefer_non_abi_reg_names {
            reg.get().name_non_abi()
        } else {
            reg.get().name()
        }
    }

    fn format_jump(&self, imm: u32) -> impl core::fmt::Display + 'a {
        struct Formatter<'a>(Option<&'a dyn Fn(u32, &mut core::fmt::Formatter) -> core::fmt::Result>, u32);
        impl<'a> core::fmt::Display for Formatter<'a> {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                if let Some(f) = self.0 {
                    f(self.1, fmt)
                } else {
                    write!(fmt, "{}", self.1)
                }
            }
        }

        Formatter(self.format.jump_target_formatter, imm)
    }

    fn format_imm(&self, imm: i32) -> impl core::fmt::Display {
        struct Formatter {
            imm: i32,
            is_64_bit: bool,
        }

        impl core::fmt::Display for Formatter {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                if self.imm == 0 {
                    write!(fmt, "{}", self.imm)
                } else if !self.is_64_bit {
                    write!(fmt, "0x{:x}", self.imm)
                } else {
                    let imm: i64 = cast(self.imm).to_i64_sign_extend();
                    write!(fmt, "0x{:x}", imm)
                }
            }
        }

        Formatter {
            imm,
            is_64_bit: self.format.is_64_bit,
        }
    }

    fn format_offset(&self, offset: i32) -> impl core::fmt::Display {
        struct Formatter {
            offset: i32,
            prefer_unaliased: bool,
        }

        impl core::fmt::Display for Formatter {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                if self.offset == 0 && !self.prefer_unaliased {
                    Ok(())
                } else if self.offset < 0 {
                    write!(fmt, " - {}", cast(self.offset).to_i64_sign_extend() * -1)
                } else {
                    write!(fmt, " + {}", self.offset)
                }
            }
        }

        Formatter {
            offset,
            prefer_unaliased: self.format.prefer_unaliased,
        }
    }
}

impl<'a, 'b, 'c> core::fmt::Write for InstructionFormatter<'a, 'b, 'c> {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.fmt.write_str(s)
    }
}

impl<'a, 'b, 'c> InstructionVisitor for InstructionFormatter<'a, 'b, 'c> {
    type ReturnTy = core::fmt::Result;

    fn trap(&mut self) -> Self::ReturnTy {
        write!(self, "trap")
    }

    fn fallthrough(&mut self) -> Self::ReturnTy {
        write!(self, "fallthrough")
    }

    fn unlikely(&mut self) -> Self::ReturnTy {
        write!(self, "unlikely")
    }

    fn sbrk(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = sbrk {s}")
    }

    fn memset(&mut self) -> Self::ReturnTy {
        write!(self, "[a0..a0 + a2] = u8 a1")
    }

    fn ecalli(&mut self, nth_import: i32) -> Self::ReturnTy {
        write!(self, "ecalli {}", cast(nth_import).bitwise_as_u32())
    }

    fn set_less_than_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} <u {s2}")
    }

    fn set_less_than_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} <s {s2}")
    }

    fn shift_logical_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >> {s2}")
    }

    fn shift_arithmetic_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >>a {s2}")
    }

    fn shift_logical_left_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} << {s2}")
    }

    fn shift_logical_right_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} >> {s2}")
        } else {
            write!(self, "{d} = {s1} >> {s2}")
        }
    }

    fn shift_arithmetic_right_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} >>a {s2}")
        } else {
            write!(self, "{d} = {s1} >>a {s2}")
        }
    }

    fn shift_logical_left_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} << {s2}")
        } else {
            write!(self, "{d} = {s1} << {s2}")
        }
    }

    fn xor(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} ^ {s2}")
    }

    fn and(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} & {s2}")
    }

    fn or(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} | {s2}")
    }

    fn add_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} + {s2}")
        } else {
            write!(self, "{d} = {s1} + {s2}")
        }
    }

    fn add_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} + {s2}")
    }

    fn sub_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} - {s2}")
        } else {
            write!(self, "{d} = {s1} - {s2}")
        }
    }

    fn sub_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} - {s2}")
    }

    fn mul_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} * {s2}")
        } else {
            write!(self, "{d} = {s1} * {s2}")
        }
    }

    fn mul_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} * {s2}")
    }

    fn mul_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} * {s2}")
        } else {
            write!(self, "{d} = {s1} * {s2}")
        }
    }

    fn mul_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} * {s2}")
    }

    fn mul_upper_signed_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} mulh {s2}")
    }

    fn mul_upper_unsigned_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} mulhu {s2}")
    }

    fn mul_upper_signed_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} mulhsu {s2}")
    }

    fn div_unsigned_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} /u {s2}")
        } else {
            write!(self, "{d} = {s1} /u {s2}")
        }
    }

    fn div_signed_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} /s {s2}")
        } else {
            write!(self, "{d} = {s1} /s {s2}")
        }
    }

    fn rem_unsigned_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} %u {s2}")
        } else {
            write!(self, "{d} = {s1} %u {s2}")
        }
    }

    fn rem_signed_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} %s {s2}")
        } else {
            write!(self, "{d} = {s1} %s {s2}")
        }
    }

    fn div_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} /u {s2}")
    }

    fn div_signed_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} /s {s2}")
    }

    fn rem_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} %u {s2}")
    }

    fn rem_signed_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} %s {s2}")
    }

    fn and_inverted(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} & ~{s2}")
    }

    fn or_inverted(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} | ~{s2}")
    }

    fn xnor(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = ~({s1} ^ {s2})")
    }

    fn maximum(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = maxs({s1}, {s2})")
    }

    fn maximum_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = maxu({s1}, {s2})")
    }

    fn minimum(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = mins({s1}, {s2})")
    }

    fn minimum_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = minu({s1}, {s2})")
    }

    fn rotate_left_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} <<r {s2}")
        } else {
            write!(self, "{d} = {s1} <<r {s2}")
        }
    }

    fn rotate_left_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} <<r {s2}")
    }

    fn rotate_right_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} >>r {s2}")
        } else {
            write!(self, "{d} = {s1} >>r {s2}")
        }
    }

    fn rotate_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >>r {s2}")
    }

    fn set_less_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} <u {s2}")
    }

    fn set_greater_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} >u {s2}")
    }

    fn set_less_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} <s {s2}")
    }

    fn set_greater_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} >s {s2}")
    }

    fn shift_logical_right_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} >> {s2}")
        } else {
            write!(self, "{d} = {s1} >> {s2}")
        }
    }

    fn shift_logical_right_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_imm(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} >> {s2}")
        } else {
            write!(self, "{d} = {s1} >> {s2}")
        }
    }

    fn shift_arithmetic_right_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} >>a {s2}")
        } else {
            write!(self, "{d} = {s1} >>a {s2}")
        }
    }

    fn shift_logical_right_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} >> {s2}")
    }

    fn shift_logical_right_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_imm(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >> {s2}")
    }

    fn shift_arithmetic_right_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} >>a {s2}")
    }

    fn shift_arithmetic_right_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_imm(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} >>a {s2}")
        } else {
            write!(self, "{d} = {s1} >>a {s2}")
        }
    }

    fn shift_logical_left_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} << {s2}")
        } else {
            write!(self, "{d} = {s1} << {s2}")
        }
    }

    fn shift_logical_left_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_imm(s1);
        let s2 = self.format_reg(s2);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s1} << {s2}")
        } else {
            write!(self, "{d} = {s1} << {s2}")
        }
    }

    fn shift_arithmetic_right_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_imm(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >>a {s2}")
    }

    fn shift_logical_left_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} << {s2}")
    }

    fn shift_logical_left_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_imm(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} << {s2}")
    }

    fn or_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} | {s2}")
    }

    fn and_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} & {s2}")
    }

    fn xor_imm(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_imm(s2);
        write!(self, "{d} = {s1} ^ {s2}")
    }

    fn load_imm(&mut self, d: RawReg, a: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let a = self.format_imm(a);
        write!(self, "{d} = {a}")
    }

    fn load_imm64(&mut self, d: RawReg, a: u64) -> Self::ReturnTy {
        let d = self.format_reg(d);
        write!(self, "{d} = 0x{a:x}")
    }

    fn move_reg(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = {s}")
    }

    fn count_leading_zero_bits_32(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = clz {s}")
        } else {
            write!(self, "{d} = clz {s}")
        }
    }

    fn count_leading_zero_bits_64(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = clz {s}")
    }

    fn count_trailing_zero_bits_32(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = ctz {s}")
        } else {
            write!(self, "{d} = ctz {s}")
        }
    }

    fn count_trailing_zero_bits_64(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = ctz {s}")
    }

    fn count_set_bits_32(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = cpop {s}")
        } else {
            write!(self, "{d} = cpop {s}")
        }
    }

    fn count_set_bits_64(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = cpop {s}")
    }

    fn sign_extend_8(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = sext8 {s}")
    }

    fn sign_extend_16(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = sext16 {s}")
    }

    fn zero_extend_16(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = zext16 {s}")
    }

    fn reverse_byte(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = reverse {s}")
    }

    fn cmov_if_zero(&mut self, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        let c = self.format_reg(c);
        write!(self, "{d} = {s} if {c} == 0")
    }

    fn cmov_if_not_zero(&mut self, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        let c = self.format_reg(c);
        write!(self, "{d} = {s} if {c} != 0")
    }

    fn cmov_if_zero_imm(&mut self, d: RawReg, c: RawReg, s: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let c = self.format_reg(c);
        let s = self.format_imm(s);
        write!(self, "{d} = {s} if {c} == 0")
    }

    fn cmov_if_not_zero_imm(&mut self, d: RawReg, c: RawReg, s: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let c = self.format_reg(c);
        let s = self.format_imm(s);
        write!(self, "{d} = {s} if {c} != 0")
    }

    fn rotate_right_imm_32(&mut self, d: RawReg, s: RawReg, c: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        let c = self.format_imm(c);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s} >>r {c}")
        } else {
            write!(self, "{d} = {s} >> {c}")
        }
    }

    fn rotate_right_imm_alt_32(&mut self, d: RawReg, c: RawReg, s: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let c = self.format_reg(c);
        let s = self.format_imm(s);
        if self.format.is_64_bit {
            write!(self, "i32 {d} = {s} >>r {c}")
        } else {
            write!(self, "{d} = {s} >> {c}")
        }
    }

    fn rotate_right_imm_64(&mut self, d: RawReg, s: RawReg, c: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        let c = self.format_imm(c);
        write!(self, "{d} = {s} >>r {c}")
    }

    fn rotate_right_imm_alt_64(&mut self, d: RawReg, c: RawReg, s: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let c = self.format_reg(c);
        let s = self.format_imm(s);
        write!(self, "{d} = {s} >>r {c}")
    }

    fn add_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        if !self.format.prefer_unaliased && i64::from(s2) < 0 && i64::from(s2) > -4096 {
            write!(self, "{d} = {s1} - {s2}", s2 = -i64::from(s2))
        } else {
            let s2 = self.format_imm(s2);
            write!(self, "{d} = {s1} + {s2}")
        }
    }

    fn add_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let prefix = if self.format.is_64_bit { "i32 " } else { "" };
        if !self.format.prefer_unaliased && i64::from(s2) < 0 && i64::from(s2) > -4096 {
            write!(self, "{prefix}{d} = {s1} - {s2}", s2 = -i64::from(s2))
        } else {
            let s2 = self.format_imm(s2);
            write!(self, "{prefix}{d} = {s1} + {s2}")
        }
    }

    fn negate_and_add_imm_32(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let prefix = if self.format.is_64_bit { "i32 " } else { "" };
        if !self.format.prefer_unaliased && s2 == 0 {
            write!(self, "{prefix}{d} = -{s1}")
        } else {
            let s2 = self.format_imm(s2);
            write!(self, "{prefix}{d} = {s2} - {s1}")
        }
    }

    fn negate_and_add_imm_64(&mut self, d: RawReg, s1: RawReg, s2: i32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        if !self.format.prefer_unaliased && s2 == 0 {
            write!(self, "{d} = -{s1}")
        } else {
            let s2 = self.format_imm(s2);
            write!(self, "{d} = {s2} - {s1}")
        }
    }

    fn store_imm_indirect_u8(&mut self, base: RawReg, offset: i32, value: i32) -> Self::ReturnTy {
        let base = self.format_reg(base);
        let value = self.format_imm(value);
        let offset = self.format_offset(offset);
        write!(self, "u8 [{base}{offset}] = {value}")
    }

    fn store_imm_indirect_u16(&mut self, base: RawReg, offset: i32, value: i32) -> Self::ReturnTy {
        let base = self.format_reg(base);
        let value = self.format_imm(value);
        let offset = self.format_offset(offset);
        write!(self, "u16 [{base}{offset}] = {value}")
    }

    fn store_imm_indirect_u32(&mut self, base: RawReg, offset: i32, value: i32) -> Self::ReturnTy {
        let base = self.format_reg(base);
        let value = self.format_imm(value);
        let offset = self.format_offset(offset);
        write!(self, "u32 [{base}{offset}] = {value}")
    }

    fn store_imm_indirect_u64(&mut self, base: RawReg, offset: i32, value: i32) -> Self::ReturnTy {
        let base = self.format_reg(base);
        let value = self.format_imm(value);
        let offset = self.format_offset(offset);
        write!(self, "u64 [{base}{offset}] = {value}")
    }

    fn store_indirect_u8(&mut self, src: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "u8 [{base}{offset}] = {src}")
    }

    fn store_indirect_u16(&mut self, src: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "u16 [{base}{offset}] = {src}")
    }

    fn store_indirect_u32(&mut self, src: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "u32 [{base}{offset}] = {src}")
    }

    fn store_indirect_u64(&mut self, src: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "u64 [{base}{offset}] = {src}")
    }

    fn store_imm_u8(&mut self, offset: i32, value: i32) -> Self::ReturnTy {
        let offset = self.format_imm(offset);
        let value = self.format_imm(value);
        write!(self, "u8 [{offset}] = {value}")
    }

    fn store_imm_u16(&mut self, offset: i32, value: i32) -> Self::ReturnTy {
        let offset = self.format_imm(offset);
        let value = self.format_imm(value);
        write!(self, "u16 [{offset}] = {value}")
    }

    fn store_imm_u32(&mut self, offset: i32, value: i32) -> Self::ReturnTy {
        let offset = self.format_imm(offset);
        let value = self.format_imm(value);
        write!(self, "u32 [{offset}] = {value}")
    }

    fn store_imm_u64(&mut self, offset: i32, value: i32) -> Self::ReturnTy {
        let offset = self.format_imm(offset);
        let value = self.format_imm(value);
        write!(self, "u64 [{offset}] = {value}")
    }

    fn store_u8(&mut self, src: RawReg, offset: i32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        let offset = self.format_imm(offset);
        write!(self, "u8 [{offset}] = {src}")
    }

    fn store_u16(&mut self, src: RawReg, offset: i32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        let offset = self.format_imm(offset);
        write!(self, "u16 [{offset}] = {src}")
    }

    fn store_u32(&mut self, src: RawReg, offset: i32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        let offset = self.format_imm(offset);
        write!(self, "u32 [{offset}] = {src}")
    }

    fn store_u64(&mut self, src: RawReg, offset: i32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        let offset = self.format_imm(offset);
        write!(self, "u64 [{offset}] = {src}")
    }

    fn load_indirect_u8(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "{} = u8 [{}{}]", dst, base, offset)
    }

    fn load_indirect_i8(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "{} = i8 [{}{}]", dst, base, offset)
    }

    fn load_indirect_u16(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "{} = u16 [{}{}]", dst, base, offset)
    }

    fn load_indirect_i16(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "{} = i16 [{}{}]", dst, base, offset)
    }

    fn load_indirect_u32(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "{} = u32 [{}{}]", dst, base, offset)
    }

    fn load_indirect_i32(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "{} = i32 [{}{}]", dst, base, offset)
    }

    fn load_indirect_u64(&mut self, dst: RawReg, base: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        let offset = self.format_offset(offset);
        write!(self, "{} = u64 [{}{}]", dst, base, offset)
    }

    fn load_u8(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let offset = self.format_imm(offset);
        write!(self, "{} = u8 [{}]", dst, offset)
    }

    fn load_i8(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let offset = self.format_imm(offset);
        write!(self, "{} = i8 [{}]", dst, offset)
    }

    fn load_u16(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let offset = self.format_imm(offset);
        write!(self, "{} = u16 [{}]", dst, offset)
    }

    fn load_i16(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let offset = self.format_imm(offset);
        write!(self, "{} = i16 [{}]", dst, offset)
    }

    fn load_i32(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let offset = self.format_imm(offset);
        write!(self, "{} = i32 [{}]", dst, offset)
    }

    fn load_u32(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let offset = self.format_imm(offset);
        write!(self, "{} = u32 [{}]", dst, offset)
    }

    fn load_u64(&mut self, dst: RawReg, offset: i32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let offset = self.format_imm(offset);
        write!(self, "{} = u64 [{}]", dst, offset)
    }

    fn branch_less_unsigned(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} <u {}", imm, s1, s2)
    }

    fn branch_less_signed(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} <s {}", imm, s1, s2)
    }

    fn branch_less_unsigned_imm(&mut self, s1: RawReg, s2: i32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} <u {}", imm, s1, s2)
    }

    fn branch_less_signed_imm(&mut self, s1: RawReg, s2: i32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} <s {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} >=u {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_signed(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} >=s {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: i32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} >=u {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_signed_imm(&mut self, s1: RawReg, s2: i32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} >=s {}", imm, s1, s2)
    }

    fn branch_eq(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} == {}", imm, s1, s2)
    }

    fn branch_not_eq(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} != {}", imm, s1, s2)
    }

    fn branch_eq_imm(&mut self, s1: RawReg, s2: i32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} == {}", imm, s1, s2)
    }

    fn branch_not_eq_imm(&mut self, s1: RawReg, s2: i32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} != {}", imm, s1, s2)
    }

    fn branch_less_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: i32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} <=u {}", imm, s1, s2)
    }

    fn branch_less_or_equal_signed_imm(&mut self, s1: RawReg, s2: i32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} <=s {}", imm, s1, s2)
    }

    fn branch_greater_unsigned_imm(&mut self, s1: RawReg, s2: i32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} >u {}", imm, s1, s2)
    }

    fn branch_greater_signed_imm(&mut self, s1: RawReg, s2: i32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} >s {}", imm, s1, s2)
    }

    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        let target = self.format_jump(target);
        write!(self, "jump {}", target)
    }

    fn load_imm_and_jump(&mut self, ra: RawReg, value: i32, target: u32) -> Self::ReturnTy {
        let ra = self.format_reg(ra);
        let target = self.format_jump(target);
        write!(self, "{ra} = {value}, jump {target}")
    }

    fn jump_indirect(&mut self, base: RawReg, offset: i32) -> Self::ReturnTy {
        if !self.format.prefer_unaliased {
            match (base, offset) {
                (_, 0) if base == Reg::RA.into() => return write!(self, "ret"),
                (_, 0) => return write!(self, "jump [{}]", self.format_reg(base)),
                (_, _) => {}
            }
        }

        let offset = self.format_offset(offset);
        write!(self, "jump [{}{}]", self.format_reg(base), offset)
    }

    fn load_imm_and_jump_indirect(&mut self, ra: RawReg, base: RawReg, value: i32, offset: i32) -> Self::ReturnTy {
        let ra = self.format_reg(ra);
        let base = self.format_reg(base);
        if ra != base {
            if !self.format.prefer_unaliased && offset == 0 {
                write!(self, "{ra} = {value}, jump [{base}]")
            } else {
                let offset = self.format_offset(offset);
                write!(self, "{ra} = {value}, jump [{base}{offset}]")
            }
        } else if !self.format.prefer_unaliased && offset == 0 {
            write!(self, "tmp = {base}, {ra} = {value}, jump [tmp]")
        } else {
            let offset = self.format_offset(offset);
            write!(self, "tmp = {base}, {ra} = {value}, jump [tmp{offset}]")
        }
    }

    fn invalid(&mut self) -> Self::ReturnTy {
        write!(self, "invalid")
    }
}

#[derive(Debug)]
pub struct ProgramParseError(ProgramParseErrorKind);

#[derive(Debug)]
enum ProgramParseErrorKind {
    FailedToReadVarint {
        offset: usize,
    },
    FailedToReadStringNonUtf {
        offset: usize,
    },
    UnexpectedSection {
        offset: usize,
        section: u8,
    },
    UnexpectedEnd {
        offset: usize,
        expected_count: usize,
        actual_count: usize,
    },
    UnsupportedVersion {
        version: u8,
    },
    Other(&'static str),
}

impl ProgramParseError {
    #[cold]
    #[inline]
    fn failed_to_read_varint(offset: usize) -> ProgramParseError {
        ProgramParseError(ProgramParseErrorKind::FailedToReadVarint { offset })
    }

    #[cold]
    #[inline]
    fn unexpected_end_of_file(offset: usize, expected_count: usize, actual_count: usize) -> ProgramParseError {
        ProgramParseError(ProgramParseErrorKind::UnexpectedEnd {
            offset,
            expected_count,
            actual_count,
        })
    }
}

impl core::fmt::Display for ProgramParseError {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self.0 {
            ProgramParseErrorKind::FailedToReadVarint { offset } => {
                write!(
                    fmt,
                    "failed to parse program blob: failed to parse a varint at offset 0x{:x}",
                    offset
                )
            }
            ProgramParseErrorKind::FailedToReadStringNonUtf { offset } => {
                write!(
                    fmt,
                    "failed to parse program blob: failed to parse a string at offset 0x{:x} (not valid UTF-8)",
                    offset
                )
            }
            ProgramParseErrorKind::UnexpectedSection { offset, section } => {
                write!(
                    fmt,
                    "failed to parse program blob: found unexpected section as offset 0x{:x}: 0x{:x}",
                    offset, section
                )
            }
            ProgramParseErrorKind::UnexpectedEnd {
                offset,
                expected_count,
                actual_count,
            } => {
                write!(fmt, "failed to parse program blob: unexpected end of file at offset 0x{:x}: expected to be able to read at least {} bytes, found {} bytes", offset, expected_count, actual_count)
            }
            ProgramParseErrorKind::UnsupportedVersion { version } => {
                write!(fmt, "failed to parse program blob: unsupported version: {}", version)
            }
            ProgramParseErrorKind::Other(error) => {
                write!(fmt, "failed to parse program blob: {}", error)
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl From<ProgramParseError> for alloc::string::String {
    fn from(error: ProgramParseError) -> alloc::string::String {
        use alloc::string::ToString;
        error.to_string()
    }
}

impl core::error::Error for ProgramParseError {}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(transparent)]
pub struct ProgramCounter(pub u32);

impl core::fmt::Display for ProgramCounter {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.0.fmt(fmt)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProgramExport<T> {
    program_counter: ProgramCounter,
    symbol: ProgramSymbol<T>,
}

impl<T> ProgramExport<T>
where
    T: AsRef<[u8]>,
{
    pub fn new(program_counter: ProgramCounter, symbol: ProgramSymbol<T>) -> Self {
        Self { program_counter, symbol }
    }

    pub fn program_counter(&self) -> ProgramCounter {
        self.program_counter
    }

    pub fn symbol(&self) -> &ProgramSymbol<T> {
        &self.symbol
    }
}

impl<T> PartialEq<str> for ProgramExport<T>
where
    T: AsRef<[u8]>,
{
    fn eq(&self, rhs: &str) -> bool {
        self.symbol.as_bytes() == rhs.as_bytes()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProgramSymbol<T>(T);

impl<T> ProgramSymbol<T>
where
    T: AsRef<[u8]>,
{
    pub fn new(bytes: T) -> Self {
        Self(bytes)
    }

    pub fn into_inner(self) -> T {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> PartialEq<str> for ProgramSymbol<T>
where
    T: AsRef<[u8]>,
{
    fn eq(&self, rhs: &str) -> bool {
        self.as_bytes() == rhs.as_bytes()
    }
}

impl<'a, T> PartialEq<&'a str> for ProgramSymbol<T>
where
    T: AsRef<[u8]>,
{
    fn eq(&self, rhs: &&'a str) -> bool {
        self.as_bytes() == rhs.as_bytes()
    }
}

impl<T> core::fmt::Display for ProgramSymbol<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let bytes = self.0.as_ref();
        if let Ok(ident) = core::str::from_utf8(bytes) {
            fmt.write_str("'")?;
            fmt.write_str(ident)?;
            fmt.write_str("'")?;
        } else {
            fmt.write_str("0x")?;
            for &byte in bytes.iter() {
                core::write!(fmt, "{:02x}", byte)?;
            }
        }

        Ok(())
    }
}

/// A partially deserialized PolkaVM program.
#[derive(Clone)]
pub struct ProgramBlob {
    #[cfg(feature = "unique-id")]
    unique_id: u64,

    isa: InstructionSetKind,

    ro_data_size: u32,
    rw_data_size: u32,
    stack_size: u32,

    ro_data: ArcBytes,
    rw_data: ArcBytes,
    code: ArcBytes,
    jump_table: ArcBytes,
    jump_table_entry_size: u8,
    bitmask: ArcBytes,
    import_offsets: ArcBytes,
    import_symbols: ArcBytes,
    exports: ArcBytes,

    debug_strings: ArcBytes,
    debug_line_program_ranges: ArcBytes,
    debug_line_programs: ArcBytes,

    metadata_hash: ArcBytes,
}

struct Reader<'a, T>
where
    T: ?Sized,
{
    blob: &'a T,
    position: usize,
}

impl<'a, T> Clone for Reader<'a, T>
where
    T: ?Sized,
{
    fn clone(&self) -> Self {
        Reader {
            blob: self.blob,
            position: self.position,
        }
    }
}

impl<'a, T> From<&'a T> for Reader<'a, T> {
    fn from(blob: &'a T) -> Self {
        Self { blob, position: 0 }
    }
}

impl<'a, T> Reader<'a, T>
where
    T: ?Sized + AsRef<[u8]>,
{
    fn skip(&mut self, count: usize) -> Result<(), ProgramParseError> {
        self.read_slice_as_range(count).map(|_| ())
    }

    #[inline(always)]
    fn read_byte(&mut self) -> Result<u8, ProgramParseError> {
        Ok(self.read_slice(1)?[0])
    }

    #[inline(always)]
    fn read_slice(&mut self, length: usize) -> Result<&'a [u8], ProgramParseError> {
        let blob = &self.blob.as_ref()[self.position..];
        let Some(slice) = blob.get(..length) else {
            return Err(ProgramParseError::unexpected_end_of_file(self.position, length, blob.len()));
        };

        self.position += length;
        Ok(slice)
    }

    #[inline(always)]
    fn read_varint(&mut self) -> Result<u32, ProgramParseError> {
        let first_byte = self.read_byte()?;
        let Some((length, value)) = read_varint(&self.blob.as_ref()[self.position..], first_byte) else {
            return Err(ProgramParseError::failed_to_read_varint(self.position - 1));
        };

        self.position += length;
        Ok(value)
    }

    fn read_bytes_with_length(&mut self) -> Result<&'a [u8], ProgramParseError> {
        let length = self.read_varint()? as usize;
        self.read_slice(length)
    }

    fn read_string_with_length(&mut self) -> Result<&'a str, ProgramParseError> {
        let offset = self.position;
        let slice = self.read_bytes_with_length()?;

        core::str::from_utf8(slice)
            .ok()
            .ok_or(ProgramParseError(ProgramParseErrorKind::FailedToReadStringNonUtf { offset }))
    }

    fn read_slice_as_range(&mut self, count: usize) -> Result<Range<usize>, ProgramParseError> {
        let blob = &self.blob.as_ref()[self.position..];
        if blob.len() < count {
            return Err(ProgramParseError::unexpected_end_of_file(self.position, count, blob.len()));
        };

        let range = self.position..self.position + count;
        self.position += count;
        Ok(range)
    }
}

impl<'a> Reader<'a, ArcBytes> {
    fn read_slice_as_bytes(&mut self, length: usize) -> Result<ArcBytes, ProgramParseError> {
        let range = self.read_slice_as_range(length)?;
        Ok(self.blob.subslice(range))
    }

    fn read_section_as_bytes(&mut self, out_section: &mut u8, expected_section: u8) -> Result<ArcBytes, ProgramParseError> {
        if *out_section != expected_section {
            return Ok(ArcBytes::default());
        }

        let section_length = self.read_varint()? as usize;
        let range = self.read_slice_as_range(section_length)?;
        *out_section = self.read_byte()?;

        Ok(self.blob.subslice(range))
    }
}

#[derive(Copy, Clone)]
pub struct Imports<'a> {
    offsets: &'a [u8],
    symbols: &'a [u8],
}

impl<'a> Imports<'a> {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> u32 {
        (self.offsets.len() / 4) as u32
    }

    pub fn get(&self, index: u32) -> Option<ProgramSymbol<&'a [u8]>> {
        let offset_start = index.checked_mul(4)?;
        let offset_end = offset_start.checked_add(4)?;
        let xs = self.offsets.get(offset_start as usize..offset_end as usize)?;
        let offset = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]) as usize;
        let next_offset = offset_end
            .checked_add(4)
            .and_then(|next_offset_end| self.offsets.get(offset_end as usize..next_offset_end as usize))
            .map_or(self.symbols.len(), |xs| u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]) as usize);

        let symbol = self.symbols.get(offset..next_offset)?;
        Some(ProgramSymbol::new(symbol))
    }

    pub fn iter(&self) -> ImportsIter<'a> {
        ImportsIter { imports: *self, index: 0 }
    }
}

impl<'a> IntoIterator for Imports<'a> {
    type Item = Option<ProgramSymbol<&'a [u8]>>;
    type IntoIter = ImportsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a Imports<'a> {
    type Item = Option<ProgramSymbol<&'a [u8]>>;
    type IntoIter = ImportsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct ImportsIter<'a> {
    imports: Imports<'a>,
    index: u32,
}

impl<'a> Iterator for ImportsIter<'a> {
    type Item = Option<ProgramSymbol<&'a [u8]>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.imports.len() {
            None
        } else {
            let value = self.imports.get(self.index);
            self.index += 1;
            Some(value)
        }
    }
}

#[derive(Copy, Clone)]
pub struct JumpTable<'a> {
    blob: &'a [u8],
    entry_size: u32,
}

impl<'a> JumpTable<'a> {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> u32 {
        if self.entry_size == 0 {
            0
        } else {
            self.blob.len() as u32 / self.entry_size
        }
    }

    pub fn get_by_address(&self, address: u32) -> Option<ProgramCounter> {
        if address & (VM_CODE_ADDRESS_ALIGNMENT - 1) != 0 || address == 0 {
            return None;
        }

        self.get_by_index((address - VM_CODE_ADDRESS_ALIGNMENT) / VM_CODE_ADDRESS_ALIGNMENT)
    }

    pub fn get_by_index(&self, index: u32) -> Option<ProgramCounter> {
        if self.entry_size == 0 {
            return None;
        }

        let start = index.checked_mul(self.entry_size)?;
        let end = start.checked_add(self.entry_size)?;
        self.blob
            .get(start as usize..end as usize)
            .map(|xs| match xs.len() {
                1 => u32::from(xs[0]),
                2 => u32::from(u16::from_le_bytes([xs[0], xs[1]])),
                3 => u32::from_le_bytes([xs[0], xs[1], xs[2], 0]),
                4 => u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]),
                _ => unreachable!(),
            })
            .map(ProgramCounter)
    }

    pub fn iter(&self) -> JumpTableIter<'a> {
        JumpTableIter {
            jump_table: *self,
            index: 0,
        }
    }
}

impl<'a> IntoIterator for JumpTable<'a> {
    type Item = ProgramCounter;
    type IntoIter = JumpTableIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a JumpTable<'a> {
    type Item = ProgramCounter;
    type IntoIter = JumpTableIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct JumpTableIter<'a> {
    jump_table: JumpTable<'a>,
    index: u32,
}

impl<'a> Iterator for JumpTableIter<'a> {
    type Item = ProgramCounter;
    fn next(&mut self) -> Option<Self::Item> {
        let value = self.jump_table.get_by_index(self.index)?;
        self.index += 1;
        Some(value)
    }
}

pub const BITMASK_MAX: u32 = 24;

fn get_bit_for_offset(bitmask: &[u8], code_len: usize, offset: u32) -> bool {
    let Some(byte) = bitmask.get(offset as usize >> 3) else {
        return false;
    };

    if offset as usize > code_len {
        return false;
    }

    let shift = offset & 7;
    ((byte >> shift) & 1) == 1
}

fn get_previous_instruction_skip(bitmask: &[u8], offset: u32) -> Option<u32> {
    let shift = offset & 7;
    let mut mask = u64::from(bitmask[offset as usize >> 3]) << 56;
    if offset >= 8 {
        mask |= u64::from(bitmask[(offset as usize >> 3) - 1]) << 48;
    }
    if offset >= 16 {
        mask |= u64::from(bitmask[(offset as usize >> 3) - 2]) << 40;
    }
    if offset >= 24 {
        mask |= u64::from(bitmask[(offset as usize >> 3) - 3]) << 32;
    }
    if offset >= 32 {
        mask |= u64::from(bitmask[(offset as usize >> 3) - 4]) << 24;
    }

    mask <<= 8 - shift;
    mask >>= 1;
    let skip = mask.leading_zeros() - 1;
    if skip > BITMASK_MAX {
        None
    } else {
        Some(skip)
    }
}

#[test]
fn test_get_previous_instruction_skip() {
    assert_eq!(get_previous_instruction_skip(&[0b00000001], 0), None);
    assert_eq!(get_previous_instruction_skip(&[0b00000011], 0), None);
    assert_eq!(get_previous_instruction_skip(&[0b00000010], 1), None);
    assert_eq!(get_previous_instruction_skip(&[0b00000011], 1), Some(0));
    assert_eq!(get_previous_instruction_skip(&[0b00000001], 1), Some(0));
    assert_eq!(get_previous_instruction_skip(&[0b00000001, 0b00000001], 8), Some(7));
    assert_eq!(get_previous_instruction_skip(&[0b00000001, 0b00000000], 8), Some(7));
}

#[test]
fn test_get_previous_instruction_skip_max_length() {
    for previous in 0_u32..64 {
        let mut bitmask = [0_u8; 16];
        bitmask[cast(previous).to_usize() >> 3] |= 1 << (previous & 7);

        let offset = previous + BITMASK_MAX + 1;
        assert_eq!(
            get_previous_instruction_skip(&bitmask, offset),
            Some(BITMASK_MAX),
            "the instruction at {previous} is out of reach from {offset}"
        );

        assert_eq!(get_previous_instruction_skip(&bitmask, offset + 1), None);
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct RawOpcodeLength(u8);

impl RawOpcodeLength {
    #[inline]
    pub fn get(self) -> u32 {
        u32::from(self.0)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct RawOpcodeEntry(u16);

impl RawOpcodeEntry {
    pub const fn empty() -> Self {
        Self::new(EXTENDED_INVALID_RAW_OPCODE as u16, 0)
    }

    pub const fn is_empty(self) -> bool {
        self.raw_opcode() == EXTENDED_INVALID_RAW_OPCODE as u16
    }

    pub const fn new(raw_opcode: u16, args_length: u16) -> Self {
        assert!(args_length < 2_u16.pow(4));
        assert!(raw_opcode < 2_u16.pow(12));
        Self(raw_opcode | (args_length << 12))
    }

    pub const fn raw_opcode(self) -> u16 {
        self.0 & 0x0fff
    }

    pub const fn args_length(self) -> u16 {
        self.0 >> 12
    }
}

pub struct RawOpcodeTable {
    length_table: [RawOpcodeLength; EXTENDED_RAW_OPCODE_COUNT],
    starts_new_basic_block_table: [bool; EXTENDED_RAW_OPCODE_COUNT],
}

impl RawOpcodeTable {
    #[inline(always)]
    fn ends_basic_block(&self, raw_opcode: usize) -> bool {
        let Some(&ends_basic_block) = self.starts_new_basic_block_table.get(raw_opcode) else {
            unreachable!();
        };

        ends_basic_block
    }
}

pub trait InstructionSet: Copy {
    fn opcode_from_raw(self, raw_opcode: u32) -> Option<Opcode>;
    fn opcode_to_raw(self, opcode: Opcode, args_length: u32) -> Option<(u32, u32)>;
    fn parse_instruction(self, raw_opcode: usize, chunk: u128, offset: u32, length: u32) -> Instruction;
    fn supports_opcode(self, opcode: Opcode) -> bool;
    fn is_legacy(self) -> bool;

    fn raw_opcode_table(self) -> &'static RawOpcodeTable {
        unimplemented!();
    }
}

pub const CODE_BLOCK_SIZE: usize = 1024;
const _: () = assert!(CODE_BLOCK_SIZE.is_power_of_two());

#[inline(always)]
fn start_of_block_boundary(offset: usize) -> usize {
    offset & !(CODE_BLOCK_SIZE - 1)
}

#[inline(always)]
fn is_on_a_block_boundary(offset: usize) -> bool {
    offset % CODE_BLOCK_SIZE == 0
}

#[inline(always)]
pub(crate) fn next_block_boundary(offset: usize) -> usize {
    start_of_block_boundary(offset) + CODE_BLOCK_SIZE
}

#[inline(always)]
fn end_of_macro_block(offset: usize, code_len: usize) -> usize {
    next_block_boundary(offset).min(code_len)
}

const EXTENDED_OPCODE_PREFIX: u8 = 255;
const EXTENDED_INVALID_RAW_OPCODE: usize = 512;

#[doc(hidden)]
pub const EXTENDED_RAW_OPCODE_COUNT: usize = 513;
const EXTENDED_MAX_ARGS_LENGTH: usize = 10;

fn extended_scan_is_instruction_boundary<I>(instruction_set: I, code: &[u8], offset: u32) -> bool
where
    I: InstructionSet,
{
    debug_assert!(!instruction_set.is_legacy());

    let offset = cast(offset).to_usize();
    if offset >= code.len() {
        return false;
    }

    let mut position = start_of_block_boundary(offset);
    while position < offset {
        position = parse_simple_extended(instruction_set, code, position).next_offset;
    }

    position == offset
}

fn extended_scan_find_next_offset<I>(instruction_set: I, code: &[u8], offset: u32) -> u32
where
    I: InstructionSet,
{
    let offset = cast(offset).to_usize();
    if offset >= code.len() {
        return code.len() as u32;
    }

    let mut position = start_of_block_boundary(offset);
    while position <= offset {
        debug_assert!(position < code.len());
        position = parse_simple_extended(instruction_set, code, position).next_offset;
    }

    core::cmp::min(position, code.len()) as u32
}

#[cfg(feature = "alloc")]
pub fn extended_assert_decode_is_deterministic<I>(instruction_set: I, code: &[u8])
where
    I: InstructionSet,
{
    use alloc::vec::Vec;

    assert!(!instruction_set.is_legacy());
    assert!(code.len() <= u32::MAX as usize);

    let mut linear: Vec<usize> = Vec::new();
    let mut offset = 0;
    while offset < code.len() {
        linear.push(offset);
        let next_offset = parse_simple_extended(instruction_set, code, offset).next_offset;
        assert!(next_offset > offset);
        offset = next_offset;
    }

    let mut linear_iter = linear.iter().copied().peekable();
    let mut block_start = 0;
    while block_start < code.len() {
        assert_eq!(linear_iter.peek(), Some(&block_start));

        let block_end = core::cmp::min(code.len(), block_start + CODE_BLOCK_SIZE);
        let mut offset = block_start;
        let mut last_raw_opcode = EXTENDED_INVALID_RAW_OPCODE;
        while offset < block_end {
            assert_eq!(linear_iter.next(), Some(offset));

            let step = parse_simple_extended(instruction_set, code, offset);
            assert_eq!(offset + step.length as usize, step.next_offset, "mismatch at offset {offset}");
            offset = step.next_offset;
            last_raw_opcode = step.raw_opcode;
        }

        assert_eq!(offset, block_end);
        assert!(
            ends_basic_block_extended(instruction_set, last_raw_opcode),
            "the macro block at offset {block_start} doesn't end a basic block"
        );

        block_start += CODE_BLOCK_SIZE;
    }

    assert_eq!(linear_iter.next(), None);

    for offset in 0..=code.len() {
        assert_eq!(
            extended_scan_is_instruction_boundary(instruction_set, code, offset as u32),
            linear.binary_search(&offset).is_ok(),
            "mismatch at offset {offset}"
        );
    }

    for &offset in &linear {
        let step = parse_simple_extended(instruction_set, code, offset);
        if ends_basic_block_extended(instruction_set, step.raw_opcode) && step.next_offset < code.len() {
            assert!(
                scan_is_jump_target_valid_extended(instruction_set, code, step.next_offset as u32),
                "the instruction after the one at offset {offset} is not a valid jump target"
            );
        }
    }

    let mut block_start = 0;
    while block_start < code.len() {
        let mut bitmap = CodeBlockBitmap::new();
        bitmap.build(instruction_set, code, block_start as u32);

        for bit in 0..CODE_BLOCK_SIZE {
            let offset = block_start + bit;
            let is_valid = scan_is_jump_target_valid_extended(instruction_set, code, offset as u32);
            assert_eq!(bitmap.get_local_raw(bit), is_valid, "mismatch at offset {offset}");

            if cfg!(test) || block_start <= 2 * CODE_BLOCK_SIZE {
                // Don't slow down the fuzz test unnecessarily.
                assert_eq!(
                    is_valid,
                    scan_find_start_of_basic_block_extended(instruction_set, code, offset as u32) == Some(offset as u32),
                    "mismatch at offset {offset}"
                );
            }

            if is_valid {
                assert!(linear.binary_search(&offset).is_ok());
            }
        }

        let block_end = core::cmp::min(code.len(), block_start + CODE_BLOCK_SIZE);
        let mut offset = block_start;
        while offset < block_end {
            let step = parse_simple_extended(instruction_set, code, offset);
            if ends_basic_block_extended(instruction_set, step.raw_opcode) && step.next_offset < block_end {
                assert!(
                    bitmap.get_local_raw(step.next_offset - block_start),
                    "the instruction after the one at offset {offset} is not a valid jump target"
                );
            }

            offset = step.next_offset;
        }

        block_start += CODE_BLOCK_SIZE;
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_extended_decode_is_deterministic() {
    let mut state: u64 = 0x853c49e6748fea9b;
    let mut rng = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..50 {
        let length = (rng() % (CODE_BLOCK_SIZE as u64 * 5 / 2)) as usize;
        let mut code = alloc::vec![0; length];
        for byte in code.iter_mut() {
            *byte = match rng() % 4 {
                0 => EXTENDED_OPCODE_PREFIX,
                _ => (rng() & 0xff) as u8,
            };
        }

        extended_assert_decode_is_deterministic(ISA_Latest64, &code);
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_extended_serialization_round_trip() {
    let r1 = Reg::A1;
    let r2 = Reg::A5;
    let r3 = Reg::SP;

    let mut instructions = alloc::vec::Vec::new();
    for imm in [
        0_i32,
        1,
        -1,
        63,
        64,
        127,
        128,
        -128,
        255,
        256,
        -257,
        0x7fff,
        -0x8000,
        0x10000,
        i32::MAX,
        i32::MIN,
    ] {
        instructions.extend([
            asm::load_imm(r1, imm),
            asm::add_imm_64(r1, r2, imm),
            asm::add_imm_32(r1, r2, imm),
            asm::store_imm_indirect_u32(r1, imm, imm.wrapping_mul(3)),
            asm::store_imm_u64(imm, imm.wrapping_add(7)),
            asm::cmov_if_zero_imm(r1, r2, imm),
            asm::jump_indirect(r2, imm),
            asm::load_u16(r1, imm),
            asm::store_u8(r2, imm),
        ]);
    }

    instructions.extend([
        asm::trap(),
        asm::fallthrough(),
        asm::memset(),
        asm::unlikely(),
        asm::sbrk(r1, r2),
        asm::move_reg(r1, r2),
        asm::add_64(r1, r2, r3),
        asm::mul_upper_signed_signed(r1, r2, r3),
        asm::load_imm64(r1, 0x1234_5678_9abc_def0),
        asm::load_imm64(r2, u64::MAX),
        asm::ecalli(0),
        asm::ecalli(100_000),
    ]);

    for target in [0_u32, 60, 300, 70_000] {
        instructions.extend([
            asm::jump(target),
            asm::load_imm_and_jump(r1, -5, target),
            asm::branch_eq(r1, r2, target),
            asm::branch_less_signed_imm(r1, -100, target),
        ]);
    }

    let mut position: u32 = 12345;
    for instruction in instructions {
        let mut buffer = [0; MAX_INSTRUCTION_LENGTH];
        let length = instruction.serialize_into(ISA_Latest64, position, &mut buffer) as u32;
        assert!(length > 0 && length <= MAX_INSTRUCTION_LENGTH as u32);

        let chunk = load_chunk(&buffer, 0);
        let step = parse_simple_extended(ISA_Latest64, &buffer, 0);
        assert_eq!(step.length, length, "length mismatch for {instruction:?}");

        let parsed = ISA_Latest64.parse_instruction(step.raw_opcode, chunk, position, step.length);
        assert_eq!(parsed, instruction, "round trip failed at length {length}");
        position += length;
    }
}

#[test]
fn test_extended_jumping_after_an_invalid_instruction_is_allowed() {
    let invalid_opcode = (0..EXTENDED_OPCODE_PREFIX)
        .find(|&raw_opcode| ISA_Latest64.opcode_from_raw(u32::from(raw_opcode)).is_none())
        .expect("no unused opcode found to test with");

    let mut buffer = [0; MAX_INSTRUCTION_LENGTH];
    let filler = asm::add_imm_64(Reg::A0, Reg::A0, 1);
    let filler_length = filler.serialize_into(ISA_Latest64, 0, &mut buffer);

    let mut code = [0; CODE_BLOCK_SIZE];
    code[..filler_length].copy_from_slice(&buffer[..filler_length]);
    code[filler_length] = invalid_opcode;

    let step = parse_simple_extended(ISA_Latest64, &code, filler_length);
    assert_eq!(step.raw_opcode, usize::from(invalid_opcode));
    let after_invalid = step.next_offset;

    let mut bitmap = CodeBlockBitmap::new();
    bitmap.build(ISA_Latest64, &code, 0);

    assert!(!scan_is_jump_target_valid_extended(ISA_Latest64, &code, filler_length as u32));
    assert!(!bitmap.get_local_raw(filler_length));
    assert_eq!(
        scan_find_start_of_basic_block_extended(ISA_Latest64, &code, filler_length as u32),
        Some(0)
    );

    assert!(scan_is_jump_target_valid_extended(ISA_Latest64, &code, after_invalid as u32));
    assert!(bitmap.get_local_raw(after_invalid));
    assert_eq!(
        scan_find_start_of_basic_block_extended(ISA_Latest64, &code, after_invalid as u32),
        Some(after_invalid as u32)
    );
}

#[test]
fn test_extended_instruction_overhanging_a_block_boundary_is_a_trap() {
    let mut buffer = [0; MAX_INSTRUCTION_LENGTH];
    let instruction = asm::load_imm64(Reg::A0, u64::MAX);
    let length = instruction.serialize_into(ISA_Latest64, 0, &mut buffer);
    assert_eq!(length, 10);

    let mut code = [0; 2048];
    let offset = CODE_BLOCK_SIZE - 1;
    code[offset..offset + length].copy_from_slice(&buffer[..length]);

    let step = parse_simple_extended(ISA_Latest64, &code, offset);
    assert_eq!(step.raw_opcode, EXTENDED_INVALID_RAW_OPCODE);
    assert_eq!(step.length as usize, CODE_BLOCK_SIZE - offset);
    assert_eq!(step.next_offset, CODE_BLOCK_SIZE);

    let chunk = load_chunk(&code, offset);
    assert_eq!(
        ISA_Latest64.parse_instruction(step.raw_opcode, chunk, offset as u32, step.length),
        Instruction::invalid
    );

    // The very same instruction is decoded normally when it fits.
    code[CODE_BLOCK_SIZE..CODE_BLOCK_SIZE + length].copy_from_slice(&buffer[..length]);
    let step = parse_simple_extended(ISA_Latest64, &code, CODE_BLOCK_SIZE);
    assert_eq!(step.next_offset, CODE_BLOCK_SIZE + length);
    let chunk = load_chunk(&code, CODE_BLOCK_SIZE);
    assert_eq!(
        ISA_Latest64.parse_instruction(step.raw_opcode, chunk, CODE_BLOCK_SIZE as u32, step.length),
        instruction
    );
}

/// Returns whether a jump to a given `offset` is allowed.
#[inline]
pub fn scan_is_jump_target_valid<I>(instruction_set: I, code: &[u8], bitmask: &[u8], offset: u32) -> bool
where
    I: InstructionSet,
{
    if instruction_set.is_legacy() {
        is_jump_target_valid_legacy(instruction_set, code, bitmask, offset)
    } else {
        scan_is_jump_target_valid_extended(instruction_set, code, offset)
    }
}

fn is_instruction_start_legacy(bitmask: &[u8], code_len: usize, offset: u32) -> bool {
    if cast(offset).to_usize() >= code_len {
        return false;
    }

    offset == 0 || get_bit_for_offset(bitmask, code_len, offset) || get_previous_instruction_skip(bitmask, offset) == Some(BITMASK_MAX)
}

#[inline(never)]
fn is_jump_target_valid_legacy<I>(instruction_set: I, code: &[u8], bitmask: &[u8], offset: u32) -> bool
where
    I: InstructionSet,
{
    debug_assert!(instruction_set.is_legacy());

    if !is_instruction_start_legacy(bitmask, code.len(), offset) {
        // We can't jump if there's no instruction here.
        return false;
    }

    previous_instruction_legacy(instruction_set, code, bitmask, offset).is_none_or(|(_, opcode)| opcode.starts_new_basic_block())
}

#[inline]
fn previous_instruction_legacy<I>(instruction_set: I, code: &[u8], bitmask: &[u8], offset: u32) -> Option<(u32, Opcode)>
where
    I: InstructionSet,
{
    let skip = get_previous_instruction_skip(bitmask, offset)?;
    let previous_offset = offset - skip - 1;
    let opcode = instruction_set
        .opcode_from_raw(u32::from(code[cast(previous_offset).to_usize()]))
        .unwrap_or(Opcode::trap);

    Some((previous_offset, opcode))
}

#[inline(never)]
fn scan_is_jump_target_valid_extended<I>(instruction_set: I, code: &[u8], offset: u32) -> bool
where
    I: InstructionSet,
{
    debug_assert!(!instruction_set.is_legacy());

    let offset = cast(offset).to_usize();
    if offset >= code.len() {
        return false;
    }

    let start_of_block = start_of_block_boundary(offset);
    if offset == start_of_block {
        // A macro block boundary always starts a new basic block, so we can always jump here.
        return true;
    }

    let mut position = start_of_block;
    while position < offset {
        let step = parse_simple_extended(instruction_set, code, position);
        if step.next_offset == offset {
            return ends_basic_block_extended(instruction_set, step.raw_opcode);
        }

        position = step.next_offset;
    }

    // There's no instruction boundary at `offset`, so we can't jump here.
    false
}

#[inline]
fn ends_basic_block_extended<I>(instruction_set: I, raw_opcode: usize) -> bool
where
    I: InstructionSet,
{
    debug_assert!(!instruction_set.is_legacy());
    instruction_set.raw_opcode_table().ends_basic_block(raw_opcode)
}

#[inline]
pub fn scan_find_start_of_basic_block<I>(instruction_set: I, code: &[u8], bitmask: &[u8], offset: u32) -> Option<u32>
where
    I: InstructionSet,
{
    if instruction_set.is_legacy() {
        find_start_of_basic_block_legacy(instruction_set, code, bitmask, offset)
    } else {
        scan_find_start_of_basic_block_extended(instruction_set, code, offset)
    }
}

fn find_start_of_basic_block_legacy<I>(instruction_set: I, code: &[u8], bitmask: &[u8], mut offset: u32) -> Option<u32>
where
    I: InstructionSet,
{
    if !is_instruction_start_legacy(bitmask, code.len(), offset) {
        // We can't jump if there's no instruction here.
        return None;
    }

    while let Some((previous_offset, opcode)) = previous_instruction_legacy(instruction_set, code, bitmask, offset) {
        if opcode.starts_new_basic_block() {
            break;
        }

        offset = previous_offset;
    }

    Some(offset)
}

fn scan_find_start_of_basic_block_extended<I>(instruction_set: I, code: &[u8], offset: u32) -> Option<u32>
where
    I: InstructionSet,
{
    let offset = cast(offset).to_usize();
    if offset >= code.len() {
        // We can't jump if there's no instruction here.
        return None;
    }

    let start_of_block = start_of_block_boundary(offset);
    let mut block_start = start_of_block;
    let mut position = start_of_block;
    while position < offset {
        let step = parse_simple_extended(instruction_set, code, position);
        if ends_basic_block_extended(instruction_set, step.raw_opcode) {
            block_start = step.next_offset;
        }

        position = step.next_offset;
    }

    if position != offset {
        // There's no instruction boundary at `offset`, so we can't jump here.
        return None;
    }

    Some(block_start as u32)
}

const CODE_BLOCK_BITMAP_ELEMENTS: usize = CODE_BLOCK_SIZE / 64;

#[derive(Copy, Clone)]
pub struct CodeBlockBitmap {
    /// Address of the macro block; `u32::MAX` when none.
    block_start: u32,
    bits: [u64; CODE_BLOCK_BITMAP_ELEMENTS],
}

#[cfg(feature = "alloc")]
pub type CodeBlockBitmapBox = alloc::boxed::Box<CodeBlockBitmap>;

impl Default for CodeBlockBitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeBlockBitmap {
    pub fn new() -> Self {
        Self {
            block_start: u32::MAX,
            bits: [0_u64; CODE_BLOCK_BITMAP_ELEMENTS],
        }
    }

    #[cfg(feature = "alloc")]
    pub fn new_boxed() -> CodeBlockBitmapBox {
        alloc::boxed::Box::new(Self::new())
    }

    pub fn get(&self, pc: ProgramCounter) -> bool {
        self.is_for_the_block_containing(pc) && self.get_local_raw(cast(pc.0).to_usize() % CODE_BLOCK_SIZE)
    }

    fn is_for_the_block_containing(&self, pc: ProgramCounter) -> bool {
        cast(start_of_block_boundary(cast(pc.0).to_usize())).to_u32_or_debug_panic() == self.block_start
    }

    pub fn get_local_raw(&self, bit: usize) -> bool {
        self.bits[bit / 64] & (1 << (bit % 64)) != 0
    }

    pub fn set_local_raw(&mut self, bit: usize) {
        self.bits[bit / 64] |= 1 << (bit % 64);
    }

    pub fn clear(&mut self) {
        self.block_start = u32::MAX;
        self.bits.fill(0);
    }

    /// Computes the valid jump target bitmap for the whole macro block containing `offset` in a single scan.
    pub fn build<I>(&mut self, instruction_set: I, code: &[u8], offset: u32)
    where
        I: InstructionSet,
    {
        assert!(!instruction_set.is_legacy());
        self.clear();

        let block_start = start_of_block_boundary(cast(offset).to_usize());
        self.block_start = cast(block_start).to_u32_or_debug_panic();
        if block_start >= code.len() {
            return;
        }

        // A macro block boundary always starts a new basic block.
        self.set_local_raw(0);

        let block_end = core::cmp::min(code.len(), block_start + CODE_BLOCK_SIZE);
        let mut position = block_start;
        while position < block_end {
            let step = parse_simple_extended(instruction_set, code, position);
            if ends_basic_block_extended(instruction_set, step.raw_opcode) && step.next_offset < block_end {
                self.set_local_raw(step.next_offset - block_start);
            }

            position = step.next_offset;
        }
    }

    /// Returns the index of the closest set bit at or before `bit`.
    fn find_previous_set_bit(&self, bit: usize) -> Option<usize> {
        let mut index = bit / 64;
        let mut word = self.bits[index] & (u64::MAX >> (63 - bit % 64));
        while word == 0 {
            index = index.checked_sub(1)?;
            word = self.bits[index];
        }

        Some(index * 64 + cast(u64::BITS - 1 - word.leading_zeros()).to_usize())
    }

    pub fn find_start_of_basic_block(&self, program_counter: ProgramCounter) -> Option<ProgramCounter> {
        if !self.is_for_the_block_containing(program_counter) {
            return None;
        }

        let offset = cast(program_counter.0).to_usize();
        let bit = offset % CODE_BLOCK_SIZE;
        let block_start = offset - bit;

        Some(ProgramCounter(
            cast(block_start + self.find_previous_set_bit(bit)?).to_u32_or_debug_panic(),
        ))
    }
}

#[test]
fn test_find_previous_set_bit_matches_a_linear_search() {
    let mut state: u64 = 0x243f6a8885a308d3;
    let mut rng = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for iteration in 0..100 {
        let mut bitmap = CodeBlockBitmap::new();
        for word in bitmap.bits.iter_mut() {
            *word = match iteration % 4 {
                0 => 0,
                1 => rng(),
                2 => rng() & rng() & rng(),
                _ => u64::MAX,
            };
        }

        for bit in 0..CODE_BLOCK_SIZE {
            let expected = (0..=bit).rev().find(|&bit| bitmap.get_local_raw(bit));
            assert_eq!(bitmap.find_previous_set_bit(bit), expected, "mismatch at bit {bit}");
        }
    }
}

#[test]
fn test_code_block_bitmap_only_answers_queries_about_its_own_block() {
    let opcode_unlikely = ISA_Latest64.opcode_to_raw(Opcode::unlikely, 0).unwrap().0 as u8;
    let opcode_fallthrough = ISA_Latest64.opcode_to_raw(Opcode::fallthrough, 0).unwrap().0 as u8;

    // Nothing in the first macro block ends a basic block, while everything does in the second one.
    let mut code = [opcode_unlikely; CODE_BLOCK_SIZE * 2];
    code[CODE_BLOCK_SIZE..].fill(opcode_fallthrough);

    let mut bitmap = CodeBlockBitmap::new();
    bitmap.build(ISA_Latest64, &code, CODE_BLOCK_SIZE as u32);

    let inside = ProgramCounter(CODE_BLOCK_SIZE as u32 + 5);
    assert!(bitmap.get(inside));
    assert_eq!(bitmap.find_start_of_basic_block(inside), Some(inside));

    let outside = ProgramCounter(5);
    assert!(!scan_is_jump_target_valid_extended(ISA_Latest64, &code, outside.0));
    assert!(!bitmap.get(outside));
    assert_eq!(bitmap.find_start_of_basic_block(outside), None);
}

#[test]
fn test_is_jump_target_valid() {
    fn assert_get_previous_instruction_skip_matches_instruction_parser(code: &[u8], bitmask: &[u8]) {
        for instruction in Instructions::new(ISA_Latest32, code, bitmask, 0, false) {
            match instruction.kind {
                Instruction::trap => {
                    let skip = get_previous_instruction_skip(bitmask, instruction.offset.0);
                    if let Some(skip) = skip {
                        let previous_offset = instruction.offset.0 - skip - 1;
                        assert_eq!(
                            Instructions::new(ISA_Latest32, code, bitmask, previous_offset, true)
                                .next()
                                .unwrap(),
                            ParsedInstruction {
                                kind: Instruction::trap,
                                offset: ProgramCounter(previous_offset),
                                next_offset: instruction.offset,
                            }
                        );
                    } else {
                        for skip in 0..=24 {
                            let Some(previous_offset) = instruction.offset.0.checked_sub(skip + 1) else {
                                continue;
                            };
                            assert_eq!(
                                Instructions::new(ISA_Latest32, code, bitmask, previous_offset, true)
                                    .next()
                                    .unwrap()
                                    .kind,
                                Instruction::invalid,
                            );
                        }
                    }
                }
                Instruction::invalid => {}
                _ => unreachable!(),
            }
        }
    }

    let opcode_trap = ISA_Latest64.opcode_to_raw(Opcode::trap, 0).unwrap().0 as u8;

    macro_rules! g {
        ($code_length:expr, $bits:expr) => {{
            let mut bitmask = [0; {
                let value: usize = $code_length;
                value.div_ceil(8)
            }];
            for bit in $bits {
                let bit: usize = bit;
                assert!(bit < $code_length);
                bitmask[bit / 8] |= (1 << (bit % 8));
            }

            let code = [opcode_trap; $code_length];
            assert_get_previous_instruction_skip_matches_instruction_parser(&code, &bitmask);
            (code, bitmask)
        }};
    }

    // Make sure the helper macro works correctly.
    assert_eq!(g!(1, [0]).1, [0b00000001]);
    assert_eq!(g!(2, [1]).1, [0b00000010]);
    assert_eq!(g!(8, [7]).1, [0b10000000]);
    assert_eq!(g!(9, [8]).1, [0b00000000, 0b00000001]);
    assert_eq!(g!(10, [9]).1, [0b00000000, 0b00000010]);
    assert_eq!(g!(10, [2, 9]).1, [0b00000100, 0b00000010]);

    macro_rules! assert_valid {
        ($code_length:expr, $bits:expr, $offset:expr) => {{
            let (code, bitmask) = g!($code_length, $bits);
            assert!(is_jump_target_valid_legacy(ISA_Latest32, &code, &bitmask, $offset));
        }};
    }

    macro_rules! assert_invalid {
        ($code_length:expr, $bits:expr, $offset:expr) => {{
            let (code, bitmask) = g!($code_length, $bits);
            assert!(!is_jump_target_valid_legacy(ISA_Latest32, &code, &bitmask, $offset));
        }};
    }

    assert_valid!(1, [0], 0);
    assert_valid!(2, [0, 1], 1);
    assert_valid!(8, [0, 7], 7);
    assert_valid!(9, [0, 8], 8);
    assert_valid!(25, [0, 24], 24);
    assert_valid!(26, [0, 25], 25);

    assert_invalid!(3, [0, 2], 1);
    assert_invalid!(27, [0], 24);

    assert_valid!(1, [], 0);
    assert_valid!(2, [1], 1);
    assert_valid!(27, [0], 25);
    assert_valid!(27, [0, 26], 26);

    let opcode_load_imm = ISA_Latest32.opcode_to_raw(Opcode::load_imm, 1).unwrap().0 as u8;
    assert!(is_jump_target_valid_legacy(ISA_Latest32, &[opcode_load_imm], &[0b00000001], 0));

    assert!(!is_jump_target_valid_legacy(
        ISA_Latest32,
        &[opcode_load_imm, opcode_load_imm],
        &[0b00000011],
        1
    ));

    assert!(is_jump_target_valid_legacy(
        ISA_Latest32,
        &[opcode_trap, opcode_load_imm],
        &[0b00000011],
        1
    ));

    // An unassigned opcode is an invalid instruction, which is a trap, so it also ends a basic block.
    let opcode_unassigned = (0..=u8::MAX)
        .find(|&raw_opcode| ISA_Latest32.opcode_from_raw(u32::from(raw_opcode)).is_none())
        .unwrap();

    assert!(is_jump_target_valid_legacy(
        ISA_Latest32,
        &[opcode_unassigned, opcode_load_imm],
        &[0b00000011],
        1
    ));
}

#[test]
fn test_legacy_runner_and_free_functions_match() {
    #[derive(Copy, Clone)]
    struct CollectInstructionStarts<I>(I);

    impl<I> OpcodeVisitor for CollectInstructionStarts<I>
    where
        I: InstructionSet,
    {
        type State = [bool; 256];
        type ReturnTy = ();
        type InstructionSet = I;

        fn instruction_set(self) -> I {
            self.0
        }

        fn dispatch(self, state: &mut Self::State, _opcode: usize, _chunk: u128, offset: u32, _length: u32) {
            if let Some(is_start) = state.get_mut(cast(offset).to_usize()) {
                *is_start = true;
            }
        }
    }

    let mut state: u64 = 0x243f6a8885a308d3;
    let mut rng = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as u8
    };

    let instruction_set = ISA_Latest32;
    let mut injected_instructions = 0;
    for iteration in 0..100 {
        let mut code = [0_u8; 256];
        code.fill_with(&mut rng);

        let mut bitmask = [0_u8; 256 / 8];
        bitmask.fill_with(|| match iteration % 4 {
            0 => 0,
            1 => rng(),
            2 => rng() & rng() & rng(),
            _ => u8::MAX,
        });

        let mut decoded_starts = [false; 256];
        visitor_run_legacy(&mut decoded_starts, &code, &bitmask, CollectInstructionStarts(instruction_set));

        for offset in 0..cast(code.len()).to_u32_or_debug_panic() {
            let is_instruction_start = is_instruction_start_legacy(&bitmask, code.len(), offset);
            assert_eq!(
                is_instruction_start,
                decoded_starts[cast(offset).to_usize()],
                "mismatch at offset {offset} of iteration {iteration}"
            );

            assert_eq!(
                is_jump_target_valid_legacy(instruction_set, &code, &bitmask, offset),
                find_start_of_basic_block_legacy(instruction_set, &code, &bitmask, offset) == Some(offset),
                "jump target and start of basic block mismatch at offset {offset} of iteration {iteration}"
            );

            if is_instruction_start && offset != 0 && !get_bit_for_offset(&bitmask, code.len(), offset) {
                injected_instructions += 1;
            }
        }
    }

    assert!(injected_instructions > 0);
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn parse_bitmask_slow(bitmask: &[u8], code_length: usize, offset: u32) -> (u32, bool) {
    let mut offset = offset as usize + 1;
    let mut is_next_instruction_invalid = true;
    let origin = offset;
    while let Some(&byte) = bitmask.get(offset >> 3) {
        let shift = offset & 7;
        let mask = byte >> shift;
        if mask == 0 {
            offset += 8 - shift;
            if (offset - origin) < BITMASK_MAX as usize {
                continue;
            }
        } else {
            offset += mask.trailing_zeros() as usize;
            is_next_instruction_invalid = offset >= code_length || (offset - origin) > BITMASK_MAX as usize;
        }
        break;
    }

    use core::cmp::min;
    let offset = min(offset, code_length);
    let skip = min((offset - origin) as u32, BITMASK_MAX);
    (skip, is_next_instruction_invalid)
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn parse_bitmask_fast(bitmask: &[u8], mut offset: u32) -> Option<u32> {
    debug_assert!(offset < u32::MAX);
    debug_assert!(get_bit_for_offset(bitmask, offset as usize + 1, offset));
    offset += 1;

    let bitmask = bitmask.get(offset as usize >> 3..(offset as usize >> 3) + 4)?;
    let shift = offset & 7;
    let mask: u32 = (u32::from_le_bytes([bitmask[0], bitmask[1], bitmask[2], bitmask[3]]) >> shift) | (1 << BITMASK_MAX);
    Some(mask.trailing_zeros())
}

#[test]
fn test_parse_bitmask() {
    #[track_caller]
    fn parse_both(bitmask: &[u8], offset: u32) -> u32 {
        let result_fast = parse_bitmask_fast(bitmask, offset).unwrap();
        let result_slow = parse_bitmask_slow(bitmask, bitmask.len() * 8, offset).0;
        assert_eq!(result_fast, result_slow);

        result_fast
    }

    assert_eq!(parse_both(&[0b00000011, 0, 0, 0], 0), 0);
    assert_eq!(parse_both(&[0b00000101, 0, 0, 0], 0), 1);
    assert_eq!(parse_both(&[0b10000001, 0, 0, 0], 0), 6);
    assert_eq!(parse_both(&[0b00000001, 1, 0, 0], 0), 7);
    assert_eq!(parse_both(&[0b00000001, 1 << 7, 0, 0], 0), 14);
    assert_eq!(parse_both(&[0b00000001, 0, 1, 0], 0), 15);
    assert_eq!(parse_both(&[0b00000001, 0, 1 << 7, 0], 0), 22);
    assert_eq!(parse_both(&[0b00000001, 0, 0, 1], 0), 23);

    assert_eq!(parse_both(&[0b11000000, 0, 0, 0, 0], 6), 0);
    assert_eq!(parse_both(&[0b01000000, 1, 0, 0, 0], 6), 1);

    assert_eq!(parse_both(&[0b10000000, 1, 0, 0, 0], 7), 0);
    assert_eq!(parse_both(&[0b10000000, 1 << 1, 0, 0, 0], 7), 1);
}

#[derive(Clone)]
pub struct Instructions<'a, I> {
    code: &'a [u8],
    bitmask: &'a [u8],
    offset: u32,
    invalid_offset: Option<u32>,
    is_bounded: bool,
    is_done: bool,
    instruction_set: I,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ParsedInstruction {
    pub kind: Instruction,
    pub offset: ProgramCounter,
    pub next_offset: ProgramCounter,
}

impl ParsedInstruction {
    #[inline]
    pub fn visit_parsing<T>(&self, visitor: &mut T) -> <T as ParsingVisitor>::ReturnTy
    where
        T: ParsingVisitor,
    {
        self.kind
            .visit_parsing(self.offset.0, self.next_offset.0.saturating_sub(self.offset.0), visitor)
    }
}

impl core::ops::Deref for ParsedInstruction {
    type Target = Instruction;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.kind
    }
}

impl core::fmt::Display for ParsedInstruction {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "{:>7}: {}", self.offset, self.kind)
    }
}

impl<'a, I> Instructions<'a, I>
where
    I: InstructionSet,
{
    #[inline]
    pub fn new_bounded(instruction_set: I, code: &'a [u8], bitmask: &'a [u8], offset: u32) -> Self {
        Self::new(instruction_set, code, bitmask, offset, true)
    }

    #[inline]
    pub fn new_bounded_known_boundary(instruction_set: I, code: &'a [u8], bitmask: &'a [u8], offset: u32) -> Self {
        Self::new_impl(instruction_set, code, bitmask, offset, true, true)
    }

    #[inline]
    pub fn new_unbounded(instruction_set: I, code: &'a [u8], bitmask: &'a [u8], offset: u32) -> Self {
        Self::new(instruction_set, code, bitmask, offset, false)
    }

    #[inline]
    fn new(instruction_set: I, code: &'a [u8], bitmask: &'a [u8], offset: u32, is_bounded: bool) -> Self {
        Self::new_impl(instruction_set, code, bitmask, offset, is_bounded, false)
    }

    #[inline]
    fn new_impl(instruction_set: I, code: &'a [u8], bitmask: &'a [u8], offset: u32, is_bounded: bool, is_known_boundary: bool) -> Self {
        assert!(code.len() <= u32::MAX as usize);
        let is_legacy = instruction_set.is_legacy();
        if is_legacy {
            assert_eq!(bitmask.len(), code.len().div_ceil(8));
        }

        let is_valid = if is_legacy {
            debug_assert!(
                !is_known_boundary || cast(offset).to_usize() >= code.len() || is_instruction_start_legacy(bitmask, code.len(), offset)
            );
            get_bit_for_offset(bitmask, code.len(), offset)
        } else if is_known_boundary && (offset as usize) < code.len() {
            debug_assert!(extended_scan_is_instruction_boundary(instruction_set, code, offset));
            true
        } else {
            extended_scan_is_instruction_boundary(instruction_set, code, offset)
        };

        let mut is_done = false;
        let (offset, invalid_offset) = if is_valid {
            (offset, None)
        } else if is_bounded {
            is_done = true;
            if offset == u32::MAX {
                (u32::MAX, None)
            } else {
                (core::cmp::min(offset + 1, code.len() as u32), Some(offset))
            }
        } else {
            let next_offset = if is_legacy {
                find_next_offset_legacy_unbounded(bitmask, code.len() as u32, offset)
            } else {
                extended_scan_find_next_offset(instruction_set, code, offset)
            };
            debug_assert!(
                next_offset as usize == code.len() || !is_legacy || get_bit_for_offset(bitmask, code.len(), next_offset),
                "bit at {offset} is zero"
            );
            (next_offset, Some(offset))
        };

        Self {
            code,
            bitmask,
            offset,
            invalid_offset,
            is_bounded,
            is_done,
            instruction_set,
        }
    }

    #[inline]
    pub fn offset(&self) -> u32 {
        self.invalid_offset.unwrap_or(self.offset)
    }

    #[inline]
    pub fn visit<T>(&mut self, visitor: &mut T) -> Option<<T as InstructionVisitor>::ReturnTy>
    where
        T: InstructionVisitor,
    {
        // TODO: Make this directly dispatched?
        Some(self.next()?.visit(visitor))
    }

    #[inline]
    pub fn visit_parsing<T>(&mut self, visitor: &mut T) -> Option<<T as ParsingVisitor>::ReturnTy>
    where
        T: ParsingVisitor,
    {
        Some(self.next()?.visit_parsing(visitor))
    }
}

impl<'a, I> Iterator for Instructions<'a, I>
where
    I: InstructionSet,
{
    type Item = ParsedInstruction;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(offset) = self.invalid_offset.take() {
            return Some(ParsedInstruction {
                kind: Instruction::invalid,
                offset: ProgramCounter(offset),
                next_offset: ProgramCounter(self.offset),
            });
        }

        if self.is_done || self.offset as usize >= self.code.len() {
            return None;
        }

        if !self.instruction_set.is_legacy() {
            self.next_extended()
        } else {
            self.next_legacy()
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.code.len() - core::cmp::min(self.offset() as usize, self.code.len())))
    }
}

impl<'a, I> Instructions<'a, I>
where
    I: InstructionSet,
{
    fn next_legacy(&mut self) -> Option<ParsedInstruction> {
        let offset = self.offset;
        debug_assert!(get_bit_for_offset(self.bitmask, self.code.len(), offset), "bit at {offset} is zero");

        let (next_offset, instruction, is_next_instruction_invalid) =
            parse_instruction_legacy(self.instruction_set, self.code, self.bitmask, self.offset);

        debug_assert!(next_offset > self.offset);

        if !is_next_instruction_invalid {
            self.offset = next_offset;
            debug_assert!(
                self.offset as usize == self.code.len() || get_bit_for_offset(self.bitmask, self.code.len(), self.offset),
                "bit at {} is zero",
                self.offset
            );
        } else {
            if next_offset as usize == self.code.len() {
                self.offset = self.code.len() as u32 + 1;
            } else if self.is_bounded {
                self.is_done = true;
                self.offset = self.code.len() as u32;
            } else {
                self.offset = find_next_offset_legacy_unbounded(self.bitmask, self.code.len() as u32, next_offset);
                debug_assert!(
                    self.offset as usize == self.code.len() || get_bit_for_offset(self.bitmask, self.code.len(), self.offset),
                    "bit at {} is zero",
                    self.offset
                );
            }

            self.invalid_offset = Some(next_offset);
        }

        Some(ParsedInstruction {
            kind: instruction,
            offset: ProgramCounter(offset),
            next_offset: ProgramCounter(next_offset),
        })
    }

    fn next_extended(&mut self) -> Option<ParsedInstruction> {
        let offset = self.offset;
        let (instruction, next_offset) = parse_raw_extended(
            self.code,
            cast(offset).to_usize(),
            end_of_macro_block(cast(offset).to_usize(), self.code.len()),
            self.instruction_set.raw_opcode_table(),
            |raw_opcode, chunk, offset, length| {
                self.instruction_set
                    .parse_instruction(cast(raw_opcode).to_usize(), chunk, cast(offset).to_u32_or_debug_panic(), length)
            },
        );

        let next_offset = cast(next_offset).to_u32_or_debug_panic();
        self.offset = next_offset;

        Some(ParsedInstruction {
            kind: instruction,
            offset: ProgramCounter(offset),
            next_offset: ProgramCounter(next_offset),
        })
    }
}

#[test]
fn test_instructions_iterator_with_implicit_trap() {
    let opcode_fallthrough = ISA_Latest32.opcode_to_raw(Opcode::fallthrough, 0).unwrap().0 as u8;
    let code = [opcode_fallthrough];
    for is_bounded in [false, true] {
        let mut i = Instructions::new(ISA_Latest32, &code, &[0b00000001], 0, is_bounded);
        assert_eq!(
            i.next(),
            Some(ParsedInstruction {
                kind: Instruction::fallthrough,
                offset: ProgramCounter(0),
                next_offset: ProgramCounter(1),
            })
        );

        assert_eq!(
            i.next(),
            Some(ParsedInstruction {
                kind: Instruction::invalid,
                offset: ProgramCounter(1),
                next_offset: ProgramCounter(2),
            })
        );

        assert_eq!(i.next(), None);
    }
}

#[test]
fn test_instructions_iterator_without_implicit_trap() {
    let opcode_trap = ISA_Latest32.opcode_to_raw(Opcode::trap, 0).unwrap().0 as u8;
    let code = [opcode_trap];
    for is_bounded in [false, true] {
        let mut i = Instructions::new(ISA_Latest32, &code, &[0b00000001], 0, is_bounded);
        assert_eq!(
            i.next(),
            Some(ParsedInstruction {
                kind: Instruction::trap,
                offset: ProgramCounter(0),
                next_offset: ProgramCounter(1),
            })
        );

        assert_eq!(i.next(), None);
    }
}

#[test]
fn test_instructions_iterator_very_long_bitmask_bounded() {
    let mut code = [0_u8; 64];
    code[0] = ISA_Latest32.opcode_to_raw(Opcode::fallthrough, 0).unwrap().0 as u8;
    let mut bitmask = [0_u8; 8];
    bitmask[0] = 0b00000001;
    bitmask[7] = 0b10000000;

    let mut i = Instructions::new(ISA_Latest32, &code, &bitmask, 0, true);
    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::fallthrough,
            offset: ProgramCounter(0),
            next_offset: ProgramCounter(25),
        })
    );

    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::invalid,
            offset: ProgramCounter(25),
            next_offset: ProgramCounter(64),
        })
    );

    assert_eq!(i.next(), None);
}

#[test]
fn test_instructions_iterator_very_long_bitmask_unbounded() {
    let mut code = [0_u8; 64];
    code[0] = ISA_Latest32.opcode_to_raw(Opcode::fallthrough, 0).unwrap().0 as u8;
    let mut bitmask = [0_u8; 8];
    bitmask[0] = 0b00000001;
    bitmask[7] = 0b10000000;

    let mut i = Instructions::new(ISA_Latest32, &code, &bitmask, 0, false);
    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::fallthrough,
            offset: ProgramCounter(0),
            next_offset: ProgramCounter(25),
        })
    );

    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::invalid,
            offset: ProgramCounter(25),
            next_offset: ProgramCounter(63),
        })
    );

    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::trap,
            offset: ProgramCounter(63),
            next_offset: ProgramCounter(64),
        })
    );

    assert_eq!(i.next(), None);
}

#[test]
fn test_instructions_iterator_start_at_invalid_offset_bounded() {
    let opcode_trap = ISA_Latest32.opcode_to_raw(Opcode::trap, 0).unwrap().0 as u8;
    let code = [opcode_trap; 8];
    let mut i = Instructions::new(ISA_Latest32, &code, &[0b10000001], 1, true);
    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::invalid,
            offset: ProgramCounter(1),
            // Since a bounded iterator doesn't scan forward it just assumes the next offset.
            next_offset: ProgramCounter(2),
        })
    );

    assert_eq!(i.next(), None);
}

#[test]
fn test_instructions_iterator_start_at_invalid_offset_unbounded() {
    let opcode_trap = ISA_Latest32.opcode_to_raw(Opcode::trap, 0).unwrap().0 as u8;
    let code = [opcode_trap; 8];
    let mut i = Instructions::new(ISA_Latest32, &code, &[0b10000001], 1, false);
    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::invalid,
            offset: ProgramCounter(1),
            next_offset: ProgramCounter(7),
        })
    );

    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::trap,
            offset: ProgramCounter(7),
            next_offset: ProgramCounter(8),
        })
    );

    assert_eq!(i.next(), None);
}

#[test]
fn test_instructions_iterator_emits_an_injected_invalid_instruction_if_bounded_and_ends_with_a_trap() {
    let opcode_trap = ISA_Latest32.opcode_to_raw(Opcode::trap, 0).unwrap().0 as u8;
    let code = [opcode_trap; 32];
    let bitmask = [0b00000001, 0b00000000, 0b00000000, 0b00000100];
    let mut i = Instructions::new(ISA_Latest32, &code, &bitmask, 0, true);
    assert_eq!(i.offset(), 0);
    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::trap,
            offset: ProgramCounter(0),
            next_offset: ProgramCounter(25)
        })
    );
    assert_eq!(i.offset(), 25);
    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::invalid,
            offset: ProgramCounter(25),
            next_offset: ProgramCounter(32)
        })
    );
    assert_eq!(i.next(), None);
}

#[test]
fn test_instructions_iterator_emits_an_injected_invalid_instruction_if_unbounded_and_ends_with_a_trap() {
    let opcode_trap = ISA_Latest32.opcode_to_raw(Opcode::trap, 0).unwrap().0 as u8;
    let code = [opcode_trap; 32];
    let bitmask = [0b00000001, 0b00000000, 0b00000000, 0b00000100];
    let mut i = Instructions::new(ISA_Latest32, &code, &bitmask, 0, false);
    assert_eq!(i.offset(), 0);
    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::trap,
            offset: ProgramCounter(0),
            next_offset: ProgramCounter(25)
        })
    );
    assert_eq!(i.offset(), 25);
    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::invalid,
            offset: ProgramCounter(25),
            next_offset: ProgramCounter(26)
        })
    );
    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::trap,
            offset: ProgramCounter(26),
            next_offset: ProgramCounter(32)
        })
    );
    assert_eq!(i.next(), None);
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EstimateInterpreterMemoryUsageArgs {
    UnboundedCache {
        instruction_count: u32,
        basic_block_count: u32,
        page_size: u32,
    },
    BoundedCache {
        instruction_count: u32,
        basic_block_count: u32,
        max_cache_size_bytes: u32,
        max_block_size: u32,
        page_size: u32,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ProgramMemoryInfo {
    pub baseline_ram_consumption: u32,
    pub purgeable_ram_consumption: u32,
}

#[derive(Clone)]
#[non_exhaustive]
pub struct ProgramParts {
    pub isa: InstructionSetKind,
    pub ro_data_size: u32,
    pub rw_data_size: u32,
    pub stack_size: u32,

    pub ro_data: ArcBytes,
    pub rw_data: ArcBytes,
    pub code_and_jump_table: ArcBytes,
    pub import_offsets: ArcBytes,
    pub import_symbols: ArcBytes,
    pub exports: ArcBytes,

    pub debug_strings: ArcBytes,
    pub debug_line_program_ranges: ArcBytes,
    pub debug_line_programs: ArcBytes,

    pub metadata_hash: ArcBytes,
}

impl ProgramParts {
    pub fn empty(isa: InstructionSetKind) -> Self {
        Self {
            isa,
            ro_data_size: 0,
            rw_data_size: 0,
            stack_size: 0,

            ro_data: Default::default(),
            rw_data: Default::default(),
            code_and_jump_table: Default::default(),
            import_offsets: Default::default(),
            import_symbols: Default::default(),
            exports: Default::default(),

            debug_strings: Default::default(),
            debug_line_program_ranges: Default::default(),
            debug_line_programs: Default::default(),

            metadata_hash: Default::default(),
        }
    }

    pub fn from_bytes(blob: ArcBytes) -> Result<Self, ProgramParseError> {
        if !blob.starts_with(&BLOB_MAGIC) {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "blob doesn't start with the expected magic bytes",
            )));
        }

        let mut reader = Reader {
            blob: &blob,
            position: BLOB_MAGIC.len(),
        };

        let blob_version = reader.read_byte()?;
        let Some(isa) = InstructionSetKind::from_blob_version(blob_version) else {
            return Err(ProgramParseError(ProgramParseErrorKind::UnsupportedVersion {
                version: blob_version,
            }));
        };

        let blob_len = BlobLen::from_le_bytes(reader.read_slice(BLOB_LEN_SIZE)?.try_into().unwrap());
        if blob_len != blob.len() as u64 {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "blob size doesn't match the blob length metadata",
            )));
        }

        let mut parts = ProgramParts::empty(isa);
        let mut section = reader.read_byte()?;
        if section == SECTION_MEMORY_CONFIG {
            let section_length = reader.read_varint()?;
            let position = reader.position;
            parts.ro_data_size = reader.read_varint()?;
            parts.rw_data_size = reader.read_varint()?;
            parts.stack_size = reader.read_varint()?;
            if position + section_length as usize != reader.position {
                return Err(ProgramParseError(ProgramParseErrorKind::Other(
                    "the memory config section contains more data than expected",
                )));
            }
            section = reader.read_byte()?;
        }

        parts.ro_data = reader.read_section_as_bytes(&mut section, SECTION_RO_DATA)?;
        parts.rw_data = reader.read_section_as_bytes(&mut section, SECTION_RW_DATA)?;

        if section == SECTION_IMPORTS {
            let section_length = reader.read_varint()? as usize;
            let section_start = reader.position;
            let import_count = reader.read_varint()?;
            if import_count > VM_MAXIMUM_IMPORT_COUNT {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("too many imports")));
            }

            let Some(import_offsets_size) = import_count.checked_mul(4) else {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the imports section is invalid")));
            };

            parts.import_offsets = reader.read_slice_as_bytes(import_offsets_size as usize)?;
            let Some(import_symbols_size) = section_length.checked_sub(reader.position - section_start) else {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the imports section is invalid")));
            };

            parts.import_symbols = reader.read_slice_as_bytes(import_symbols_size)?;
            section = reader.read_byte()?;
        }

        parts.exports = reader.read_section_as_bytes(&mut section, SECTION_EXPORTS)?;
        parts.code_and_jump_table = reader.read_section_as_bytes(&mut section, SECTION_CODE_AND_JUMP_TABLE)?;
        parts.debug_strings = reader.read_section_as_bytes(&mut section, SECTION_OPT_DEBUG_STRINGS)?;
        parts.debug_line_programs = reader.read_section_as_bytes(&mut section, SECTION_OPT_DEBUG_LINE_PROGRAMS)?;
        parts.debug_line_program_ranges = reader.read_section_as_bytes(&mut section, SECTION_OPT_DEBUG_LINE_PROGRAM_RANGES)?;
        parts.metadata_hash = reader.read_section_as_bytes(&mut section, SECTION_OPT_METADATA_HASH)?;

        while (section & 0b10000000) != 0 {
            // We don't know this section, but it's optional, so just skip it.
            #[cfg(feature = "logging")]
            log::debug!("Skipping unsupported optional section: {}", section);
            let section_length = reader.read_varint()?;
            reader.skip(section_length as usize)?;
            section = reader.read_byte()?;
        }

        if section != SECTION_END_OF_FILE {
            return Err(ProgramParseError(ProgramParseErrorKind::UnexpectedSection {
                offset: reader.position - 1,
                section,
            }));
        }

        Ok(parts)
    }
}

impl ProgramBlob {
    /// Parses the blob length information from the given `raw_blob` bytes.
    ///
    /// Returns `None` if `raw_blob` doesn't contain enough bytes to read the length.
    pub fn blob_length(raw_blob: &[u8]) -> Option<BlobLen> {
        let end = BLOB_LEN_OFFSET + BLOB_LEN_SIZE;
        if raw_blob.len() < end {
            return None;
        }
        Some(BlobLen::from_le_bytes(raw_blob[BLOB_LEN_OFFSET..end].try_into().unwrap()))
    }

    /// Parses the given bytes into a program blob.
    pub fn parse(bytes: ArcBytes) -> Result<Self, ProgramParseError> {
        let blob_length = Self::blob_length(&bytes).ok_or(ProgramParseError(ProgramParseErrorKind::Other(
            "blob does not contain the blob length",
        )))?;
        let bytes = bytes.subslice(0..blob_length as usize);
        let parts = ProgramParts::from_bytes(bytes)?;
        Self::from_parts(parts)
    }

    /// Creates a program blob from parts.
    pub fn from_parts(parts: ProgramParts) -> Result<Self, ProgramParseError> {
        let mut blob = ProgramBlob {
            #[cfg(feature = "unique-id")]
            unique_id: 0,

            isa: parts.isa,

            ro_data_size: parts.ro_data_size,
            rw_data_size: parts.rw_data_size,
            stack_size: parts.stack_size,

            ro_data: parts.ro_data,
            rw_data: parts.rw_data,
            exports: parts.exports,
            import_symbols: parts.import_symbols,
            import_offsets: parts.import_offsets,
            code: Default::default(),
            jump_table: Default::default(),
            jump_table_entry_size: Default::default(),
            bitmask: Default::default(),

            debug_strings: parts.debug_strings,
            debug_line_program_ranges: parts.debug_line_program_ranges,
            debug_line_programs: parts.debug_line_programs,

            metadata_hash: parts.metadata_hash,
        };

        if blob.ro_data.len() > blob.ro_data_size as usize {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "size of the read-only data payload exceeds the declared size of the section",
            )));
        }

        if blob.rw_data.len() > blob.rw_data_size as usize {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "size of the read-write data payload exceeds the declared size of the section",
            )));
        }

        if parts.code_and_jump_table.is_empty() {
            return Err(ProgramParseError(ProgramParseErrorKind::Other("no code found")));
        }

        {
            let mut reader = Reader {
                blob: &parts.code_and_jump_table,
                position: 0,
            };

            let initial_position = reader.position;
            let jump_table_entry_count = reader.read_varint()?;
            if jump_table_entry_count > VM_MAXIMUM_JUMP_TABLE_ENTRIES {
                return Err(ProgramParseError(ProgramParseErrorKind::Other(
                    "the jump table section is too long",
                )));
            }

            let jump_table_entry_size = reader.read_byte()?;
            let legacy_code_length = if blob.isa.is_legacy() { Some(reader.read_varint()?) } else { None };

            if !matches!(jump_table_entry_size, 0..=4) {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("invalid jump table entry size")));
            }

            let Some(jump_table_length) = jump_table_entry_count.checked_mul(u32::from(jump_table_entry_size)) else {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the jump table is too long")));
            };

            blob.jump_table_entry_size = jump_table_entry_size;
            blob.jump_table = reader.read_slice_as_bytes(jump_table_length as usize)?;

            let code_length = match legacy_code_length {
                Some(code_length) => cast(code_length).to_usize(),
                None => parts.code_and_jump_table.len() - (reader.position - initial_position),
            };

            if code_length > cast(VM_MAXIMUM_CODE_SIZE).to_usize() {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the code section is too long")));
            }

            blob.code = reader.read_slice_as_bytes(code_length)?;

            if blob.code.len() > (i32::MAX as usize) {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the program blob is too large")));
            }

            if blob.isa.is_legacy() {
                let bitmask_length = parts.code_and_jump_table.len() - (reader.position - initial_position);
                blob.bitmask = reader.read_slice_as_bytes(bitmask_length)?;

                let mut expected_bitmask_length = blob.code.len() / 8;
                let is_bitmask_padded = blob.code.len() % 8 != 0;
                expected_bitmask_length += usize::from(is_bitmask_padded);

                if blob.bitmask.len() != expected_bitmask_length {
                    return Err(ProgramParseError(ProgramParseErrorKind::Other(
                        "the bitmask length doesn't match the code length",
                    )));
                }

                if is_bitmask_padded {
                    let last_byte = *blob.bitmask.last().unwrap();
                    let padding_bits = blob.bitmask.len() * 8 - blob.code.len();
                    let padding_mask = ((0b10000000_u8 as i8) >> (padding_bits - 1)) as u8;
                    if last_byte & padding_mask != 0 {
                        return Err(ProgramParseError(ProgramParseErrorKind::Other(
                            "the bitmask is padded with non-zero bits",
                        )));
                    }
                }
            }
        }

        #[cfg(feature = "unique-id")]
        {
            static ID_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
            blob.unique_id = ID_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }

        Ok(blob)
    }

    #[cfg(feature = "unique-id")]
    /// Returns an unique ID of the program blob.
    ///
    /// This is an automatically incremented counter every time a `ProgramBlob` is created.
    pub fn unique_id(&self) -> u64 {
        self.unique_id
    }

    /// Returns the instruction set of this program blob.
    pub fn isa(&self) -> InstructionSetKind {
        self.isa
    }

    /// Returns whether the blob contains a 64-bit program.
    pub fn is_64_bit(&self) -> bool {
        self.isa.is_64_bit()
    }

    /// Returns the metadata hash embedded in the blob, or an empty slice if none is present.
    pub fn metadata_hash(&self) -> &[u8] {
        &self.metadata_hash
    }

    /// Calculates an unique hash of the program blob.
    pub fn unique_hash(&self, include_debug: bool) -> crate::hasher::Hash {
        let ProgramBlob {
            #[cfg(feature = "unique-id")]
                unique_id: _,
            isa,
            ro_data_size,
            rw_data_size,
            stack_size,
            ro_data,
            rw_data,
            code,
            jump_table,
            jump_table_entry_size,
            bitmask,
            import_offsets,
            import_symbols,
            exports,
            debug_strings,
            debug_line_program_ranges,
            debug_line_programs,
            metadata_hash: _,
        } = self;

        let mut hasher = crate::hasher::Hasher::new();

        hasher.update_u32_array([
            1_u32, // VERSION
            *isa as u32,
            *ro_data_size,
            *rw_data_size,
            *stack_size,
            ro_data.len() as u32,
            rw_data.len() as u32,
            code.len() as u32,
            jump_table.len() as u32,
            u32::from(*jump_table_entry_size),
            bitmask.len() as u32,
            import_offsets.len() as u32,
            import_symbols.len() as u32,
            exports.len() as u32,
        ]);

        hasher.update(ro_data);
        hasher.update(rw_data);
        hasher.update(code);
        hasher.update(jump_table);
        hasher.update(bitmask);
        hasher.update(import_offsets);
        hasher.update(import_symbols);
        hasher.update(exports);

        if include_debug {
            hasher.update_u32_array([
                debug_strings.len() as u32,
                debug_line_program_ranges.len() as u32,
                debug_line_programs.len() as u32,
            ]);

            hasher.update(debug_strings);
            hasher.update(debug_line_program_ranges);
            hasher.update(debug_line_programs);
        }

        hasher.finalize()
    }

    /// Returns the contents of the read-only data section.
    ///
    /// This only covers the initial non-zero portion of the section; use `ro_data_size` to get the full size.
    pub fn ro_data(&self) -> &[u8] {
        &self.ro_data
    }

    /// Returns an Arc of the read-only data section.
    pub fn ro_data_arc(&self) -> &ArcBytes {
        &self.ro_data
    }

    /// Returns the size of the read-only data section.
    ///
    /// This can be larger than the length of `ro_data`, in which case the rest of the space is assumed to be filled with zeros.
    pub fn ro_data_size(&self) -> u32 {
        self.ro_data_size
    }

    /// Returns the contents of the read-write data section.
    ///
    /// This only covers the initial non-zero portion of the section; use `rw_data_size` to get the full size.
    pub fn rw_data(&self) -> &[u8] {
        &self.rw_data
    }

    /// Returns an Arc of the read-write data section.
    pub fn rw_data_arc(&self) -> &ArcBytes {
        &self.rw_data
    }

    /// Returns the size of the read-write data section.
    ///
    /// This can be larger than the length of `rw_data`, in which case the rest of the space is assumed to be filled with zeros.
    pub fn rw_data_size(&self) -> u32 {
        self.rw_data_size
    }

    /// Returns the initial size of the stack.
    pub fn stack_size(&self) -> u32 {
        self.stack_size
    }

    /// Returns the program code in its raw form.
    pub fn code(&self) -> &[u8] {
        &self.code
    }

    #[cfg(feature = "export-internals-for-testing")]
    #[doc(hidden)]
    pub fn set_code(&mut self, code: ArcBytes) {
        self.code = code;
    }

    /// Returns the code bitmask in its raw form.
    pub fn bitmask(&self) -> &[u8] {
        &self.bitmask
    }

    #[cfg(feature = "export-internals-for-testing")]
    #[doc(hidden)]
    pub fn set_bitmask(&mut self, bitmask: ArcBytes) {
        self.bitmask = bitmask;
    }

    pub fn imports(&self) -> Imports {
        Imports {
            offsets: &self.import_offsets,
            symbols: &self.import_symbols,
        }
    }

    /// Returns an iterator over program exports.
    pub fn exports(&self) -> impl Iterator<Item = ProgramExport<&[u8]>> + Clone {
        #[derive(Clone)]
        enum State {
            Uninitialized,
            Pending(u32),
            Finished,
        }

        #[derive(Clone)]
        struct ExportIterator<'a> {
            state: State,
            reader: Reader<'a, [u8]>,
        }

        impl<'a> Iterator for ExportIterator<'a> {
            type Item = ProgramExport<&'a [u8]>;
            fn next(&mut self) -> Option<Self::Item> {
                let remaining = match core::mem::replace(&mut self.state, State::Finished) {
                    State::Uninitialized => self.reader.read_varint().ok()?,
                    State::Pending(remaining) => remaining,
                    State::Finished => return None,
                };

                if remaining == 0 {
                    return None;
                }

                let target_code_offset = self.reader.read_varint().ok()?;
                let symbol = self.reader.read_bytes_with_length().ok()?;
                let export = ProgramExport {
                    program_counter: ProgramCounter(target_code_offset),
                    symbol: ProgramSymbol::new(symbol),
                };

                self.state = State::Pending(remaining - 1);
                Some(export)
            }
        }

        ExportIterator {
            state: if !self.exports.is_empty() {
                State::Uninitialized
            } else {
                State::Finished
            },
            reader: Reader {
                blob: &self.exports,
                position: 0,
            },
        }
    }

    /// Visits every instruction in the program.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn visit<T>(&self, dispatch_table: T, visitor: &mut T::State)
    where
        T: OpcodeVisitor<ReturnTy = ()>,
    {
        visitor_run(visitor, self, dispatch_table);
    }

    #[inline]
    pub fn instructions(&self) -> Instructions<InstructionSetKind> {
        self.instructions_with_isa(self.isa)
    }

    #[inline]
    pub fn instructions_bounded_at(&self, offset: ProgramCounter) -> Instructions<InstructionSetKind> {
        self.instructions_bounded_at_with_isa(self.isa, offset)
    }

    /// Returns an iterator over all of the instructions in the program.
    ///
    /// WARNING: this is unbounded and has O(n) complexity; just creating this iterator can iterate over the whole program, even if `next` is never called!
    #[inline]
    pub fn instructions_with_isa<I>(&self, instruction_set: I) -> Instructions<I>
    where
        I: InstructionSet,
    {
        Instructions::new_unbounded(instruction_set, self.code(), self.bitmask(), 0)
    }

    /// Returns an interator over instructions starting at a given offset.
    ///
    /// This iterator is bounded and has O(1) complexity.
    #[inline]
    pub fn instructions_bounded_at_with_isa<I>(&self, instruction_set: I, offset: ProgramCounter) -> Instructions<I>
    where
        I: InstructionSet,
    {
        Instructions::new_bounded(instruction_set, self.code(), self.bitmask(), offset.0)
    }

    /// Same as [`Self::instructions_bounded_at`], but assumes `offset` is a known instruction boundary
    /// (e.g. it was validated with `is_jump_target_valid`), skipping the boundary check.
    ///
    /// Calling this with an offset which is *not* an instruction boundary may decode in a way
    /// which disagrees with a linear decode of the program.
    #[inline]
    pub fn instructions_bounded_at_known_boundary(&self, offset: ProgramCounter) -> Instructions<InstructionSetKind> {
        Instructions::new_bounded_known_boundary(self.isa, self.code(), self.bitmask(), offset.0)
    }

    /// Returns whether the code of the module is well formed. Has worst-case O(n) complexity.
    pub fn validate_code_with_isa<I>(&self, instruction_set: I) -> Result<(), ProgramCounter>
    where
        I: InstructionSet,
    {
        for instruction in self.instructions_bounded_at_with_isa(instruction_set, ProgramCounter(0)) {
            if matches!(instruction.kind, Instruction::invalid) {
                return Err(instruction.offset);
            }
        }

        Ok(())
    }

    /// Returns whether the given program counter is a valid target for a jump.
    pub fn scan_is_jump_target_valid<I>(&self, instruction_set: I, target: ProgramCounter) -> bool
    where
        I: InstructionSet,
    {
        if instruction_set.is_legacy() {
            is_jump_target_valid_legacy(instruction_set, self.code(), self.bitmask(), target.0)
        } else {
            scan_is_jump_target_valid_extended(instruction_set, self.code(), target.0)
        }
    }

    /// Returns a jump table.
    pub fn jump_table(&self) -> JumpTable {
        JumpTable {
            blob: &self.jump_table,
            entry_size: u32::from(self.jump_table_entry_size),
        }
    }

    /// Returns the debug string for the given relative offset.
    pub fn get_debug_string(&self, offset: u32) -> Result<&str, ProgramParseError> {
        let mut reader = Reader {
            blob: &self.debug_strings,
            position: 0,
        };
        reader.skip(offset as usize)?;
        reader.read_string_with_length()
    }

    /// Returns the line program for the given instruction.
    pub fn get_debug_line_program_at(&self, program_counter: ProgramCounter) -> Result<Option<LineProgram>, ProgramParseError> {
        let program_counter = program_counter.0;
        if self.debug_line_program_ranges.is_empty() || self.debug_line_programs.is_empty() {
            return Ok(None);
        }

        if self.debug_line_programs[0] != VERSION_DEBUG_LINE_PROGRAM_V1 {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "the debug line programs section has an unsupported version",
            )));
        }

        const ENTRY_SIZE: usize = 12;

        let slice = &self.debug_line_program_ranges;
        if slice.len() % ENTRY_SIZE != 0 {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "the debug function ranges section has an invalid size",
            )));
        }

        let offset = binary_search(slice, ENTRY_SIZE, |xs| {
            let begin = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
            if program_counter < begin {
                return core::cmp::Ordering::Greater;
            }

            let end = u32::from_le_bytes([xs[4], xs[5], xs[6], xs[7]]);
            if program_counter >= end {
                return core::cmp::Ordering::Less;
            }

            core::cmp::Ordering::Equal
        });

        let Ok(offset) = offset else { return Ok(None) };

        let xs = &slice[offset..offset + ENTRY_SIZE];
        let index_begin = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
        let index_end = u32::from_le_bytes([xs[4], xs[5], xs[6], xs[7]]);
        let info_offset = u32::from_le_bytes([xs[8], xs[9], xs[10], xs[11]]);

        if program_counter < index_begin || program_counter >= index_end {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "binary search for function debug info failed",
            )));
        }

        let mut reader = Reader {
            blob: &self.debug_line_programs,
            position: 0,
        };

        reader.skip(info_offset as usize)?;

        Ok(Some(LineProgram {
            entry_index: offset / ENTRY_SIZE,
            region_counter: 0,
            blob: self,
            reader,
            is_finished: false,
            program_counter: index_begin,
            stack: Default::default(),
            stack_depth: 0,
            mutation_depth: 0,
        }))
    }

    pub fn get_frame_info_for<'a>(
        &'a self,
        program_counter: ProgramCounter,
        iteration_limit: Option<usize>,
    ) -> impl Iterator<Item = FrameInfo<'a>> {
        struct FrameInfoIter<'a> {
            program_counter: ProgramCounter,
            line_program: Option<LineProgram<'a>>,
            region_info: Option<RawRegionInfo>,
            current_frame: usize,
            iteration_limit: usize,
        }

        impl<'a> Iterator for FrameInfoIter<'a> {
            type Item = FrameInfo<'a>;
            fn next(&mut self) -> Option<Self::Item> {
                self.line_program.as_ref()?;

                loop {
                    if let Some(ref region_info) = self.region_info {
                        let line_program = self.line_program.as_ref()?;
                        let region_info = line_program.convert_region_info(region_info.clone());
                        if let Some(frame) = region_info.frames.get(self.current_frame) {
                            self.current_frame += 1;
                            return Some(FrameInfo {
                                blob: line_program.blob,
                                inner: frame.clone(),
                            });
                        }
                    }

                    let line_program = self.line_program.as_mut()?;
                    loop {
                        if self.iteration_limit == 0 {
                            return None;
                        }

                        self.iteration_limit -= 1;

                        let Ok(Some(region_info)) = line_program.raw_run(INSTRUCTION_LIMIT_PER_REGION) else {
                            self.iteration_limit = 0;
                            return None;
                        };

                        if !region_info.range.contains(&self.program_counter) {
                            continue;
                        }

                        self.region_info = Some(region_info);
                        self.current_frame = 0;
                        break;
                    }
                }
            }
        }

        let line_program = match self.get_debug_line_program_at(program_counter) {
            Ok(Some(line_program)) => Some(line_program),
            _ => None,
        };

        FrameInfoIter {
            program_counter,
            line_program,
            region_info: None,
            current_frame: 0,
            iteration_limit: iteration_limit.unwrap_or(self.debug_line_programs.len()),
        }
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn calculate_blob_length(&self) -> u64 {
        let ProgramBlob {
            #[cfg(feature = "unique-id")]
                unique_id: _,
            isa: _,
            ro_data_size: _,
            rw_data_size: _,
            stack_size: _,
            ro_data,
            rw_data,
            code,
            jump_table,
            jump_table_entry_size: _,
            bitmask,
            import_offsets,
            import_symbols,
            exports,
            debug_strings,
            debug_line_program_ranges,
            debug_line_programs,
            metadata_hash,
        } = self;

        let mut ranges = [
            ro_data.parent_address_range(),
            rw_data.parent_address_range(),
            code.parent_address_range(),
            jump_table.parent_address_range(),
            bitmask.parent_address_range(),
            import_offsets.parent_address_range(),
            import_symbols.parent_address_range(),
            exports.parent_address_range(),
            debug_strings.parent_address_range(),
            debug_line_program_ranges.parent_address_range(),
            debug_line_programs.parent_address_range(),
            metadata_hash.parent_address_range(),
        ];

        ranges.sort_unstable_by_key(|r| r.start);

        let mut blob_length = 0;
        let mut last_range = 0..0;
        for range in ranges {
            if range == last_range {
                continue;
            }
            blob_length += cast(range.len()).to_u64();
            last_range = range;
        }
        blob_length
    }

    #[cfg(feature = "alloc")]
    pub fn estimate_interpreter_memory_usage(&self, args: EstimateInterpreterMemoryUsageArgs) -> Result<ProgramMemoryInfo, &'static str> {
        let (page_size, instruction_count, basic_block_count) = match args {
            EstimateInterpreterMemoryUsageArgs::UnboundedCache {
                page_size,
                instruction_count,
                basic_block_count,
                ..
            } => (page_size, instruction_count, basic_block_count),
            EstimateInterpreterMemoryUsageArgs::BoundedCache {
                page_size,
                instruction_count,
                basic_block_count,
                ..
            } => (page_size, instruction_count, basic_block_count),
        };

        let cache_entry_count_upper_bound = cast(instruction_count).to_usize() + cast(basic_block_count).to_usize();
        let cache_size_upper_bound = interpreter_calculate_cache_size(cache_entry_count_upper_bound);

        let mut purgeable_ram_consumption = match args {
            EstimateInterpreterMemoryUsageArgs::UnboundedCache { .. } => cache_size_upper_bound,
            EstimateInterpreterMemoryUsageArgs::BoundedCache {
                max_cache_size_bytes,
                max_block_size,
                ..
            } => {
                let max_cache_size_bytes = cast(max_cache_size_bytes).to_usize();
                let cache_entry_count_hard_limit = cast(max_block_size).to_usize();
                let cache_bytes_hard_limit = interpreter_calculate_cache_size(cache_entry_count_hard_limit);
                if cache_bytes_hard_limit > max_cache_size_bytes {
                    return Err("maximum cache size is too small for the given max block size");
                }

                max_cache_size_bytes.min(cache_size_upper_bound)
            }
        };

        let code_length = self.code.len();
        purgeable_ram_consumption = purgeable_ram_consumption.saturating_add((code_length + 1) * INTERPRETER_FLATMAP_ENTRY_SIZE as usize);

        if !self.isa.is_legacy() {
            purgeable_ram_consumption = purgeable_ram_consumption.saturating_add(
                code_length.div_ceil(CODE_BLOCK_SIZE) * (core::mem::size_of::<CodeBlockBitmap>() + core::mem::size_of::<usize>()),
            );
        }

        let Ok(purgeable_ram_consumption) = u32::try_from(purgeable_ram_consumption) else {
            return Err("estimated interpreter cache size is too large");
        };

        let memory_map = MemoryMapBuilder::new(page_size)
            .ro_data_size(self.ro_data_size)
            .rw_data_size(self.rw_data_size)
            .stack_size(self.stack_size)
            .build()?;

        let blob_length = self.calculate_blob_length();
        let Ok(baseline_ram_consumption) = u32::try_from(
            blob_length
                .saturating_add(u64::from(memory_map.ro_data_size()))
                .saturating_sub(self.ro_data.len() as u64)
                .saturating_add(u64::from(memory_map.rw_data_size()))
                .saturating_sub(self.rw_data.len() as u64)
                .saturating_add(u64::from(memory_map.stack_size())),
        ) else {
            return Err("calculated baseline RAM consumption is too large");
        };

        Ok(ProgramMemoryInfo {
            baseline_ram_consumption,
            purgeable_ram_consumption,
        })
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_estimate_interpreter_memory_usage_accounts_for_the_jump_target_bitmaps() {
    fn estimate(isa: InstructionSetKind) -> (usize, usize) {
        let mut code = alloc::vec![asm::add_imm_64(Reg::A0, Reg::A0, 1); 2000];
        code.push(asm::trap());

        let mut builder = crate::writer::ProgramBlobBuilder::new(isa);
        builder.set_code(&code, &[]);
        let blob = ProgramBlob::parse(builder.into_vec().unwrap().into()).unwrap();
        let info = blob
            .estimate_interpreter_memory_usage(EstimateInterpreterMemoryUsageArgs::UnboundedCache {
                instruction_count: code.len() as u32,
                basic_block_count: 1,
                page_size: 0x4000,
            })
            .unwrap();

        let cache = interpreter_calculate_cache_size(code.len() + 1);
        let flat_map = (blob.code().len() + 1) * INTERPRETER_FLATMAP_ENTRY_SIZE as usize;
        (
            blob.code().len(),
            cast(info.purgeable_ram_consumption).to_usize() - cache - flat_map,
        )
    }

    assert_eq!(estimate(InstructionSetKind::ReviveV1).1, 0);

    let (code_length, extra) = estimate(InstructionSetKind::Latest64);
    assert!(code_length > CODE_BLOCK_SIZE);
    assert_eq!(
        extra,
        code_length.div_ceil(CODE_BLOCK_SIZE) * (core::mem::size_of::<CodeBlockBitmap>() + 8)
    );
}

#[cfg(feature = "alloc")]
#[test]
fn test_calculate_blob_length() {
    let mut builder = crate::writer::ProgramBlobBuilder::new(InstructionSetKind::Latest64);
    builder.set_code(&[Instruction::trap], &[]);
    let blob = builder.into_vec().unwrap();
    let parts = ProgramParts::from_bytes(blob.into()).unwrap();

    let big_blob = ArcBytes::from(alloc::vec![0; 1024]);
    let small_blob = ArcBytes::from(&parts.code_and_jump_table[..]);
    let parts = ProgramParts {
        ro_data: big_blob.subslice(10..20),
        ro_data_size: 24,
        rw_data: big_blob.subslice(24..28),
        rw_data_size: 4,
        code_and_jump_table: small_blob.clone(),
        debug_strings: small_blob.clone(),

        isa: InstructionSetKind::Latest64,
        stack_size: 0,
        import_offsets: Default::default(),
        import_symbols: Default::default(),
        exports: Default::default(),
        debug_line_program_ranges: Default::default(),
        debug_line_programs: Default::default(),
        metadata_hash: Default::default(),
    };

    let blob = ProgramBlob::from_parts(parts).unwrap();
    assert_eq!(
        blob.calculate_blob_length(),
        (big_blob.len() + small_blob.len()).try_into().unwrap()
    );
}

#[cfg(feature = "alloc")]
#[test]
fn test_jump_table_entry_width_with_interior_zero_byte() {
    const TARGET_POSITION: u32 = 0x0100FB;

    let mut code = alloc::vec![Instruction::trap; TARGET_POSITION as usize];
    code.push(Instruction::fallthrough);

    let mut builder = crate::writer::ProgramBlobBuilder::new(InstructionSetKind::Latest64);
    builder.set_code(&code, &[TARGET_POSITION]);
    let blob = ProgramBlob::parse(builder.into_vec().unwrap().into()).unwrap();
    assert_eq!(blob.jump_table().get_by_index(0), Some(ProgramCounter(TARGET_POSITION)));
}

#[cfg(feature = "alloc")]
#[test]
fn test_from_parts_rejects_non_canonical_varints() {
    for code_and_jump_table in [
        // |j| = [80, 01]
        alloc::vec![0x80, 0x01, 0x01, 0x00, 0x00],
        // |j| = [c0, 01, 00]
        alloc::vec![0xc0, 0x01, 0x00, 0x01, 0x00, 0x00],
        // |j| = [e0, 01, 00, 00]
        alloc::vec![0xe0, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00],
    ] {
        let mut parts = ProgramParts::empty(InstructionSetKind::Latest64);
        parts.code_and_jump_table = ArcBytes::from(code_and_jump_table);
        assert!(ProgramBlob::from_parts(parts).is_err());
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_from_parts_rejects_varints_outside_u32() {
    let mut parts = ProgramParts::empty(InstructionSetKind::Latest64);
    parts.code_and_jump_table = ArcBytes::from(alloc::vec![0xf1, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
    assert!(ProgramBlob::from_parts(parts).is_err());
}

#[cfg(feature = "alloc")]
#[test]
fn test_from_parts_accepts_canonical_varints() {
    // |j| = 1, z = 1, j = [0], c = [trap]
    let mut parts = ProgramParts::empty(InstructionSetKind::Latest64);
    parts.code_and_jump_table = ArcBytes::from(alloc::vec![0x01, 0x01, 0x00, 0x00]);
    let blob = ProgramBlob::from_parts(parts).unwrap();
    assert_eq!(blob.jump_table().len(), 1);
    assert_eq!(blob.instructions().count(), 1);
}

/// The source location.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SourceLocation<'a> {
    Path { path: &'a str },
    PathAndLine { path: &'a str, line: u32 },
    Full { path: &'a str, line: u32, column: u32 },
}

impl<'a> SourceLocation<'a> {
    /// The path to the original source file.
    pub fn path(&self) -> &'a str {
        match *self {
            Self::Path { path, .. } => path,
            Self::PathAndLine { path, .. } => path,
            Self::Full { path, .. } => path,
        }
    }

    /// The line in the original source file.
    pub fn line(&self) -> Option<u32> {
        match *self {
            Self::Path { .. } => None,
            Self::PathAndLine { line, .. } => Some(line),
            Self::Full { line, .. } => Some(line),
        }
    }

    /// The column in the original source file.
    pub fn column(&self) -> Option<u32> {
        match *self {
            Self::Path { .. } => None,
            Self::PathAndLine { .. } => None,
            Self::Full { column, .. } => Some(column),
        }
    }
}

impl<'a> core::fmt::Display for SourceLocation<'a> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            Self::Path { path } => fmt.write_str(path),
            Self::PathAndLine { path, line } => write!(fmt, "{}:{}", path, line),
            Self::Full { path, line, column } => write!(fmt, "{}:{}:{}", path, line, column),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum FrameKind {
    Enter,
    Call,
    Line,
}

pub struct FrameInfo<'a> {
    blob: &'a ProgramBlob,
    inner: LineProgramFrame,
}

impl<'a> FrameInfo<'a> {
    /// Returns the namespace of this location, if available.
    pub fn namespace(&self) -> Result<Option<&str>, ProgramParseError> {
        let namespace = self.blob.get_debug_string(self.inner.namespace_offset)?;
        if namespace.is_empty() {
            Ok(None)
        } else {
            Ok(Some(namespace))
        }
    }

    /// Returns the function name of location without the namespace, if available.
    pub fn function_name_without_namespace(&self) -> Result<Option<&str>, ProgramParseError> {
        let function_name = self.blob.get_debug_string(self.inner.function_name_offset)?;
        if function_name.is_empty() {
            Ok(None)
        } else {
            Ok(Some(function_name))
        }
    }

    /// Returns the offset into the debug strings section containing the source code path of this location, if available.
    pub fn path_debug_string_offset(&self) -> Option<u32> {
        if self.inner.path_offset == 0 {
            None
        } else {
            Some(self.inner.path_offset)
        }
    }

    /// Returns the source code path of this location, if available.
    pub fn path(&self) -> Result<Option<&str>, ProgramParseError> {
        let path = self.blob.get_debug_string(self.inner.path_offset)?;
        if path.is_empty() {
            Ok(None)
        } else {
            Ok(Some(path))
        }
    }

    /// Returns the source code line of this location, if available.
    pub fn line(&self) -> Option<u32> {
        if self.inner.line == 0 {
            None
        } else {
            Some(self.inner.line)
        }
    }

    /// Returns the source code column of this location, if available.
    pub fn column(&self) -> Option<u32> {
        if self.inner.column == 0 {
            None
        } else {
            Some(self.inner.column)
        }
    }

    pub fn kind(&self) -> FrameKind {
        self.inner.kind.unwrap_or(FrameKind::Line)
    }

    /// Returns the full name of the function.
    pub fn full_name(&'_ self) -> Result<impl core::fmt::Display + '_, ProgramParseError> {
        Ok(DisplayName {
            prefix: self.namespace()?.unwrap_or(""),
            suffix: self.function_name_without_namespace()?.unwrap_or(""),
        })
    }

    /// Returns the source location of where this frame comes from.
    pub fn location(&self) -> Result<Option<SourceLocation>, ProgramParseError> {
        if let Some(path) = self.path()? {
            if let Some(line) = self.line() {
                if let Some(column) = self.column() {
                    Ok(Some(SourceLocation::Full { path, line, column }))
                } else {
                    Ok(Some(SourceLocation::PathAndLine { path, line }))
                }
            } else {
                Ok(Some(SourceLocation::Path { path }))
            }
        } else {
            Ok(None)
        }
    }
}

/// Debug information about a given region of bytecode.
pub struct RegionInfo<'a> {
    entry_index: usize,
    blob: &'a ProgramBlob,
    range: Range<ProgramCounter>,
    frames: &'a [LineProgramFrame],
}

#[derive(Clone)]
struct RawRegionInfo {
    entry_index: usize,
    range: Range<ProgramCounter>,
    frame_count: usize,
}

impl<'a> RegionInfo<'a> {
    /// Returns the entry index of this region info within the parent line program object.
    pub fn entry_index(&self) -> usize {
        self.entry_index
    }

    /// The range of instructions this region covers.
    pub fn instruction_range(&self) -> Range<ProgramCounter> {
        self.range.clone()
    }

    /// Returns an iterator over the frames this region covers.
    pub fn frames(&self) -> impl ExactSizeIterator<Item = FrameInfo> {
        self.frames.iter().map(|inner| FrameInfo {
            blob: self.blob,
            inner: inner.clone(),
        })
    }
}

#[derive(Clone, Default)]
struct LineProgramFrame {
    kind: Option<FrameKind>,
    namespace_offset: u32,
    function_name_offset: u32,
    path_offset: u32,
    line: u32,
    column: u32,
}

/// The default maximum number of line program opcodes parsed for a single region.
const INSTRUCTION_LIMIT_PER_REGION: usize = 512;

/// A configuration for how a [`LineProgram`] is run.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct LineProgramConfig {
    /// The maximum number of line program opcodes parsed for a single region.
    ///
    /// Parsing fails once a region exceeds this many opcodes, which bounds the work
    /// a single region can trigger. Set it to [`usize::MAX`] to disable the limit.
    pub instruction_limit_per_region: usize,
}

impl Default for LineProgramConfig {
    fn default() -> Self {
        LineProgramConfig {
            instruction_limit_per_region: INSTRUCTION_LIMIT_PER_REGION,
        }
    }
}

/// A line program state machine.
pub struct LineProgram<'a> {
    entry_index: usize,
    region_counter: usize,
    blob: &'a ProgramBlob,
    reader: Reader<'a, ArcBytes>,
    is_finished: bool,
    program_counter: u32,
    // Support inline call stacks ~16 frames deep. Picked entirely arbitrarily.
    stack: [LineProgramFrame; 16],
    stack_depth: u32,
    mutation_depth: u32,
}

impl<'a> LineProgram<'a> {
    /// Returns the entry index of this line program object.
    pub fn entry_index(&self) -> usize {
        self.entry_index
    }

    /// Runs the line program until the next region becomes available, or until the program ends.
    pub fn run(&mut self) -> Result<Option<RegionInfo>, ProgramParseError> {
        self.run_with_config(LineProgramConfig::default())
    }

    /// Runs the line program until the next region becomes available, or until the program ends,
    /// using the provided `config` to control how the program is parsed.
    pub fn run_with_config(&mut self, config: LineProgramConfig) -> Result<Option<RegionInfo>, ProgramParseError> {
        match self.raw_run(config.instruction_limit_per_region) {
            Ok(Some(region_info)) => Ok(Some(self.convert_region_info(region_info))),
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn convert_region_info(&self, region_info: RawRegionInfo) -> RegionInfo {
        RegionInfo {
            entry_index: region_info.entry_index,
            blob: self.blob,
            range: region_info.range,
            frames: &self.stack[..region_info.frame_count],
        }
    }

    fn raw_run(&mut self, instruction_limit_per_region: usize) -> Result<Option<RawRegionInfo>, ProgramParseError> {
        struct SetTrueOnDrop<'a>(&'a mut bool);
        impl<'a> Drop for SetTrueOnDrop<'a> {
            fn drop(&mut self) {
                *self.0 = true;
            }
        }

        if self.is_finished {
            return Ok(None);
        }

        let mark_as_finished_on_drop = SetTrueOnDrop(&mut self.is_finished);
        for _ in 0..instruction_limit_per_region {
            let byte = match self.reader.read_byte() {
                Ok(byte) => byte,
                Err(error) => {
                    return Err(error);
                }
            };

            let Some(opcode) = LineProgramOp::from_u8(byte) else {
                return Err(ProgramParseError(ProgramParseErrorKind::Other(
                    "found an unrecognized line program opcode",
                )));
            };

            let (count, stack_depth) = match opcode {
                LineProgramOp::FinishProgram => {
                    return Ok(None);
                }
                LineProgramOp::SetMutationDepth => {
                    self.mutation_depth = self.reader.read_varint()?;
                    continue;
                }
                LineProgramOp::SetKindEnter => {
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.kind = Some(FrameKind::Enter);
                    }
                    continue;
                }
                LineProgramOp::SetKindCall => {
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.kind = Some(FrameKind::Call);
                    }
                    continue;
                }
                LineProgramOp::SetKindLine => {
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.kind = Some(FrameKind::Line);
                    }
                    continue;
                }
                LineProgramOp::SetNamespace => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.namespace_offset = value;
                    }
                    continue;
                }
                LineProgramOp::SetFunctionName => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.function_name_offset = value;
                    }
                    continue;
                }
                LineProgramOp::SetPath => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.path_offset = value;
                    }
                    continue;
                }
                LineProgramOp::SetLine => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.line = value;
                    }
                    continue;
                }
                LineProgramOp::SetColumn => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.column = value;
                    }
                    continue;
                }
                LineProgramOp::SetStackDepth => {
                    self.stack_depth = self.reader.read_varint()?;
                    continue;
                }
                LineProgramOp::IncrementLine => {
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.line += 1;
                    }
                    continue;
                }
                LineProgramOp::AddLine => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.line = frame.line.wrapping_add(value);
                    }
                    continue;
                }
                LineProgramOp::SubLine => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.line = frame.line.wrapping_sub(value);
                    }
                    continue;
                }
                LineProgramOp::FinishInstruction => (1, self.stack_depth),
                LineProgramOp::FinishMultipleInstructions => {
                    let count = self.reader.read_varint()?;
                    (count, self.stack_depth)
                }
                LineProgramOp::FinishInstructionAndIncrementStackDepth => {
                    let depth = self.stack_depth;
                    self.stack_depth = self.stack_depth.saturating_add(1);
                    (1, depth)
                }
                LineProgramOp::FinishMultipleInstructionsAndIncrementStackDepth => {
                    let count = self.reader.read_varint()?;
                    let depth = self.stack_depth;
                    self.stack_depth = self.stack_depth.saturating_add(1);
                    (count, depth)
                }
                LineProgramOp::FinishInstructionAndDecrementStackDepth => {
                    let depth = self.stack_depth;
                    self.stack_depth = self.stack_depth.saturating_sub(1);
                    (1, depth)
                }
                LineProgramOp::FinishMultipleInstructionsAndDecrementStackDepth => {
                    let count = self.reader.read_varint()?;
                    let depth = self.stack_depth;
                    self.stack_depth = self.stack_depth.saturating_sub(1);
                    (count, depth)
                }
            };

            let range = ProgramCounter(self.program_counter)..ProgramCounter(self.program_counter + count);
            self.program_counter += count;

            core::mem::forget(mark_as_finished_on_drop);

            let entry_index = self.region_counter;
            self.region_counter += 1;
            return Ok(Some(RawRegionInfo {
                entry_index,
                range,
                frame_count: core::cmp::min(stack_depth as usize, self.stack.len()),
            }));
        }

        Err(ProgramParseError(ProgramParseErrorKind::Other(
            "found a line program with too many instructions",
        )))
    }
}

#[test]
fn test_default_line_program_config_uses_the_constant_limit() {
    assert_eq!(
        LineProgramConfig::default().instruction_limit_per_region,
        INSTRUCTION_LIMIT_PER_REGION
    );
}

#[cfg(feature = "alloc")]
#[test]
fn test_run_with_config_can_raise_the_instruction_limit() {
    // One region padded with exactly the default budget of non-finishing opcodes, so its
    // finishing opcode falls just past the budget and the default parse should give up.
    let mut line_programs = alloc::vec![VERSION_DEBUG_LINE_PROGRAM_V1];
    for _ in 0..INSTRUCTION_LIMIT_PER_REGION {
        line_programs.push(LineProgramOp::IncrementLine as u8);
    }
    line_programs.push(LineProgramOp::FinishInstruction as u8);
    line_programs.push(LineProgramOp::FinishProgram as u8);

    // A single range entry covering program counter 0, whose program starts right after the
    // one-byte version marker.
    let mut ranges = alloc::vec::Vec::new();
    ranges.extend_from_slice(&0_u32.to_le_bytes()); // program_counter_start
    ranges.extend_from_slice(&1_u32.to_le_bytes()); // program_counter_end
    ranges.extend_from_slice(&1_u32.to_le_bytes()); // info_offset (past the version marker)

    let mut builder = crate::writer::ProgramBlobBuilder::new(InstructionSetKind::Latest64);
    builder.set_code(&[Instruction::trap], &[]);
    builder.add_custom_section(SECTION_OPT_DEBUG_LINE_PROGRAMS, line_programs);
    builder.add_custom_section(SECTION_OPT_DEBUG_LINE_PROGRAM_RANGES, ranges);

    let blob = ProgramBlob::parse(builder.into_vec().unwrap().into()).unwrap();

    // The default limit rejects the over-long region, exactly as a runtime consumer would.
    let mut line_program = blob.get_debug_line_program_at(ProgramCounter(0)).unwrap().unwrap();
    let Err(error) = line_program.run() else {
        panic!("the default limit should reject the over-long region");
    };
    assert!(
        alloc::format!("{error}").contains("too many instructions"),
        "unexpected error: {error}"
    );

    // Raising the limit lets the same region parse: one region, then the program ends.
    let config = LineProgramConfig {
        instruction_limit_per_region: usize::MAX,
    };
    let mut line_program = blob.get_debug_line_program_at(ProgramCounter(0)).unwrap().unwrap();
    assert!(line_program.run_with_config(config).unwrap().is_some());
    assert!(line_program.run_with_config(config).unwrap().is_none());
}

struct DisplayName<'a> {
    prefix: &'a str,
    suffix: &'a str,
}

impl<'a> core::fmt::Display for DisplayName<'a> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self.prefix)?;
        if !self.prefix.is_empty() {
            fmt.write_str("::")?;
        }
        fmt.write_str(self.suffix)
    }
}

/// A binary search implementation which can work on chunks of items, and guarantees that it
/// will always return the first item if there are multiple identical consecutive items.
fn binary_search(slice: &[u8], chunk_size: usize, compare: impl Fn(&[u8]) -> core::cmp::Ordering) -> Result<usize, usize> {
    let mut size = slice.len() / chunk_size;
    if size == 0 {
        return Err(0);
    }

    let mut base = 0_usize;
    while size > 1 {
        let half = size / 2;
        let mid = base + half;
        let item = &slice[mid * chunk_size..(mid + 1) * chunk_size];
        match compare(item) {
            core::cmp::Ordering::Greater => {
                // The value we're looking for is to the left of the midpoint.
                size -= half;
            }
            core::cmp::Ordering::Less => {
                // The value we're looking for is to the right of the midpoint.
                size -= half;
                base = mid;
            }
            core::cmp::Ordering::Equal => {
                // We've found the value, but it might not be the first value.
                let previous_item = &slice[(mid - 1) * chunk_size..mid * chunk_size];
                if compare(previous_item) != core::cmp::Ordering::Equal {
                    // It is the first value.
                    return Ok(mid * chunk_size);
                }

                // It's not the first value. Let's continue.
                //
                // We could do a linear search here which in the average case
                // would probably be faster, but keeping it as a binary search
                // will avoid a worst-case O(n) scenario.
                size -= half;
            }
        }
    }

    let item = &slice[base * chunk_size..(base + 1) * chunk_size];
    let ord = compare(item);
    if ord == core::cmp::Ordering::Equal {
        Ok(base * chunk_size)
    } else {
        Err((base + usize::from(ord == core::cmp::Ordering::Less)) * chunk_size)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(20000))]
    #[allow(clippy::ignored_unit_patterns)]
    #[test]
    fn test_binary_search(needle: u8, mut xs: std::vec::Vec<u8>) {
        xs.sort();
        let binary_result = binary_search(&xs, 1, |slice| slice[0].cmp(&needle));
        let mut linear_result = Err(0);
        for (index, value) in xs.iter().copied().enumerate() {
            #[allow(clippy::comparison_chain)]
            if value == needle {
                linear_result = Ok(index);
                break;
            } else if value < needle {
                linear_result = Err(index + 1);
                continue;
            } else {
                break;
            }
        }

        assert_eq!(binary_result, linear_result, "linear search = {:?}, binary search = {:?}, needle = {}, xs = {:?}", linear_result, binary_result, needle, xs);
    }
}

/// The magic bytes with which every program blob must start with.
pub const BLOB_MAGIC: [u8; 4] = [b'P', b'V', b'M', b'\0'];

/// The blob length is the length of the blob itself encoded as an 64bit LE integer.
/// By embedding this metadata into the header, program blobs stay opaque,
/// however this information can still easily be retrieved.
/// Found at offset 5 after the magic bytes and version number.
pub type BlobLen = u64;
pub const BLOB_LEN_SIZE: usize = core::mem::size_of::<BlobLen>();
pub const BLOB_LEN_OFFSET: usize = BLOB_MAGIC.len() + 1;

pub const SECTION_MEMORY_CONFIG: u8 = 1;
pub const SECTION_RO_DATA: u8 = 2;
pub const SECTION_RW_DATA: u8 = 3;
pub const SECTION_IMPORTS: u8 = 4;
pub const SECTION_EXPORTS: u8 = 5;
pub const SECTION_CODE_AND_JUMP_TABLE: u8 = 6;
pub const SECTION_OPT_DEBUG_STRINGS: u8 = 128;
pub const SECTION_OPT_DEBUG_LINE_PROGRAMS: u8 = 129;
pub const SECTION_OPT_DEBUG_LINE_PROGRAM_RANGES: u8 = 130;
pub const SECTION_OPT_METADATA_HASH: u8 = 131;
pub const SECTION_END_OF_FILE: u8 = 0;

pub const VERSION_DEBUG_LINE_PROGRAM_V1: u8 = 1;

#[derive(Copy, Clone, Debug)]
pub enum LineProgramOp {
    FinishProgram = 0,
    SetMutationDepth = 1,
    SetKindEnter = 2,
    SetKindCall = 3,
    SetKindLine = 4,
    SetNamespace = 5,
    SetFunctionName = 6,
    SetPath = 7,
    SetLine = 8,
    SetColumn = 9,
    SetStackDepth = 10,
    IncrementLine = 11,
    AddLine = 12,
    SubLine = 13,
    FinishInstruction = 14,
    FinishMultipleInstructions = 15,
    FinishInstructionAndIncrementStackDepth = 16,
    FinishMultipleInstructionsAndIncrementStackDepth = 17,
    FinishInstructionAndDecrementStackDepth = 18,
    FinishMultipleInstructionsAndDecrementStackDepth = 19,
}

impl LineProgramOp {
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::FinishProgram),
            1 => Some(Self::SetMutationDepth),
            2 => Some(Self::SetKindEnter),
            3 => Some(Self::SetKindCall),
            4 => Some(Self::SetKindLine),
            5 => Some(Self::SetNamespace),
            6 => Some(Self::SetFunctionName),
            7 => Some(Self::SetPath),
            8 => Some(Self::SetLine),
            9 => Some(Self::SetColumn),
            10 => Some(Self::SetStackDepth),
            11 => Some(Self::IncrementLine),
            12 => Some(Self::AddLine),
            13 => Some(Self::SubLine),
            14 => Some(Self::FinishInstruction),
            15 => Some(Self::FinishMultipleInstructions),
            16 => Some(Self::FinishInstructionAndIncrementStackDepth),
            17 => Some(Self::FinishMultipleInstructionsAndIncrementStackDepth),
            18 => Some(Self::FinishInstructionAndDecrementStackDepth),
            19 => Some(Self::FinishMultipleInstructionsAndDecrementStackDepth),
            _ => None,
        }
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_instruction_formatting() {
    use crate::alloc::string::ToString;
    assert_eq!(self::asm::store_imm_indirect_u8(Reg::A0, 0, 2).to_string(), "u8 [a0] = 0x2");
    assert_eq!(self::asm::store_imm_indirect_u8(Reg::A0, 1, 2).to_string(), "u8 [a0 + 1] = 0x2");
    assert_eq!(self::asm::store_imm_indirect_u8(Reg::A0, -1, 2).to_string(), "u8 [a0 - 1] = 0x2");
}
