use crate::abi::{VM_CODE_ADDRESS_ALIGNMENT, VM_MAXIMUM_CODE_SIZE, VM_MAXIMUM_IMPORT_COUNT, VM_MAXIMUM_JUMP_TABLE_ENTRIES};
use crate::utils::ArcBytes;
use crate::varint::{read_simple_varint, read_varint, write_simple_varint, MAX_VARINT_LENGTH};
use core::fmt::Write;
use core::ops::Range;

#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct RawReg(u32);

impl Eq for RawReg {}
impl PartialEq for RawReg {
    fn eq(&self, rhs: &Self) -> bool {
        self.get() == rhs.get()
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

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
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
fn find_next_offset_unbounded(bitmask: &[u8], code_len: u32, mut offset: u32) -> u32 {
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
fn visitor_step_slow<T>(
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
        return (offset + 1, visitor_step_invalid_instruction(state, offset, opcode_visitor), true);
    }

    debug_assert!(code.len() <= u32::MAX as usize);
    debug_assert_eq!(bitmask.len(), (code.len() + 7) / 8);
    debug_assert!(offset as usize <= code.len());
    debug_assert!(get_bit_for_offset(bitmask, code.len(), offset), "bit at {offset} is zero");

    let (skip, mut is_next_instruction_invalid) = parse_bitmask_slow(bitmask, code.len(), offset);
    let chunk = &code[offset as usize..core::cmp::min(offset as usize + 17, code.len())];
    let opcode = chunk[0];

    if is_next_instruction_invalid && offset as usize + skip as usize + 1 >= code.len() {
        // This is the last instruction.
        if !opcode_visitor
            .instruction_set()
            .opcode_from_u8(opcode)
            .unwrap_or(Opcode::trap)
            .can_fallthrough()
        {
            // We can't fallthrough, so there's no need to inject a trap after this instruction.
            is_next_instruction_invalid = false;
        }
    }

    let mut t: [u8; 16] = [0; 16];
    t[..chunk.len() - 1].copy_from_slice(&chunk[1..]);
    let chunk = u128::from_le_bytes([
        t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], t[9], t[10], t[11], t[12], t[13], t[14], t[15],
    ]);

    debug_assert!(
        opcode_visitor.instruction_set().opcode_from_u8(opcode).is_some()
            || !is_jump_target_valid(opcode_visitor.instruction_set(), code, bitmask, offset + skip + 1)
    );

    (
        offset + skip + 1,
        opcode_visitor.dispatch(state, usize::from(opcode), chunk, offset, skip),
        is_next_instruction_invalid,
    )
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn visitor_step_fast<T>(
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
    debug_assert_eq!(bitmask.len(), (code.len() + 7) / 8);
    debug_assert!(offset as usize <= code.len());
    debug_assert!(get_bit_for_offset(bitmask, code.len(), offset), "bit at {offset} is zero");

    debug_assert!(offset as usize + 32 <= code.len());

    let Some(chunk) = code.get(offset as usize..offset as usize + 32) else {
        unreachable!()
    };
    let Some(skip) = parse_bitmask_fast(bitmask, offset) else {
        unreachable!()
    };
    let opcode = usize::from(chunk[0]);

    // NOTE: This should produce the same assembly as the unsafe `read_unaligned`.
    let chunk = u128::from_le_bytes([
        chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7], chunk[8], chunk[9], chunk[10], chunk[11], chunk[12],
        chunk[13], chunk[14], chunk[15], chunk[16],
    ]);

    debug_assert!(skip <= BITMASK_MAX);
    debug_assert!(
        opcode_visitor.instruction_set().opcode_from_u8(opcode as u8).is_some()
            || !is_jump_target_valid(opcode_visitor.instruction_set(), code, bitmask, offset + skip + 1)
    );
    let result = opcode_visitor.dispatch(state, opcode, chunk, offset, skip);

    let next_offset = offset + skip + 1;
    let is_next_instruction_invalid = skip == 24 && !get_bit_for_offset(bitmask, code.len(), next_offset);
    (next_offset, result, is_next_instruction_invalid)
}

#[cfg_attr(not(debug_assertions), inline(always))]
#[cold]
fn visitor_step_invalid_instruction<T>(state: &mut <T as OpcodeVisitor>::State, offset: u32, opcode_visitor: T) -> T::ReturnTy
where
    T: OpcodeVisitor,
{
    opcode_visitor.dispatch(state, INVALID_INSTRUCTION_INDEX as usize, 0, offset, 0)
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn visitor_step_runner<T, const FAST_PATH: bool>(
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
        visitor_step_fast(state, code, bitmask, offset, opcode_visitor)
    } else {
        visitor_step_slow(state, code, bitmask, offset, opcode_visitor)
    };

    offset = next_offset;
    if is_next_instruction_invalid {
        visitor_step_invalid_instruction(state, offset, opcode_visitor);
        if (offset as usize) < code.len() {
            let next_offset = find_next_offset_unbounded(bitmask, code.len() as u32, offset);
            debug_assert!(next_offset > offset);
            offset = next_offset;
        }
    }

    offset
}

// Having this be never inlined makes it easier to analyze the resulting assembly/machine code,
// and it also seems to make the code mariginally faster for some reason.
#[inline(never)]
fn visitor_run<T>(state: &mut <T as OpcodeVisitor>::State, blob: &ProgramBlob, opcode_visitor: T)
where
    T: OpcodeVisitor<ReturnTy = ()>,
{
    let code = blob.code();
    let bitmask = blob.bitmask();

    let mut offset = 0;
    if !get_bit_for_offset(bitmask, code.len(), 0) {
        visitor_step_invalid_instruction(state, 0, opcode_visitor);
        offset = find_next_offset_unbounded(bitmask, code.len() as u32, 0);
    }

    while offset as usize + 32 <= code.len() {
        offset = visitor_step_runner::<T, true>(state, code, bitmask, offset, opcode_visitor);
    }

    while (offset as usize) < code.len() {
        offset = visitor_step_runner::<T, false>(state, code, bitmask, offset, opcode_visitor);
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

static TABLE_1: LookupTable = LookupTable::build(1);
static TABLE_2: LookupTable = LookupTable::build(2);

#[inline(always)]
pub fn read_args_imm(chunk: u128, skip: u32) -> u32 {
    read_simple_varint(chunk as u32, skip)
}

#[inline(always)]
pub fn read_args_offset(chunk: u128, instruction_offset: u32, skip: u32) -> u32 {
    instruction_offset.wrapping_add(read_args_imm(chunk, skip))
}

#[inline(always)]
pub fn read_args_imm2(chunk: u128, skip: u32) -> (u32, u32) {
    let (imm1_bits, imm1_skip, imm2_bits) = TABLE_1.get(skip, chunk as u32);
    let chunk = chunk >> 8;
    let chunk = chunk as u64;
    let imm1 = sign_extend_at(chunk as u32, imm1_bits);
    let chunk = chunk >> imm1_skip;
    let imm2 = sign_extend_at(chunk as u32, imm2_bits);
    (imm1, imm2)
}

#[inline(always)]
pub fn read_args_reg_imm(chunk: u128, skip: u32) -> (RawReg, u32) {
    let chunk = chunk as u64;
    let reg = RawReg(chunk as u32);
    let chunk = chunk >> 8;
    let (_, _, imm_bits) = TABLE_1.get(skip, 0);
    let imm = sign_extend_at(chunk as u32, imm_bits);
    (reg, imm)
}

#[inline(always)]
pub fn read_args_reg_imm2(chunk: u128, skip: u32) -> (RawReg, u32, u32) {
    let reg = RawReg(chunk as u32);
    let (imm1_bits, imm1_skip, imm2_bits) = TABLE_1.get(skip, chunk as u32 >> 4);
    let chunk = chunk >> 8;
    let chunk = chunk as u64;
    let imm1 = sign_extend_at(chunk as u32, imm1_bits);
    let chunk = chunk >> imm1_skip;
    let imm2 = sign_extend_at(chunk as u32, imm2_bits);
    (reg, imm1, imm2)
}

#[inline(always)]
pub fn read_args_reg_imm_offset(chunk: u128, instruction_offset: u32, skip: u32) -> (RawReg, u32, u32) {
    let (reg, imm1, imm2) = read_args_reg_imm2(chunk, skip);
    let imm2 = instruction_offset.wrapping_add(imm2);
    (reg, imm1, imm2)
}

#[inline(always)]
pub fn read_args_regs2_imm2(chunk: u128, skip: u32) -> (RawReg, RawReg, u32, u32) {
    let (reg1, reg2, imm1_aux) = {
        let value = chunk as u32;
        (RawReg(value), RawReg(value >> 4), value >> 8)
    };

    let (imm1_bits, imm1_skip, imm2_bits) = TABLE_2.get(skip, imm1_aux);
    let chunk = chunk >> 16;
    let chunk = chunk as u64;
    let imm1 = sign_extend_at(chunk as u32, imm1_bits);
    let chunk = chunk >> imm1_skip;
    let imm2 = sign_extend_at(chunk as u32, imm2_bits);
    (reg1, reg2, imm1, imm2)
}

#[inline(always)]
pub fn read_args_regs2_imm(chunk: u128, skip: u32) -> (RawReg, RawReg, u32) {
    let chunk = chunk as u64;
    let (reg1, reg2) = {
        let value = chunk as u32;
        (RawReg(value), RawReg(value >> 4))
    };
    let chunk = chunk >> 8;
    let (_, _, imm_bits) = TABLE_1.get(skip, 0);
    let imm = sign_extend_at(chunk as u32, imm_bits);
    (reg1, reg2, imm)
}

#[inline(always)]
pub fn read_args_regs2_offset(chunk: u128, instruction_offset: u32, skip: u32) -> (RawReg, RawReg, u32) {
    let (reg1, reg2, imm) = read_args_regs2_imm(chunk, skip);
    let imm = instruction_offset.wrapping_add(imm);
    (reg1, reg2, imm)
}

#[inline(always)]
pub fn read_args_regs3(chunk: u128) -> (RawReg, RawReg, RawReg) {
    let chunk = chunk as u32;
    let (reg2, reg3, reg1) = (RawReg(chunk), RawReg(chunk >> 4), RawReg(chunk >> 8));
    (reg1, reg2, reg3)
}

#[inline(always)]
pub fn read_args_regs2(chunk: u128) -> (RawReg, RawReg) {
    let chunk = chunk as u32;
    let (reg1, reg2) = (RawReg(chunk), RawReg(chunk >> 4));
    (reg1, reg2)
}

#[cfg(kani)]
mod kani {
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
        () => {{
            let code: [u8; 16] = kani::any();
            let chunk = u128::from_le_bytes(code);
            let skip: u32 = kani::any_where(|x| *x <= super::BITMASK_MAX);

            (code, chunk, skip)
        }};
    }

    #[kani::proof]
    fn verify_read_args_imm() {
        fn simple_read_args_imm(code: &[u8], skip: u32) -> u32 {
            let imm_length = min(4, skip);
            sext(read(code, 0, imm_length), imm_length)
        }

        let (code, chunk, skip) = args!();
        assert_eq!(super::read_args_imm(chunk, skip), simple_read_args_imm(&code, skip));
    }

    #[kani::proof]
    fn verify_read_args_imm2() {
        fn simple_read_args_imm2(code: &[u8], skip: i32) -> (u32, u32) {
            let imm1_length = min(4, i32::from(code[0]) & 0b111);
            let imm2_length = clamp(0..=4, skip - imm1_length - 1);
            let imm1 = sext(read(code, 1, imm1_length), imm1_length);
            let imm2 = sext(read(code, 1 + imm1_length, imm2_length), imm2_length);
            (imm1, imm2)
        }

        let (code, chunk, skip) = args!();
        assert_eq!(super::read_args_imm2(chunk, skip), simple_read_args_imm2(&code, skip as i32));
    }

    #[kani::proof]
    fn verify_read_args_reg_imm() {
        fn simple_read_args_reg_imm(code: &[u8], skip: i32) -> (u8, u32) {
            let reg = min(12, code[0] & 0b1111);
            let imm_length = clamp(0..=4, skip - 1);
            let imm = sext(read(code, 1, imm_length), imm_length);
            (reg, imm)
        }

        let (code, chunk, skip) = args!();
        let (reg, imm) = super::read_args_reg_imm(chunk, skip);
        let reg = reg.get() as u8;
        assert_eq!((reg, imm), simple_read_args_reg_imm(&code, skip as i32));
    }

    #[kani::proof]
    fn verify_read_args_reg_imm2() {
        fn simple_read_args_reg_imm2(code: &[u8], skip: i32) -> (u8, u32, u32) {
            let reg = min(12, code[0] & 0b1111);
            let imm1_length = min(4, i32::from(code[0] >> 4) & 0b111);
            let imm2_length = clamp(0..=4, skip - imm1_length - 1);
            let imm1 = sext(read(code, 1, imm1_length), imm1_length);
            let imm2 = sext(read(code, 1 + imm1_length, imm2_length), imm2_length);
            (reg, imm1, imm2)
        }

        let (code, chunk, skip) = args!();
        let (reg, imm1, imm2) = super::read_args_reg_imm2(chunk, skip);
        let reg = reg.get() as u8;
        assert_eq!((reg, imm1, imm2), simple_read_args_reg_imm2(&code, skip as i32));
    }

    #[kani::proof]
    fn verify_read_args_regs2_imm2() {
        fn simple_read_args_regs2_imm2(code: &[u8], skip: i32) -> (u8, u8, u32, u32) {
            let reg1 = min(12, code[0] & 0b1111);
            let reg2 = min(12, code[0] >> 4);
            let imm1_length = min(4, i32::from(code[1]) & 0b111);
            let imm2_length = clamp(0..=4, skip - imm1_length - 2);
            let imm1 = sext(read(code, 2, imm1_length), imm1_length);
            let imm2 = sext(read(code, 2 + imm1_length, imm2_length), imm2_length);
            (reg1, reg2, imm1, imm2)
        }

        let (code, chunk, skip) = args!();
        let (reg1, reg2, imm1, imm2) = super::read_args_regs2_imm2(chunk, skip);
        let reg1 = reg1.get() as u8;
        let reg2 = reg2.get() as u8;
        assert_eq!((reg1, reg2, imm1, imm2), simple_read_args_regs2_imm2(&code, skip as i32))
    }

    #[kani::proof]
    fn verify_read_args_regs2_imm() {
        fn simple_read_args_regs2_imm(code: &[u8], skip: u32) -> (u8, u8, u32) {
            let reg1 = min(12, code[0] & 0b1111);
            let reg2 = min(12, code[0] >> 4);
            let imm_length = clamp(0..=4, skip as i32 - 1);
            let imm = sext(read(code, 1, imm_length), imm_length);
            (reg1, reg2, imm)
        }

        let (code, chunk, skip) = args!();
        let (reg1, reg2, imm) = super::read_args_regs2_imm(chunk, skip);
        let reg1 = reg1.get() as u8;
        let reg2 = reg2.get() as u8;
        assert_eq!((reg1, reg2, imm), simple_read_args_regs2_imm(&code, skip));
    }

    #[kani::proof]
    fn verify_read_args_regs3() {
        fn simple_read_args_regs3(code: &[u8]) -> (u8, u8, u8) {
            let reg2 = min(12, code[0] & 0b1111);
            let reg3 = min(12, code[0] >> 4);
            let reg1 = min(12, code[1] & 0b1111);
            (reg1, reg2, reg3)
        }

        let (code, chunk, _) = args!();
        let (reg1, reg2, reg3) = super::read_args_regs3(chunk);
        let reg1 = reg1.get() as u8;
        let reg2 = reg2.get() as u8;
        let reg3 = reg3.get() as u8;
        assert_eq!((reg1, reg2, reg3), simple_read_args_regs3(&code));
    }

    #[kani::proof]
    fn verify_read_args_regs2() {
        fn simple_read_args_regs2(code: &[u8]) -> (u8, u8) {
            let reg1 = min(12, code[0] & 0b1111);
            let reg2 = min(12, code[0] >> 4);
            (reg1, reg2)
        }

        let (code, chunk, _) = args!();
        let (reg1, reg2) = super::read_args_regs2(chunk);
        let reg1 = reg1.get() as u8;
        let reg2 = reg2.get() as u8;
        assert_eq!((reg1, reg2), simple_read_args_regs2(&code));
    }
}

/// The lowest level visitor; dispatches directly on opcode numbers.
pub trait OpcodeVisitor: Copy {
    type State;
    type ReturnTy;
    type InstructionSet: InstructionSet;

    fn instruction_set(self) -> Self::InstructionSet;
    fn dispatch(self, state: &mut Self::State, opcode: usize, chunk: u128, offset: u32, skip: u32) -> Self::ReturnTy;
}

macro_rules! define_opcodes {
    (@impl_instruction_set $instruction_set:ident [$($instruction_set_tag:tt),+] $([$($tag:tt),+] $name:ident = $value:expr,)+) => {
        impl $instruction_set {
            #[doc(hidden)]
            pub const IS_INSTRUCTION_VALID_CONST: [bool; 256] = {
                let mut is_valid = [false; 256];
                let b = [$($instruction_set_tag),+];
                $(
                    is_valid[$value] = {
                        let a = [$($tag),+];
                        let mut found = false;
                        let mut i = 0;
                        'outer: while i < a.len() {
                            let mut j = 0;
                            while j < b.len() {
                                if a[i] == b[j] {
                                    found = true;
                                    break 'outer;
                                }
                                j += 1;
                            }
                            i += 1;
                        }
                        found
                    };
                )+
                is_valid
            };
        }

        impl InstructionSet for $instruction_set {
            #[cfg_attr(feature = "alloc", inline)]
            fn opcode_from_u8(self, byte: u8) -> Option<Opcode> {
                static IS_INSTRUCTION_VALID: [bool; 256] = $instruction_set::IS_INSTRUCTION_VALID_CONST;

                if !IS_INSTRUCTION_VALID[byte as usize] {
                    return None;
                }

                #[allow(unsafe_code)]
                // SAFETY: We already checked that this opcode is valid, so this is safe.
                unsafe {
                    Some(core::mem::transmute(byte))
                }
            }
        }
    };

    (@impl_shared $([$($tag:tt),+] $name:ident = $value:expr,)+) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
        #[repr(u8)]
        pub enum Opcode {
            $(
                $name = $value,
            )+
        }

        impl Opcode {
            pub fn from_u8_any(byte: u8) -> Option<Opcode> {
                match byte {
                    $($value => Some(Opcode::$name),)+
                    _ => None
                }
            }
        }

        define_opcodes!(@impl_instruction_set ISA32_V1         [I_32, I_SBRK]  $([$($tag),+] $name = $value,)+);
        define_opcodes!(@impl_instruction_set ISA32_V1_NoSbrk  [I_32]          $([$($tag),+] $name = $value,)+);
        define_opcodes!(@impl_instruction_set ISA64_V1         [I_64, I_SBRK]  $([$($tag),+] $name = $value,)+);

        #[test]
        fn test_opcode_from_u8() {
            for byte in 0..=255 {
                if let Some(opcode) = Opcode::from_u8_any(byte) {
                    assert_eq!(ISA32_V1.opcode_from_u8(byte).unwrap_or(opcode), opcode);
                    assert_eq!(ISA32_V1_NoSbrk.opcode_from_u8(byte).unwrap_or(opcode), opcode);
                    assert_eq!(ISA64_V1.opcode_from_u8(byte).unwrap_or(opcode), opcode);
                } else {
                    assert_eq!(ISA32_V1.opcode_from_u8(byte), None);
                    assert_eq!(ISA32_V1_NoSbrk.opcode_from_u8(byte), None);
                    assert_eq!(ISA64_V1.opcode_from_u8(byte), None);
                }
            }

            assert!(ISA32_V1.opcode_from_u8(Opcode::sbrk as u8).is_some());
            assert!(ISA32_V1_NoSbrk.opcode_from_u8(Opcode::sbrk as u8).is_none());
        }
    };

    (
        $d:tt

        [$([$($tag_argless:tt),+] $name_argless:ident = $value_argless:expr,)+]
        [$([$($tag_reg_imm:tt),+] $name_reg_imm:ident = $value_reg_imm:expr,)+]
        [$([$($tag_reg_imm_offset:tt),+] $name_reg_imm_offset:ident = $value_reg_imm_offset:expr,)+]
        [$([$($tag_reg_imm_imm:tt),+] $name_reg_imm_imm:ident = $value_reg_imm_imm:expr,)+]
        [$([$($tag_reg_reg_imm:tt),+] $name_reg_reg_imm:ident = $value_reg_reg_imm:expr,)+]
        [$([$($tag_reg_reg_offset:tt),+] $name_reg_reg_offset:ident = $value_reg_reg_offset:expr,)+]
        [$([$($tag_reg_reg_reg:tt),+] $name_reg_reg_reg:ident = $value_reg_reg_reg:expr,)+]
        [$([$($tag_offset:tt),+] $name_offset:ident = $value_offset:expr,)+]
        [$([$($tag_imm:tt),+] $name_imm:ident = $value_imm:expr,)+]
        [$([$($tag_imm_imm:tt),+] $name_imm_imm:ident = $value_imm_imm:expr,)+]
        [$([$($tag_reg_reg:tt),+] $name_reg_reg:ident = $value_reg_reg:expr,)+]
        [$([$($tag_reg_reg_imm_imm:tt),+] $name_reg_reg_imm_imm:ident = $value_reg_reg_imm_imm:expr,)+]
    ) => {
        pub trait ParsingVisitor {
            type ReturnTy;

            $(fn $name_argless(&mut self, offset: u32, args_length: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm(&mut self, offset: u32, args_length: u32, reg: RawReg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_offset(&mut self, offset: u32, args_length: u32, reg: RawReg, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_imm(&mut self, offset: u32, args_length: u32, reg: RawReg, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm(&mut self, offset: u32, args_length: u32, reg1: RawReg, reg2: RawReg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_offset(&mut self, offset: u32, args_length: u32, reg1: RawReg, reg2: RawReg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_reg(&mut self, offset: u32, args_length: u32, reg1: RawReg, reg2: RawReg, reg3: RawReg) -> Self::ReturnTy;)+
            $(fn $name_offset(&mut self, offset: u32, args_length: u32, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_imm(&mut self, offset: u32, args_length: u32, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_imm_imm(&mut self, offset: u32, args_length: u32, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg(&mut self, offset: u32, args_length: u32, reg1: RawReg, reg2: RawReg) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm_imm(&mut self, offset: u32, args_length: u32, reg1: RawReg, reg2: RawReg, imm1: u32, imm2: u32) -> Self::ReturnTy;)+

            fn invalid(&mut self, offset: u32, args_length: u32) -> Self::ReturnTy;
        }

        pub trait InstructionVisitor {
            type ReturnTy;

            $(fn $name_argless(&mut self) -> Self::ReturnTy;)+
            $(fn $name_reg_imm(&mut self, reg: RawReg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_offset(&mut self, reg: RawReg, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_imm(&mut self, reg: RawReg, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm(&mut self, reg1: RawReg, reg2: RawReg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_offset(&mut self, reg1: RawReg, reg2: RawReg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_reg(&mut self, reg1: RawReg, reg2: RawReg, reg3: RawReg) -> Self::ReturnTy;)+
            $(fn $name_offset(&mut self, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_imm(&mut self, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_imm_imm(&mut self, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg(&mut self, reg1: RawReg, reg2: RawReg) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm_imm(&mut self, reg1: RawReg, reg2: RawReg, imm1: u32, imm2: u32) -> Self::ReturnTy;)+

            fn invalid(&mut self) -> Self::ReturnTy;
        }

        #[derive(Copy, Clone, PartialEq, Eq, Debug)]
        #[allow(non_camel_case_types)]
        #[repr(u32)]
        pub enum Instruction {
            $($name_argless = $value_argless,)+
            $($name_reg_imm(RawReg, u32) = $value_reg_imm,)+
            $($name_reg_imm_offset(RawReg, u32, u32) = $value_reg_imm_offset,)+
            $($name_reg_imm_imm(RawReg, u32, u32) = $value_reg_imm_imm,)+
            $($name_reg_reg_imm(RawReg, RawReg, u32) = $value_reg_reg_imm,)+
            $($name_reg_reg_offset(RawReg, RawReg, u32) = $value_reg_reg_offset,)+
            $($name_reg_reg_reg(RawReg, RawReg, RawReg) = $value_reg_reg_reg,)+
            $($name_offset(u32) = $value_offset,)+
            $($name_imm(u32) = $value_imm,)+
            $($name_imm_imm(u32, u32) = $value_imm_imm,)+
            $($name_reg_reg(RawReg, RawReg) = $value_reg_reg,)+
            $($name_reg_reg_imm_imm(RawReg, RawReg, u32, u32) = $value_reg_reg_imm_imm,)+
            invalid = INVALID_INSTRUCTION_INDEX as u32,
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
                    Self::invalid => visitor.invalid(),
                }
            }

            pub fn serialize_into(self, position: u32, buffer: &mut [u8]) -> usize {
                match self {
                    $(Self::$name_argless => Self::serialize_argless(buffer, Opcode::$name_argless),)+
                    $(Self::$name_reg_imm(reg, imm) => Self::serialize_reg_imm(buffer, Opcode::$name_reg_imm, reg, imm),)+
                    $(Self::$name_reg_imm_offset(reg, imm1, imm2) => Self::serialize_reg_imm_offset(buffer, position, Opcode::$name_reg_imm_offset, reg, imm1, imm2),)+
                    $(Self::$name_reg_imm_imm(reg, imm1, imm2) => Self::serialize_reg_imm_imm(buffer, Opcode::$name_reg_imm_imm, reg, imm1, imm2),)+
                    $(Self::$name_reg_reg_imm(reg1, reg2, imm) => Self::serialize_reg_reg_imm(buffer, Opcode::$name_reg_reg_imm, reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_offset(reg1, reg2, imm) => Self::serialize_reg_reg_offset(buffer, position, Opcode::$name_reg_reg_offset, reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_reg(reg1, reg2, reg3) => Self::serialize_reg_reg_reg(buffer, Opcode::$name_reg_reg_reg, reg1, reg2, reg3),)+
                    $(Self::$name_offset(imm) => Self::serialize_offset(buffer, position, Opcode::$name_offset, imm),)+
                    $(Self::$name_imm(imm) => Self::serialize_imm(buffer, Opcode::$name_imm, imm),)+
                    $(Self::$name_imm_imm(imm1, imm2) => Self::serialize_imm_imm(buffer, Opcode::$name_imm_imm, imm1, imm2),)+
                    $(Self::$name_reg_reg(reg1, reg2) => Self::serialize_reg_reg(buffer, Opcode::$name_reg_reg, reg1, reg2),)+
                    $(Self::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2) => Self::serialize_reg_reg_imm_imm(buffer, Opcode::$name_reg_reg_imm_imm, reg1, reg2, imm1, imm2),)+
                    Self::invalid => Self::serialize_argless(buffer, Opcode::trap),

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
                pub fn $name_reg_imm(reg: Reg, imm: u32) -> Instruction {
                    Instruction::$name_reg_imm(reg.into(), imm)
                }
            )+

            $(
                pub fn $name_reg_imm_offset(reg: Reg, imm1: u32, imm2: u32) -> Instruction {
                    Instruction::$name_reg_imm_offset(reg.into(), imm1, imm2)
                }
            )+

            $(
                pub fn $name_reg_imm_imm(reg: Reg, imm1: u32, imm2: u32) -> Instruction {
                    Instruction::$name_reg_imm_imm(reg.into(), imm1, imm2)
                }
            )+

            $(
                pub fn $name_reg_reg_imm(reg1: Reg, reg2: Reg, imm: u32) -> Instruction {
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
                pub fn $name_imm(imm: u32) -> Instruction {
                    Instruction::$name_imm(imm)
                }
            )+

            $(
                pub fn $name_imm_imm(imm1: u32, imm2: u32) -> Instruction {
                    Instruction::$name_imm_imm(imm1, imm2)
                }
            )+

            $(
                pub fn $name_reg_reg(reg1: Reg, reg2: Reg) -> Instruction {
                    Instruction::$name_reg_reg(reg1.into(), reg2.into())
                }
            )+

            $(
                pub fn $name_reg_reg_imm_imm(reg1: Reg, reg2: Reg, imm1: u32, imm2: u32) -> Instruction {
                    Instruction::$name_reg_reg_imm_imm(reg1.into(), reg2.into(), imm1, imm2)
                }
            )+

            pub fn ret() -> Instruction {
                jump_indirect(Reg::RA, 0)
            }
        }

        #[macro_export]
        macro_rules! build_static_dispatch_table {
            ($table_name:ident, $instruction_set:tt, $visitor_ty:ident<$d($visitor_ty_params:tt),*>) => {{
                use $crate::program::{
                    ParsingVisitor
                };

                type ReturnTy<$d($visitor_ty_params),*> = <$visitor_ty<$d($visitor_ty_params),*> as ParsingVisitor>::ReturnTy;
                type VisitFn<$d($visitor_ty_params),*> = fn(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, args_length: u32);

                #[derive(Copy, Clone)]
                struct DispatchTable<'a>(&'a [VisitFn<'a>; 257]);

                impl<'a> $crate::program::OpcodeVisitor for DispatchTable<'a> {
                    type State = $visitor_ty<'a>;
                    type ReturnTy = ();
                    type InstructionSet = $instruction_set;

                    #[inline]
                    fn instruction_set(self) -> Self::InstructionSet {
                        $instruction_set
                    }

                    #[inline]
                    fn dispatch(self, state: &mut $visitor_ty<'a>, opcode: usize, chunk: u128, offset: u32, skip: u32) {
                        self.0[opcode](state, chunk, offset, skip)
                    }
                }

                static $table_name: [VisitFn; 257] = {
                    let mut table = [invalid_instruction as VisitFn; 257];

                    $({
                        // Putting all of the handlers in a single link section can make a big difference
                        // when it comes to performance, even up to 10% in some cases. This will force the
                        // compiler and the linker to put all of this code near each other, minimizing
                        // instruction cache misses.
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_argless<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, _chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            state.$name_argless(instruction_offset, skip)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_argless] {
                            table[$value_argless] = $name_argless;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm) = $crate::program::read_args_reg_imm(chunk, skip);
                            state.$name_reg_imm(instruction_offset, skip, reg, imm)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_reg_imm] {
                            table[$value_reg_imm] = $name_reg_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_offset<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm_offset(chunk, instruction_offset, skip);
                            state.$name_reg_imm_offset(instruction_offset, skip, reg, imm1, imm2)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_reg_imm_offset] {
                            table[$value_reg_imm_offset] = $name_reg_imm_offset;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm2(chunk, skip);
                            state.$name_reg_imm_imm(instruction_offset, skip, reg, imm1, imm2)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_reg_imm_imm] {
                            table[$value_reg_imm_imm] = $name_reg_imm_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_imm(chunk, skip);
                            state.$name_reg_reg_imm(instruction_offset, skip, reg1, reg2, imm)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_reg_reg_imm] {
                            table[$value_reg_reg_imm] = $name_reg_reg_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_offset<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_offset(chunk, instruction_offset, skip);
                            state.$name_reg_reg_offset(instruction_offset, skip, reg1, reg2, imm)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_reg_reg_offset] {
                            table[$value_reg_reg_offset] = $name_reg_reg_offset;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_reg<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, reg3) = $crate::program::read_args_regs3(chunk);
                            state.$name_reg_reg_reg(instruction_offset, skip, reg1, reg2, reg3)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_reg_reg_reg] {
                            table[$value_reg_reg_reg] = $name_reg_reg_reg;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_offset<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let imm = $crate::program::read_args_offset(chunk, instruction_offset, skip);
                            state.$name_offset(instruction_offset, skip, imm)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_offset] {
                            table[$value_offset] = $name_offset;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let imm = $crate::program::read_args_imm(chunk, skip);
                            state.$name_imm(instruction_offset, skip, imm)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_imm] {
                            table[$value_imm] = $name_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (imm1, imm2) = $crate::program::read_args_imm2(chunk, skip);
                            state.$name_imm_imm(instruction_offset, skip, imm1, imm2)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_imm_imm] {
                            table[$value_imm_imm] = $name_imm_imm;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2) = $crate::program::read_args_regs2(chunk);
                            state.$name_reg_reg(instruction_offset, skip, reg1, reg2)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_reg_reg] {
                            table[$value_reg_reg] = $name_reg_reg;
                        }
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm_imm<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm1, imm2) = $crate::program::read_args_regs2_imm2(chunk, skip);
                            state.$name_reg_reg_imm_imm(instruction_offset, skip, reg1, reg2, imm1, imm2)
                        }

                        if $instruction_set::IS_INSTRUCTION_VALID_CONST[$value_reg_reg_imm_imm] {
                            table[$value_reg_reg_imm_imm] = $name_reg_reg_imm_imm;
                        }
                    })*

                    #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                    #[cold]
                    fn invalid_instruction<$d($visitor_ty_params),*>(state: &mut $visitor_ty<$d($visitor_ty_params),*>, _chunk: u128, instruction_offset: u32, skip: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                        state.invalid(instruction_offset, skip)
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

        pub use build_static_dispatch_table;

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

            fn dispatch(self, _state: &mut (), opcode: usize, chunk: u128, offset: u32, skip: u32) -> Instruction {
                if self.instruction_set().opcode_from_u8(opcode as u8).is_none() {
                    return Instruction::invalid
                }

                match opcode {
                    $(
                        $value_argless => Instruction::$name_argless,
                    )+
                    $(
                        $value_reg_imm => {
                            let (reg, imm) = $crate::program::read_args_reg_imm(chunk, skip);
                            Instruction::$name_reg_imm(reg, imm)
                        },
                    )+
                    $(
                        $value_reg_imm_offset => {
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm_offset(chunk, offset, skip);
                            Instruction::$name_reg_imm_offset(reg, imm1, imm2)
                        },
                    )+
                    $(
                        $value_reg_imm_imm => {
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm2(chunk, skip);
                            Instruction::$name_reg_imm_imm(reg, imm1, imm2)
                        },
                    )+
                    $(
                        $value_reg_reg_imm => {
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_imm(chunk, skip);
                            Instruction::$name_reg_reg_imm(reg1, reg2, imm)
                        }
                    )+
                    $(
                        $value_reg_reg_offset => {
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_offset(chunk, offset, skip);
                            Instruction::$name_reg_reg_offset(reg1, reg2, imm)
                        }
                    )+
                    $(
                        $value_reg_reg_reg => {
                            let (reg1, reg2, reg3) = $crate::program::read_args_regs3(chunk);
                            Instruction::$name_reg_reg_reg(reg1, reg2, reg3)
                        }
                    )+
                    $(
                        $value_offset => {
                            let imm = $crate::program::read_args_offset(chunk, offset, skip);
                            Instruction::$name_offset(imm)
                        }
                    )+
                    $(
                        $value_imm => {
                            let imm = $crate::program::read_args_imm(chunk, skip);
                            Instruction::$name_imm(imm)
                        }
                    )+
                    $(
                        $value_imm_imm => {
                            let (imm1, imm2) = $crate::program::read_args_imm2(chunk, skip);
                            Instruction::$name_imm_imm(imm1, imm2)
                        }
                    )+
                    $(
                        $value_reg_reg => {
                            let (reg1, reg2) = $crate::program::read_args_regs2(chunk);
                            Instruction::$name_reg_reg(reg1, reg2)
                        }
                    )+
                    $(
                        $value_reg_reg_imm_imm => {
                            let (reg1, reg2, imm1, imm2) = $crate::program::read_args_regs2_imm2(chunk, skip);
                            Instruction::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2)
                        }
                    )+
                    _ => Instruction::invalid,
                }
            }
        }

        define_opcodes!(
            @impl_shared
            $([$($tag_argless),+] $name_argless = $value_argless,)+
            $([$($tag_reg_imm),+] $name_reg_imm = $value_reg_imm,)+
            $([$($tag_reg_imm_offset),+] $name_reg_imm_offset = $value_reg_imm_offset,)+
            $([$($tag_reg_imm_imm),+] $name_reg_imm_imm = $value_reg_imm_imm,)+
            $([$($tag_reg_reg_imm),+] $name_reg_reg_imm = $value_reg_reg_imm,)+
            $([$($tag_reg_reg_offset),+] $name_reg_reg_offset = $value_reg_reg_offset,)+
            $([$($tag_reg_reg_reg),+] $name_reg_reg_reg = $value_reg_reg_reg,)+
            $([$($tag_offset),+] $name_offset = $value_offset,)+
            $([$($tag_imm),+] $name_imm = $value_imm,)+
            $([$($tag_imm_imm),+] $name_imm_imm = $value_imm_imm,)+
            $([$($tag_reg_reg),+] $name_reg_reg = $value_reg_reg,)+
            $([$($tag_reg_reg_imm_imm),+] $name_reg_reg_imm_imm = $value_reg_reg_imm_imm,)+
        );
    }
}

#[inline]
fn parse_instruction<I>(instruction_set: I, code: &[u8], bitmask: &[u8], offset: u32) -> (u32, Instruction, bool)
where
    I: InstructionSet,
{
    let visitor = EnumVisitor { instruction_set };
    if offset as usize + 32 <= code.len() {
        visitor_step_fast(&mut (), code, bitmask, offset, visitor)
    } else {
        visitor_step_slow(&mut (), code, bitmask, offset, visitor)
    }
}

const INVALID_INSTRUCTION_INDEX: u32 = 256;

// Constants so that `define_opcodes` works. The exact values don't matter.
const I_32: usize = 0;
const I_64: usize = 1;
const I_SBRK: usize = 2;

// NOTE: The opcodes here are assigned roughly in the order of how common a given instruction is,
// except the `trap` which is deliberately hardcoded as zero.
define_opcodes! {
    $

    // Instructions with args: none
    [
        [I_64, I_32] trap                                     = 0,
        [I_64, I_32] fallthrough                              = 17,
    ]

    // Instructions with args: reg, imm
    [
        [I_64, I_32] jump_indirect                            = 19,
        [I_64, I_32] load_imm                                 = 4,
        [I_64, I_32] load_u8                                  = 60,
        [I_64, I_32] load_i8                                  = 74,
        [I_64, I_32] load_u16                                 = 76,
        [I_64, I_32] load_i16                                 = 66,
        [I_64, I_32] load_u32                                 = 10,
        [I_64]       load_i32                                 = 102,
        [I_64]       load_u64                                 = 95,
        [I_64, I_32] store_u8                                 = 71,
        [I_64, I_32] store_u16                                = 69,
        [I_64, I_32] store_u32                                = 22,
        [I_64]       store_u64                                = 96,
    ]

    // Instructions with args: reg, imm, offset
    [
        [I_64, I_32] load_imm_and_jump                        = 6,
        [I_64, I_32] branch_eq_imm                            = 7,
        [I_64, I_32] branch_not_eq_imm                        = 15,
        [I_64, I_32] branch_less_unsigned_imm                 = 44,
        [I_64, I_32] branch_less_signed_imm                   = 32,
        [I_64, I_32] branch_greater_or_equal_unsigned_imm     = 52,
        [I_64, I_32] branch_greater_or_equal_signed_imm       = 45,
        [I_64, I_32] branch_less_or_equal_signed_imm          = 46,
        [I_64, I_32] branch_less_or_equal_unsigned_imm        = 59,
        [I_64, I_32] branch_greater_signed_imm                = 53,
        [I_64, I_32] branch_greater_unsigned_imm              = 50,
    ]

    // Instructions with args: reg, imm, imm
    [
        [I_64, I_32] store_imm_indirect_u8                    = 26,
        [I_64, I_32] store_imm_indirect_u16                   = 54,
        [I_64, I_32] store_imm_indirect_u32                   = 13,
        [I_64]       store_imm_indirect_u64                   = 93,
    ]

    // Instructions with args: reg, reg, imm
    [
        [I_64, I_32] store_indirect_u8                        = 16,
        [I_64, I_32] store_indirect_u16                       = 29,
        [I_64, I_32] store_indirect_u32                       = 3,
        [I_64]       store_indirect_u64                       = 90,
        [I_64, I_32] load_indirect_u8                         = 11,
        [I_64, I_32] load_indirect_i8                         = 21,
        [I_64, I_32] load_indirect_u16                        = 37,
        [I_64, I_32] load_indirect_i16                        = 33,
        [I_64]       load_indirect_i32                        = 99,
        [I_64, I_32] load_indirect_u32                        = 1,
        [I_64]       load_indirect_u64                        = 91,
        [I_64, I_32] add_imm                                  = 2,
        [I_64]       add_64_imm                               = 104,
        [I_64, I_32] and_imm                                  = 18,
        [I_64]       and_64_imm                               = 118,
        [I_64, I_32] xor_imm                                  = 31,
        [I_64]       xor_64_imm                               = 119,
        [I_64, I_32] or_imm                                   = 49,
        [I_64]       or_64_imm                                = 120,
        [I_64, I_32] mul_imm                                  = 35,
        [I_64]       mul_64_imm                               = 121,
        [I_64, I_32] mul_upper_signed_signed_imm              = 65,
        [I_64]       mul_upper_signed_signed_imm_64           = 131,
        [I_64, I_32] mul_upper_unsigned_unsigned_imm          = 63,
        [I_64]       mul_upper_unsigned_unsigned_imm_64       = 132,
        [I_64, I_32] set_less_than_unsigned_imm               = 27,
        [I_64]       set_less_than_unsigned_64_imm            = 125,
        [I_64, I_32] set_less_than_signed_imm                 = 56,
        [I_64]       set_less_than_signed_64_imm              = 126,
        [I_64, I_32] shift_logical_left_imm                   = 9,
        [I_64]       shift_logical_left_64_imm                = 105,
        [I_64, I_32] shift_logical_right_imm                  = 14,
        [I_64]       shift_logical_right_64_imm               = 106,
        [I_64, I_32] shift_arithmetic_right_imm               = 25,
        [I_64]       shift_arithmetic_right_64_imm            = 107,
        [I_64, I_32] negate_and_add_imm                       = 40,
        [I_64, I_32] set_greater_than_unsigned_imm            = 39,
        [I_64]       set_greater_than_unsigned_64_imm         = 129,
        [I_64, I_32] set_greater_than_signed_imm              = 61,
        [I_64]       set_greater_than_signed_64_imm           = 130,
        [I_64, I_32] shift_logical_right_imm_alt              = 72,
        [I_64]       shift_logical_right_64_imm_alt           = 103,
        [I_64, I_32] shift_arithmetic_right_imm_alt           = 80,
        [I_64]       shift_arithmetic_right_64_imm_alt        = 111,
        [I_64, I_32] shift_logical_left_imm_alt               = 75,
        [I_64]       shift_logical_left_64_imm_alt            = 110,

        [I_64, I_32] cmov_if_zero_imm                         = 85,
        [I_64, I_32] cmov_if_not_zero_imm                     = 86,
    ]

    // Instructions with args: reg, reg, offset
    [
        [I_64, I_32] branch_eq                                = 24,
        [I_64, I_32] branch_not_eq                            = 30,
        [I_64, I_32] branch_less_unsigned                     = 47,
        [I_64, I_32] branch_less_signed                       = 48,
        [I_64, I_32] branch_greater_or_equal_unsigned         = 41,
        [I_64, I_32] branch_greater_or_equal_signed           = 43,
    ]

    // Instructions with args: reg, reg, reg
    [
        [I_64, I_32] add                                      = 8,
        [I_64]       add_64                                   = 101,
        [I_64, I_32] sub                                      = 20,
        [I_64]       sub_64                                   = 112,
        [I_64, I_32] and                                      = 23,
        [I_64]       and_64                                   = 124,
        [I_64, I_32] xor                                      = 28,
        [I_64]       xor_64                                   = 122,
        [I_64, I_32] or                                       = 12,
        [I_64]       or_64                                    = 123,
        [I_64, I_32] mul                                      = 34,
        [I_64]       mul_64                                   = 113,
        [I_64, I_32] mul_upper_signed_signed                  = 67,
        [I_64]       mul_upper_signed_signed_64               = 133,
        [I_64, I_32] mul_upper_unsigned_unsigned              = 57,
        [I_64]       mul_upper_unsigned_unsigned_64           = 134,
        [I_64, I_32] mul_upper_signed_unsigned                = 81,
        [I_64]       mul_upper_signed_unsigned_64             = 135,
        [I_64, I_32] set_less_than_unsigned                   = 36,
        [I_64]       set_less_than_unsigned_64                = 127,
        [I_64, I_32] set_less_than_signed                     = 58,
        [I_64]       set_less_than_signed_64                  = 128,
        [I_64, I_32] shift_logical_left                       = 55,
        [I_64]       shift_logical_left_64                    = 100,
        [I_64, I_32] shift_logical_right                      = 51,
        [I_64]       shift_logical_right_64                   = 108,
        [I_64, I_32] shift_arithmetic_right                   = 77,
        [I_64]       shift_arithmetic_right_64                = 109,
        [I_64, I_32] div_unsigned                             = 68,
        [I_64]       div_unsigned_64                          = 114,
        [I_64, I_32] div_signed                               = 64,
        [I_64]       div_signed_64                            = 115,
        [I_64, I_32] rem_unsigned                             = 73,
        [I_64]       rem_unsigned_64                          = 116,
        [I_64, I_32] rem_signed                               = 70,
        [I_64]       rem_signed_64                            = 117,

        [I_64, I_32] cmov_if_zero                             = 83,
        [I_64, I_32] cmov_if_not_zero                         = 84,
    ]

    // Instructions with args: offset
    [
        [I_64, I_32] jump                                     = 5,
    ]

    // Instructions with args: imm
    [
        [I_64, I_32] ecalli                                   = 78,
    ]

    // Instructions with args: imm, imm
    [
        [I_64, I_32] store_imm_u8                             = 62,
        [I_64, I_32] store_imm_u16                            = 79,
        [I_64, I_32] store_imm_u32                            = 38,
        [I_64]       store_imm_u64                            = 98,
    ]

    // Instructions with args: reg, reg
    [
        [I_64, I_32] move_reg                                 = 82,
        [I_SBRK]     sbrk                                     = 87,
    ]

    // Instructions with args: reg, reg, imm, imm
    [
        [I_64, I_32] load_imm_and_jump_indirect               = 42,
    ]
}

impl Opcode {
    pub fn can_fallthrough(self) -> bool {
        !matches!(
            self,
            Self::trap | Self::jump | Self::jump_indirect | Self::load_imm_and_jump | Self::load_imm_and_jump_indirect
        )
    }

    pub fn starts_new_basic_block(self) -> bool {
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

    fn serialize_argless(buffer: &mut [u8], opcode: Opcode) -> usize {
        buffer[0] = opcode as u8;
        1
    }

    fn serialize_reg_imm_offset(buffer: &mut [u8], position: u32, opcode: Opcode, reg: RawReg, imm1: u32, imm2: u32) -> usize {
        let imm2 = imm2.wrapping_sub(position);
        buffer[0] = opcode as u8;
        let mut position = 2;
        let imm1_length = write_simple_varint(imm1, &mut buffer[position..]);
        position += imm1_length;
        buffer[1] = reg.0 as u8 | (imm1_length << 4) as u8;
        position += write_simple_varint(imm2, &mut buffer[position..]);
        position
    }

    fn serialize_reg_imm_imm(buffer: &mut [u8], opcode: Opcode, reg: RawReg, imm1: u32, imm2: u32) -> usize {
        buffer[0] = opcode as u8;
        let mut position = 2;
        let imm1_length = write_simple_varint(imm1, &mut buffer[position..]);
        position += imm1_length;
        buffer[1] = reg.0 as u8 | (imm1_length << 4) as u8;
        position += write_simple_varint(imm2, &mut buffer[position..]);
        position
    }
    fn serialize_reg_reg_imm_imm(buffer: &mut [u8], opcode: Opcode, reg1: RawReg, reg2: RawReg, imm1: u32, imm2: u32) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg1.0 as u8 | (reg2.0 as u8) << 4;
        let mut position = 3;
        let imm1_length = write_simple_varint(imm1, &mut buffer[position..]);
        buffer[2] = imm1_length as u8;
        position += imm1_length;
        position += write_simple_varint(imm2, &mut buffer[position..]);
        position
    }

    fn serialize_reg_reg_reg(buffer: &mut [u8], opcode: Opcode, reg1: RawReg, reg2: RawReg, reg3: RawReg) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg2.0 as u8 | (reg3.0 as u8) << 4;
        buffer[2] = reg1.0 as u8;
        3
    }

    fn serialize_reg_reg_imm(buffer: &mut [u8], opcode: Opcode, reg1: RawReg, reg2: RawReg, imm: u32) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg1.0 as u8 | (reg2.0 as u8) << 4;
        write_simple_varint(imm, &mut buffer[2..]) + 2
    }

    fn serialize_reg_reg_offset(buffer: &mut [u8], position: u32, opcode: Opcode, reg1: RawReg, reg2: RawReg, imm: u32) -> usize {
        let imm = imm.wrapping_sub(position);
        buffer[0] = opcode as u8;
        buffer[1] = reg1.0 as u8 | (reg2.0 as u8) << 4;
        write_simple_varint(imm, &mut buffer[2..]) + 2
    }

    fn serialize_reg_imm(buffer: &mut [u8], opcode: Opcode, reg: RawReg, imm: u32) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg.0 as u8;
        write_simple_varint(imm, &mut buffer[2..]) + 2
    }

    fn serialize_offset(buffer: &mut [u8], position: u32, opcode: Opcode, imm: u32) -> usize {
        let imm = imm.wrapping_sub(position);
        buffer[0] = opcode as u8;
        write_simple_varint(imm, &mut buffer[1..]) + 1
    }

    fn serialize_imm(buffer: &mut [u8], opcode: Opcode, imm: u32) -> usize {
        buffer[0] = opcode as u8;
        write_simple_varint(imm, &mut buffer[1..]) + 1
    }

    fn serialize_imm_imm(buffer: &mut [u8], opcode: Opcode, imm1: u32, imm2: u32) -> usize {
        buffer[0] = opcode as u8;
        let mut position = 2;
        let imm1_length = write_simple_varint(imm1, &mut buffer[position..]);
        buffer[1] = imm1_length as u8;
        position += imm1_length;
        position += write_simple_varint(imm2, &mut buffer[position..]);
        position
    }

    fn serialize_reg_reg(buffer: &mut [u8], opcode: Opcode, reg1: RawReg, reg2: RawReg) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg1.0 as u8 | (reg2.0 as u8) << 4;
        2
    }
}

pub const MAX_INSTRUCTION_LENGTH: usize = 2 + MAX_VARINT_LENGTH * 2;

#[derive(Default)]
#[non_exhaustive]
pub struct InstructionFormat<'a> {
    pub prefer_non_abi_reg_names: bool,
    pub prefer_unaliased: bool,
    pub jump_target_formatter: Option<&'a dyn Fn(u32, &mut core::fmt::Formatter) -> core::fmt::Result>,
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

    fn sbrk(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = sbrk {s}")
    }

    fn ecalli(&mut self, nth_import: u32) -> Self::ReturnTy {
        write!(self, "ecalli {nth_import}")
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

    fn set_less_than_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} <u64 {s2}")
    }

    fn set_less_than_signed_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} <s64 {s2}")
    }

    fn shift_logical_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >>64 {s2}")
    }

    fn shift_arithmetic_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >>a64 {s2}")
    }

    fn shift_logical_left_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} <<64 {s2}")
    }

    fn shift_logical_right(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >> {s2}")
    }

    fn shift_arithmetic_right(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >>a {s2}")
    }

    fn shift_logical_left(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} << {s2}")
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

    fn xor_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "i64 {d} = {s1} ^ {s2}")
    }

    fn and_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "i64 {d} = {s1} & {s2}")
    }

    fn or_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "i64 {d} = {s1} | {s2}")
    }

    fn add(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} + {s2}")
    }

    fn add_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "i64 {d} = {s1} + {s2}")
    }

    fn sub(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} - {s2}")
    }

    fn sub_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "i64 {d} = i64 {s1} - i64 {s2}")
    }

    fn mul(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} * {s2}")
    }

    fn mul_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "i64 {d} = i64 {s1} * i64 {s2}")
    }

    fn mul_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} * {s2}")
    }

    fn mul_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "i64 {d} = {s1} * {s2}")
    }

    fn mul_upper_signed_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = ({s1} as i64 * {s2} as i64) >> 32")
    }

    fn mul_upper_signed_signed_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = ({s1} as i128 * {s2} as i128) >> 64")
    }

    fn mul_upper_signed_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = ({s1} as i64 * {s2} as i64) >> 32", s2 = s2 as i32)
    }

    fn mul_upper_signed_signed_imm_64(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = ({s1} as i128 * {s2} as i128) >> 64", s2 = i64::from(s2))
    }

    fn mul_upper_unsigned_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = ({s1} as u64 * {s2} as u64) >> 32")
    }

    fn mul_upper_unsigned_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = ({s1} as u128 * {s2} as u128) >> 64")
    }

    fn mul_upper_unsigned_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = ({s1} as u64 * {s2} as u64) >> 32")
    }

    fn mul_upper_unsigned_unsigned_imm_64(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = ({s1} as u128 * {s2} as u128) >> 64")
    }

    fn mul_upper_signed_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = ({s1} as i64 * {s2} as u64) >> 32")
    }

    fn mul_upper_signed_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = ({s1} as i128 * {s2} as u128) >> 64")
    }

    fn div_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} /u {s2}")
    }

    fn div_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} /s {s2}")
    }

    fn rem_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} %u {s2}")
    }

    fn rem_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} %s {s2}")
    }

    fn div_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "i64 {d} = i64 {s1} /u i64 {s2}")
    }

    fn div_signed_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "i32 {d} = i64 {s1} /s i64 {s2}")
    }

    fn rem_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "i64 {d} = i64 {s1} %u i64 {s2}")
    }

    fn rem_signed_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "i64 {d} = i64 {s1} %s i64 {s2}")
    }

    fn set_less_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} <u 0x{s2:x}")
    }

    fn set_less_than_unsigned_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "i64 {d} = {s1} <u 0x{s2:x}")
    }

    fn set_greater_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} >u 0x{s2:x}")
    }

    fn set_greater_than_unsigned_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} >u 0x{s2:x}")
    }

    fn set_less_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} <s {s2}", s2 = s2 as i32)
    }

    fn set_less_than_signed_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "i64 {d} = {s1} <s {s2}", s2 = s2 as i32)
    }

    fn set_greater_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} >s {s2}", s2 = s2 as i32)
    }

    fn set_greater_than_signed_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} >s {s2}", s2 = s2 as i32)
    }

    fn shift_logical_right_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} >> {s2}")
    }

    fn shift_logical_right_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >> {s2}")
    }

    fn shift_arithmetic_right_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} >>a {s2}")
    }

    fn shift_logical_right_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} >>64 {s2}")
    }

    fn shift_logical_right_64_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >>64 {s2}")
    }

    fn shift_arithmetic_right_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} >>a64 {s2}")
    }

    fn shift_arithmetic_right_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >>a {s2}")
    }

    fn shift_logical_left_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} << {s2}")
    }

    fn shift_logical_left_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} << {s2}")
    }

    fn shift_arithmetic_right_64_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} >>a64 {s2}")
    }

    fn shift_logical_left_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} <<64 {s2}")
    }

    fn shift_logical_left_64_imm_alt(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} <<64 {s2}")
    }

    fn or_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} | 0x{s2:x}")
    }

    fn and_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} & 0x{s2:x}")
    }

    fn xor_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} ^ 0x{s2:x}")
    }

    fn or_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "i64 {d} = {s1} | 0x{s2:x}")
    }

    fn and_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "i64 {d} = {s1} & 0x{s2:x}")
    }

    fn xor_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "i64 {d} = {s1} ^ 0x{s2:x}")
    }

    fn load_imm(&mut self, d: RawReg, a: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        write!(self, "{d} = 0x{a:x}")
    }

    fn move_reg(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s = self.format_reg(s);
        write!(self, "{d} = {s}")
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

    fn cmov_if_zero_imm(&mut self, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let c = self.format_reg(c);
        write!(self, "{d} = {s} if {c} == 0")
    }

    fn cmov_if_not_zero_imm(&mut self, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let c = self.format_reg(c);
        write!(self, "{d} = {s} if {c} != 0")
    }

    fn add_64_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        if !self.format.prefer_unaliased && (s2 as i32) < 0 && (s2 as i32) > -4096 {
            write!(self, "i64 {d} = i64 {s1} - i64 {s2}", s2 = -(s2 as i32))
        } else {
            write!(self, "i64 {d} = i64 {s1} + 0x{s2:x}")
        }
    }

    fn add_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        if !self.format.prefer_unaliased && (s2 as i32) < 0 && (s2 as i32) > -4096 {
            write!(self, "{d} = {s1} - {s2}", s2 = -(s2 as i32))
        } else {
            write!(self, "{d} = {s1} + 0x{s2:x}")
        }
    }

    fn negate_and_add_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        if !self.format.prefer_unaliased && s2 == 0 {
            write!(self, "{d} = -{s1}")
        } else {
            write!(self, "{d} = -{s1} + {s2}")
        }
    }

    fn store_imm_indirect_u8(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        let base = self.format_reg(base);
        write!(self, "u8 [{base} + {offset}] = {value}")
    }

    fn store_imm_indirect_u16(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        let base = self.format_reg(base);
        write!(self, "u16 [{base} + {offset}] = {value}")
    }

    fn store_imm_indirect_u32(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        let base = self.format_reg(base);
        write!(self, "u32 [{base} + {offset}] = {value}")
    }

    fn store_imm_indirect_u64(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        let base = self.format_reg(base);
        write!(self, "u64 [{base} + {offset}] = {value}")
    }

    fn store_indirect_u8(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "u8 [{base} + {offset}] = {src}")
        } else {
            write!(self, "u8 [{base}] = {src}")
        }
    }

    fn store_indirect_u16(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "u16 [{base} + {offset}] = {src}")
        } else {
            write!(self, "u16 [{base}] = {src}")
        }
    }

    fn store_indirect_u32(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "u32 [{base} + {offset}] = {src}")
        } else {
            write!(self, "u32 [{base}] = {src}")
        }
    }

    fn store_indirect_u64(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "u64 [{base} + {offset}] = {src}")
        } else {
            write!(self, "u64 [{base}] = {src}")
        }
    }

    fn store_imm_u8(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        write!(self, "u8 [0x{offset:x}] = {value}")
    }

    fn store_imm_u16(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        write!(self, "u16 [0x{offset:x}] = {value}")
    }

    fn store_imm_u32(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        write!(self, "u32 [0x{offset:x}] = {value}")
    }

    fn store_imm_u64(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        write!(self, "u64 [0x{offset:x}] = {value}")
    }

    fn store_u8(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        write!(self, "u8 [0x{offset:x}] = {src}")
    }

    fn store_u16(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        write!(self, "u16 [0x{offset:x}] = {src}")
    }

    fn store_u32(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        write!(self, "u32 [0x{offset:x}] = {src}")
    }

    fn store_u64(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        let src = self.format_reg(src);
        write!(self, "u64 [0x{offset:x}] = {src}")
    }

    fn load_indirect_u8(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "{} = u8 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = u8 [{}]", dst, base)
        }
    }

    fn load_indirect_i8(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "{} = i8 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = i8 [{}]", dst, base)
        }
    }

    fn load_indirect_u16(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "{} = u16 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = u16 [{} ]", dst, base)
        }
    }

    fn load_indirect_i16(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "{} = i16 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = i16 [{}]", dst, base)
        }
    }

    fn load_indirect_u32(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "{} = u32 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = u32 [{}]", dst, base)
        }
    }

    fn load_indirect_i32(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "{} = i32 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = i32 [{}]", dst, base)
        }
    }

    fn load_indirect_u64(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        let base = self.format_reg(base);
        if self.format.prefer_unaliased || offset != 0 {
            write!(self, "{} = u64 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = u64 [{}]", dst, base)
        }
    }

    fn load_u8(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        write!(self, "{} = u8 [0x{:x}]", dst, offset)
    }

    fn load_i8(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        write!(self, "{} = i8 [0x{:x}]", dst, offset)
    }

    fn load_u16(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        write!(self, "{} = u16 [0x{:x}]", dst, offset)
    }

    fn load_i16(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        write!(self, "{} = i16 [0x{:x}]", dst, offset)
    }

    fn load_i32(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        write!(self, "{} = i32 [0x{:x}]", dst, offset)
    }

    fn load_u32(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        write!(self, "{} = u32 [0x{:x}]", dst, offset)
    }

    fn load_u64(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        write!(self, "{} = u64 [0x{:x}]", dst, offset)
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

    fn branch_less_unsigned_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} <u {}", imm, s1, s2)
    }

    fn branch_less_signed_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
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

    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} >=u {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_signed_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
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

    fn branch_eq_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} == {}", imm, s1, s2)
    }

    fn branch_not_eq_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} != {}", imm, s1, s2)
    }

    fn branch_less_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} <=u {}", imm, s1, s2)
    }

    fn branch_less_or_equal_signed_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} <=s {}", imm, s1, s2)
    }

    fn branch_greater_unsigned_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} >u {}", imm, s1, s2)
    }

    fn branch_greater_signed_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let imm = self.format_jump(imm);
        write!(self, "jump {} if {} >s {}", imm, s1, s2)
    }

    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        let target = self.format_jump(target);
        write!(self, "jump {}", target)
    }

    fn load_imm_and_jump(&mut self, ra: RawReg, value: u32, target: u32) -> Self::ReturnTy {
        let ra = self.format_reg(ra);
        let target = self.format_jump(target);
        write!(self, "{ra} = {value}, jump {target}")
    }

    fn jump_indirect(&mut self, base: RawReg, offset: u32) -> Self::ReturnTy {
        if !self.format.prefer_unaliased {
            match (base, offset) {
                (_, 0) if base == Reg::RA.into() => return write!(self, "ret"),
                (_, 0) => return write!(self, "jump [{}]", self.format_reg(base)),
                (_, _) => {}
            }
        }

        write!(self, "jump [{} + {}]", self.format_reg(base), offset)
    }

    fn load_imm_and_jump_indirect(&mut self, ra: RawReg, base: RawReg, value: u32, offset: u32) -> Self::ReturnTy {
        let ra = self.format_reg(ra);
        let base = self.format_reg(base);
        if ra != base {
            if !self.format.prefer_unaliased && offset == 0 {
                write!(self, "{ra} = {value}, jump [{base}]")
            } else {
                write!(self, "{ra} = {value}, jump [{base} + {offset}]")
            }
        } else if !self.format.prefer_unaliased && offset == 0 {
            write!(self, "tmp = {base}, {ra} = {value}, jump [tmp]")
        } else {
            write!(self, "tmp = {base}, {ra} = {value}, jump [tmp + {offset}]")
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

#[cfg(feature = "std")]
impl std::error::Error for ProgramParseError {}

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
#[derive(Clone, Default)]
pub struct ProgramBlob {
    #[cfg(feature = "unique-id")]
    unique_id: u64,

    is_64_bit: bool,

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

pub fn get_bit_for_offset(bitmask: &[u8], code_len: usize, offset: u32) -> bool {
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
    let mut mask = u32::from(bitmask[offset as usize >> 3]) << 24;
    if offset >= 8 {
        mask |= u32::from(bitmask[(offset as usize >> 3) - 1]) << 16;
    }
    if offset >= 16 {
        mask |= u32::from(bitmask[(offset as usize >> 3) - 2]) << 8;
    }
    if offset >= 24 {
        mask |= u32::from(bitmask[(offset as usize >> 3) - 3]);
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

pub trait InstructionSet: Copy {
    fn opcode_from_u8(self, byte: u8) -> Option<Opcode>;
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ISA32_V1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ISA32_V1_NoSbrk;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ISA64_V1;

pub type DefaultInstructionSet = ISA32_V1;

/// Returns whether a jump to a given `offset` is allowed.
#[inline]
pub fn is_jump_target_valid<I>(instruction_set: I, code: &[u8], bitmask: &[u8], offset: u32) -> bool
where
    I: InstructionSet,
{
    if !get_bit_for_offset(bitmask, code.len(), offset) {
        // We can't jump if there's no instruction here.
        return false;
    }

    if offset == 0 {
        // This is the very first instruction, so we can always jump here.
        return true;
    }

    let Some(skip) = get_previous_instruction_skip(bitmask, offset) else {
        // We can't jump if there's no previous instruction in range.
        return false;
    };

    let Some(opcode) = instruction_set.opcode_from_u8(code[offset as usize - skip as usize - 1]) else {
        // We can't jump after an invalid instruction.
        return false;
    };

    if !opcode.starts_new_basic_block() {
        // We can't jump after this instruction.
        return false;
    }

    true
}

#[inline]
pub fn find_start_of_basic_block<I>(instruction_set: I, code: &[u8], bitmask: &[u8], mut offset: u32) -> Option<u32>
where
    I: InstructionSet,
{
    if !get_bit_for_offset(bitmask, code.len(), offset) {
        // We can't jump if there's no instruction here.
        return None;
    }

    if offset == 0 {
        // This is the very first instruction, so we can always jump here.
        return Some(0);
    }

    loop {
        // We can't jump if there's no previous instruction in range.
        let skip = get_previous_instruction_skip(bitmask, offset)?;
        let previous_offset = offset - skip - 1;
        let opcode = instruction_set
            .opcode_from_u8(code[previous_offset as usize])
            .unwrap_or(Opcode::trap);
        if opcode.starts_new_basic_block() {
            // We can jump after this instruction.
            return Some(offset);
        }

        offset = previous_offset;
        if offset == 0 {
            return Some(0);
        }
    }
}

#[test]
fn test_is_jump_target_valid() {
    fn assert_get_previous_instruction_skip_matches_instruction_parser(code: &[u8], bitmask: &[u8]) {
        for instruction in Instructions::new(DefaultInstructionSet::default(), code, bitmask, 0, false) {
            match instruction.kind {
                Instruction::trap => {
                    let skip = get_previous_instruction_skip(bitmask, instruction.offset.0);
                    if let Some(skip) = skip {
                        let previous_offset = instruction.offset.0 - skip - 1;
                        assert_eq!(
                            Instructions::new(DefaultInstructionSet::default(), code, bitmask, previous_offset, true)
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
                                Instructions::new(DefaultInstructionSet::default(), code, bitmask, previous_offset, true)
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

    macro_rules! gen {
        ($code_length:expr, $bits:expr) => {{
            let mut bitmask = [0; ($code_length + 7) / 8];
            for bit in $bits {
                let bit: usize = bit;
                assert!(bit < $code_length);
                bitmask[bit / 8] |= (1 << (bit % 8));
            }

            let code = [Opcode::trap as u8; $code_length];
            assert_get_previous_instruction_skip_matches_instruction_parser(&code, &bitmask);
            (code, bitmask)
        }};
    }

    // Make sure the helper macro works correctly.
    assert_eq!(gen!(1, [0]).1, [0b00000001]);
    assert_eq!(gen!(2, [1]).1, [0b00000010]);
    assert_eq!(gen!(8, [7]).1, [0b10000000]);
    assert_eq!(gen!(9, [8]).1, [0b00000000, 0b00000001]);
    assert_eq!(gen!(10, [9]).1, [0b00000000, 0b00000010]);
    assert_eq!(gen!(10, [2, 9]).1, [0b00000100, 0b00000010]);

    macro_rules! assert_valid {
        ($code_length:expr, $bits:expr, $offset:expr) => {{
            let (code, bitmask) = gen!($code_length, $bits);
            assert!(is_jump_target_valid(DefaultInstructionSet::default(), &code, &bitmask, $offset));
        }};
    }

    macro_rules! assert_invalid {
        ($code_length:expr, $bits:expr, $offset:expr) => {{
            let (code, bitmask) = gen!($code_length, $bits);
            assert!(!is_jump_target_valid(DefaultInstructionSet::default(), &code, &bitmask, $offset));
        }};
    }

    assert_valid!(1, [0], 0);
    assert_invalid!(1, [], 0);
    assert_valid!(2, [0, 1], 1);
    assert_invalid!(2, [1], 1);
    assert_valid!(8, [0, 7], 7);
    assert_valid!(9, [0, 8], 8);
    assert_valid!(25, [0, 24], 24);
    assert_valid!(26, [0, 25], 25);
    assert_invalid!(27, [0, 26], 26);

    assert!(is_jump_target_valid(
        DefaultInstructionSet::default(),
        &[Opcode::load_imm as u8],
        &[0b00000001],
        0
    ));

    assert!(!is_jump_target_valid(
        DefaultInstructionSet::default(),
        &[Opcode::load_imm as u8, Opcode::load_imm as u8],
        &[0b00000011],
        1
    ));

    assert!(is_jump_target_valid(
        DefaultInstructionSet::default(),
        &[Opcode::trap as u8, Opcode::load_imm as u8],
        &[0b00000011],
        1
    ));
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
    pub fn new_unbounded(instruction_set: I, code: &'a [u8], bitmask: &'a [u8], offset: u32) -> Self {
        Self::new(instruction_set, code, bitmask, offset, false)
    }

    #[inline]
    fn new(instruction_set: I, code: &'a [u8], bitmask: &'a [u8], offset: u32, is_bounded: bool) -> Self {
        assert!(code.len() <= u32::MAX as usize);
        assert_eq!(bitmask.len(), (code.len() + 7) / 8);

        let is_valid = get_bit_for_offset(bitmask, code.len(), offset);
        let mut is_done = false;
        let (offset, invalid_offset) = if is_valid {
            (offset, None)
        } else if is_bounded {
            is_done = true;
            (core::cmp::min(offset + 1, code.len() as u32), Some(offset))
        } else {
            let next_offset = find_next_offset_unbounded(bitmask, code.len() as u32, offset);
            debug_assert!(
                next_offset as usize == code.len() || get_bit_for_offset(bitmask, code.len(), next_offset),
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

        let offset = self.offset;
        debug_assert!(get_bit_for_offset(self.bitmask, self.code.len(), offset), "bit at {offset} is zero");

        let (next_offset, instruction, is_next_instruction_invalid) =
            parse_instruction(self.instruction_set, self.code, self.bitmask, self.offset);
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
                if instruction.opcode().can_fallthrough() {
                    self.offset = self.code.len() as u32;
                } else {
                    self.offset = next_offset;
                }
            } else {
                self.offset = find_next_offset_unbounded(self.bitmask, self.code.len() as u32, next_offset);
                debug_assert!(
                    self.offset as usize == self.code.len() || get_bit_for_offset(self.bitmask, self.code.len(), self.offset),
                    "bit at {} is zero",
                    self.offset
                );
            }

            if instruction.opcode().can_fallthrough() {
                self.invalid_offset = Some(next_offset);
            }
        }

        Some(ParsedInstruction {
            kind: instruction,
            offset: ProgramCounter(offset),
            next_offset: ProgramCounter(next_offset),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.code.len() - core::cmp::min(self.offset() as usize, self.code.len())))
    }
}

#[test]
fn test_instructions_iterator_with_implicit_trap() {
    for is_bounded in [false, true] {
        let mut i = Instructions::new(
            DefaultInstructionSet::default(),
            &[Opcode::fallthrough as u8],
            &[0b00000001],
            0,
            is_bounded,
        );
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
    for is_bounded in [false, true] {
        let mut i = Instructions::new(
            DefaultInstructionSet::default(),
            &[Opcode::trap as u8],
            &[0b00000001],
            0,
            is_bounded,
        );
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
    code[0] = Opcode::fallthrough as u8;
    let mut bitmask = [0_u8; 8];
    bitmask[0] = 0b00000001;
    bitmask[7] = 0b10000000;

    let mut i = Instructions::new(DefaultInstructionSet::default(), &code, &bitmask, 0, true);
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
    code[0] = Opcode::fallthrough as u8;
    let mut bitmask = [0_u8; 8];
    bitmask[0] = 0b00000001;
    bitmask[7] = 0b10000000;

    let mut i = Instructions::new(DefaultInstructionSet::default(), &code, &bitmask, 0, false);
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
    let mut i = Instructions::new(DefaultInstructionSet::default(), &[Opcode::trap as u8; 8], &[0b10000001], 1, true);
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
    let mut i = Instructions::new(DefaultInstructionSet::default(), &[Opcode::trap as u8; 8], &[0b10000001], 1, false);
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
fn test_instructions_iterator_does_not_emit_unnecessary_invalid_instructions_if_bounded_and_ends_with_a_trap() {
    let code = [Opcode::trap as u8; 32];
    let bitmask = [0b00000001, 0b00000000, 0b00000000, 0b00000100];
    let mut i = Instructions::new(DefaultInstructionSet::default(), &code, &bitmask, 0, true);
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
    assert_eq!(i.next(), None);
}

#[test]
fn test_instructions_iterator_does_not_emit_unnecessary_invalid_instructions_if_unbounded_and_ends_with_a_trap() {
    let code = [Opcode::trap as u8; 32];
    let bitmask = [0b00000001, 0b00000000, 0b00000000, 0b00000100];
    let mut i = Instructions::new(DefaultInstructionSet::default(), &code, &bitmask, 0, false);
    assert_eq!(i.offset(), 0);
    assert_eq!(
        i.next(),
        Some(ParsedInstruction {
            kind: Instruction::trap,
            offset: ProgramCounter(0),
            next_offset: ProgramCounter(25)
        })
    );
    assert_eq!(i.offset(), 26);
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

#[derive(Clone, Default)]
#[non_exhaustive]
pub struct ProgramParts {
    pub is_64_bit: bool,
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
}

impl ProgramParts {
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
        let is_64_bit = if blob_version == BLOB_VERSION_V1_32 {
            false
        } else if blob_version == BLOB_VERSION_V1_64 {
            true
        } else {
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

        let mut parts = ProgramParts {
            is_64_bit,
            ..ProgramParts::default()
        };

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
        let parts = ProgramParts::from_bytes(bytes)?;
        Self::from_parts(parts)
    }

    /// Creates a program blob from parts.
    pub fn from_parts(parts: ProgramParts) -> Result<Self, ProgramParseError> {
        let mut blob = ProgramBlob {
            #[cfg(feature = "unique-id")]
            unique_id: 0,

            is_64_bit: parts.is_64_bit,

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
            let code_length = reader.read_varint()?;
            if code_length > VM_MAXIMUM_CODE_SIZE {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the code section is too long")));
            }

            if !matches!(jump_table_entry_size, 0..=4) {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("invalid jump table entry size")));
            }

            let Some(jump_table_length) = jump_table_entry_count.checked_mul(u32::from(jump_table_entry_size)) else {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the jump table is too long")));
            };

            blob.jump_table_entry_size = jump_table_entry_size;
            blob.jump_table = reader.read_slice_as_bytes(jump_table_length as usize)?;
            blob.code = reader.read_slice_as_bytes(code_length as usize)?;

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

    /// Returns whether the blob contains a 64-bit program.
    pub fn is_64_bit(&self) -> bool {
        self.is_64_bit
    }

    /// Calculates an unique hash of the program blob.
    pub fn unique_hash(&self, include_debug: bool) -> crate::hasher::Hash {
        let ProgramBlob {
            #[cfg(feature = "unique-id")]
                unique_id: _,
            is_64_bit,
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
        } = self;

        let mut hasher = crate::hasher::Hasher::new();

        hasher.update_u32_array([
            1_u32, // VERSION
            u32::from(*is_64_bit),
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

    /// Visits every instrution in the program.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn visit<T>(&self, dispatch_table: T, visitor: &mut T::State)
    where
        T: OpcodeVisitor<ReturnTy = ()>,
    {
        visitor_run(visitor, self, dispatch_table);
    }

    /// Returns an iterator over all of the instructions in the program.
    ///
    /// WARNING: this is unbounded and has O(n) complexity; just creating this iterator can iterate over the whole program, even if `next` is never called!
    #[inline]
    pub fn instructions<I>(&self, instruction_set: I) -> Instructions<I>
    where
        I: InstructionSet,
    {
        Instructions::new_unbounded(instruction_set, self.code(), self.bitmask(), 0)
    }

    /// Returns an interator over instructions starting at a given offset.
    ///
    /// This iterator is bounded and has O(1) complexity.
    #[inline]
    pub fn instructions_bounded_at<I>(&self, instruction_set: I, offset: ProgramCounter) -> Instructions<I>
    where
        I: InstructionSet,
    {
        Instructions::new_bounded(instruction_set, self.code(), self.bitmask(), offset.0)
    }

    /// Returns whether the given program counter is a valid target for a jump.
    pub fn is_jump_target_valid<I>(&self, instruction_set: I, target: ProgramCounter) -> bool
    where
        I: InstructionSet,
    {
        is_jump_target_valid(instruction_set, self.code(), self.bitmask(), target.0)
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
    inner: &'a LineProgramFrame,
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
        self.frames.iter().map(|inner| FrameInfo { blob: self.blob, inner })
    }
}

#[derive(Default)]
struct LineProgramFrame {
    kind: Option<FrameKind>,
    namespace_offset: u32,
    function_name_offset: u32,
    path_offset: u32,
    line: u32,
    column: u32,
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
        struct SetTrueOnDrop<'a>(&'a mut bool);
        impl<'a> Drop for SetTrueOnDrop<'a> {
            fn drop(&mut self) {
                *self.0 = true;
            }
        }

        if self.is_finished {
            return Ok(None);
        }

        // Put an upper limit to how many instructions we'll process.
        const INSTRUCTION_LIMIT_PER_REGION: usize = 512;

        let mark_as_finished_on_drop = SetTrueOnDrop(&mut self.is_finished);
        for _ in 0..INSTRUCTION_LIMIT_PER_REGION {
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

            let frames = &self.stack[..core::cmp::min(stack_depth as usize, self.stack.len())];
            core::mem::forget(mark_as_finished_on_drop);

            let entry_index = self.region_counter;
            self.region_counter += 1;
            return Ok(Some(RegionInfo {
                entry_index,
                blob: self.blob,
                range,
                frames,
            }));
        }

        Err(ProgramParseError(ProgramParseErrorKind::Other(
            "found a line program with too many instructions",
        )))
    }
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
pub const SECTION_END_OF_FILE: u8 = 0;

pub const BLOB_VERSION_V1_64: u8 = 0;
pub const BLOB_VERSION_V1_32: u8 = 1;

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
