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

#[allow(clippy::partial_pub_fields)]
#[doc(hidden)]
pub struct VisitorHelper<T> {
    pub visitor: T,
}

impl<T> VisitorHelper<T> {
    #[allow(clippy::type_complexity)]
    #[inline(never)]
    #[cold]
    fn step_slow(
        &mut self,
        code: &[u8],
        bitmask: &[u8],
        instruction_offset: usize,
        decode_table: &[fn(state: &mut Self, chunk: u128, instruction_offset: u32, args_length: u32) -> <T as ParsingVisitor>::ReturnTy],
    ) -> Option<(usize, <T as ParsingVisitor>::ReturnTy)>
    where
        T: ParsingVisitor,
    {
        let (next_offset, args_length) = parse_bitmask_slow(bitmask, instruction_offset)?;
        let chunk_length = core::cmp::min(16, args_length + 1);
        let chunk = code.get(instruction_offset..instruction_offset + chunk_length)?;
        let opcode = chunk[0];

        let mut t: [u8; 16] = [0; 16];
        t[..chunk_length].copy_from_slice(chunk);
        let chunk = u128::from_le_bytes([
            t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], t[9], t[10], t[11], t[12], t[13], t[14], t[15],
        ]) >> 8;

        Some((
            next_offset,
            decode_table[opcode as usize](self, chunk, instruction_offset as u32, args_length as u32),
        ))
    }

    #[allow(clippy::type_complexity)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn step(
        &mut self,
        code: &[u8],
        bitmask: &[u8],
        instruction_offset: usize,
        decode_table: &[fn(state: &mut Self, chunk: u128, instruction_offset: u32, args_length: u32) -> <T as ParsingVisitor>::ReturnTy],
    ) -> Option<(usize, <T as ParsingVisitor>::ReturnTy)>
    where
        T: ParsingVisitor,
    {
        if let Some((next_offset, args_length)) = parse_bitmask_fast(bitmask, instruction_offset) {
            debug_assert!(args_length <= BITMASK_MAX as usize);
            if let Some(chunk) = code.get(instruction_offset..instruction_offset + 32) {
                assert!(chunk.len() >= 32);
                let opcode = chunk[0];

                // NOTE: This should produce the same assembly as the unsafe `read_unaligned`.
                let chunk = u128::from_le_bytes([
                    chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7], chunk[8], chunk[9], chunk[10], chunk[11],
                    chunk[12], chunk[13], chunk[14], chunk[15], chunk[16],
                ]);

                return Some((
                    next_offset,
                    decode_table[opcode as usize](self, chunk, instruction_offset as u32, args_length as u32),
                ));
            }
        }

        self.step_slow(code, bitmask, instruction_offset, decode_table)
    }

    #[inline]
    pub fn new(visitor: T) -> Self {
        VisitorHelper { visitor }
    }

    #[allow(clippy::type_complexity)]
    #[inline]
    pub fn run(
        mut self,
        blob: &ProgramBlob,
        decode_table: &[fn(&mut Self, chunk: u128, instruction_offset: u32, args_length: u32) -> <T as ParsingVisitor>::ReturnTy; 256],
    ) -> T
    where
        T: ParsingVisitor<ReturnTy = ()>,
    {
        let code = blob.code();
        let bitmask = blob.bitmask();
        debug_assert_eq!(bitmask[0] & 0b1, 1);

        let mut offset = 0;
        loop {
            let Some((next_offset, ())) = self.step(code, bitmask, offset, decode_table) else {
                break;
            };
            offset = next_offset;
        }

        self.visitor
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

macro_rules! define_opcodes {
    (@impl_shared $($name:ident = $value:expr,)+) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
        #[repr(u8)]
        pub enum Opcode {
            $(
                $name = $value,
            )+
        }

        impl Opcode {
            #[cfg_attr(feature = "alloc", inline)]
            pub fn from_u8(byte: u8) -> Option<Opcode> {
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

        #[test]
        fn test_opcode_from_u8() {
            fn from_u8_naive(byte: u8) -> Option<Opcode> {
                match byte {
                    $($value => Some(Opcode::$name),)+
                    _ => None
                }
            }

            for byte in 0..=255 {
                assert_eq!(from_u8_naive(byte), Opcode::from_u8(byte));
            }
        }

        const IS_INSTRUCTION_VALID_CONST: [bool; 256] = {
            let mut is_valid = [false; 256];
            $(
                is_valid[$value] = true;
            )+
            is_valid
        };

        #[cfg(feature = "alloc")]
        static IS_INSTRUCTION_VALID: [bool; 256] = IS_INSTRUCTION_VALID_CONST;

        #[cfg(not(feature = "alloc"))]
        use IS_INSTRUCTION_VALID_CONST as IS_INSTRUCTION_VALID;
    };

    (
        $d:tt

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

            #[inline(never)]
            #[cold]
            fn invalid(&mut self, offset: u32, args_length: u32) -> Self::ReturnTy {
                self.trap(offset, args_length)
            }
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

            #[inline(never)]
            #[cold]
            fn invalid(&mut self) -> Self::ReturnTy {
                self.trap()
            }
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
            invalid = 88,
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
        macro_rules! prepare_visitor {
            (@define_table $table_name:ident, $visitor_ty:ident<$d($visitor_ty_params:tt),*>) => {
                use $crate::program::{
                    ParsingVisitor,
                    VisitorHelper,
                };

                type ReturnTy<$d($visitor_ty_params),*> = <$visitor_ty<$d($visitor_ty_params),*> as ParsingVisitor>::ReturnTy;
                type VisitFn<$d($visitor_ty_params),*> = fn(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>;

                #[allow(unsafe_code)]
                static $table_name: [VisitFn; 256] = {
                    let mut table = [invalid_instruction as VisitFn; 256];
                    $({
                        // Putting all of the handlers in a single link section can make a big difference
                        // when it comes to performance, even up to 10% in some cases. This will force the
                        // compiler and the linker to put all of this code near each other, minimizing
                        // instruction cache misses.
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_argless<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, _chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            state.visitor.$name_argless(instruction_offset, args_length)
                        }

                        table[$value_argless] = $name_argless;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm) = $crate::program::read_args_reg_imm(chunk, args_length);
                            state.visitor.$name_reg_imm(instruction_offset, args_length, reg, imm)
                        }

                        table[$value_reg_imm] = $name_reg_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_offset<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm_offset(chunk, instruction_offset, args_length);
                            state.visitor.$name_reg_imm_offset(instruction_offset, args_length, reg, imm1, imm2)
                        }

                        table[$value_reg_imm_offset] = $name_reg_imm_offset;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm1, imm2) = $crate::program::read_args_reg_imm2(chunk, args_length);
                            state.visitor.$name_reg_imm_imm(instruction_offset, args_length, reg, imm1, imm2)
                        }

                        table[$value_reg_imm_imm] = $name_reg_imm_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_imm(chunk, args_length);
                            state.visitor.$name_reg_reg_imm(instruction_offset, args_length, reg1, reg2, imm)
                        }

                        table[$value_reg_reg_imm] = $name_reg_reg_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_offset<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm) = $crate::program::read_args_regs2_offset(chunk, instruction_offset, args_length);
                            state.visitor.$name_reg_reg_offset(instruction_offset, args_length, reg1, reg2, imm)
                        }

                        table[$value_reg_reg_offset] = $name_reg_reg_offset;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_reg<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, reg3) = $crate::program::read_args_regs3(chunk);
                            state.visitor.$name_reg_reg_reg(instruction_offset, args_length, reg1, reg2, reg3)
                        }

                        table[$value_reg_reg_reg] = $name_reg_reg_reg;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_offset<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let imm = $crate::program::read_args_offset(chunk, instruction_offset, args_length);
                            state.visitor.$name_offset(instruction_offset, args_length, imm)
                        }

                        table[$value_offset] = $name_offset;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let imm = $crate::program::read_args_imm(chunk, args_length);
                            state.visitor.$name_imm(instruction_offset, args_length, imm)
                        }

                        table[$value_imm] = $name_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (imm1, imm2) = $crate::program::read_args_imm2(chunk, args_length);
                            state.visitor.$name_imm_imm(instruction_offset, args_length, imm1, imm2)
                        }

                        table[$value_imm_imm] = $name_imm_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2) = $crate::program::read_args_regs2(chunk);
                            state.visitor.$name_reg_reg(instruction_offset, args_length, reg1, reg2)
                        }

                        table[$value_reg_reg] = $name_reg_reg;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm1, imm2) = $crate::program::read_args_regs2_imm2(chunk, args_length);
                            state.visitor.$name_reg_reg_imm_imm(instruction_offset, args_length, reg1, reg2, imm1, imm2)
                        }

                        table[$value_reg_reg_imm_imm] = $name_reg_reg_imm_imm;
                    })*

                    #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                    #[cold]
                    fn invalid_instruction<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>, _chunk: u128, instruction_offset: u32, args_length: u32) -> ReturnTy<$d($visitor_ty_params),*>{
                        state.visitor.invalid(instruction_offset, args_length)
                    }

                    table
                };
            };

            ($table_name:ident, $visitor_ty:ident<$d($visitor_ty_params:tt),*>) => {{
                $crate::program::prepare_visitor!(@define_table $table_name, $visitor_ty<$d($visitor_ty_params),*>);

                #[inline]
                fn run<$d($visitor_ty_params),*>(
                    blob: &ProgramBlob,
                    visitor: $visitor_ty<$d($visitor_ty_params),*>,
                )
                    -> $visitor_ty<$d($visitor_ty_params),*>
                {
                    let decode_table: &'static [VisitFn; 256] = &$table_name;

                    #[allow(unsafe_code)]
                    // SAFETY: Here we transmute the lifetimes which were unnecessarily extended to be 'static due to the table here being a `static`.
                    let decode_table: &[VisitFn; 256] = unsafe { core::mem::transmute(decode_table) };

                    VisitorHelper::new(visitor).run(blob, decode_table)
                }

                run
            }};
        }

        pub use prepare_visitor;

        impl<'a> ParsingVisitor for ToEnumVisitor<'a> {
            type ReturnTy = Instruction;

            $(fn $name_argless(&mut self, _offset: u32, args_length: u32) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_argless
            })+
            $(fn $name_reg_imm(&mut self, _offset: u32, args_length: u32, reg: RawReg, imm: u32) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_reg_imm(reg, imm)
            })+
            $(fn $name_reg_imm_offset(&mut self, _offset: u32, args_length: u32, reg: RawReg, imm1: u32, imm2: u32) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_reg_imm_offset(reg, imm1, imm2)
            })+
            $(fn $name_reg_imm_imm(&mut self, _offset: u32, args_length: u32, reg: RawReg, imm1: u32, imm2: u32) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_reg_imm_imm(reg, imm1, imm2)
            })+
            $(fn $name_reg_reg_imm(&mut self, _offset: u32, args_length: u32, reg1: RawReg, reg2: RawReg, imm: u32) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_reg_reg_imm(reg1, reg2, imm)
            })+
            $(fn $name_reg_reg_offset(&mut self, _offset: u32, args_length: u32, reg1: RawReg, reg2: RawReg, imm: u32) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_reg_reg_offset(reg1, reg2, imm)
            })+
            $(fn $name_reg_reg_reg(&mut self, _offset: u32, args_length: u32, reg1: RawReg, reg2: RawReg, reg3: RawReg) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_reg_reg_reg(reg1, reg2, reg3)
            })+
            $(fn $name_offset(&mut self, _offset: u32, args_length: u32, imm: u32) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_offset(imm)
            })+
            $(fn $name_imm(&mut self, _offset: u32, args_length: u32, imm: u32) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_imm(imm)
            })+
            $(fn $name_imm_imm(&mut self, _offset: u32, args_length: u32, imm1: u32, imm2: u32) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_imm_imm(imm1, imm2)
            })+
            $(fn $name_reg_reg(&mut self, _offset: u32, args_length: u32, reg1: RawReg, reg2: RawReg) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_reg_reg(reg1, reg2)
            })+
            $(fn $name_reg_reg_imm_imm(&mut self, _offset: u32, args_length: u32, reg1: RawReg, reg2: RawReg, imm1: u32, imm2: u32) -> Self::ReturnTy {
                self.args_length = args_length;
                Instruction::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2)
            })+
        }

        define_opcodes!(
            @impl_shared
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
        );
    }
}

struct ToEnumVisitor<'a> {
    args_length: u32,
    phantom: core::marker::PhantomData<&'a ()>,
}

#[inline]
fn parse_instruction(code: &[u8], bitmask: &[u8], offset: &mut usize) -> Option<ParsedInstruction> {
    prepare_visitor!(@define_table TO_ENUM_VISITOR, ToEnumVisitor<'a>);

    let decode_table: &[VisitFn; 256] = &TO_ENUM_VISITOR;

    #[allow(unsafe_code)]
    // SAFETY: Here we transmute the lifetimes which were unnecessarily extended to be 'static due to the table here being a `static`.
    let decode_table: &[VisitFn; 256] = unsafe { core::mem::transmute(decode_table) };

    let mut helper = VisitorHelper::new(ToEnumVisitor {
        args_length: 0,
        phantom: core::marker::PhantomData,
    });

    let origin = *offset;
    let (next_offset, instruction) = helper.step(code, bitmask, origin, decode_table)?;
    *offset = next_offset;

    let length = helper.visitor.args_length + 1;
    Some(ParsedInstruction {
        kind: instruction,
        offset: ProgramCounter(origin as u32),
        length,
    })
}

#[test]
#[ignore]
fn test_parse_instruction() {
    // Instruction with no arguments.
    assert_eq!(
        parse_instruction(&[Opcode::fallthrough as u8], &[0b11111111], &mut 0),
        Some(ParsedInstruction {
            kind: Instruction::fallthrough,
            offset: ProgramCounter(0),
            length: 1
        })
    );

    // Instruction with no arguments, overparametrized.
    assert_eq!(
        parse_instruction(&[Opcode::fallthrough as u8, 0xff], &[0b00000101], &mut 0),
        Some(ParsedInstruction {
            kind: Instruction::fallthrough,
            offset: ProgramCounter(0),
            length: 2
        })
    );

    // Instruction with no arguments, overparametrized, truncated code.
    assert_eq!(parse_instruction(&[Opcode::fallthrough as u8], &[0b00000101], &mut 0), None);

    // Instruction with no arguments, overparametrized until end of code.
    assert_eq!(
        parse_instruction(
            &[Opcode::fallthrough as u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0b00000001],
            &mut 0
        ),
        Some(ParsedInstruction {
            kind: Instruction::fallthrough,
            offset: ProgramCounter(0),
            length: 8
        })
    );

    // Instruction with one immediate argument.
    assert_eq!(
        parse_instruction(&[Opcode::ecalli as u8], &[0b00000011], &mut 0),
        Some(ParsedInstruction {
            kind: Instruction::ecalli(0),
            offset: ProgramCounter(0),
            length: 1
        })
    );

    assert_eq!(
        parse_instruction(&[Opcode::ecalli as u8, 0xff, 0xff, 0xff, 0xff], &[0b00100001], &mut 0),
        Some(ParsedInstruction {
            kind: Instruction::ecalli(0x80000000),
            offset: ProgramCounter(0),
            length: 5
        })
    );

    // Instruction with one immediate argument, overparametrized.
    assert_eq!(
        parse_instruction(&[Opcode::ecalli as u8, 0xff, 0xff, 0xff, 0xff, 0x66], &[0b01000001], &mut 0),
        Some(ParsedInstruction {
            kind: Instruction::ecalli(0x80000000),
            offset: ProgramCounter(0),
            length: 6
        })
    );

    // Instruction with two registers and one immediate argument.
    assert_eq!(
        parse_instruction(&[Opcode::add_imm as u8, 0x00, 0xff, 0xff, 0xff, 0xff], &[0b01000001], &mut 0),
        Some(ParsedInstruction {
            kind: Instruction::add_imm(Reg::RA.into(), Reg::RA.into(), 0x80000000),
            offset: ProgramCounter(0),
            length: 6
        })
    );

    // Instruction with two registers and one immediate argument, overparametrized.
    assert_eq!(
        parse_instruction(&[Opcode::add_imm as u8, 0x00, 0xff, 0xff, 0xff, 0xff, 0x66], &[0b10000001], &mut 0),
        Some(ParsedInstruction {
            kind: Instruction::add_imm(Reg::RA.into(), Reg::RA.into(), 0x80000000),
            offset: ProgramCounter(0),
            length: 7
        })
    );

    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    let length = 512;
    let mut bitmask = vec![0; length / 8];
    bitmask[0] = 0b00000001;
    let mut code = Vec::new();
    code.resize(length, 0xff);
    code[0] = Opcode::add_imm as u8;
    code[1] = 0x00;
    assert_eq!(
        parse_instruction(&code, &bitmask, &mut 0),
        Some(ParsedInstruction {
            kind: Instruction::add_imm(Reg::RA.into(), Reg::RA.into(), 0x80000000),
            offset: ProgramCounter(0),
            length: 25
        })
    );
}

// NOTE: The opcodes here are assigned roughly in the order of how common a given instruction is,
// except the `trap` which is deliberately hardcoded as zero.
define_opcodes! {
    $

    // Instructions with args: none
    [
        trap                                     = 0,
        fallthrough                              = 17,
    ]

    // Instructions with args: reg, imm
    [
        jump_indirect                            = 19,
        load_imm                                 = 4,
        load_u8                                  = 60,
        load_i8                                  = 74,
        load_u16                                 = 76,
        load_i16                                 = 66,
        load_u32                                 = 10,
        store_u8                                 = 71,
        store_u16                                = 69,
        store_u32                                = 22,
    ]

    // Instructions with args: reg, imm, offset
    [
        load_imm_and_jump                        = 6,
        branch_eq_imm                            = 7,
        branch_not_eq_imm                        = 15,
        branch_less_unsigned_imm                 = 44,
        branch_less_signed_imm                   = 32,
        branch_greater_or_equal_unsigned_imm     = 52,
        branch_greater_or_equal_signed_imm       = 45,
        branch_less_or_equal_signed_imm          = 46,
        branch_less_or_equal_unsigned_imm        = 59,
        branch_greater_signed_imm                = 53,
        branch_greater_unsigned_imm              = 50,
    ]

    // Instructions with args: reg, imm, imm
    [
        store_imm_indirect_u8                    = 26,
        store_imm_indirect_u16                   = 54,
        store_imm_indirect_u32                   = 13,
    ]

    // Instructions with args: reg, reg, imm
    [
        store_indirect_u8                        = 16,
        store_indirect_u16                       = 29,
        store_indirect_u32                       = 3,
        load_indirect_u8                         = 11,
        load_indirect_i8                         = 21,
        load_indirect_u16                        = 37,
        load_indirect_i16                        = 33,
        load_indirect_u32                        = 1,
        add_imm                                  = 2,
        and_imm                                  = 18,
        xor_imm                                  = 31,
        or_imm                                   = 49,
        mul_imm                                  = 35,
        mul_upper_signed_signed_imm              = 65,
        mul_upper_unsigned_unsigned_imm          = 63,
        set_less_than_unsigned_imm               = 27,
        set_less_than_signed_imm                 = 56,
        shift_logical_left_imm                   = 9,
        shift_logical_right_imm                  = 14,
        shift_arithmetic_right_imm               = 25,
        negate_and_add_imm                       = 40,
        set_greater_than_unsigned_imm            = 39,
        set_greater_than_signed_imm              = 61,
        shift_logical_right_imm_alt              = 72,
        shift_arithmetic_right_imm_alt           = 80,
        shift_logical_left_imm_alt               = 75,

        cmov_if_zero_imm                         = 85,
        cmov_if_not_zero_imm                     = 86,
    ]

    // Instructions with args: reg, reg, offset
    [
        branch_eq                                = 24,
        branch_not_eq                            = 30,
        branch_less_unsigned                     = 47,
        branch_less_signed                       = 48,
        branch_greater_or_equal_unsigned         = 41,
        branch_greater_or_equal_signed           = 43,
    ]

    // Instructions with args: reg, reg, reg
    [
        add                                      = 8,
        sub                                      = 20,
        and                                      = 23,
        xor                                      = 28,
        or                                       = 12,
        mul                                      = 34,
        mul_upper_signed_signed                  = 67,
        mul_upper_unsigned_unsigned              = 57,
        mul_upper_signed_unsigned                = 81,
        set_less_than_unsigned                   = 36,
        set_less_than_signed                     = 58,
        shift_logical_left                       = 55,
        shift_logical_right                      = 51,
        shift_arithmetic_right                   = 77,
        div_unsigned                             = 68,
        div_signed                               = 64,
        rem_unsigned                             = 73,
        rem_signed                               = 70,

        cmov_if_zero                             = 83,
        cmov_if_not_zero                         = 84,
    ]

    // Instructions with args: offset
    [
        jump                                     = 5,
    ]

    // Instructions with args: imm
    [
        ecalli                                   = 78,
    ]

    // Instructions with args: imm, imm
    [
        store_imm_u8                             = 62,
        store_imm_u16                            = 79,
        store_imm_u32                            = 38,
    ]

    // Instructions with args: reg, reg
    [
        move_reg                                 = 82,
        sbrk                                     = 87,
    ]

    // Instructions with args: reg, reg, imm, imm
    [
        load_imm_and_jump_indirect               = 42,
    ]
}

impl Opcode {
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
    pub fn display(self, format: &'_ InstructionFormat) -> impl core::fmt::Display + '_ {
        struct Inner<'a> {
            instruction: Instruction,
            format: &'a InstructionFormat,
        }

        impl<'a> core::fmt::Display for Inner<'a> {
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
pub struct InstructionFormat {
    pub prefer_non_abi_reg_names: bool,
    pub prefer_unaliased: bool,
}

struct InstructionFormatter<'a, 'b> {
    format: &'a InstructionFormat,
    fmt: &'a mut core::fmt::Formatter<'b>,
}

impl<'a, 'b> InstructionFormatter<'a, 'b> {
    fn format_reg(&self, reg: RawReg) -> &'static str {
        if self.format.prefer_non_abi_reg_names {
            reg.get().name_non_abi()
        } else {
            reg.get().name()
        }
    }
}

impl<'a, 'b> core::fmt::Write for InstructionFormatter<'a, 'b> {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.fmt.write_str(s)
    }
}

impl<'a, 'b> InstructionVisitor for InstructionFormatter<'a, 'b> {
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

    fn add(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} + {s2}")
    }

    fn sub(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} - {s2}")
    }

    fn mul(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = {s1} * {s2}")
    }

    fn mul_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} * {s2}")
    }

    fn mul_upper_signed_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = ({s1} as i64 * {s2} as i64) >> 32")
    }

    fn mul_upper_signed_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = ({s1} as i64 * {s2} as i64) >> 32", s2 = s2 as i32)
    }

    fn mul_upper_unsigned_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = ({s1} as u64 * {s2} as u64) >> 32")
    }

    fn mul_upper_unsigned_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = ({s1} as u64 * {s2} as u64) >> 32")
    }

    fn mul_upper_signed_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "{d} = ({s1} as i64 * {s2} as u64) >> 32")
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

    fn set_less_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} <u 0x{s2:x}")
    }

    fn set_greater_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} >u 0x{s2:x}")
    }

    fn set_less_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        let d = self.format_reg(d);
        let s1 = self.format_reg(s1);
        write!(self, "{d} = {s1} <s {s2}", s2 = s2 as i32)
    }

    fn set_greater_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
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

    fn store_imm_u8(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        write!(self, "u8 [0x{offset:x}] = {value}")
    }

    fn store_imm_u16(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        write!(self, "u16 [0x{offset:x}] = {value}")
    }

    fn store_imm_u32(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        write!(self, "u32 [0x{offset:x}] = {value}")
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

    fn load_u32(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        let dst = self.format_reg(dst);
        write!(self, "{} = u32 [0x{:x}]", dst, offset)
    }

    fn branch_less_unsigned(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "jump {} if {} <u {}", imm, s1, s2)
    }

    fn branch_less_signed(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "jump {} if {} <s {}", imm, s1, s2)
    }

    fn branch_less_unsigned_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        write!(self, "jump {} if {} <u {}", imm, s1, s2)
    }

    fn branch_less_signed_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        write!(self, "jump {} if {} <s {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "jump {} if {} >=u {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_signed(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "jump {} if {} >=s {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        write!(self, "jump {} if {} >=u {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_signed_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        write!(self, "jump {} if {} >=s {}", imm, s1, s2)
    }

    fn branch_eq(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "jump {} if {} == {}", imm, s1, s2)
    }

    fn branch_not_eq(&mut self, s1: RawReg, s2: RawReg, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        let s2 = self.format_reg(s2);
        write!(self, "jump {} if {} != {}", imm, s1, s2)
    }

    fn branch_eq_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        write!(self, "jump {} if {} == {}", imm, s1, s2)
    }

    fn branch_not_eq_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        write!(self, "jump {} if {} != {}", imm, s1, s2)
    }

    fn branch_less_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        write!(self, "jump {} if {} <=u {}", imm, s1, s2)
    }

    fn branch_less_or_equal_signed_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        write!(self, "jump {} if {} <=s {}", imm, s1, s2)
    }

    fn branch_greater_unsigned_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        write!(self, "jump {} if {} >u {}", imm, s1, s2)
    }

    fn branch_greater_signed_imm(&mut self, s1: RawReg, s2: u32, imm: u32) -> Self::ReturnTy {
        let s1 = self.format_reg(s1);
        write!(self, "jump {} if {} >s {}", imm, s1, s2)
    }

    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        write!(self, "jump {}", target)
    }

    fn load_imm_and_jump(&mut self, ra: RawReg, value: u32, target: u32) -> Self::ReturnTy {
        let ra = self.format_reg(ra);
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

const BITMASK_MAX: u32 = 24;

#[cfg_attr(not(debug_assertions), inline(always))]
fn parse_bitmask_slow(bitmask: &[u8], mut offset: usize) -> Option<(usize, usize)> {
    if bitmask.is_empty() {
        return None;
    }

    offset += 1;
    let mut args_length = 0;
    while let Some(&byte) = bitmask.get(offset >> 3) {
        let shift = offset & 7;
        let mask = byte >> shift;
        let length = if mask == 0 {
            8 - shift
        } else {
            let length = mask.trailing_zeros() as usize;
            if length == 0 {
                break;
            }
            length
        };

        let new_args_length = args_length + length;
        if new_args_length >= BITMASK_MAX as usize {
            offset += BITMASK_MAX as usize - args_length;
            args_length = BITMASK_MAX as usize;
            break;
        }

        args_length = new_args_length;
        offset += length;
    }

    Some((offset, args_length))
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn parse_bitmask_fast(bitmask: &[u8], mut offset: usize) -> Option<(usize, usize)> {
    offset += 1;

    let bitmask = bitmask.get(offset >> 3..(offset >> 3) + 4)?;
    let shift = offset & 7;
    let mask: u32 = (u32::from_le_bytes([bitmask[0], bitmask[1], bitmask[2], bitmask[3]]) >> shift) | (1 << BITMASK_MAX);
    let args_length = mask.trailing_zeros() as usize;
    debug_assert!(args_length <= BITMASK_MAX as usize);
    offset += args_length;

    Some((offset, args_length))
}

#[test]
fn test_parse_bitmask() {
    #[track_caller]
    fn parse_both(bitmask: &[u8], offset: usize) -> Option<(usize, usize)> {
        let result_fast = parse_bitmask_fast(bitmask, offset);
        let result_slow = parse_bitmask_slow(bitmask, offset);
        assert_eq!(result_fast, result_slow);

        result_fast
    }

    assert_eq!(parse_both(&[0b00000011, 0, 0, 0], 0), Some((1, 0)));
    assert_eq!(parse_both(&[0b00000101, 0, 0, 0], 0), Some((2, 1)));
    assert_eq!(parse_both(&[0b10000001, 0, 0, 0], 0), Some((7, 6)));
    assert_eq!(parse_both(&[0b00000001, 1, 0, 0], 0), Some((8, 7)));
    assert_eq!(parse_both(&[0b00000001, 1 << 7, 0, 0], 0), Some((15, 14)));
    assert_eq!(parse_both(&[0b00000001, 0, 1, 0], 0), Some((16, 15)));
    assert_eq!(parse_both(&[0b00000001, 0, 1 << 7, 0], 0), Some((23, 22)));
    assert_eq!(parse_both(&[0b00000001, 0, 0, 1], 0), Some((24, 23)));

    assert_eq!(parse_both(&[0b11000000, 0, 0, 0, 0], 6), Some((7, 0)));
    assert_eq!(parse_both(&[0b01000000, 1, 0, 0, 0], 6), Some((8, 1)));

    assert_eq!(parse_both(&[0b10000000, 1, 0, 0, 0], 7), Some((8, 0)));
    assert_eq!(parse_both(&[0b10000000, 1 << 1, 0, 0, 0], 7), Some((9, 1)));

    assert_eq!(parse_both(&[0, 0, 0, 0, 0b00000001], 0), Some((25, 24)));
    assert_eq!(parse_both(&[0, 0, 0, 0, 0b00000001], 6), Some((31, 24)));
    assert_eq!(parse_both(&[0, 0, 0, 0, 0b00000001], 7), Some((32, 24)));
}

#[derive(Clone)]
pub struct Instructions<'a> {
    code: &'a [u8],
    bitmask: &'a [u8],
    offset: usize,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ParsedInstruction {
    pub kind: Instruction,
    pub offset: ProgramCounter,
    pub length: u32,
}

impl ParsedInstruction {
    pub fn next_offset(&self) -> ProgramCounter {
        ProgramCounter(self.offset.0 + self.length)
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

impl<'a> Instructions<'a> {
    #[inline]
    pub fn new(code: &'a [u8], bitmask: &'a [u8], offset: u32) -> Self {
        Self {
            code,
            bitmask,
            offset: offset as usize,
        }
    }

    #[inline]
    pub fn offset(&self) -> u32 {
        self.offset as u32
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

impl<'a> Iterator for Instructions<'a> {
    type Item = ParsedInstruction;
    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        parse_instruction(self.code, self.bitmask, &mut self.offset)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.code.len() - core::cmp::min(self.offset, self.code.len())))
    }
}

impl<'a> DoubleEndedIterator for Instructions<'a> {
    #[inline(always)]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.offset == 0 {
            return None;
        }

        self.offset -= 1;
        loop {
            let offset = self.offset;
            if (self.bitmask[self.offset >> 3] >> (offset & 7)) & 1 == 1 {
                return parse_instruction(self.code, self.bitmask, &mut self.offset);
            }

            self.offset -= 1;
            if self.offset == 0 {
                return None;
            }
        }
    }
}

#[derive(Clone, Default)]
#[non_exhaustive]
pub struct ProgramParts {
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
        if blob_version != BLOB_VERSION_V1 {
            return Err(ProgramParseError(ProgramParseErrorKind::UnsupportedVersion {
                version: blob_version,
            }));
        }

        let mut parts = ProgramParts::default();

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
    /// Parses the given bytes into a program blob.
    pub fn parse(bytes: ArcBytes) -> Result<Self, ProgramParseError> {
        let parts = ProgramParts::from_bytes(bytes)?;
        Self::from_parts(parts)
    }

    /// Creates a program blob from parts.
    pub fn from_parts(parts: ProgramParts) -> Result<Self, ProgramParseError> {
        let mut blob = ProgramBlob {
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
            if blob.code.len() % 8 != 0 {
                expected_bitmask_length += 1;
            }

            if blob.bitmask.len() != expected_bitmask_length {
                return Err(ProgramParseError(ProgramParseErrorKind::Other(
                    "the bitmask length doesn't match the code length",
                )));
            }
        }

        Ok(blob)
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

    #[inline]
    pub fn instructions(&self) -> Instructions {
        Instructions {
            code: self.code(),
            bitmask: self.bitmask(),
            offset: 0,
        }
    }

    #[inline]
    pub fn instructions_at(&self, offset: ProgramCounter) -> Option<Instructions> {
        let offset = offset.0;
        let bitmask = self.bitmask();
        if (bitmask.get(offset as usize >> 3)? >> (offset as usize & 7)) & 1 == 0 {
            None
        } else {
            Some(Instructions {
                code: self.code(),
                bitmask,
                offset: offset as usize,
            })
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

pub const BLOB_VERSION_V1: u8 = 1;

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
