use core::num::NonZeroU32;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Label(NonZeroU32);

impl Label {
    #[inline]
    pub fn raw(self) -> u32 {
        self.0.get() - 1
    }

    #[inline]
    pub fn from_raw(value: u32) -> Self {
        Label(NonZeroU32::new(value + 1).unwrap())
    }
}

impl core::fmt::Display for Label {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_fmt(core::format_args!("<{}>", self.0))
    }
}

#[derive(Copy, Clone)]
pub struct Instruction<T> {
    pub(crate) instruction: T,
    pub(crate) bytes: InstBuf,

    #[cfg_attr(not(feature = "alloc"), allow(dead_code))]
    pub(crate) fixup: Option<(Label, FixupKind)>,
}

impl<T> core::fmt::Debug for Instruction<T>
where
    T: core::fmt::Debug,
{
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.instruction.fmt(fmt)
    }
}

impl<T> core::fmt::Display for Instruction<T>
where
    T: core::fmt::Display,
{
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.instruction.fmt(fmt)
    }
}

impl<T> Instruction<T> {
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Copy, Clone)]
#[repr(transparent)]
pub(crate) struct FixupKind(pub u32);

impl FixupKind {
    #[cfg_attr(not(feature = "alloc"), allow(dead_code))]
    #[inline]
    pub const fn offset(self) -> u32 {
        (self.0 >> 24) & 0b11
    }

    #[cfg_attr(not(feature = "alloc"), allow(dead_code))]
    #[inline]
    pub const fn length(self) -> u32 {
        self.0 >> 28
    }

    #[inline]
    pub const fn new_1(opcode: u32, length: u32) -> Self {
        FixupKind((1 << 24) | (length << 28) | opcode)
    }

    #[inline]
    pub const fn new_2(opcode: [u32; 2], length: u32) -> Self {
        let opcode = opcode[0] | (opcode[1] << 8);
        FixupKind((2 << 24) | (length << 28) | opcode)
    }

    #[inline]
    pub const fn new_3(opcode: [u32; 3], length: u32) -> Self {
        let opcode = opcode[0] | (opcode[1] << 8) | (opcode[2] << 16);
        FixupKind((3 << 24) | (length << 28) | opcode)
    }
}

const MAXIMUM_INSTRUCTION_SIZE: usize = 16;

#[derive(Copy, Clone)]
pub struct InstBuf {
    out: u128,
    length: u32,
}

#[allow(clippy::new_without_default)]
impl InstBuf {
    #[inline]
    pub fn new() -> Self {
        Self { out: 0, length: 0 }
    }

    #[inline]
    pub fn len(&self) -> usize {
        (self.length >> 3) as usize
    }

    #[inline]
    pub fn append(&mut self, byte: u8) {
        self.out |= u128::from(byte).wrapping_shl(self.length);
        self.length += 8;
    }

    #[inline]
    pub fn append_packed_bytes(&mut self, value: u32, length: u32) {
        self.out |= u128::from(value).wrapping_shl(self.length);
        self.length += length;
    }

    #[cfg(feature = "alloc")]
    #[inline]
    unsafe fn encode_into_raw(self, output: *mut u8) {
        core::ptr::write_unaligned(output.cast::<u64>(), u64::from_le(self.out as u64));
        core::ptr::write_unaligned(output.add(8).cast::<u64>(), u64::from_le((self.out >> 64) as u64));
    }

    #[cfg(feature = "alloc")]
    #[allow(clippy::debug_assert_with_mut_call)]
    #[inline]
    pub unsafe fn encode_into_vec_unsafe(self, output: &mut Vec<u8>) {
        debug_assert!(output.spare_capacity_mut().len() >= MAXIMUM_INSTRUCTION_SIZE);

        self.encode_into_raw(output.spare_capacity_mut().as_mut_ptr().cast());
        let new_length = output.len() + (self.length as usize >> 3);
        output.set_len(new_length);
    }

    #[cfg(feature = "alloc")]
    #[cold]
    #[inline(never)]
    fn reserve_impl(output: &mut Vec<u8>, length: usize) {
        output.reserve(length);
    }

    #[cfg(feature = "alloc")]
    #[inline(always)]
    pub fn reserve_const<const INSTRUCTIONS: usize>(output: &mut Vec<u8>) {
        Self::reserve(output, INSTRUCTIONS);
    }

    #[cfg(feature = "alloc")]
    #[inline(always)]
    pub fn reserve(output: &mut Vec<u8>, count: usize) {
        let count = count.checked_mul(MAXIMUM_INSTRUCTION_SIZE).unwrap();
        if output.spare_capacity_mut().len() < count {
            Self::reserve_impl(output, count);
            if output.spare_capacity_mut().len() < count {
                // SAFETY: `reserve` made sure that we have this much capacity, so this is safe.
                unsafe {
                    core::hint::unreachable_unchecked();
                }
            }
        }
    }

    #[inline]
    pub fn from_array<const N: usize>(array: [u8; N]) -> Self {
        if N > MAXIMUM_INSTRUCTION_SIZE {
            panic!();
        }

        let mut out = Self::new();
        for value in array {
            out.append(value);
        }
        out
    }

    #[cfg(feature = "alloc")]
    pub fn to_vec(self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(MAXIMUM_INSTRUCTION_SIZE);

        // SAFETY: We've reserved space for at least one instruction.
        unsafe {
            self.encode_into_vec_unsafe(&mut vec);
        }

        vec
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_inst_buf() {
    assert_eq!(InstBuf::from_array([0x01]).to_vec(), [0x01]);
    assert_eq!(InstBuf::from_array([0x01, 0x02]).to_vec(), [0x01, 0x02]);
    assert_eq!(InstBuf::from_array([0x01, 0x02, 0x03]).to_vec(), [0x01, 0x02, 0x03]);
    assert_eq!(InstBuf::from_array([0x01, 0x02, 0x03, 0x04]).to_vec(), [0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        InstBuf::from_array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]).to_vec(),
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
    assert_eq!(
        InstBuf::from_array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]).to_vec(),
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
    );
    assert_eq!(
        InstBuf::from_array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]).to_vec(),
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]
    );

    let mut buf = InstBuf::from_array([0x01]);
    assert_eq!(buf.to_vec(), [0x01]);
    buf.append_packed_bytes(0x05040302, 32);
    assert_eq!(buf.to_vec(), [0x01, 0x02, 0x03, 0x04, 0x05]);
    buf.append_packed_bytes(0x09080706, 32);
    assert_eq!(buf.to_vec(), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);

    let mut buf = InstBuf::from_array([0x01]);
    assert_eq!(buf.to_vec(), [0x01]);
    buf.append_packed_bytes(0x0302, 16);
    assert_eq!(buf.to_vec(), [0x01, 0x02, 0x03]);
    buf.append_packed_bytes(0x0504, 16);
    assert_eq!(buf.to_vec(), [0x01, 0x02, 0x03, 0x04, 0x05]);
    buf.append_packed_bytes(0x0706, 16);
    assert_eq!(buf.to_vec(), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    buf.append_packed_bytes(0x0908, 16);
    assert_eq!(buf.to_vec(), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
}
