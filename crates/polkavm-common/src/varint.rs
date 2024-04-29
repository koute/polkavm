#[inline]
fn get_varint_length(leading_zeros: u32) -> u32 {
    let bits_required = 32 - leading_zeros;
    let x = bits_required >> 3;
    ((x + bits_required) ^ x) >> 3
}

pub const MAX_VARINT_LENGTH: usize = 5;

#[inline(always)]
pub(crate) fn read_varint_fast(chunk: u64) -> Option<(u32, u32)> {
    let first_byte = chunk as u8;
    let length = (!first_byte).leading_zeros();
    if length > 4 {
        return None;
    }

    let upper_mask = 0b11111111_u32 >> length;
    let lower_mask = ((1_u64 << (length << 3)) - 1) as u32;
    let value = (upper_mask & u32::from(first_byte)).wrapping_shl(length * 8) | (((chunk >> 8) as u32) & lower_mask);
    Some((length + 1, value))
}

#[inline]
pub(crate) fn read_varint(input: &[u8], first_byte: u8) -> Option<(usize, u32)> {
    let length = (!first_byte).leading_zeros();
    let upper_mask = 0b11111111_u32 >> length;
    let upper_bits = (upper_mask & u32::from(first_byte)).wrapping_shl(length * 8);
    let input = input.get(..length as usize)?;
    let value = match input.len() {
        0 => upper_bits,
        1 => upper_bits | u32::from(input[0]),
        2 => upper_bits | u32::from(u16::from_le_bytes([input[0], input[1]])),
        3 => upper_bits | u32::from_le_bytes([input[0], input[1], input[2], 0]),
        4 => upper_bits | u32::from_le_bytes([input[0], input[1], input[2], input[3]]),
        _ => return None,
    };

    Some((length as usize, value))
}

#[inline]
pub fn write_varint(value: u32, buffer: &mut [u8]) -> usize {
    let varint_length = get_varint_length(value.leading_zeros());
    match varint_length {
        0 => buffer[0] = value as u8,
        1 => {
            buffer[0] = 0b10000000 | (value >> 8) as u8;
            let bytes = value.to_le_bytes();
            buffer[1] = bytes[0];
        }
        2 => {
            buffer[0] = 0b11000000 | (value >> 16) as u8;
            let bytes = value.to_le_bytes();
            buffer[1] = bytes[0];
            buffer[2] = bytes[1];
        }
        3 => {
            buffer[0] = 0b11100000 | (value >> 24) as u8;
            let bytes = value.to_le_bytes();
            buffer[1] = bytes[0];
            buffer[2] = bytes[1];
            buffer[3] = bytes[2];
        }
        4 => {
            buffer[0] = 0b11110000;
            let bytes = value.to_le_bytes();
            buffer[1] = bytes[0];
            buffer[2] = bytes[1];
            buffer[3] = bytes[2];
            buffer[4] = bytes[3];
        }
        _ => unreachable!(),
    }

    varint_length as usize + 1
}

#[cfg(test)]
proptest::proptest! {
    #[allow(clippy::ignored_unit_patterns)]
    #[test]
    fn varint_serialization(value in 0u32..=0xffffffff) {
        let mut buffer = [0; MAX_VARINT_LENGTH];
        let length = write_varint(value, &mut buffer);
        let (parsed_length, parsed_value) = read_varint(&buffer[1..], buffer[0]).unwrap();
        assert_eq!(parsed_value, value, "value mismatch");
        assert_eq!(parsed_length + 1, length, "length mismatch")
    }
}

#[inline(always)]
pub(crate) fn read_simple_varint_fast(chunk: u32, length: u32) -> u32 {
    let mask = ((1_u64 << (length << 3)) - 1) as u32;
    let value = chunk & mask;
    (value >> 1) ^ (-((value & 1) as i32)) as u32
}

#[inline]
fn get_simple_varint_length(leading_zeros: u32) -> u32 {
    let bits_required = 32 - leading_zeros;
    bits_required / 8 + (if leading_zeros % 8 > 0 { 1 } else { 0 })
}

#[inline]
pub(crate) fn write_simple_varint(value: u32, buffer: &mut [u8]) -> usize {
    let value = value as i32;
    let value = (value << 1) ^ (value >> 31);
    let value = value as u32;
    let varint_length = get_simple_varint_length(value.leading_zeros());
    match varint_length {
        0 => {}
        1 => {
            buffer[0] = value as u8;
        }
        2 => {
            let bytes = value.to_le_bytes();
            buffer[0] = bytes[0];
            buffer[1] = bytes[1];
        }
        3 => {
            let bytes = value.to_le_bytes();
            buffer[0] = bytes[0];
            buffer[1] = bytes[1];
            buffer[2] = bytes[2];
        }
        4 => {
            let bytes = value.to_le_bytes();
            buffer[0] = bytes[0];
            buffer[1] = bytes[1];
            buffer[2] = bytes[2];
            buffer[3] = bytes[3];
        }
        _ => unreachable!(),
    }

    varint_length as usize
}

#[cfg(test)]
proptest::proptest! {
    #[allow(clippy::ignored_unit_patterns)]
    #[test]
    fn simple_varint_serialization(value in 0u32..=0xffffffff) {
        fn read_simple_varint(input: &[u8]) -> Option<u32> {
            let value = match input.len() {
                0 => 0,
                1 => u32::from(input[0]),
                2 => u32::from(u16::from_le_bytes([input[0], input[1]])),
                3 => u32::from_le_bytes([input[0], input[1], input[2], 0]),
                4 => u32::from_le_bytes([input[0], input[1], input[2], input[3]]),
                _ => return None,
            };

            let value = (value >> 1) ^ (-((value & 1) as i32)) as u32;
            Some(value)
        }

        let mut buffer = [0; MAX_VARINT_LENGTH];
        let length = write_simple_varint(value, &mut buffer);
        let parsed_value = read_simple_varint(&buffer[..length]).unwrap();
        assert_eq!(parsed_value, value, "value mismatch");
    }
}
