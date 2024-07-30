#[inline]
fn get_varint_length(leading_zeros: u32) -> u32 {
    let bits_required = 32 - leading_zeros;
    let x = bits_required >> 3;
    ((x + bits_required) ^ x) >> 3
}

pub const MAX_VARINT_LENGTH: usize = 5;

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

static LENGTH_TO_SHIFT: [u32; 256] = {
    let mut output = [0; 256];
    let mut length = 0_u32;
    while length < 256 {
        let shift = match length {
            0 => 32,
            1 => 24,
            2 => 16,
            3 => 8,
            _ => 0,
        };

        output[length as usize] = shift;
        length += 1;
    }
    output
};

#[inline(always)]
pub(crate) fn read_simple_varint(chunk: u32, length: u32) -> u32 {
    let shift = LENGTH_TO_SHIFT[length as usize];
    (((u64::from(chunk) << shift) as u32 as i32).wrapping_shr(shift)) as u32
}

#[inline]
fn get_bytes_required(value: u32) -> u32 {
    let zeros = value.leading_zeros();
    if zeros == 32 {
        0
    } else if zeros > 24 {
        1
    } else if zeros > 16 {
        2
    } else if zeros > 8 {
        3
    } else if zeros != 0 {
        4
    } else {
        let ones = value.leading_ones();
        if ones > 24 {
            1
        } else if ones > 16 {
            2
        } else if ones > 8 {
            3
        } else {
            4
        }
    }
}

#[inline]
pub(crate) fn write_simple_varint(value: u32, buffer: &mut [u8]) -> usize {
    let varint_length = get_bytes_required(value);
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

#[test]
fn test_simple_varint() {
    assert_eq!(get_bytes_required(0b00000000_00000000_00000000_00000000), 0);
    assert_eq!(get_bytes_required(0b00000000_00000000_00000000_00000001), 1);
    assert_eq!(get_bytes_required(0b00000000_00000000_00000000_01000001), 1);
    assert_eq!(get_bytes_required(0b00000000_00000000_00000000_10000000), 2);
    assert_eq!(get_bytes_required(0b00000000_00000000_00000000_11111111), 2);
    assert_eq!(get_bytes_required(0b00000000_00000000_00000001_00000000), 2);
    assert_eq!(get_bytes_required(0b00000000_00000000_01000000_00000000), 2);
    assert_eq!(get_bytes_required(0b00000000_00000000_10000000_00000000), 3);
    assert_eq!(get_bytes_required(0b00000000_00000001_00000000_00000000), 3);
    assert_eq!(get_bytes_required(0b00000000_01000000_00000000_00000000), 3);
    assert_eq!(get_bytes_required(0b00000000_10000000_00000000_00000000), 4);
    assert_eq!(get_bytes_required(0b00000001_00000000_00000000_00000000), 4);
    assert_eq!(get_bytes_required(0b10000000_00000000_00000000_00000000), 4);
    assert_eq!(get_bytes_required(0b11111111_11111111_11111111_11111111), 1);
    assert_eq!(get_bytes_required(0b10111111_11111111_11111111_11111111), 4);
    assert_eq!(get_bytes_required(0b11111110_11111111_11111111_11111111), 4);
    assert_eq!(get_bytes_required(0b11111111_01111111_11111111_11111111), 4);
    assert_eq!(get_bytes_required(0b11111111_10111111_11111111_11111111), 3);
    assert_eq!(get_bytes_required(0b11111111_11111110_11111111_11111111), 3);
    assert_eq!(get_bytes_required(0b11111111_11111111_01111111_11111111), 3);
    assert_eq!(get_bytes_required(0b11111111_11111111_10111111_11111111), 2);
    assert_eq!(get_bytes_required(0b11111111_11111111_11111110_11111111), 2);
    assert_eq!(get_bytes_required(0b11111111_11111111_11111111_01111111), 2);
    assert_eq!(get_bytes_required(0b11111111_11111111_11111111_10111111), 1);

    assert_eq!(read_simple_varint(0x000000ff, 1), 0xffffffff);
    assert_eq!(read_simple_varint(0x555555ff, 1), 0xffffffff);
    assert_eq!(read_simple_varint(0xaaaaaaff, 1), 0xffffffff);
    assert_eq!(read_simple_varint(0xffffffff, 1), 0xffffffff);

    assert_eq!(read_simple_varint(0x000000ff, 0), 0);
    assert_eq!(read_simple_varint(0x555555ff, 0), 0);
    assert_eq!(read_simple_varint(0xaaaaaaff, 0), 0);
    assert_eq!(read_simple_varint(0xffffffff, 0), 0);
}

#[cfg(test)]
proptest::proptest! {
    #[allow(clippy::ignored_unit_patterns)]
    #[test]
    fn proptest_simple_varint(value in 0u32..=0xffffffff) {
        fn read_simple_varint_from_slice(input: [u8; 4], length: usize) -> u32 {
            let chunk = u32::from_le_bytes(input);
            read_simple_varint(chunk, length as u32)
        }

        for fill_byte in [0x00, 0x55, 0xaa, 0xff] {
            let mut t = [fill_byte; 4];
            let length = write_simple_varint(value, &mut t);
            assert_eq!(read_simple_varint_from_slice(t, length), value, "value mismatch");
        }
    }
}
