#[inline]
fn get_varint_length(leading_zeros: u32) -> u32 {
    let bits_required = 32 - leading_zeros;
    let x = bits_required >> 3;
    ((x + bits_required) ^ x) >> 3
}

pub const MAX_VARINT_LENGTH: usize = 5;

// TODO: Apply zigzag encoding to the varints before serialization/after deserialization.
// (Otherwise negative offsets will always be encoded with the maximum number of bytes.)

#[inline]
pub(crate) fn read_varint(input: &[u8], first_byte: u8) -> Option<(usize, u32)> {
    let length = (!first_byte).leading_zeros();
    let upper_mask = 0b11111111_u32 >> length;
    let upper_bits = (upper_mask & (first_byte as u32)).wrapping_shl(length * 8);
    let input = input.get(..length as usize)?;
    let value = match input.len() {
        0 => upper_bits,
        1 => upper_bits | input[0] as u32,
        2 => upper_bits | u16::from_le_bytes([input[0], input[1]]) as u32,
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
    #[test]
    fn varint_serialization(value in 0u32..=0xffffffff) {
        let mut buffer = [0; MAX_VARINT_LENGTH];
        let length = write_varint(value, &mut buffer);
        let (parsed_length, parsed_value) = read_varint(&buffer[1..], buffer[0]).unwrap();
        assert_eq!(parsed_value, value, "value mismatch");
        assert_eq!(parsed_length + 1, length, "length mismatch")
    }
}
