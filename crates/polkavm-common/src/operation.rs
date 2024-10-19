// This is mostly here so that we can share the implementation between the interpreter and the optimizer.

#[inline]
pub const fn divu(lhs: u32, rhs: u32) -> u32 {
    if rhs == 0 {
        u32::MAX
    } else {
        lhs / rhs
    }
}

#[inline]
pub const fn divu64(lhs: u64, rhs: u64) -> u64 {
    if rhs == 0 {
        u64::MAX
    } else {
        lhs / rhs
    }
}

#[inline]
pub const fn remu(lhs: u32, rhs: u32) -> u32 {
    if rhs == 0 {
        lhs
    } else {
        lhs % rhs
    }
}

#[inline]
pub const fn remu64(lhs: u64, rhs: u64) -> u64 {
    if rhs == 0 {
        lhs
    } else {
        lhs % rhs
    }
}

#[inline]
pub const fn div(lhs: i32, rhs: i32) -> i32 {
    if rhs == 0 {
        -1
    } else if lhs == i32::MIN && rhs == -1 {
        lhs
    } else {
        lhs / rhs
    }
}

#[inline]
pub const fn div64(lhs: i64, rhs: i64) -> i64 {
    if rhs == 0 {
        -1
    } else if lhs == i64::MIN && rhs == -1 {
        lhs
    } else {
        lhs / rhs
    }
}

#[inline]
pub const fn rem(lhs: i32, rhs: i32) -> i32 {
    if rhs == 0 {
        lhs
    } else if lhs == i32::MIN && rhs == -1 {
        0
    } else {
        lhs % rhs
    }
}

#[inline]
pub const fn rem64(lhs: i64, rhs: i64) -> i64 {
    if rhs == 0 {
        lhs
    } else if lhs == i64::MIN && rhs == -1 {
        0
    } else {
        lhs % rhs
    }
}

#[inline]
pub const fn mulh(lhs: i32, rhs: i32) -> i32 {
    ((lhs as i64).wrapping_mul(rhs as i64) >> 32) as i32
}

#[inline]
pub const fn mulh64(lhs: i64, rhs: i64) -> i64 {
    ((lhs as i128).wrapping_mul(rhs as i128) >> 64) as i64
}

#[inline]
pub const fn mulhsu(lhs: i32, rhs: u32) -> i32 {
    ((lhs as i64).wrapping_mul(rhs as i64) >> 32) as i32
}

#[inline]
pub const fn mulhsu64(lhs: i64, rhs: u64) -> i64 {
    ((lhs as i128).wrapping_mul(rhs as i128) >> 64) as i64
}

#[inline]
pub const fn mulhu(lhs: u32, rhs: u32) -> u32 {
    ((lhs as i64).wrapping_mul(rhs as i64) >> 32) as u32
}

#[inline]
pub const fn mulhu64(lhs: u64, rhs: u64) -> u64 {
    ((lhs as i128).wrapping_mul(rhs as i128) >> 32) as u64
}

#[test]
fn test_div_rem() {
    assert_eq!(divu(10, 2), 5);
    assert_eq!(divu(10, 0), u32::MAX);

    assert_eq!(divu64(10, 2), 5);
    assert_eq!(divu64(10, 0), u64::MAX);

    assert_eq!(div(10, 2), 5);
    assert_eq!(div(10, 0), -1);
    assert_eq!(div(i32::MIN, -1), i32::MIN);

    assert_eq!(div64(10, 2), 5);
    assert_eq!(div64(10, 0), -1);
    assert_eq!(div64(i64::MIN, -1), i64::MIN);

    assert_eq!(remu(10, 9), 1);
    assert_eq!(remu(10, 5), 0);
    assert_eq!(remu(10, 0), 10);

    assert_eq!(remu64(10, 9), 1);
    assert_eq!(remu64(10, 5), 0);
    assert_eq!(remu64(10, 0), 10);

    assert_eq!(rem(10, 9), 1);
    assert_eq!(rem(10, 5), 0);
    assert_eq!(rem(10, 0), 10);
    assert_eq!(rem(i32::MIN, -1), 0);

    assert_eq!(rem64(10, 9), 1);
    assert_eq!(rem64(10, 5), 0);
    assert_eq!(rem64(10, 0), 10);
    assert_eq!(rem64(i64::MIN, -1), 0);
}
