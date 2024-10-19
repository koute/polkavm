use polkavm_common::program::{InstructionSet, InstructionVisitor, Instructions, RawReg};

// TODO: Come up with a better cost model.
#[derive(Default)]
pub struct GasVisitor {
    cost: u32,
    last_block_cost: Option<u32>,
}

impl GasVisitor {
    #[inline]
    fn start_new_basic_block(&mut self) {
        self.last_block_cost = Some(self.cost);
        self.cost = 0;
    }

    #[inline]
    pub fn take_block_cost(&mut self) -> Option<u32> {
        self.last_block_cost.take()
    }
}

impl InstructionVisitor for GasVisitor {
    type ReturnTy = ();

    #[cold]
    fn invalid(&mut self) -> Self::ReturnTy {
        self.trap();
    }

    #[inline(always)]
    fn trap(&mut self) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn fallthrough(&mut self) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn sbrk(&mut self, _d: RawReg, _s: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn ecalli(&mut self, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_less_than_unsigned(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_less_than_signed(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_less_than_unsigned_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_less_than_signed_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_right(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_arithmetic_right(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_left(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_right_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_arithmetic_right_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_left_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn xor(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn and(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn or(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }
    #[inline(always)]
    fn add(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn xor_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn and_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn or_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn add_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn sub(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn sub_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn mul(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn mul_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn mul_upper_signed_signed(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn mul_upper_unsigned_unsigned(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn mul_upper_signed_unsigned(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    fn mul_upper_signed_signed_imm_64(&mut self, _: RawReg, _: RawReg, _: u32) -> <Self as InstructionVisitor>::ReturnTy {
        self.cost += 1;
    }

    fn mul_upper_unsigned_unsigned_imm_64(&mut self, _: RawReg, _: RawReg, _: u32) -> <Self as InstructionVisitor>::ReturnTy {
        self.cost += 1;
    }

    fn mul_upper_signed_signed_64(&mut self, _: RawReg, _: RawReg, _: RawReg) -> <Self as InstructionVisitor>::ReturnTy {
        self.cost += 1;
    }

    fn mul_upper_unsigned_unsigned_64(&mut self, _: RawReg, _: RawReg, _: RawReg) -> <Self as InstructionVisitor>::ReturnTy {
        self.cost += 1;
    }

    fn mul_upper_signed_unsigned_64(&mut self, _: RawReg, _: RawReg, _: RawReg) -> <Self as InstructionVisitor>::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn div_unsigned(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn div_signed(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn rem_unsigned(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn rem_signed(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn div_unsigned_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn div_signed_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn rem_unsigned_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn rem_signed_64(&mut self, _d: RawReg, _s1: RawReg, _s2: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn mul_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn mul_64_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn mul_upper_signed_signed_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn mul_upper_unsigned_unsigned_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_less_than_unsigned_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_less_than_unsigned_64_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_less_than_signed_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_less_than_signed_64_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_greater_than_unsigned_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_greater_than_unsigned_64_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_greater_than_signed_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn set_greater_than_signed_64_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_right_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_arithmetic_right_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_left_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_right_imm_alt(&mut self, _d: RawReg, _s2: RawReg, _s1: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_arithmetic_right_imm_alt(&mut self, _d: RawReg, _s2: RawReg, _s1: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_left_imm_alt(&mut self, _d: RawReg, _s2: RawReg, _s1: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_right_64_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_arithmetic_right_64_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_left_64_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_right_64_imm_alt(&mut self, _d: RawReg, _s2: RawReg, _s1: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_arithmetic_right_64_imm_alt(&mut self, _d: RawReg, _s2: RawReg, _s1: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn shift_logical_left_64_imm_alt(&mut self, _d: RawReg, _s2: RawReg, _s1: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn or_imm(&mut self, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn and_imm(&mut self, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn xor_imm(&mut self, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn or_64_imm(&mut self, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn and_64_imm(&mut self, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn xor_64_imm(&mut self, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn move_reg(&mut self, _d: RawReg, _s: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn cmov_if_zero(&mut self, _d: RawReg, _s: RawReg, _c: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn cmov_if_not_zero(&mut self, _d: RawReg, _s: RawReg, _c: RawReg) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn cmov_if_zero_imm(&mut self, _d: RawReg, _c: RawReg, _s: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn cmov_if_not_zero_imm(&mut self, _d: RawReg, _c: RawReg, _s: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn add_imm(&mut self, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn add_64_imm(&mut self, _d: RawReg, _s: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn negate_and_add_imm(&mut self, _d: RawReg, _s1: RawReg, _s2: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_imm_indirect_u8(&mut self, _base: RawReg, _offset: u32, _value: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_imm_indirect_u16(&mut self, _base: RawReg, _offset: u32, _value: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_imm_indirect_u32(&mut self, _base: RawReg, _offset: u32, _value: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_imm_indirect_u64(&mut self, _base: RawReg, _offset: u32, _value: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_indirect_u8(&mut self, _src: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_indirect_u16(&mut self, _src: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_indirect_u32(&mut self, _src: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_indirect_u64(&mut self, _src: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_imm_u8(&mut self, _offset: u32, _value: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_imm_u16(&mut self, _offset: u32, _value: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_imm_u32(&mut self, _offset: u32, _value: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_imm_u64(&mut self, _offset: u32, _value: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_u8(&mut self, _src: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_u16(&mut self, _src: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_u32(&mut self, _src: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn store_u64(&mut self, _src: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_indirect_u8(&mut self, _dst: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_indirect_i8(&mut self, _dst: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_indirect_u16(&mut self, _dst: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_indirect_i16(&mut self, _dst: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_indirect_u32(&mut self, _dst: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_indirect_i32(&mut self, _dst: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_indirect_u64(&mut self, _dst: RawReg, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_u8(&mut self, _dst: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_i8(&mut self, _dst: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_u16(&mut self, _dst: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_i16(&mut self, _dst: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_u32(&mut self, _dst: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_i32(&mut self, _dst: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_u64(&mut self, _dst: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn branch_less_unsigned(&mut self, _s1: RawReg, _s2: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_less_signed(&mut self, _s1: RawReg, _s2: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_or_equal_unsigned(&mut self, _s1: RawReg, _s2: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_or_equal_signed(&mut self, _s1: RawReg, _s2: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_eq(&mut self, _s1: RawReg, _s2: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_not_eq(&mut self, _s1: RawReg, _s2: RawReg, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_eq_imm(&mut self, _s1: RawReg, _s2: u32, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_not_eq_imm(&mut self, _s1: RawReg, _s2: u32, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_less_unsigned_imm(&mut self, _s1: RawReg, _s2: u32, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_less_signed_imm(&mut self, _s1: RawReg, _s2: u32, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_or_equal_unsigned_imm(&mut self, _s1: RawReg, _s2: u32, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_or_equal_signed_imm(&mut self, _s1: RawReg, _s2: u32, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_less_or_equal_unsigned_imm(&mut self, _s1: RawReg, _s2: u32, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_less_or_equal_signed_imm(&mut self, _s1: RawReg, _s2: u32, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_unsigned_imm(&mut self, _s1: RawReg, _s2: u32, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn branch_greater_signed_imm(&mut self, _s1: RawReg, _s2: u32, _imm: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn load_imm(&mut self, _dst: RawReg, _value: u32) -> Self::ReturnTy {
        self.cost += 1;
    }

    #[inline(always)]
    fn load_imm_and_jump(&mut self, _ra: RawReg, _value: u32, _target: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn load_imm_and_jump_indirect(&mut self, _ra: RawReg, _base: RawReg, _value: u32, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn jump(&mut self, _target: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn jump_indirect(&mut self, _base: RawReg, _offset: u32) -> Self::ReturnTy {
        self.cost += 1;
        self.start_new_basic_block();
    }
}

pub fn calculate_for_block<I>(mut instructions: Instructions<I>) -> (u32, bool)
where
    I: InstructionSet,
{
    let mut visitor = GasVisitor::default();
    while instructions.visit(&mut visitor).is_some() {
        if let Some(cost) = visitor.last_block_cost {
            return (cost, false);
        }
    }

    if let Some(cost) = visitor.last_block_cost {
        (cost, false)
    } else {
        let started_out_of_bounds = visitor.cost == 0;

        // We've ended out of bounds, so assume there's an implicit trap there.
        visitor.trap();
        (visitor.last_block_cost.unwrap(), started_out_of_bounds)
    }
}

pub fn trap_cost() -> u32 {
    let mut gas_visitor = GasVisitor::default();
    gas_visitor.trap();
    gas_visitor.take_block_cost().unwrap()
}
