use crate::program::Reg;
pub use polkavm_assembler::amd64::RegIndex as NativeReg;
use polkavm_assembler::amd64::RegIndex::*;

#[inline]
pub const fn to_native_reg(reg: Reg) -> NativeReg {
    // NOTE: This is sorted roughly in the order of which registers are more commonly used.
    // We try to assign registers which result in more compact code to the more common RISC-V registers.
    match reg {
        Reg::A0 => rdi,
        Reg::A1 => rsi,
        Reg::SP => rax,
        Reg::RA => rbx,
        Reg::A2 => rdx,
        Reg::A3 => rbp,
        Reg::S0 => r8,
        Reg::S1 => r9,
        Reg::A4 => r10,
        Reg::A5 => r11,
        Reg::T0 => r13,
        Reg::T1 => r14,
        Reg::T2 => r12,
    }
}

#[inline]
pub const fn to_guest_reg(reg: NativeReg) -> Option<Reg> {
    let mut index = 0;
    while index < Reg::ALL.len() {
        let guest_reg = Reg::ALL[index];
        if to_native_reg(guest_reg) as u32 == reg as u32 {
            return Some(guest_reg);
        }

        index += 1;
    }

    None
}
