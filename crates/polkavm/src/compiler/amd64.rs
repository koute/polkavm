use polkavm_assembler::amd64::inst::*;
use polkavm_assembler::amd64::Reg as NativeReg;
use polkavm_assembler::amd64::Reg::*;
use polkavm_assembler::amd64::{Condition, LoadKind, RegSize, StoreKind};
use polkavm_assembler::Label;

use polkavm_common::program::{InstructionVisitor, Reg};
use polkavm_common::zygote::{
    VmCtx, SYSCALL_HOSTCALL, SYSCALL_RETURN, SYSCALL_TRACE, SYSCALL_TRAP, VM_ADDR_JUMP_TABLE, VM_ADDR_SYSCALL, VM_ADDR_VMCTX,
};

use crate::compiler::Compiler;

use Reg::Zero as Z;

const TMP_REG: NativeReg = rcx;

const fn conv_reg(reg: Reg) -> NativeReg {
    match reg {
        Reg::Zero => unreachable!(),
        Reg::A0 => rsi,
        Reg::A1 => rdi,
        Reg::A2 => r8,
        Reg::SP => r9,
        Reg::S1 => r10,
        Reg::A3 => r11,
        Reg::S0 => r12,
        Reg::A4 => r13,
        Reg::RA => r14,
        Reg::A5 => rbp,
        Reg::T0 => rax,
        Reg::T1 => rbx,
        Reg::T2 => rdx,
    }
}

fn regs_address() -> u64 {
    let regs_offset: usize = {
        let base = VmCtx::new();
        let base_ref = &base;
        let field_ref = base.regs().get();
        let base_addr = base_ref as *const _ as usize;
        let field_addr = field_ref as *const _ as usize;
        field_addr - base_addr
    };

    VM_ADDR_VMCTX + regs_offset as u64
}

enum Signedness {
    Signed,
    Unsigned,
}

enum DivRem {
    Div,
    Rem,
}

enum ShiftKind {
    LogicalLeft,
    LogicalRight,
    ArithmeticRight,
}

impl<'a> Compiler<'a> {
    fn reg_size(&self) -> RegSize {
        if !self.regs_are_64bit {
            RegSize::R32
        } else {
            RegSize::R64
        }
    }

    fn nop(&mut self) {
        self.push(nop());
    }

    fn load_imm(&mut self, reg: Reg, imm: u32) {
        self.push(load32_imm(conv_reg(reg), imm));
    }

    fn store(&mut self, src: Reg, base: Reg, offset: u32, kind: StoreKind) {
        if self.regs_are_64bit {
            todo!();
        }

        match (src, base, (offset as i32 >= 0)) {
            // [address] = 0
            // (address is in the lower 2GB of the address space)
            (Z, Z, true) => match kind {
                StoreKind::U8 => self.push(store8_abs_imm(offset as i32, 0)),
                StoreKind::U16 => self.push(store16_abs_imm(offset as i32, 0)),
                StoreKind::U32 => self.push(store32_abs_imm(offset as i32, 0)),
                StoreKind::U64 => {
                    self.push(xor(RegSize::R32, TMP_REG, TMP_REG));
                    self.push(store_abs(offset as i32, TMP_REG, StoreKind::U64));
                }
            },

            // [address] = src
            // (address is in the lower 2GB of the address space)
            (_, Z, true) => {
                self.push(store_abs(offset as i32, conv_reg(src), kind));
            }

            // [address] = 0
            // (address is in the upper 2GB of the address space)
            (Z, Z, false) => {
                // The offset would get sign extended to full 64-bits if we'd use it
                // in a displacement, so we need to do an indirect store here.
                self.push(load32_imm(TMP_REG, offset));
                self.push(store32_indirect_imm(RegSize::R32, TMP_REG, 0, 0));
            }

            // [address] = src
            // (address is in the upper 2GB of the address space)
            (_, Z, false) => {
                self.push(load32_imm(TMP_REG, offset));
                self.push(store_indirect(RegSize::R32, TMP_REG, 0, conv_reg(src), kind));
            }

            // [base + offset] = 0
            (Z, _, _) => match kind {
                StoreKind::U8 => self.push(store8_indirect_imm(RegSize::R32, conv_reg(base), offset as i32, 0)),
                StoreKind::U16 => self.push(store16_indirect_imm(RegSize::R32, conv_reg(base), offset as i32, 0)),
                StoreKind::U32 => self.push(store32_indirect_imm(RegSize::R32, conv_reg(base), offset as i32, 0)),
                StoreKind::U64 => {
                    self.push(xor(RegSize::R32, TMP_REG, TMP_REG));
                    self.push(store_indirect(RegSize::R32, conv_reg(base), offset as i32, TMP_REG, kind));
                }
            },

            // [base + offset] = src
            (_, _, _) => {
                self.push(store_indirect(RegSize::R32, conv_reg(base), offset as i32, conv_reg(src), kind));
            }
        }
    }

    fn load(&mut self, dst: Reg, base: Reg, offset: u32, kind: LoadKind) {
        if self.regs_are_64bit {
            todo!();
        }

        let dst_native = if dst == Reg::Zero {
            // Do a dummy load. We can't just skip this since an invalid load can trigger a trap.
            TMP_REG
        } else {
            conv_reg(dst)
        };

        if base == Reg::Zero {
            if (offset as i32) < 0 {
                self.push(load32_imm(TMP_REG, offset));
                self.push(load_indirect(dst_native, RegSize::R32, TMP_REG, 0, kind));
            } else {
                self.push(load_abs(dst_native, offset as i32, kind));
            }
        } else {
            self.push(load_indirect(dst_native, RegSize::R32, conv_reg(base), offset as i32, kind));
        }
    }

    fn clear_reg(&mut self, reg: Reg) {
        if reg == Reg::Zero {
            return;
        }

        let reg = conv_reg(reg);
        self.push(xor(RegSize::R32, reg, reg));
    }

    fn fill_with_ones(&mut self, reg: Reg) {
        if reg == Reg::Zero {
            return;
        }

        if !self.regs_are_64bit {
            self.push(load32_imm(conv_reg(reg), 0xffffffff));
        } else {
            self.clear_reg(reg);
            self.push(not(RegSize::R64, conv_reg(reg)));
        }
    }

    fn set_less_than(&mut self, d: Reg, s1: Reg, s2: Reg, kind: Signedness) {
        match (d, s1, s2) {
            // 0 = s1 < s2
            (Z, _, _) => self.nop(),
            // d = s1 < s1
            (_, _, _) if s1 == s2 => self.clear_reg(d),
            // d = 0 < s2
            (_, Z, _) => match kind {
                Signedness::Signed => {
                    self.push(cmp_imm(self.reg_size(), conv_reg(s2), 0));
                    self.push(setcc(Condition::GreaterOrEqual, conv_reg(d)));
                    self.push(and_imm(RegSize::R32, conv_reg(d), 1));
                }
                Signedness::Unsigned => {
                    self.push(test(self.reg_size(), conv_reg(s2), conv_reg(s2)));
                    self.push(setcc(Condition::NotEqual, conv_reg(d)));
                    self.push(and_imm(RegSize::R32, conv_reg(d), 1));
                }
            },
            // d = s1 < 0
            (_, _, Z) => {
                self.set_less_than_imm(d, s1, 0, kind);
            }
            // d = s1 < s2
            _ => {
                self.push(cmp(self.reg_size(), conv_reg(s1), conv_reg(s2)));
                let condition = match kind {
                    Signedness::Signed => Condition::Less,
                    Signedness::Unsigned => Condition::Below,
                };
                self.push(setcc(condition, conv_reg(d)));
                self.push(and_imm(RegSize::R32, conv_reg(d), 1));
            }
        }
    }

    fn set_less_than_imm(&mut self, d: Reg, s: Reg, imm: u32, kind: Signedness) {
        match (d, s, imm) {
            // 0 = s < imm
            (Z, _, _) => self.nop(),
            // d = 0 < imm
            (_, Z, _) => {
                #[allow(clippy::unnecessary_cast)]
                let value = match kind {
                    Signedness::Signed => 0 < (imm as i32),
                    Signedness::Unsigned => 0 < (imm as u32),
                };
                self.load_imm(d, value as u32);
            }
            // d = s < 0
            (_, _, 0) if matches!(kind, Signedness::Unsigned) => {
                self.clear_reg(d);
            }
            // d = s < imm
            _ => {
                let condition = match kind {
                    Signedness::Signed => Condition::Less,
                    Signedness::Unsigned => Condition::Below,
                };

                self.push(cmp_imm(self.reg_size(), conv_reg(s), imm as i32));
                self.push(setcc(condition, conv_reg(d)));
                self.push(and_imm(RegSize::R32, conv_reg(d), 1));
            }
        }
    }

    fn shift_imm(&mut self, d: Reg, s: Reg, imm: u32, kind: ShiftKind) {
        match (d, s) {
            // 0 = s << imm
            (Z, _) => self.nop(),
            // d = 0 << imm
            (_, Z) => self.clear_reg(d),
            // d = s << 32+
            (_, _) if imm >= 32 => self.clear_reg(d),
            // d = d << imm
            (_, _) if d == s => match kind {
                ShiftKind::LogicalLeft => self.push(shl_imm(self.reg_size(), conv_reg(d), imm as u8)),
                ShiftKind::LogicalRight => self.push(shr_imm(self.reg_size(), conv_reg(d), imm as u8)),
                ShiftKind::ArithmeticRight => self.push(sar_imm(self.reg_size(), conv_reg(d), imm as u8)),
            },
            // d = s << imm
            (_, _) => {
                self.mov(d, s);
                match kind {
                    ShiftKind::LogicalLeft => self.push(shl_imm(self.reg_size(), conv_reg(d), imm as u8)),
                    ShiftKind::LogicalRight => self.push(shr_imm(self.reg_size(), conv_reg(d), imm as u8)),
                    ShiftKind::ArithmeticRight => self.push(sar_imm(self.reg_size(), conv_reg(d), imm as u8)),
                }
            }
        }
    }

    fn shift(&mut self, d: Reg, s1: Reg, s2: Reg, kind: ShiftKind) {
        match (d, s1, s2) {
            // 0 = s1 << s2
            (Z, _, _) => self.nop(),
            // d = 0 << s2
            (_, Z, _) => self.clear_reg(d),
            // d = d << 0
            (_, _, Z) if d == s1 => self.nop(),
            // d = s1 << 0
            (_, _, Z) => self.mov(d, s1),
            // d = s1 << s2
            (_, _, _) => {
                // TODO: Consider using shlx/shrx/sarx when BMI2 is available.
                self.push(mov(self.reg_size(), rcx, conv_reg(s2)));
                if s1 != d {
                    self.mov(d, s1);
                }
                match kind {
                    ShiftKind::LogicalLeft => self.push(shl_cl(self.reg_size(), conv_reg(d))),
                    ShiftKind::LogicalRight => self.push(shr_cl(self.reg_size(), conv_reg(d))),
                    ShiftKind::ArithmeticRight => self.push(sar_cl(self.reg_size(), conv_reg(d))),
                }
            }
        }
    }

    fn mov(&mut self, dst: Reg, src: Reg) {
        self.push(mov(self.reg_size(), conv_reg(dst), conv_reg(src)))
    }

    fn branch(&mut self, s1: Reg, s2: Reg, imm: u32, mut condition: Condition) {
        let mut invert = false;
        match (s1, s2) {
            (Z, Z) => {
                let should_jump = match condition {
                    Condition::Equal => true,
                    Condition::NotEqual => false,
                    Condition::Below => false,
                    Condition::AboveOrEqual => true,
                    Condition::Less => false,
                    Condition::GreaterOrEqual => true,
                    _ => unreachable!(),
                };

                if should_jump {
                    let label = self.get_or_forward_declare_label(imm);
                    self.push(jmp_label32(label));
                } else {
                    self.nop();
                }

                return;
            }
            (_, Z) => {
                self.push(cmp_imm(self.reg_size(), conv_reg(s1), 0));
            }
            (Z, _) => {
                self.push(cmp_imm(self.reg_size(), conv_reg(s2), 0));
                invert = true;
            }
            (_, _) => {
                self.push(cmp(self.reg_size(), conv_reg(s1), conv_reg(s2)));
            }
        }

        if invert {
            condition = match condition {
                Condition::Equal => Condition::NotEqual,
                Condition::NotEqual => Condition::Equal,
                Condition::Below => Condition::AboveOrEqual,
                Condition::AboveOrEqual => Condition::Below,
                Condition::Less => Condition::GreaterOrEqual,
                Condition::GreaterOrEqual => Condition::Less,
                _ => unreachable!(),
            };
        }

        let label = self.get_or_forward_declare_label(imm);
        self.push(jcc_label32(condition, label));
    }

    fn div_rem(&mut self, d: Reg, s1: Reg, s2: Reg, div_rem: DivRem, kind: Signedness) {
        // Unlike most other architectures RISC-V doesn't trap on division by zero
        // nor on division with overflow, and has well defined results in such cases.

        match (d, s1, s2) {
            // 0 = s1 / s2
            (Z, _, _) => self.nop(),
            // d = s1 / 0
            (_, _, Z) => match div_rem {
                DivRem::Div => self.fill_with_ones(d),
                DivRem::Rem if d == s1 => self.nop(),
                DivRem::Rem => self.mov(d, s1),
            },
            // d = 0 / s2
            (_, Z, _) => {
                todo!();
            }
            // d = s1 / s2
            _ => {
                let label_divisor_is_zero = self.asm.forward_declare_label();
                let label_next = self.asm.forward_declare_label();

                self.push(test(self.reg_size(), conv_reg(s2), conv_reg(s2)));
                self.push(jcc_label8(Condition::Equal, label_divisor_is_zero));

                if matches!(kind, Signedness::Signed) {
                    let label_normal = self.asm.forward_declare_label();
                    match self.reg_size() {
                        RegSize::R32 => {
                            self.push(cmp_imm(RegSize::R32, conv_reg(s1), i32::MIN));
                            self.push(jcc_label8(Condition::NotEqual, label_normal));
                            self.push(cmp_imm(RegSize::R32, conv_reg(s2), -1));
                            self.push(jcc_label8(Condition::NotEqual, label_normal));
                            match div_rem {
                                DivRem::Div => self.mov(d, s1),
                                DivRem::Rem => self.clear_reg(d),
                            }
                            self.push(jmp_label8(label_next));
                        }
                        RegSize::R64 => todo!(),
                    }

                    self.asm.define_label(label_normal);
                }

                if s1 == Reg::Zero {
                    self.clear_reg(d);
                } else {
                    // The division instruction always accepts the dividend and returns the result in rdx:rax.
                    // This isn't great because we're using these registers for the VM's registers, so we need
                    // to do all of this in such a way that those won't be accidentally overwritten.

                    const _: () = {
                        assert!(TMP_REG as u32 != rdx as u32);
                        assert!(TMP_REG as u32 != rax as u32);
                    };

                    // Push the registers that will be clobbered.
                    self.push(push(rdx));
                    self.push(push(rax));

                    // Push the operands.
                    self.push(push(conv_reg(s1)));
                    self.push(push(conv_reg(s2)));

                    // Pop the divisor.
                    self.push(pop(TMP_REG));

                    // Pop the dividend.
                    self.push(xor(RegSize::R32, rdx, rdx));
                    self.push(pop(rax));

                    match kind {
                        Signedness::Unsigned => self.push(div(self.reg_size(), TMP_REG)),
                        Signedness::Signed => {
                            self.push(cdq());
                            self.push(idiv(self.reg_size(), TMP_REG))
                        }
                    }

                    // Move the result to the temporary register.
                    match div_rem {
                        DivRem::Div => self.push(mov(self.reg_size(), TMP_REG, rax)),
                        DivRem::Rem => self.push(mov(self.reg_size(), TMP_REG, rdx)),
                    }

                    // Restore the original registers.
                    self.push(pop(rax));
                    self.push(pop(rdx));

                    // Move the output into the destination registers.
                    self.push(mov(self.reg_size(), conv_reg(d), TMP_REG));
                }

                // Go to the next instruction.
                self.push(jmp_label8(label_next));

                self.asm.define_label(label_divisor_is_zero);
                match div_rem {
                    DivRem::Div => self.fill_with_ones(d),
                    DivRem::Rem if d == s1 => {}
                    DivRem::Rem => self.mov(d, s1),
                }

                self.asm.define_label(label_next);
            }
        }
    }

    fn save_registers_to_vmctx(&mut self) {
        if self.regs_are_64bit {
            todo!();
        }

        assert_eq!(Reg::ALL_NON_ZERO.len(), core::mem::size_of_val(VmCtx::new().regs()) / 4);

        self.push(load64_imm(TMP_REG, regs_address()));
        for (nth, reg) in Reg::ALL_NON_ZERO.iter().copied().enumerate() {
            self.push(store_indirect(RegSize::R64, TMP_REG, nth as i32 * 4, conv_reg(reg), StoreKind::U32));
        }
    }

    fn restore_registers_from_vmctx(&mut self) {
        if self.regs_are_64bit {
            todo!();
        }

        self.push(load64_imm(TMP_REG, regs_address()));
        for (nth, reg) in Reg::ALL_NON_ZERO.iter().copied().enumerate() {
            self.push(load_indirect(conv_reg(reg), RegSize::R64, TMP_REG, nth as i32 * 4, LoadKind::U32));
        }
    }

    pub(crate) fn emit_export_trampolines(&mut self) {
        if self.regs_are_64bit {
            todo!();
        }

        for export in self.exports {
            log::trace!("Emitting trampoline: export: '{}'", export.prototype().name());

            let trampoline_label = self.asm.create_label();
            self.export_to_label.insert(export.address(), trampoline_label);
            self.restore_registers_from_vmctx();

            let target_label = self.get_or_forward_declare_label(export.address());
            self.push(jmp_label32(target_label));
        }
    }

    pub(crate) fn emit_sysreturn(&mut self) -> Label {
        if self.regs_are_64bit {
            todo!();
        }

        log::trace!("Emitting trampoline: sysreturn");
        let label = self.asm.create_label();

        self.save_registers_to_vmctx();
        self.push(load64_imm(TMP_REG, VM_ADDR_SYSCALL));
        self.push(load32_imm(rdi, SYSCALL_RETURN));
        self.push(jmp_reg(TMP_REG));

        label
    }

    pub(crate) fn emit_ecall_trampoline(&mut self) {
        log::trace!("Emitting trampoline: ecall");
        self.asm.define_label(self.ecall_label);

        self.push(push(TMP_REG)); // Save the ecall number.
        self.save_registers_to_vmctx();
        self.push(load64_imm(TMP_REG, VM_ADDR_SYSCALL));
        self.push(load32_imm(rdi, SYSCALL_HOSTCALL));
        self.push(pop(rsi)); // Pop the ecall number as an argument.
        self.push(call_reg(TMP_REG));
        self.restore_registers_from_vmctx();
        self.push(ret());
    }

    pub(crate) fn emit_trace_trampoline(&mut self) {
        log::trace!("Emitting trampoline: trace");
        self.asm.define_label(self.trace_label);

        self.push(push(TMP_REG)); // Save the instruction number.
        self.save_registers_to_vmctx();
        self.push(load64_imm(TMP_REG, VM_ADDR_SYSCALL));
        self.push(load32_imm(rdi, SYSCALL_TRACE));
        self.push(pop(rsi)); // Pop the instruction number as an argument.
        self.push(load_indirect(rdx, RegSize::R64, rsp, -8, LoadKind::U64)); // Grab the return address.
        self.push(call_reg(TMP_REG));
        self.restore_registers_from_vmctx();
        self.push(ret());
    }

    pub(crate) fn emit_trap_trampoline(&mut self) {
        log::trace!("Emitting trampoline: trap");
        self.asm.define_label(self.trap_label);

        self.save_registers_to_vmctx();
        self.push(load64_imm(TMP_REG, VM_ADDR_SYSCALL));
        self.push(load32_imm(rdi, SYSCALL_TRAP));
        self.push(jmp_reg(TMP_REG));
    }

    pub(crate) fn trace_execution(&mut self, nth_instruction: usize) {
        self.push(load32_imm(TMP_REG, nth_instruction as u32));
        self.push(call_label32(self.trace_label));
    }
}

impl<'a> InstructionVisitor for Compiler<'a> {
    type ReturnTy = Result<(), &'static str>;

    fn trap(&mut self) -> Self::ReturnTy {
        self.push(jmp_label32(self.trap_label));
        Ok(())
    }

    fn jump_target(&mut self, pcrel: u32) -> Self::ReturnTy {
        let label = self
            .pc_to_label_pending
            .remove(&pcrel)
            .unwrap_or_else(|| self.asm.forward_declare_label());
        log::trace!("label: {}", label);

        self.asm.define_label(label);
        if self.pc_to_label.insert(pcrel, label).is_some() {
            // TODO: Make the jump target numbering implicit, and then this won't be necessary.
            log::debug!("Duplicate jump target label: 0x{:x}", pcrel);
            return Err("found a duplicate jump target label");
        }
        self.max_jump_target = core::cmp::max(self.max_jump_target, pcrel);

        Ok(())
    }

    fn ecalli(&mut self, imm: u32) -> Self::ReturnTy {
        self.push(load32_imm(TMP_REG, imm));
        self.push(call_label32(self.ecall_label));

        Ok(())
    }

    fn set_less_than_unsigned(&mut self, dst: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set_less_than(dst, s1, s2, Signedness::Unsigned);
        Ok(())
    }

    fn set_less_than_signed(&mut self, dst: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set_less_than(dst, s1, s2, Signedness::Signed);
        Ok(())
    }

    fn shift_logical_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.shift(d, s1, s2, ShiftKind::LogicalRight);
        Ok(())
    }

    fn shift_arithmetic_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.shift(d, s1, s2, ShiftKind::ArithmeticRight);
        Ok(())
    }

    fn shift_logical_left(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.shift(d, s1, s2, ShiftKind::LogicalLeft);
        Ok(())
    }

    fn xor(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        match (d, s1, s2) {
            // 0 = s1 ^ s2
            (Z, _, _) => self.nop(),
            // d = s ^ s
            (_, _, _) if s1 == s2 => self.clear_reg(d),
            // d = 0 ^ d
            (_, Z, _) if d == s2 => self.nop(),
            // d = 0 ^ s2
            (_, Z, _) => self.mov(d, s2),
            // d = d ^ 0
            (_, _, Z) if d == s1 => self.nop(),
            // d = s1 ^ 0
            (_, _, Z) => self.mov(d, s1),
            // d = d ^ s2
            (_, _, _) if d == s1 => self.push(xor(self.reg_size(), conv_reg(d), conv_reg(s2))),
            // d = s1 ^ d
            (_, _, _) if d == s2 => self.push(xor(self.reg_size(), conv_reg(d), conv_reg(s1))),
            // d = s1 ^ s2
            _ => {
                self.mov(d, s1);
                self.push(xor(self.reg_size(), conv_reg(d), conv_reg(s2)));
            }
        }

        Ok(())
    }

    fn and(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        match (d, s1, s2) {
            // 0 = s1 & s2
            (Z, _, _) => self.nop(),
            // d = 0 & s2
            (_, Z, _) => self.clear_reg(d),
            // d = s1 & 0
            (_, _, Z) => self.clear_reg(d),
            // d = d & d
            (_, _, _) if d == s1 && d == s2 => self.nop(),
            // d = s & s
            (_, _, _) if s1 == s2 => self.mov(d, s1),
            // d = d & s2
            (_, _, _) if d == s1 => self.push(and(self.reg_size(), conv_reg(d), conv_reg(s2))),
            // d = s1 & d
            (_, _, _) if d == s2 => self.push(and(self.reg_size(), conv_reg(d), conv_reg(s1))),
            // d = s1 & s2
            _ => {
                self.mov(d, s1);
                self.push(and(self.reg_size(), conv_reg(d), conv_reg(s2)));
            }
        }

        Ok(())
    }

    fn or(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        match (d, s1, s2) {
            // 0 = s1 | s2
            (Z, _, _) => self.nop(),
            // d = 0 | 0
            (_, Z, Z) => self.clear_reg(d),
            // d = 0 | d
            (_, Z, _) if d == s2 => self.nop(),
            // d = 0 | s2
            (_, Z, _) => self.mov(d, s2),
            // d = d | 0
            (_, _, Z) if d == s1 => self.nop(),
            // d = s1 | 0
            (_, _, Z) => self.mov(d, s1),
            // d = d | d
            (_, _, _) if d == s1 && d == s2 => self.nop(),
            // d = s | s
            (_, _, _) if s1 == s2 => self.mov(d, s1),
            // d = d | s2
            (_, _, _) if d == s1 => self.push(or(self.reg_size(), conv_reg(d), conv_reg(s2))),
            // d = s1 | d
            (_, _, _) if d == s2 => self.push(or(self.reg_size(), conv_reg(d), conv_reg(s1))),
            // d = s1 | s2
            _ => {
                self.mov(d, s1);
                self.push(or(self.reg_size(), conv_reg(d), conv_reg(s2)));
            }
        }

        Ok(())
    }

    fn add(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        match (d, s1, s2) {
            // 0 = s1 + s2
            (Z, _, _) => self.nop(),
            // d = 0 + 0
            (_, Z, Z) => self.clear_reg(d),
            // d = 0 + d
            (_, Z, _) if d == s2 => self.nop(),
            // d = 0 + s2
            (_, Z, _) => self.mov(d, s2),
            // d = d + 0
            (_, _, Z) if d == s1 => self.nop(),
            // d = s1 + 0
            (_, _, Z) => self.mov(d, s1),
            // d = d + s2
            (_, _, _) if d == s1 => self.push(add(self.reg_size(), conv_reg(d), conv_reg(s2))),
            // d = s1 + d
            (_, _, _) if d == s2 => self.push(add(self.reg_size(), conv_reg(d), conv_reg(s1))),
            // d = s1 + s2
            _ => {
                if d != s1 {
                    self.mov(d, s1);
                }
                self.push(add(self.reg_size(), conv_reg(d), conv_reg(s2)));
            }
        }

        Ok(())
    }

    fn sub(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        match (d, s1, s2) {
            // 0 = s1 - s2
            (Z, _, _) => self.nop(),
            // d = s - s
            (_, _, _) if s1 == s2 => self.clear_reg(d),
            // d = 0 - d
            (_, Z, _) if d == s2 => self.push(neg(self.reg_size(), conv_reg(d))),
            // d = 0 - s2
            (_, Z, _) => {
                self.mov(d, s2);
                self.push(neg(self.reg_size(), conv_reg(d)));
            }
            // d = d - 0
            (_, _, Z) if d == s1 => self.nop(),
            // d = s1 - 0
            (_, _, Z) => self.mov(d, s1),
            // d = d - d
            (_, _, _) if d == s1 && d == s2 => self.clear_reg(d),
            // d = d - s2
            (_, _, _) if d == s1 => self.push(sub(self.reg_size(), conv_reg(d), conv_reg(s2))),
            // d = s1 - d
            (_, _, _) if d == s2 => {
                self.push(neg(self.reg_size(), conv_reg(d)));
                self.push(add(self.reg_size(), conv_reg(d), conv_reg(s1)));
            }
            // d = s1 - s2
            _ => {
                self.mov(d, s1);
                self.push(sub(self.reg_size(), conv_reg(d), conv_reg(s2)));
            }
        }

        Ok(())
    }

    fn mul(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        match (d, s1, s2) {
            // 0 = s1 * s2
            (Z, _, _) => self.nop(),
            // d = 0 * s2
            (_, Z, _) => self.clear_reg(d),
            // d = s1 * 0
            (_, _, Z) => self.clear_reg(d),
            // d = d * s2
            (_, _, _) if d == s1 => self.push(imul(self.reg_size(), conv_reg(d), conv_reg(s2))),
            // d = s1 * d
            (_, _, _) if d == s2 => self.push(imul(self.reg_size(), conv_reg(d), conv_reg(s1))),
            // d = s1 * s2
            _ => {
                self.mov(d, s1);
                self.push(imul(self.reg_size(), conv_reg(d), conv_reg(s2)));
            }
        }

        Ok(())
    }

    fn mul_upper_signed_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        if self.regs_are_64bit {
            todo!();
        }

        match (d, s1, s2) {
            // 0 = s1 * s2
            (Z, _, _) => self.nop(),
            // d = 0 * s2
            (_, Z, _) => self.clear_reg(d),
            // d = s1 * 0
            (_, _, Z) => self.clear_reg(d),
            // d = s1 * s2
            _ => {
                self.push(movsxd_32_to_64(TMP_REG, conv_reg(s2)));
                self.push(movsxd_32_to_64(conv_reg(d), conv_reg(s1)));
                self.push(imul(RegSize::R64, conv_reg(d), TMP_REG));
                self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
            }
        }

        Ok(())
    }

    fn mul_upper_unsigned_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        if self.regs_are_64bit {
            todo!();
        }

        match (d, s1, s2) {
            // 0 = s1 * s2
            (Z, _, _) => self.nop(),
            // d = 0 * s2
            (_, Z, _) => self.clear_reg(d),
            // d = s1 * 0
            (_, _, Z) => self.clear_reg(d),
            // d = d * s2
            (_, _, _) if d == s1 => {
                self.push(imul(RegSize::R64, conv_reg(d), conv_reg(s2)));
                self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
            }
            // d = s1 * d
            (_, _, _) if d == s2 => {
                self.push(imul(RegSize::R64, conv_reg(d), conv_reg(s1)));
                self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
            }
            // d = s1 * s2
            _ => {
                self.push(mov(RegSize::R32, conv_reg(d), conv_reg(s1)));
                self.push(imul(RegSize::R64, conv_reg(d), conv_reg(s2)));
                self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
            }
        }

        Ok(())
    }

    fn mul_upper_signed_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        if self.regs_are_64bit {
            todo!();
        }

        // This instruction is equivalent to:
        //   let s1: i32;
        //   let s2: u32;
        //   let s1: i64 = s1 as i64;
        //   let s2: i64 = s2 as u64 as i64;
        //   let d: u32 = ((s1 * s2) >> 32) as u32;
        //
        // So, basically:
        //   1) sign-extend the s1 to 64-bits,
        //   2) zero-extend the s2 to 64-bits,
        //   3) multiply,
        //   4) return the upper 32-bits.
        match (d, s1, s2) {
            // 0 = s1 * s2
            (Z, _, _) => self.nop(),
            // d = 0 * s2
            (_, Z, _) => self.clear_reg(d),
            // d = s1 * 0
            (_, _, Z) => self.clear_reg(d),
            // d = s1 * d
            (_, _, _) if d == s2 => {
                self.push(mov(RegSize::R32, TMP_REG, conv_reg(s2)));
                self.push(movsxd_32_to_64(conv_reg(d), conv_reg(s1)));
                self.push(imul(RegSize::R64, conv_reg(d), TMP_REG));
                self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
            }
            // d = s1 * s2
            _ => {
                self.push(movsxd_32_to_64(conv_reg(d), conv_reg(s1)));
                self.push(imul(RegSize::R64, conv_reg(d), conv_reg(s2)));
                self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
            }
        }

        Ok(())
    }

    fn div_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Div, Signedness::Unsigned);
        Ok(())
    }

    fn div_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Div, Signedness::Signed);
        Ok(())
    }

    fn rem_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Rem, Signedness::Unsigned);
        Ok(())
    }

    fn rem_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Rem, Signedness::Signed);
        Ok(())
    }

    fn set_less_than_unsigned_imm(&mut self, dst: Reg, src: Reg, imm: u32) -> Self::ReturnTy {
        self.set_less_than_imm(dst, src, imm, Signedness::Unsigned);
        Ok(())
    }

    fn set_less_than_signed_imm(&mut self, dst: Reg, src: Reg, imm: u32) -> Self::ReturnTy {
        self.set_less_than_imm(dst, src, imm, Signedness::Signed);
        Ok(())
    }

    fn shift_logical_right_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        self.shift_imm(d, s, imm, ShiftKind::LogicalRight);
        Ok(())
    }

    fn shift_arithmetic_right_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        self.shift_imm(d, s, imm, ShiftKind::ArithmeticRight);
        Ok(())
    }

    fn shift_logical_left_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        self.shift_imm(d, s, imm, ShiftKind::LogicalLeft);
        Ok(())
    }

    fn or_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        if self.regs_are_64bit {
            todo!();
        }

        match (d, s, imm) {
            // 0 = s | imm
            (Z, _, _) => self.nop(),
            // d = 0 | imm
            (_, Z, _) => self.load_imm(d, imm),
            // d = s | 0
            (_, _, 0) => self.mov(d, s),
            // d = d | imm
            (_, _, _) if d == s => self.push(or_imm(self.reg_size(), conv_reg(d), imm as i32)),
            // d = s | imm
            (_, _, _) => {
                self.mov(d, s);
                self.push(or_imm(self.reg_size(), conv_reg(d), imm as i32));
            }
        }

        Ok(())
    }

    fn and_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        if self.regs_are_64bit {
            todo!();
        }

        match (d, s, imm) {
            // 0 = s & imm
            (Z, _, _) => self.nop(),
            // d = 0 & imm
            (_, Z, _) => self.clear_reg(d),
            // d = s & 0
            (_, _, 0) => self.clear_reg(d),
            // d = d & imm
            (_, _, _) if d == s => self.push(and_imm(self.reg_size(), conv_reg(d), imm as i32)),
            // d = s & imm
            (_, _, _) => {
                self.mov(d, s);
                self.push(and_imm(self.reg_size(), conv_reg(d), imm as i32));
            }
        }

        Ok(())
    }

    fn xor_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        if self.regs_are_64bit {
            todo!();
        }

        match (d, s, imm) {
            // 0 = s ^ imm
            (Z, _, _) => self.nop(),
            // d = 0 ^ imm
            (_, Z, _) => self.load_imm(d, imm),
            // d = s ^ 0
            (_, _, 0) => self.mov(d, s),
            // d = d ^ 0xfffffff
            (_, _, _) if d == s && imm == !0 => self.push(not(self.reg_size(), conv_reg(d))),
            // d = s ^ 0xfffffff
            (_, _, _) if imm == !0 => {
                self.mov(d, s);
                self.push(not(self.reg_size(), conv_reg(d)))
            }
            // d = d ^ imm
            (_, _, _) if d == s => self.push(xor_imm(self.reg_size(), conv_reg(d), imm as i32)),
            // d = s ^ imm
            (_, _, _) => {
                self.mov(d, s);
                self.push(xor_imm(self.reg_size(), conv_reg(d), imm as i32));
            }
        }

        Ok(())
    }

    fn add_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        if self.regs_are_64bit {
            todo!();
        }

        match (d, s, imm) {
            // 0 = s + imm
            (Z, _, _) => self.nop(),
            // d = 0 + imm
            (_, Z, _) => self.load_imm(d, imm),
            // d = s + 0
            (_, _, 0) => self.mov(d, s),
            // d = d + 1
            (_, _, 1) if d == s => self.push(inc(self.reg_size(), conv_reg(d))),
            // d = d + imm
            (_, _, _) if d == s => self.push(add_imm(self.reg_size(), conv_reg(d), imm as i32)),
            // d = s + imm
            (_, _, _) => {
                self.mov(d, s);
                self.push(add_imm(self.reg_size(), conv_reg(d), imm as i32));
            }
        }

        Ok(())
    }

    fn store_u8(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, base, offset, StoreKind::U8);
        Ok(())
    }

    fn store_u16(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, base, offset, StoreKind::U16);
        Ok(())
    }

    fn store_u32(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, base, offset, StoreKind::U32);
        Ok(())
    }

    fn load_u8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, base, offset, LoadKind::U8);
        Ok(())
    }

    fn load_i8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, base, offset, LoadKind::I8);
        Ok(())
    }

    fn load_u16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, base, offset, LoadKind::U16);
        Ok(())
    }

    fn load_i16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, base, offset, LoadKind::I16);
        Ok(())
    }

    fn load_u32(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, base, offset, LoadKind::U32);
        Ok(())
    }

    fn branch_less_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::Below);
        Ok(())
    }

    fn branch_less_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::Less);
        Ok(())
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::AboveOrEqual);
        Ok(())
    }

    fn branch_greater_or_equal_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::GreaterOrEqual);
        Ok(())
    }

    fn branch_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::Equal);
        Ok(())
    }

    fn branch_not_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::NotEqual);
        Ok(())
    }

    fn jump_and_link_register(&mut self, ra: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if self.regs_are_64bit {
            todo!();
        }

        if base == Reg::Zero {
            let label = self.get_or_forward_declare_label(offset);
            if ra != Reg::Zero {
                match self.next_instruction_jump_target() {
                    Some(return_address) => {
                        self.load_imm(ra, return_address);
                    }
                    None => {
                        // TODO: Make this jump target implicit, and then this won't be necessary.
                        return Err("found a jump instruction which is not followed by a jump target instruction");
                    }
                }
            }

            self.push(jmp_label32(label));
        } else {
            let offset = offset.wrapping_mul(4);

            // TODO: This could be more efficient. Maybe use fs/gs selector?
            if offset == 0 {
                self.push(mov(RegSize::R32, TMP_REG, conv_reg(base)));
            } else {
                self.push(lea(RegSize::R32, TMP_REG, RegSize::R32, conv_reg(base), offset as i32));
            }
            self.push(ror_imm(RegSize::R32, TMP_REG, 2));
            self.push(shl_imm(RegSize::R64, TMP_REG, 3));
            self.push(bts(RegSize::R64, TMP_REG, VM_ADDR_JUMP_TABLE.trailing_zeros() as u8));
            self.push(load_indirect(TMP_REG, RegSize::R64, TMP_REG, 0, LoadKind::U64));

            if ra != Reg::Zero {
                match self.next_instruction_jump_target() {
                    Some(return_address) => {
                        self.load_imm(ra, return_address);
                    }
                    None => {
                        // TODO: Make this jump target implicit, and then this won't be necessary.
                        return Err("found a jump instruction which is not followed by a jump target instruction");
                    }
                }
            }

            self.push(jmp_reg(TMP_REG));
        }

        Ok(())
    }
}
