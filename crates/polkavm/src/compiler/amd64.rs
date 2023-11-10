use polkavm_assembler::amd64::addr::*;
use polkavm_assembler::amd64::inst::*;
use polkavm_assembler::amd64::Reg as NativeReg;
use polkavm_assembler::amd64::Reg::*;
use polkavm_assembler::amd64::{Condition, LoadKind, RegSize, Size, ImmKind};
use polkavm_assembler::Label;

use polkavm_common::program::{InstructionVisitor, Reg};
use polkavm_common::abi::VM_CODE_ADDRESS_ALIGNMENT;
use polkavm_common::zygote::{
    VmCtx as LinuxVmCtx,
    SYSCALL_HOSTCALL, SYSCALL_RETURN, SYSCALL_TRACE, SYSCALL_TRAP, VM_ADDR_JUMP_TABLE, VM_ADDR_SYSCALL, VM_ADDR_VMCTX,
};

use crate::compiler::{Compiler, SandboxKind};
use crate::sandbox::generic::VmCtx as GenericVmCtx;

use Reg::Zero as Z;

macro_rules! get_field_offset {
    ($struct:expr, |$struct_ident:ident| $get_field:expr) => {{
        let $struct_ident = $struct;
        let struct_ref = &$struct_ident;
        let field_ref = $get_field;
        let struct_addr = struct_ref as *const _ as usize;
        let field_addr = field_ref as *const _ as usize;
        field_addr - struct_addr
    }}
}

const TMP_REG: NativeReg = rcx;

// The register used for the embedded sandbox to hold the base address of the guest's linear memory.
const GUEST_MEMORY_REG: NativeReg = r15;

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
    pub const PADDING_BYTE: u8 = 0x90; // NOP

    fn reg_size(&self) -> RegSize {
        if !self.regs_are_64bit {
            RegSize::R32
        } else {
            RegSize::R64
        }
    }

    fn imm_zero(&self) -> ImmKind {
        match self.reg_size() {
            RegSize::R32 => imm32(0),
            RegSize::R64 => imm64(0)
        }
    }

    fn nop(&mut self) {
        self.push(nop());
    }

    fn load_imm(&mut self, reg: Reg, imm: u32) {
        self.push(mov_imm(conv_reg(reg), imm32(imm)));
    }

    fn embedded_load_store(
        &mut self,
        src_or_dst: Reg,
        base: Reg,
        offset: u32,
        cb: impl FnOnce(&mut Self, NativeReg, NativeReg)
    ) {
        // TODO: This could be more efficient.
        if base != Reg::Zero {
            self.push(mov(RegSize::R32, TMP_REG, conv_reg(base)));
        } else {
            self.push(xor((RegSize::R32, TMP_REG, TMP_REG)));
        }

        if offset != 0 {
            self.push(add((TMP_REG, imm32(offset))));
        }

        self.push(add((RegSize::R64, TMP_REG, GUEST_MEMORY_REG)));
        if src_or_dst != Reg::Zero {
            cb(self, TMP_REG, conv_reg(src_or_dst));
        } else {
            self.push(push(GUEST_MEMORY_REG));
            self.push(xor((RegSize::R32, GUEST_MEMORY_REG, GUEST_MEMORY_REG)));
            cb(self, TMP_REG, GUEST_MEMORY_REG);
            self.push(pop(GUEST_MEMORY_REG));
        }
    }

    fn store(&mut self, src: Reg, base: Reg, offset: u32, kind: Size) {
        if self.regs_are_64bit {
            todo!();
        }

        match self.sandbox_kind {
            SandboxKind::Linux => {
                match (src, base, (offset as i32 >= 0)) {
                    // [address] = 0
                    // (address is in the lower 2GB of the address space)
                    (Z, Z, true) => match kind {
                        Size::U8 => self.push(mov_imm(abs(offset as i32), imm8(0))),
                        Size::U16 => self.push(mov_imm(abs(offset as i32), imm16(0))),
                        Size::U32 => self.push(mov_imm(abs(offset as i32), imm32(0))),
                        Size::U64 => {
                            self.push(xor((RegSize::R32, TMP_REG, TMP_REG)));
                            self.push(store(Size::U64, abs(offset as i32), TMP_REG));
                        }
                    },

                    // [address] = src
                    // (address is in the lower 2GB of the address space)
                    (_, Z, true) => {
                        self.push(store(kind, abs(offset as i32), conv_reg(src)));
                    }

                    // [address] = 0
                    // (address is in the upper 2GB of the address space)
                    (Z, Z, false) => {
                        // The offset would get sign extended to full 64-bits if we'd use it
                        // in a displacement, so we need to do an indirect store here.
                        self.push(mov_imm(TMP_REG, imm32(offset)));
                        match kind {
                            Size::U8 => self.push(mov_imm(reg_indirect(RegSize::R32, TMP_REG), imm8(0))),
                            Size::U16 => self.push(mov_imm(reg_indirect(RegSize::R32, TMP_REG), imm16(0))),
                            Size::U32 => self.push(mov_imm(reg_indirect(RegSize::R32, TMP_REG), imm32(0))),
                            Size::U64 => {
                                self.push(mov_imm(reg_indirect(RegSize::R32, TMP_REG), imm32(0)));
                                self.push(mov_imm(reg_indirect(RegSize::R32, TMP_REG + 4), imm32(0)));
                            }
                        }
                    }

                    // [address] = src
                    // (address is in the upper 2GB of the address space)
                    (_, Z, false) => {
                        self.push(mov_imm(TMP_REG, imm32(offset)));
                        self.push(store(kind, reg_indirect(RegSize::R32, TMP_REG), conv_reg(src)));
                    }

                    // [base + offset] = 0
                    (Z, _, _) => match kind {
                        Size::U8 => self.push(mov_imm(reg_indirect(RegSize::R32, conv_reg(base) + offset as i32), imm8(0))),
                        Size::U16 => self.push(mov_imm(reg_indirect(RegSize::R32, conv_reg(base) + offset as i32), imm16(0))),
                        Size::U32 => self.push(mov_imm(reg_indirect(RegSize::R32, conv_reg(base) + offset as i32), imm32(0))),
                        Size::U64 => {
                            self.push(xor((RegSize::R32, TMP_REG, TMP_REG)));
                            self.push(store(kind, reg_indirect(RegSize::R32, conv_reg(base) + offset as i32), TMP_REG));
                        }
                    },

                    // [base + offset] = src
                    (_, _, _) => {
                        self.push(store(kind, reg_indirect(RegSize::R32, conv_reg(base) + offset as i32), conv_reg(src)));
                    }
                }
            },
            SandboxKind::Generic => {
                self.embedded_load_store(src, base, offset, move |itself, address_reg, value_reg| {
                    itself.push(store(kind, reg_indirect(RegSize::R64, address_reg), value_reg));
                });
            }
        }
    }

    fn load(&mut self, dst: Reg, base: Reg, offset: u32, kind: LoadKind) {
        if self.regs_are_64bit {
            todo!();
        }

        match self.sandbox_kind {
            SandboxKind::Linux => {
                let dst_native = if dst == Reg::Zero {
                    // Do a dummy load. We can't just skip this since an invalid load can trigger a trap.
                    TMP_REG
                } else {
                    conv_reg(dst)
                };

                if base == Reg::Zero {
                    if (offset as i32) < 0 {
                        self.push(mov_imm(TMP_REG, imm32(offset)));
                        self.push(load(kind, dst_native, reg_indirect(RegSize::R32, TMP_REG)));
                    } else {
                        self.push(load(kind, dst_native, abs(offset as i32)));
                    }
                } else {
                    self.push(load(kind, dst_native, reg_indirect(RegSize::R32, conv_reg(base) + offset as i32)));
                }
            },
            SandboxKind::Generic => {
                self.embedded_load_store(dst, base, offset, move |itself, address_reg, value_reg| {
                    itself.push(load(kind, value_reg, reg_indirect(RegSize::R64, address_reg)));
                });
            }
        }
    }

    fn clear_reg(&mut self, reg: Reg) {
        if reg == Reg::Zero {
            return;
        }

        let reg = conv_reg(reg);
        self.push(xor((RegSize::R32, reg, reg)));
    }

    fn fill_with_ones(&mut self, reg: Reg) {
        if reg == Reg::Zero {
            return;
        }

        if !self.regs_are_64bit {
            self.push(mov_imm(conv_reg(reg), imm32(0xffffffff)));
        } else {
            self.clear_reg(reg);
            self.push(not(Size::U64, conv_reg(reg)));
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
                    self.push(cmp((conv_reg(s2), self.imm_zero())));
                    self.push(setcc(Condition::Greater, conv_reg(d)));
                    self.push(and((conv_reg(d), imm32(1))));
                }
                Signedness::Unsigned => {
                    self.push(test((self.reg_size(), conv_reg(s2), conv_reg(s2))));
                    self.push(setcc(Condition::NotEqual, conv_reg(d)));
                    self.push(and((conv_reg(d), imm32(1))));
                }
            },
            // d = s1 < 0
            (_, _, Z) => {
                self.set_less_than_imm(d, s1, 0, kind);
            }
            // d = s1 < s2
            _ => {
                self.push(cmp((self.reg_size(), conv_reg(s1), conv_reg(s2))));
                let condition = match kind {
                    Signedness::Signed => Condition::Less,
                    Signedness::Unsigned => Condition::Below,
                };
                self.push(setcc(condition, conv_reg(d)));
                self.push(and((conv_reg(d), imm32(1))));
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

                match self.reg_size() {
                    RegSize::R32 => {
                        self.push(cmp((conv_reg(s), imm32(imm))));
                    },
                    RegSize::R64 => {
                        self.push(cmp((conv_reg(s), imm64(imm as i32))));
                    }
                }

                self.push(setcc(condition, conv_reg(d)));
                self.push(and((conv_reg(d), imm32(1))));
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

                self.start_new_basic_block();
                return;
            }
            (_, Z) => {
                self.push(cmp((conv_reg(s1), self.imm_zero())));
            }
            (Z, _) => {
                self.push(cmp((conv_reg(s2), self.imm_zero())));
                condition = match condition {
                    Condition::Equal => Condition::Equal,
                    Condition::NotEqual => Condition::NotEqual,
                    Condition::Below => Condition::Above,
                    Condition::AboveOrEqual => Condition::BelowOrEqual,
                    Condition::Less => Condition::Greater,
                    Condition::GreaterOrEqual => Condition::LessOrEqual,
                    _ => unreachable!(),
                };
            }
            (_, _) => {
                self.push(cmp((self.reg_size(), conv_reg(s1), conv_reg(s2))));
            }
        }

        let label = self.get_or_forward_declare_label(imm);
        self.push(jcc_label32(condition, label));
        self.start_new_basic_block();
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

                self.push(test((self.reg_size(), conv_reg(s2), conv_reg(s2))));
                self.push(jcc_label8(Condition::Equal, label_divisor_is_zero));

                if matches!(kind, Signedness::Signed) {
                    let label_normal = self.asm.forward_declare_label();
                    match self.reg_size() {
                        RegSize::R32 => {
                            self.push(cmp((conv_reg(s1), imm32(i32::MIN as u32))));
                            self.push(jcc_label8(Condition::NotEqual, label_normal));
                            self.push(cmp((conv_reg(s2), imm32(-1_i32 as u32))));
                            self.push(jcc_label8(Condition::NotEqual, label_normal));
                            match div_rem {
                                DivRem::Div => self.mov(d, s1),
                                DivRem::Rem => self.clear_reg(d),
                            }
                            self.push(jmp_label8(label_next));
                        }
                        RegSize::R64 => todo!(),
                    }

                    self.define_label(label_normal);
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
                    self.push(xor((RegSize::R32, rdx, rdx)));
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

                self.define_label(label_divisor_is_zero);
                match div_rem {
                    DivRem::Div => self.fill_with_ones(d),
                    DivRem::Rem if d == s1 => {}
                    DivRem::Rem => self.mov(d, s1),
                }

                self.define_label(label_next);
            }
        }
    }

    fn load_vmctx_field_address(&mut self, reg: NativeReg, offset: usize) {
        match self.sandbox_kind {
            SandboxKind::Linux => {
                let address = VM_ADDR_VMCTX + offset as u64;
                self.push(mov_imm64(reg, address));
            },
            SandboxKind::Generic => {
                let offset = crate::sandbox::generic::GUEST_MEMORY_TO_VMCTX_OFFSET as i32 + offset as i32;
                self.push(lea(RegSize::R64, reg, reg_indirect(RegSize::R64, GUEST_MEMORY_REG + offset)));
            }
        }
    }

    fn load_regs_address(&mut self, reg: NativeReg) {
        let regs_offset: usize = match self.sandbox_kind {
            SandboxKind::Linux => {
                get_field_offset!(LinuxVmCtx::new(), |base| base.regs().get())
            },
            SandboxKind::Generic => {
                get_field_offset!(GenericVmCtx::new(), |base| base.regs())
            }
        };

        self.load_vmctx_field_address(reg, regs_offset);
    }

    fn save_registers_to_vmctx(&mut self) {
        if self.regs_are_64bit {
            todo!();
        }

        assert_eq!(Reg::ALL_NON_ZERO.len(), core::mem::size_of_val(LinuxVmCtx::new().regs()) / 4);
        assert_eq!(Reg::ALL_NON_ZERO.len(), core::mem::size_of_val(GenericVmCtx::new().regs()) / 4);

        self.load_regs_address(TMP_REG);
        for (nth, reg) in Reg::ALL_NON_ZERO.iter().copied().enumerate() {
            self.push(store(Size::U32, reg_indirect(RegSize::R64, TMP_REG + nth as i32 * 4), conv_reg(reg)));
        }
    }

    fn restore_registers_from_vmctx(&mut self) {
        if self.regs_are_64bit {
            todo!();
        }

        self.load_regs_address(TMP_REG);
        for (nth, reg) in Reg::ALL_NON_ZERO.iter().copied().enumerate() {
            self.push(load(LoadKind::U32, conv_reg(reg), reg_indirect(RegSize::R64, TMP_REG + nth as i32 * 4)));
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
        match self.sandbox_kind {
            SandboxKind::Linux => {
                self.push(mov_imm64(TMP_REG, VM_ADDR_SYSCALL));
                self.push(mov_imm(rdi, imm32(SYSCALL_RETURN)));
                self.push(jmp(TMP_REG));
            },
            SandboxKind::Generic => {
                self.push(ret());
            }
        }

        label
    }

    pub(crate) fn emit_ecall_trampoline(&mut self) {
        log::trace!("Emitting trampoline: ecall");
        self.define_label(self.ecall_label);

        match self.sandbox_kind {
            SandboxKind::Linux => {
                self.push(push(TMP_REG)); // Save the ecall number.
                self.save_registers_to_vmctx();
                self.push(mov_imm64(TMP_REG, VM_ADDR_SYSCALL));
                self.push(mov_imm(rdi, imm32(SYSCALL_HOSTCALL)));
                self.push(pop(rsi)); // Pop the ecall number as an argument.
                self.push(call(TMP_REG));
                self.restore_registers_from_vmctx();
                self.push(ret());
            },
            SandboxKind::Generic => {
                let handler_address = crate::sandbox::generic::handle_ecall as usize as u64;
                self.push(push(TMP_REG)); // Save the ecall number.
                self.save_registers_to_vmctx();
                self.push(mov_imm64(TMP_REG, handler_address));
                self.push(mov(RegSize::R64, rdi, GUEST_MEMORY_REG));
                self.push(pop(rsi)); // Pop the ecall number as an argument.
                self.push(call(TMP_REG));
                self.restore_registers_from_vmctx();
                self.push(ret());
            }
        }
    }

    pub(crate) fn emit_trace_trampoline(&mut self) {
        log::trace!("Emitting trampoline: trace");
        self.define_label(self.trace_label);

        match self.sandbox_kind {
            SandboxKind::Linux => {
                self.push(push(TMP_REG)); // Save the instruction number.
                self.save_registers_to_vmctx();
                self.push(mov_imm64(TMP_REG, VM_ADDR_SYSCALL));
                self.push(mov_imm(rdi, imm32(SYSCALL_TRACE)));
                self.push(pop(rsi)); // Pop the instruction number as an argument.
                self.push(load(LoadKind::U64, rdx, reg_indirect(RegSize::R64, rsp - 8))); // Grab the return address.
                self.push(call(TMP_REG));
                self.restore_registers_from_vmctx();
                self.push(ret());
            },
            SandboxKind::Generic => {
                let handler_address = crate::sandbox::generic::handle_trace as usize as u64;
                self.push(push(TMP_REG)); // Save the instruction number.
                self.save_registers_to_vmctx();
                self.push(mov_imm64(TMP_REG, handler_address));
                self.push(mov(RegSize::R64, rdi, GUEST_MEMORY_REG));
                self.push(pop(rsi)); // Pop the instruction number as an argument.
                self.push(call(TMP_REG));
                self.restore_registers_from_vmctx();
                self.push(ret());
            }
        }
    }

    pub(crate) fn emit_trap_trampoline(&mut self) {
        log::trace!("Emitting trampoline: trap");
        self.define_label(self.trap_label);

        self.save_registers_to_vmctx();
        match self.sandbox_kind {
            SandboxKind::Linux => {
                self.push(mov_imm64(TMP_REG, VM_ADDR_SYSCALL));
                self.push(mov_imm(rdi, imm32(SYSCALL_TRAP)));
                self.push(jmp(TMP_REG));
            },
            SandboxKind::Generic => {
                self.push(ud2()); // TODO: FIXME
            }
        }
    }

    pub(crate) fn trace_execution(&mut self, nth_instruction: usize) {
        self.push(mov_imm(TMP_REG, imm32(nth_instruction as u32)));
        self.push(call_label32(self.trace_label));
    }
}

impl<'a> InstructionVisitor for Compiler<'a> {
    type ReturnTy = ();

    fn trap(&mut self) -> Self::ReturnTy {
        self.push(jmp_label32(self.trap_label));
        self.start_new_basic_block();
    }

    fn fallthrough(&mut self) -> Self::ReturnTy {
        self.start_new_basic_block();
    }

    fn ecalli(&mut self, imm: u32) -> Self::ReturnTy {
        self.push(mov_imm(TMP_REG, imm32(imm)));
        self.push(call_label32(self.ecall_label));
    }

    fn set_less_than_unsigned(&mut self, dst: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set_less_than(dst, s1, s2, Signedness::Unsigned);
    }

    fn set_less_than_signed(&mut self, dst: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.set_less_than(dst, s1, s2, Signedness::Signed);
    }

    fn shift_logical_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.shift(d, s1, s2, ShiftKind::LogicalRight);
    }

    fn shift_arithmetic_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.shift(d, s1, s2, ShiftKind::ArithmeticRight);
    }

    fn shift_logical_left(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.shift(d, s1, s2, ShiftKind::LogicalLeft);
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
            (_, _, _) if d == s1 => self.push(xor((self.reg_size(), conv_reg(d), conv_reg(s2)))),
            // d = s1 ^ d
            (_, _, _) if d == s2 => self.push(xor((self.reg_size(), conv_reg(d), conv_reg(s1)))),
            // d = s1 ^ s2
            _ => {
                self.mov(d, s1);
                self.push(xor((self.reg_size(), conv_reg(d), conv_reg(s2))));
            }
        }
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
            (_, _, _) if d == s1 => self.push(and((self.reg_size(), conv_reg(d), conv_reg(s2)))),
            // d = s1 & d
            (_, _, _) if d == s2 => self.push(and((self.reg_size(), conv_reg(d), conv_reg(s1)))),
            // d = s1 & s2
            _ => {
                self.mov(d, s1);
                self.push(and((self.reg_size(), conv_reg(d), conv_reg(s2))));
            }
        }
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
            (_, _, _) if d == s1 => self.push(or((self.reg_size(), conv_reg(d), conv_reg(s2)))),
            // d = s1 | d
            (_, _, _) if d == s2 => self.push(or((self.reg_size(), conv_reg(d), conv_reg(s1)))),
            // d = s1 | s2
            _ => {
                self.mov(d, s1);
                self.push(or((self.reg_size(), conv_reg(d), conv_reg(s2))));
            }
        }
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
            (_, _, _) if d == s1 => self.push(add((self.reg_size(), conv_reg(d), conv_reg(s2)))),
            // d = s1 + d
            (_, _, _) if d == s2 => self.push(add((self.reg_size(), conv_reg(d), conv_reg(s1)))),
            // d = s1 + s2
            _ => {
                if d != s1 {
                    self.mov(d, s1);
                }
                self.push(add((self.reg_size(), conv_reg(d), conv_reg(s2))));
            }
        }
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
            (_, _, _) if d == s1 => self.push(sub((self.reg_size(), conv_reg(d), conv_reg(s2)))),
            // d = s1 - d
            (_, _, _) if d == s2 => {
                self.push(neg(self.reg_size(), conv_reg(d)));
                self.push(add((self.reg_size(), conv_reg(d), conv_reg(s1))));
            }
            // d = s1 - s2
            _ => {
                self.mov(d, s1);
                self.push(sub((self.reg_size(), conv_reg(d), conv_reg(s2))));
            }
        }
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
    }

    fn div_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Div, Signedness::Unsigned);
    }

    fn div_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Div, Signedness::Signed);
    }

    fn rem_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Rem, Signedness::Unsigned);
    }

    fn rem_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Rem, Signedness::Signed);
    }

    fn set_less_than_unsigned_imm(&mut self, dst: Reg, src: Reg, imm: u32) -> Self::ReturnTy {
        self.set_less_than_imm(dst, src, imm, Signedness::Unsigned);
    }

    fn set_less_than_signed_imm(&mut self, dst: Reg, src: Reg, imm: u32) -> Self::ReturnTy {
        self.set_less_than_imm(dst, src, imm, Signedness::Signed);
    }

    fn shift_logical_right_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        self.shift_imm(d, s, imm, ShiftKind::LogicalRight);
    }

    fn shift_arithmetic_right_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        self.shift_imm(d, s, imm, ShiftKind::ArithmeticRight);
    }

    fn shift_logical_left_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        self.shift_imm(d, s, imm, ShiftKind::LogicalLeft);
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
            (_, _, _) if d == s => self.push(or((conv_reg(d), imm32(imm)))),
            // d = s | imm
            (_, _, _) => {
                self.mov(d, s);
                self.push(or((conv_reg(d), imm32(imm))));
            }
        }
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
            (_, _, _) if d == s => self.push(and((conv_reg(d), imm32(imm)))),
            // d = s & imm
            (_, _, _) => {
                self.mov(d, s);
                self.push(and((conv_reg(d), imm32(imm))));
            }
        }
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
            (_, _, _) if d == s => self.push(xor((conv_reg(d), imm32(imm)))),
            // d = s ^ imm
            (_, _, _) => {
                self.mov(d, s);
                self.push(xor((conv_reg(d), imm32(imm))));
            }
        }
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
            (_, _, _) if d == s => self.push(add((conv_reg(d), imm32(imm)))),
            // d = s + imm
            (_, _, _) => {
                self.push(lea(self.reg_size(), conv_reg(d), reg_indirect(self.reg_size(), conv_reg(s) + imm as i32)));
            }
        }
    }

    fn store_u8(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, base, offset, Size::U8);
    }

    fn store_u16(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, base, offset, Size::U16);
    }

    fn store_u32(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, base, offset, Size::U32);
    }

    fn load_u8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, base, offset, LoadKind::U8);
    }

    fn load_i8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, base, offset, LoadKind::I8);
    }

    fn load_u16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, base, offset, LoadKind::U16);
    }

    fn load_i16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, base, offset, LoadKind::I16);
    }

    fn load_u32(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, base, offset, LoadKind::U32);
    }

    fn branch_less_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::Below);
    }

    fn branch_less_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::Less);
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::AboveOrEqual);
    }

    fn branch_greater_or_equal_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::GreaterOrEqual);
    }

    fn branch_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::Equal);
    }

    fn branch_not_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        self.branch(s1, s2, imm, Condition::NotEqual);
    }

    fn jump_and_link_register(&mut self, ra: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if self.regs_are_64bit {
            todo!();
        }

        let return_address = if ra != Reg::Zero {
            let index = self.jump_table_index_by_basic_block.get(&self.next_basic_block())
                .copied()
                .expect("internal error: couldn't fetch the jump table index for the return basic block");

            Some(index * VM_CODE_ADDRESS_ALIGNMENT)
        } else {
            None
        };

        if base == Reg::Zero {
            // A static jump.
            let label = self.get_or_forward_declare_label(offset);
            if let Some(return_address) = return_address {
                self.load_imm(ra, return_address);
            }

            self.push(jmp_label32(label));
        } else {
            // A dynamic jump.
            match self.sandbox_kind {
                SandboxKind::Linux => {
                    // TODO: This could be more efficient. Maybe use fs/gs selector?
                    if offset == 0 {
                        self.push(mov(RegSize::R32, TMP_REG, conv_reg(base)));
                    } else {
                        self.push(lea(RegSize::R32, TMP_REG, reg_indirect(RegSize::R32, conv_reg(base) + offset as i32)));
                    }

                    self.push(shl_imm(RegSize::R64, TMP_REG, 3));
                    self.push(bts(RegSize::R64, TMP_REG, VM_ADDR_JUMP_TABLE.trailing_zeros() as u8));
                    self.push(load(LoadKind::U64, TMP_REG, reg_indirect(RegSize::R64, TMP_REG)));
                },
                SandboxKind::Generic => {
                    // // TODO: This also could be more efficient.
                    self.push(lea_rip_label(TMP_REG, self.jump_table_label));
                    self.push(push(conv_reg(base)));
                    self.push(shl_imm(RegSize::R64, conv_reg(base), 3));
                    if offset > 0 {
                        let offset = offset.wrapping_mul(8);
                        self.push(add((conv_reg(base), imm32(offset))));
                    }
                    self.push(add((RegSize::R64, TMP_REG, conv_reg(base))));
                    self.push(pop(conv_reg(base)));
                    self.push(load(LoadKind::U64, TMP_REG, reg_indirect(RegSize::R64, TMP_REG)));
                }
            }

            if let Some(return_address) = return_address {
                self.load_imm(ra, return_address);
            }

            self.push(jmp(TMP_REG));
        }

        self.start_new_basic_block();
    }
}
