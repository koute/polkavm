use polkavm_assembler::amd64::addr::*;
use polkavm_assembler::amd64::inst::*;
use polkavm_assembler::amd64::RegIndex as NativeReg;
use polkavm_assembler::amd64::RegIndex::*;
use polkavm_assembler::amd64::Reg::rsp;
use polkavm_assembler::amd64::{Condition, LoadKind, RegSize, Size, MemOp};
use polkavm_assembler::Label;

use polkavm_common::program::{InstructionVisitor, Reg};
use polkavm_common::abi::VM_CODE_ADDRESS_ALIGNMENT;
use polkavm_common::zygote::VM_ADDR_VMCTX;

use crate::api::VisitorWrapper;
use crate::config::GasMeteringKind;
use crate::compiler::{Compiler, SandboxKind};
use crate::utils::RegImm;

const TMP_REG: NativeReg = rcx;

/// The register used for the embedded sandbox to hold the base address of the guest's linear memory.
const GENERIC_SANDBOX_MEMORY_REG: NativeReg = r15;

/// The register used for the linux sandbox to hold the address of the VM context.
const LINUX_SANDBOX_VMCTX_REG: NativeReg = r15;

const fn conv_reg_const(reg: Reg) -> NativeReg {
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

static REG_MAP: [NativeReg; Reg::ALL.len()] = {
    let mut output = [NativeReg::rcx; Reg::ALL.len()];
    let mut index = 0;
    while index < Reg::ALL.len() {
        assert!(Reg::ALL[index] as usize == index);
        output[index] = conv_reg_const(Reg::ALL[index]);
        index += 1;
    }
    output
};

#[inline]
fn conv_reg(reg: Reg) -> NativeReg {
    REG_MAP[reg as usize]
}

#[test]
fn test_conv_reg() {
    for reg in Reg::ALL {
        assert_eq!(conv_reg(reg), conv_reg_const(reg));
    }
}

macro_rules! with_sandbox_kind {
    ($input:expr, |$kind:ident| $body:expr) => {
        match $input {
            SandboxKind::Linux => {
                #[allow(non_upper_case_globals)]
                const $kind: SandboxKind = SandboxKind::Linux;
                $body
            },
            SandboxKind::Generic => {
                #[allow(non_upper_case_globals)]
                const $kind: SandboxKind = SandboxKind::Generic;
                $body
            }
        }
    }
}

macro_rules! load_store_operand {
    ($self:ident, $base:ident, $offset:expr, |$op:ident| $body:expr) => {
        with_sandbox_kind!($self.sandbox_kind, |sandbox_kind| {
            match sandbox_kind {
                SandboxKind::Linux => {
                    if let Some($base) = $base {
                        // [address + offset]
                        let $op = reg_indirect(RegSize::R32, conv_reg($base) + $offset as i32);
                        $body
                    } else {
                        // [address] = ..
                        let $op = abs(RegSize::R32, $offset as i32);
                        $body
                    }
                },
                SandboxKind::Generic => {
                    match ($base, $offset) {
                        // [address] = ..
                        // (address is in the lower 2GB of the address space)
                        (None, _) if $offset as i32 >= 0 => {
                            let $op = reg_indirect(RegSize::R64, GENERIC_SANDBOX_MEMORY_REG + $offset as i32);
                            $body
                        },

                        // [address] = ..
                        (None, _) => {
                            $self.push(mov_imm(TMP_REG, imm32($offset)));
                            let $op = base_index(RegSize::R64, GENERIC_SANDBOX_MEMORY_REG, TMP_REG);
                            $body
                        },

                        // [base] = ..
                        (Some($base), 0) => {
                            // NOTE: This assumes that `base` has its upper 32-bits clear.
                            let $op = base_index(RegSize::R64, GENERIC_SANDBOX_MEMORY_REG, conv_reg($base));
                            $body
                        },

                        // [base + offset] = ..
                        (Some($base), _) => {
                            $self.push(lea(RegSize::R32, TMP_REG, reg_indirect(RegSize::R32, conv_reg($base) + $offset as i32)));
                            let $op = base_index(RegSize::R64, GENERIC_SANDBOX_MEMORY_REG, TMP_REG);
                            $body
                        }
                    }
                }
            }
        })
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

    #[allow(clippy::unused_self)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn reg_size(&self) -> RegSize {
        RegSize::R32
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn load_immediate(&mut self, dst: Reg, value: u32) {
        self.push(mov_imm(conv_reg(dst), imm32(value)));
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn store(&mut self, src: impl Into<RegImm>, base: Option<Reg>, offset: u32, kind: Size) {
        let src = src.into();
        load_store_operand!(self, base, offset, |dst| {
            match src {
                RegImm::Reg(src) => self.push(store(kind, dst, conv_reg(src))),
                RegImm::Imm(value) => {
                    match kind {
                        Size::U8 => self.push(mov_imm(dst, imm8(value as u8))),
                        Size::U16 => self.push(mov_imm(dst, imm16(value as u16))),
                        Size::U32 => self.push(mov_imm(dst, imm32(value))),
                        Size::U64 => unreachable!(),
                    }
                },
            }
        });
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn load(&mut self, dst: Reg, base: Option<Reg>, offset: u32, kind: LoadKind) {
        load_store_operand!(self, base, offset, |src| {
            self.push(load(kind, conv_reg(dst), src));
        });
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn clear_reg(&mut self, reg: Reg) {
        let reg = conv_reg(reg);
        self.push(xor((RegSize::R32, reg, reg)));
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fill_with_ones(&mut self, reg: Reg) {
        match self.reg_size() {
            RegSize::R32 => {
                self.push(mov_imm(conv_reg(reg), imm32(0xffffffff)));
            },
            RegSize::R64 => {
                self.clear_reg(reg);
                self.push(not(Size::U64, conv_reg(reg)));
            }
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn compare_reg_reg(&mut self, d: Reg, s1: Reg, s2: Reg, condition: Condition) {
        if d == s1 || d == s2 {
            self.push(cmp((self.reg_size(), conv_reg(s1), conv_reg(s2))));
            self.push(setcc(condition, conv_reg(d)));
            self.push(and((conv_reg(d), imm32(1))));
        } else {
            self.clear_reg(d);
            self.push(cmp((self.reg_size(), conv_reg(s1), conv_reg(s2))));
            self.push(setcc(condition, conv_reg(d)));
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn compare_reg_imm(&mut self, d: Reg, s1: Reg, s2: u32, condition: Condition) {
        if d != s1 {
            self.clear_reg(d);
        }

        if condition == Condition::Below && s2 == 1 {
            // d = s1 <u 1  =>  d = s1 == 0
            self.push(test((self.reg_size(), conv_reg(s1), conv_reg(s1))));
            self.push(setcc(Condition::Equal, conv_reg(d)));
        } else if condition == Condition::Above && s2 == 0 {
            // d = s1 >u 0  =>  d = s1 != 0
            self.push(test((self.reg_size(), conv_reg(s1), conv_reg(s1))));
            self.push(setcc(Condition::NotEqual, conv_reg(d)));
        } else {
            match self.reg_size() {
                RegSize::R32 => {
                    self.push(cmp((conv_reg(s1), imm32(s2))));
                },
                RegSize::R64 => {
                    self.push(cmp((conv_reg(s1), imm64(s2 as i32))));
                }
            }
            self.push(setcc(condition, conv_reg(d)));
        }

        if d == s1 {
            self.push(and((conv_reg(d), imm32(1))));
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn shift_imm(&mut self, d: Reg, s1: Reg, s2: u32, kind: ShiftKind) {
        if s2 >= 32 {
            // d = s << 32+
            self.clear_reg(d);
            return;
        }

        if d != s1 {
            self.mov(d, s1);
        }

        // d = d << s2
        match kind {
            ShiftKind::LogicalLeft => self.push(shl_imm(self.reg_size(), conv_reg(d), s2 as u8)),
            ShiftKind::LogicalRight => self.push(shr_imm(self.reg_size(), conv_reg(d), s2 as u8)),
            ShiftKind::ArithmeticRight => self.push(sar_imm(self.reg_size(), conv_reg(d), s2 as u8)),
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn shift(&mut self, d: Reg, s1: impl Into<RegImm>, s2: Reg, kind: ShiftKind) {
        // TODO: Consider using shlx/shrx/sarx when BMI2 is available.
        self.push(mov(self.reg_size(), rcx, conv_reg(s2)));

        match s1.into() {
            RegImm::Reg(s1) => {
                if s1 != d {
                    self.mov(d, s1);
                }
            },
            RegImm::Imm(s1) => {
                self.load_immediate(d, s1);
            }
        }

        // d = d << s2
        match kind {
            ShiftKind::LogicalLeft => self.push(shl_cl(self.reg_size(), conv_reg(d))),
            ShiftKind::LogicalRight => self.push(shr_cl(self.reg_size(), conv_reg(d))),
            ShiftKind::ArithmeticRight => self.push(sar_cl(self.reg_size(), conv_reg(d))),
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn mov(&mut self, dst: Reg, src: Reg) {
        self.push(mov(self.reg_size(), conv_reg(dst), conv_reg(src)))
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn calculate_label_offset(&self, rel8_len: usize, rel32_len: usize, offset: isize) -> Result<i8, i32> {
        let offset_near = offset - (self.asm.len() as isize + rel8_len as isize);
        if offset_near <= i8::MAX as isize && offset_near >= i8::MIN as isize {
            Ok(offset_near as i8)
        } else {
            let offset = offset - (self.asm.len() as isize + rel32_len as isize);
            Err(offset as i32)
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn jump_to_label(&mut self, label: Label) {
        if let Some(offset) = self.asm.get_label_origin_offset(label) {
            let offset = self.calculate_label_offset(
                jmp_rel8(i8::MAX).len(),
                jmp_rel32(i32::MAX).len(),
                offset
            );

            match offset {
                Ok(offset) => self.push(jmp_rel8(offset)),
                Err(offset) => self.push(jmp_rel32(offset))
            }
        } else {
            self.push(jmp_label32(label));
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn branch(&mut self, s1: Reg, s2: impl Into<RegImm>, target: u32, condition: Condition) {
        match s2.into() {
            RegImm::Reg(s2) => self.push(cmp((self.reg_size(), conv_reg(s1), conv_reg(s2)))),
            RegImm::Imm(s2) => self.push(cmp((conv_reg(s1), imm32(s2)))),
        }

        let label = self.get_or_forward_declare_label(target);
        if let Some(offset) = self.asm.get_label_origin_offset(label) {
            let offset = self.calculate_label_offset(
                jcc_rel8(condition, i8::MAX).len(),
                jcc_rel32(condition, i32::MAX).len(),
                offset
            );

            match offset {
                Ok(offset) => self.push(jcc_rel8(condition, offset)),
                Err(offset) => self.push(jcc_rel32(condition, offset))
            }
        } else {
            self.push(jcc_label32(condition, label));
        }

        self.start_new_basic_block();
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn cmov(&mut self, d: Reg, s: Reg, c: Reg, condition: Condition) {
        if d == s {
            return;
        }

        let d = conv_reg(d);
        let s = conv_reg(s);
        let c = conv_reg(c);

        self.push(test((self.reg_size(), c, c)));
        self.push(cmov(condition, self.reg_size(), d, s));
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn cmov_imm(&mut self, d: Reg, s: u32, c: Reg, condition: Condition) {
        let d = conv_reg(d);
        let c = conv_reg(c);

        self.push(test((self.reg_size(), c, c)));
        self.push(mov_imm(TMP_REG, imm32(s)));
        self.push(cmov(condition, self.reg_size(), d, TMP_REG));
    }

    fn div_rem(&mut self, d: Reg, s1: Reg, s2: Reg, div_rem: DivRem, kind: Signedness) {
        // Unlike most other architectures RISC-V doesn't trap on division by zero
        // nor on division with overflow, and has well defined results in such cases.

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

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn vmctx_field(&self, offset: usize) -> MemOp {
        match self.sandbox_kind {
            SandboxKind::Linux => {
                reg_indirect(RegSize::R64, LINUX_SANDBOX_VMCTX_REG + offset as i32)
            },
            SandboxKind::Generic => {
                let offset = crate::sandbox::generic::GUEST_MEMORY_TO_VMCTX_OFFSET as i32 + offset as i32;
                reg_indirect(RegSize::R64, GENERIC_SANDBOX_MEMORY_REG + offset)
            }
        }
    }

    fn load_vmctx_field_address(&mut self, offset: usize) -> NativeReg {
        if offset == 0 && matches!(self.sandbox_kind, SandboxKind::Linux) {
            LINUX_SANDBOX_VMCTX_REG
        } else {
            self.push(lea(RegSize::R64, TMP_REG, self.vmctx_field(offset)));
            TMP_REG
        }
    }

    fn save_registers_to_vmctx(&mut self) {
        let regs_base = self.load_vmctx_field_address(self.vmctx_regs_offset);
        for (nth, reg) in Reg::ALL.iter().copied().enumerate() {
            self.push(store(Size::U32, reg_indirect(RegSize::R64, regs_base + nth as i32 * 4), conv_reg(reg)));
        }
    }

    fn restore_registers_from_vmctx(&mut self) {
        let regs_base = self.load_vmctx_field_address(self.vmctx_regs_offset);
        for (nth, reg) in Reg::ALL.iter().copied().enumerate() {
            self.push(load(LoadKind::U32, conv_reg(reg), reg_indirect(RegSize::R64, regs_base + nth as i32 * 4)));
        }
    }

    pub(crate) fn emit_export_trampolines(&mut self) {
        for export in self.exports {
            log::trace!("Emitting trampoline: export: {}", export.symbol());

            let trampoline_label = self.asm.create_label();
            self.export_to_label.insert(export.jump_target(), trampoline_label);

            if matches!(self.sandbox_kind, SandboxKind::Linux) {
                self.push(mov_imm64(LINUX_SANDBOX_VMCTX_REG, VM_ADDR_VMCTX));
            }
            self.restore_registers_from_vmctx();

            if self.gas_metering.is_some() {
                // Did we enter again after running out of gas? If so don't even bother running anything, just immediately trap.
                self.push(cmp((self.vmctx_field(self.vmctx_gas_offset), imm64(0))));
                self.push(jcc_label32(Condition::Sign, self.trap_label));
            }

            let target_label = self.get_or_forward_declare_label(export.jump_target());
            self.push(jmp_label32(target_label));
        }
    }

    pub(crate) fn emit_sysreturn(&mut self) -> Label {
        log::trace!("Emitting trampoline: sysreturn");
        let label = self.asm.create_label();

        self.save_registers_to_vmctx();
        self.push(mov_imm64(TMP_REG, self.address_table.syscall_return));
        self.push(jmp(TMP_REG));

        label
    }

    pub(crate) fn emit_ecall_trampoline(&mut self) {
        log::trace!("Emitting trampoline: ecall");
        self.define_label(self.ecall_label);

        self.push(push(TMP_REG)); // Save the ecall number.
        self.save_registers_to_vmctx();
        self.push(mov_imm64(TMP_REG, self.address_table.syscall_hostcall));
        self.push(pop(rdi)); // Pop the ecall number as an argument.
        self.push(call(TMP_REG));
        self.restore_registers_from_vmctx();
        self.push(ret());

    }

    pub(crate) fn emit_trace_trampoline(&mut self) {
        log::trace!("Emitting trampoline: trace");
        self.define_label(self.trace_label);

        self.push(push(TMP_REG)); // Save the instruction number.
        self.save_registers_to_vmctx();
        self.push(mov_imm64(TMP_REG, self.address_table.syscall_trace));
        self.push(pop(rdi)); // Pop the instruction number as an argument.
        self.push(load(LoadKind::U64, rsi, reg_indirect(RegSize::R64, rsp - 8))); // Grab the return address.
        self.push(call(TMP_REG));
        self.restore_registers_from_vmctx();
        self.push(ret());
    }

    pub(crate) fn emit_trap_trampoline(&mut self) {
        log::trace!("Emitting trampoline: trap");
        self.define_label(self.trap_label);

        self.save_registers_to_vmctx();
        self.push(mov_imm64(TMP_REG, self.address_table.syscall_trap));
        self.push(jmp(TMP_REG));
    }

    pub(crate) fn emit_sbrk_trampoline(&mut self) {
        log::trace!("Emitting trampoline: sbrk");
        self.define_label(self.sbrk_label);

        self.push(push(TMP_REG));
        self.save_registers_to_vmctx();
        self.push(mov_imm64(TMP_REG, self.address_table.syscall_sbrk));
        self.push(pop(rdi));
        self.push(call(TMP_REG));
        self.push(push(rax));
        self.restore_registers_from_vmctx();
        self.push(pop(TMP_REG));
        self.push(ret());
    }

    #[cold]
    pub(crate) fn trace_execution(&mut self, nth_instruction: usize) {
        self.push(mov_imm(TMP_REG, imm32(nth_instruction as u32)));
        self.push(call_label32(self.trace_label));
    }

    pub(crate) fn emit_gas_metering_stub(&mut self, kind: GasMeteringKind) {
        self.push(sub((self.vmctx_field(self.vmctx_gas_offset), imm64(i32::MAX))));
        if matches!(kind, GasMeteringKind::Sync) {
            self.push(cmp((self.vmctx_field(self.vmctx_gas_offset), imm64(0))));
            self.push(jcc_label32(Condition::Sign, self.trap_label));
        }
    }

    pub(crate) fn emit_weight(&mut self, offset: usize, cost: u32) {
        let length = sub((self.vmctx_field(self.vmctx_gas_offset), imm64(i32::MAX))).len();
        let xs = cost.to_le_bytes();
        self.asm.code_mut()[offset + length - 4..offset + length].copy_from_slice(&xs);
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn get_return_address(&self) -> u32 {
        let index = self.jump_table_index_by_basic_block.get(self.next_basic_block() as usize).copied().unwrap_or(0);
        if index == 0 {
            panic!("internal error: couldn't fetch the jump table index for the return basic block");
        }

        index * VM_CODE_ADDRESS_ALIGNMENT
    }

    fn indirect_jump_or_call(&mut self, ra: Option<Reg>, base: Reg, offset: u32) {
        let return_address = ra.map(|ra| (ra, self.get_return_address()));
        match self.sandbox_kind {
            SandboxKind::Linux => {
                use polkavm_assembler::amd64::{SegReg, Scale};

                let target = if offset != 0 || ra == Some(base) {
                    self.push(lea(RegSize::R32, TMP_REG, reg_indirect(RegSize::R32, conv_reg(base) + offset as i32)));
                    TMP_REG
                } else {
                    conv_reg(base)
                };

                if let Some((return_register, return_address)) = return_address {
                    self.load_immediate(return_register, return_address);
                }

                self.asm.push(jmp(MemOp::IndexScaleOffset(Some(SegReg::gs), RegSize::R64, target, Scale::x8, 0)));
            },
            SandboxKind::Generic => {
                // TODO: This also could be more efficient.
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

                if let Some((return_register, return_address)) = return_address {
                    self.load_immediate(return_register, return_address);
                }

                self.push(jmp(TMP_REG));
            }
        }

        self.start_new_basic_block();
    }
}

impl<'a> InstructionVisitor for VisitorWrapper<'a, Compiler<'a>> {
    type ReturnTy = ();

    #[inline(always)]
    fn trap(&mut self) -> Self::ReturnTy {
        let trap_label = self.trap_label;
        self.push(jmp_label32(trap_label));
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn fallthrough(&mut self) -> Self::ReturnTy {
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn sbrk(&mut self, dst: Reg, size: Reg) -> Self::ReturnTy {
        let label_bump_only = self.asm.forward_declare_label();
        let label_continue = self.asm.forward_declare_label();
        let sbrk_label = self.sbrk_label;

        let dst = conv_reg(dst);
        let size = conv_reg(size);
        if dst != size {
            self.push(mov(RegSize::R32, dst, size));
        }

        let offset = self.vmctx_heap_info_offset;
        let heap_info_base = self.load_vmctx_field_address(offset);

        // Calculate new top-of-the-heap pointer.
        self.push(add((RegSize::R64, dst, reg_indirect(RegSize::R64, heap_info_base))));
        // Compare it to the current threshold.
        self.push(cmp((RegSize::R64, dst, reg_indirect(RegSize::R64, heap_info_base + 8))));
        // If it was less or equal to the threshold then no extra action is necessary (bump only!).
        self.push(jcc_label8(Condition::BelowOrEqual, label_bump_only));

        // The new top-of-the-heap pointer crossed the threshold, so more involved handling is necessary.
        // We'll either allocate new memory, or return a null pointer.
        self.push(mov(RegSize::R64, TMP_REG, dst));
        self.push(call_label32(sbrk_label));
        self.push(mov(RegSize::R32, dst, TMP_REG));
        // Note: `dst` can be zero here, which is why we do the pointer bump from within the handler.
        self.push(jmp_label8(label_continue));

        self.define_label(label_bump_only);
        // Only a bump was necessary, so just updated the pointer and continue.
        self.push(store(RegSize::R64, reg_indirect(RegSize::R64, heap_info_base), dst));

        self.define_label(label_continue);
    }

    #[inline(always)]
    fn bswap(&mut self, dst: Reg, src: Reg) -> Self::ReturnTy {
        let dst = conv_reg(dst);
        let src = conv_reg(src);
        if dst != src {
            self.push(mov(RegSize::R32, dst, src));
        }

        self.push(bswap(RegSize::R32, dst));
    }

    #[inline(always)]
    fn ecalli(&mut self, imm: u32) -> Self::ReturnTy {
        let ecall_label = self.ecall_label;
        self.push(mov_imm(TMP_REG, imm32(imm)));
        self.push(call_label32(ecall_label));
    }

    #[inline(always)]
    fn set_less_than_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.compare_reg_reg(d, s1, s2, Condition::Below);
    }

    #[inline(always)]
    fn set_less_than_unsigned_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.compare_reg_imm(d, s1, s2, Condition::Below);
    }

    #[inline(always)]
    fn set_greater_than_unsigned_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.compare_reg_imm(d, s1, s2, Condition::Above);
    }

    #[inline(always)]
    fn set_less_than_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.compare_reg_reg(d, s1, s2, Condition::Less);
    }

    #[inline(always)]
    fn set_less_than_signed_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.compare_reg_imm(d, s1, s2, Condition::Less);
    }

    #[inline(always)]
    fn set_greater_than_signed_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.compare_reg_imm(d, s1, s2, Condition::Greater);
    }

    #[inline(always)]
    fn shift_logical_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.shift(d, s1, s2, ShiftKind::LogicalRight);
    }

    #[inline(always)]
    fn shift_arithmetic_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.shift(d, s1, s2, ShiftKind::ArithmeticRight);
    }

    #[inline(always)]
    fn shift_logical_left(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.shift(d, s1, s2, ShiftKind::LogicalLeft);
    }

    #[inline(always)]
    fn shift_logical_right_imm_alt(&mut self, d: Reg, s2: Reg, s1: u32) -> Self::ReturnTy {
        self.shift(d, s1, s2, ShiftKind::LogicalRight);
    }

    #[inline(always)]
    fn shift_arithmetic_right_imm_alt(&mut self, d: Reg, s2: Reg, s1: u32) -> Self::ReturnTy  {
        self.shift(d, s1, s2, ShiftKind::ArithmeticRight);
    }

    #[inline(always)]
    fn shift_logical_left_imm_alt(&mut self, d: Reg, s2: Reg, s1: u32) -> Self::ReturnTy  {
        self.shift(d, s1, s2, ShiftKind::LogicalLeft);
    }

    #[inline(always)]
    fn xor(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        let reg_size = self.reg_size();
        match (d, s1, s2) {
            // d = d ^ s2
            (_, _, _) if d == s1 => self.push(xor((reg_size, conv_reg(d), conv_reg(s2)))),
            // d = s1 ^ d
            (_, _, _) if d == s2 => self.push(xor((reg_size, conv_reg(d), conv_reg(s1)))),
            // d = s1 ^ s2
            _ => {
                self.mov(d, s1);
                self.push(xor((reg_size, conv_reg(d), conv_reg(s2))));
            }
        }
    }

    #[inline(always)]
    fn and(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        let reg_size = self.reg_size();
        match (d, s1, s2) {
            // d = d & s2
            (_, _, _) if d == s1 => self.push(and((reg_size, conv_reg(d), conv_reg(s2)))),
            // d = s1 & d
            (_, _, _) if d == s2 => self.push(and((reg_size, conv_reg(d), conv_reg(s1)))),
            // d = s1 & s2
            _ => {
                self.mov(d, s1);
                self.push(and((reg_size, conv_reg(d), conv_reg(s2))));
            }
        }
    }

    #[inline(always)]
    fn or(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        let reg_size = self.reg_size();
        match (d, s1, s2) {
            // d = d | s2
            (_, _, _) if d == s1 => self.push(or((reg_size, conv_reg(d), conv_reg(s2)))),
            // d = s1 | d
            (_, _, _) if d == s2 => self.push(or((reg_size, conv_reg(d), conv_reg(s1)))),
            // d = s1 | s2
            _ => {
                self.mov(d, s1);
                self.push(or((reg_size, conv_reg(d), conv_reg(s2))));
            }
        }
    }

    #[inline(always)]
    fn add(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        let reg_size = self.reg_size();
        match (d, s1, s2) {
            // d = d + s2
            (_, _, _) if d == s1 => self.push(add((reg_size, conv_reg(d), conv_reg(s2)))),
            // d = s1 + d
            (_, _, _) if d == s2 => self.push(add((reg_size, conv_reg(d), conv_reg(s1)))),
            // d = s1 + s2
            _ => {
                if d != s1 {
                    self.mov(d, s1);
                }
                self.push(add((reg_size, conv_reg(d), conv_reg(s2))));
            }
        }
    }

    #[inline(always)]
    fn sub(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        let reg_size = self.reg_size();
        match (d, s1, s2) {
            // d = d - s2
            (_, _, _) if d == s1 => self.push(sub((reg_size, conv_reg(d), conv_reg(s2)))),
            // d = s1 - d
            (_, _, _) if d == s2 => {
                self.push(neg(reg_size, conv_reg(d)));
                self.push(add((reg_size, conv_reg(d), conv_reg(s1))));
            }
            // d = s1 - s2
            _ => {
                self.mov(d, s1);
                self.push(sub((reg_size, conv_reg(d), conv_reg(s2))));
            }
        }
    }

    #[inline(always)]
    fn negate_and_add_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        if d == s1 {
            // d = -d + s2
            self.push(neg(RegSize::R32, conv_reg(d)));
            if s2 != 0 {
                self.push(add((conv_reg(d), imm32(s2))));
            }
        } else {
            // d = -s1 + s2  =>  d = s2 - s1
            if s2 == 0 {
                self.mov(d, s1);
                self.push(neg(RegSize::R32, conv_reg(d)));
            } else {
                self.push(mov_imm(conv_reg(d), imm32(s2)));
                self.push(sub((RegSize::R32, conv_reg(d), conv_reg(s1))));
            }
        }
    }

    #[inline(always)]
    fn mul(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        let reg_size = self.reg_size();
        if d == s1 {
            // d = d * s2
            self.push(imul(reg_size, conv_reg(d), conv_reg(s2)))
        } else if d == s2 {
            // d = s1 * d
            self.push(imul(reg_size, conv_reg(d), conv_reg(s1)))
        } else {
            // d = s1 * s2
            self.mov(d, s1);
            self.push(imul(reg_size, conv_reg(d), conv_reg(s2)));
        }
    }

    #[inline(always)]
    fn mul_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.push(imul_imm(RegSize::R32, conv_reg(d), conv_reg(s1), s2 as i32));
    }

    #[inline(always)]
    fn mul_upper_signed_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.push(movsxd_32_to_64(TMP_REG, conv_reg(s2)));
        self.push(movsxd_32_to_64(conv_reg(d), conv_reg(s1)));
        self.push(imul(RegSize::R64, conv_reg(d), TMP_REG));
        self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
    }

    #[inline(always)]
    fn mul_upper_signed_signed_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.push(mov_imm(TMP_REG, imm64(s2 as i32)));
        self.push(movsxd_32_to_64(conv_reg(d), conv_reg(s1)));
        self.push(imul(RegSize::R64, conv_reg(d), TMP_REG));
        self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
    }

    #[inline(always)]
    fn mul_upper_unsigned_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        if d == s1 {
            // d = d * s2
            self.push(imul(RegSize::R64, conv_reg(d), conv_reg(s2)));
        } else if d == s2 {
            // d = s1 * d
            self.push(imul(RegSize::R64, conv_reg(d), conv_reg(s1)));
        } else {
            // d = s1 * s2
            self.push(mov(RegSize::R32, conv_reg(d), conv_reg(s1)));
            self.push(imul(RegSize::R64, conv_reg(d), conv_reg(s2)));
        }

        self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
    }

    #[inline(always)]
    fn mul_upper_unsigned_unsigned_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.push(mov_imm(TMP_REG, imm32(s2)));
        if d != s1 {
            self.push(mov(RegSize::R32, conv_reg(d), conv_reg(s1)));
        }

        self.push(imul(RegSize::R64, conv_reg(d), TMP_REG));
        self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
    }

    #[inline(always)]
    fn mul_upper_signed_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
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

        if d == s2 {
            // d = s1 * d
            self.push(mov(RegSize::R32, TMP_REG, conv_reg(s2)));
            self.push(movsxd_32_to_64(conv_reg(d), conv_reg(s1)));
            self.push(imul(RegSize::R64, conv_reg(d), TMP_REG));
        } else {
            // d = s1 * s2
            self.push(movsxd_32_to_64(conv_reg(d), conv_reg(s1)));
            self.push(imul(RegSize::R64, conv_reg(d), conv_reg(s2)));
        }

        self.push(shr_imm(RegSize::R64, conv_reg(d), 32));
    }

    #[inline(always)]
    fn div_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Div, Signedness::Unsigned);
    }

    #[inline(always)]
    fn div_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Div, Signedness::Signed);
    }

    #[inline(always)]
    fn rem_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Rem, Signedness::Unsigned);
    }

    #[inline(always)]
    fn rem_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        self.div_rem(d, s1, s2, DivRem::Rem, Signedness::Signed);
    }

    #[inline(always)]
    fn shift_logical_right_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.shift_imm(d, s1, s2, ShiftKind::LogicalRight);
    }

    #[inline(always)]
    fn shift_arithmetic_right_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.shift_imm(d, s1, s2, ShiftKind::ArithmeticRight);
    }

    #[inline(always)]
    fn shift_logical_left_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        self.shift_imm(d, s1, s2, ShiftKind::LogicalLeft);
    }

    #[inline(always)]
    fn or_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        if d != s1 {
            self.mov(d, s1);
        }

        // d = s1 | s2
        self.push(or((conv_reg(d), imm32(s2))));
    }

    #[inline(always)]
    fn and_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        if d != s1 {
            self.mov(d, s1);
        }

        // d = s1 & s2
        self.push(and((conv_reg(d), imm32(s2))));
    }

    #[inline(always)]
    fn xor_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        let reg_size = self.reg_size();
        if d != s1 {
            self.mov(d, s1);
        }

        if s2 != !0 {
            // d = s1 ^ s2
            self.push(xor((conv_reg(d), imm32(s2))));
        } else {
            // d = s1 ^ 0xfffffff
            self.push(not(reg_size, conv_reg(d)));
        }
    }

    #[inline(always)]
    fn load_imm(&mut self, dst: Reg, s2: u32) -> Self::ReturnTy {
        self.load_immediate(dst, s2);
    }

    #[inline(always)]
    fn move_reg(&mut self, d: Reg, s: Reg) -> Self::ReturnTy {
        self.mov(d, s);
    }

    #[inline(always)]
    fn cmov_if_zero(&mut self, d: Reg, s: Reg, c: Reg) -> Self::ReturnTy {
        self.cmov(d, s, c, Condition::Equal);
    }

    #[inline(always)]
    fn cmov_if_not_zero(&mut self, d: Reg, s: Reg, c: Reg) -> Self::ReturnTy {
        self.cmov(d, s, c, Condition::NotEqual);
    }

    #[inline(always)]
    fn cmov_if_zero_imm(&mut self, d: Reg, c: Reg, s: u32) -> Self::ReturnTy {
        self.cmov_imm(d, s, c, Condition::Equal);
    }

    #[inline(always)]
    fn cmov_if_not_zero_imm(&mut self, d: Reg, c: Reg, s: u32) -> Self::ReturnTy {
        self.cmov_imm(d, s, c, Condition::NotEqual);
    }

    #[inline(always)]
    fn add_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        let reg_size = self.reg_size();
        let d = conv_reg(d);
        let s1 = conv_reg(s1);
        match (d, s1, s2) {
            // d = d + 1
            (_, _, 1) if d == s1 => self.push(inc(reg_size, d)),
            // d = d + s2
            (_, _, _) if d == s1 => self.push(add((d, imm32(s2)))),
            // d = s1 + s2
            (_, _, _) => {
                self.push(lea(reg_size, d, reg_indirect(reg_size, s1 + s2 as i32)));
            }
        }
    }

    #[inline(always)]
    fn store_u8(&mut self, src: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, None, offset, Size::U8);
    }

    #[inline(always)]
    fn store_u16(&mut self, src: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, None, offset, Size::U16);
    }

    #[inline(always)]
    fn store_u32(&mut self, src: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, None, offset, Size::U32);
    }

    #[inline(always)]
    fn store_indirect_u8(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, Some(base), offset, Size::U8);
    }

    #[inline(always)]
    fn store_indirect_u16(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, Some(base), offset, Size::U16);
    }

    #[inline(always)]
    fn store_indirect_u32(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.store(src, Some(base), offset, Size::U32);
    }

    #[inline(always)]
    fn store_imm_indirect_u8(&mut self, base: Reg, offset: u32, value: u32) -> Self::ReturnTy {
        self.store(value, Some(base), offset, Size::U8);
    }

    #[inline(always)]
    fn store_imm_indirect_u16(&mut self, base: Reg, offset: u32, value: u32) -> Self::ReturnTy {
        self.store(value, Some(base), offset, Size::U16);
    }

    #[inline(always)]
    fn store_imm_indirect_u32(&mut self, base: Reg, offset: u32, value: u32) -> Self::ReturnTy {
        self.store(value, Some(base), offset, Size::U32);
    }

    #[inline(always)]
    fn store_imm_u8(&mut self, value: u32, offset: u32) -> Self::ReturnTy {
        self.store(value, None, offset, Size::U8);
    }

    #[inline(always)]
    fn store_imm_u16(&mut self, value: u32, offset: u32) -> Self::ReturnTy {
        self.store(value, None, offset, Size::U16);
    }

    #[inline(always)]
    fn store_imm_u32(&mut self, value: u32, offset: u32) -> Self::ReturnTy {
        self.store(value, None, offset, Size::U32);
    }

    #[inline(always)]
    fn load_indirect_u8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, Some(base), offset, LoadKind::U8);
    }

    #[inline(always)]
    fn load_indirect_i8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, Some(base), offset, LoadKind::I8);
    }

    #[inline(always)]
    fn load_indirect_u16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, Some(base), offset, LoadKind::U16);
    }

    #[inline(always)]
    fn load_indirect_i16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, Some(base), offset, LoadKind::I16);
    }

    #[inline(always)]
    fn load_indirect_u32(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, Some(base), offset, LoadKind::U32);
    }

    #[inline(always)]
    fn load_u8(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, None, offset, LoadKind::U8);
    }

    #[inline(always)]
    fn load_i8(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, None, offset, LoadKind::I8);
    }

    #[inline(always)]
    fn load_u16(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, None, offset, LoadKind::U16);
    }

    #[inline(always)]
    fn load_i16(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, None, offset, LoadKind::I16);
    }

    #[inline(always)]
    fn load_u32(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        self.load(dst, None, offset, LoadKind::U32);
    }

    #[inline(always)]
    fn branch_less_unsigned(&mut self, s1: Reg, s2: Reg, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::Below);
    }

    #[inline(always)]
    fn branch_less_signed(&mut self, s1: Reg, s2: Reg, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::Less);
    }

    #[inline(always)]
    fn branch_greater_or_equal_unsigned(&mut self, s1: Reg, s2: Reg, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::AboveOrEqual);
    }

    #[inline(always)]
    fn branch_greater_or_equal_signed(&mut self, s1: Reg, s2: Reg, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::GreaterOrEqual);
    }

    #[inline(always)]
    fn branch_eq(&mut self, s1: Reg, s2: Reg, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::Equal);
    }

    #[inline(always)]
    fn branch_not_eq(&mut self, s1: Reg, s2: Reg, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::NotEqual);
    }

    #[inline(always)]
    fn branch_eq_imm(&mut self, s1: Reg, s2: u32, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::Equal);
    }

    #[inline(always)]
    fn branch_not_eq_imm(&mut self, s1: Reg, s2: u32, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::NotEqual);
    }

    #[inline(always)]
    fn branch_less_unsigned_imm(&mut self, s1: Reg, s2: u32, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::Below);
    }

    #[inline(always)]
    fn branch_less_signed_imm(&mut self, s1: Reg, s2: u32, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::Less);
    }

    #[inline(always)]
    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: Reg, s2: u32, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::AboveOrEqual);
    }

    #[inline(always)]
    fn branch_greater_or_equal_signed_imm(&mut self, s1: Reg, s2: u32, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::GreaterOrEqual);
    }

    #[inline(always)]
    fn branch_less_or_equal_unsigned_imm(&mut self, s1: Reg, s2: u32, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::BelowOrEqual);
    }

    #[inline(always)]
    fn branch_less_or_equal_signed_imm(&mut self, s1: Reg, s2: u32, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::LessOrEqual);
    }

    #[inline(always)]
    fn branch_greater_unsigned_imm(&mut self, s1: Reg, s2: u32, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::Above);
    }

    #[inline(always)]
    fn branch_greater_signed_imm(&mut self, s1: Reg, s2: u32, target: u32) -> Self::ReturnTy {
        self.branch(s1, s2, target, Condition::Greater);
    }

    #[inline(always)]
    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        let label = self.get_or_forward_declare_label(target);
        self.jump_to_label(label);
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn call(&mut self, ra: Reg, target: u32) -> Self::ReturnTy {
        let label = self.get_or_forward_declare_label(target);
        let return_address = self.get_return_address();
        self.load_immediate(ra, return_address);
        self.jump_to_label(label);
        self.start_new_basic_block();
    }

    #[inline(always)]
    fn jump_indirect(&mut self, base: Reg, offset: u32) -> Self::ReturnTy {
        self.indirect_jump_or_call(None, base, offset)
    }

    #[inline(always)]
    fn call_indirect(&mut self, ra: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        self.indirect_jump_or_call(Some(ra), base, offset)
    }
}
