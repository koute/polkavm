use crate::program::{Instruction, Reg};
use crate::utils::{parse_imm, parse_reg};
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

fn split<'a>(text: &'a str, separator: &str) -> Option<(&'a str, &'a str)> {
    let index = text.find(separator)?;
    Some((text[..index].trim(), text[index + separator.len()..].trim()))
}

fn parse_reg_or_imm(text: &str) -> Option<RegImm> {
    if let Some(value) = parse_imm(text) {
        Some(RegImm::Imm(value))
    } else {
        parse_reg(text).map(RegImm::Reg)
    }
}

fn parse_absolute_memory_access(text: &str) -> Option<i32> {
    let text = text.trim().strip_prefix('[')?.strip_suffix(']')?;
    parse_imm(text)
}

fn parse_indirect_memory_access(text: &str) -> Option<(Reg, i32)> {
    let text = text.trim().strip_prefix('[')?.strip_suffix(']')?;
    if let Some(index) = text.find('+') {
        let reg = parse_reg(text[..index].trim())?;
        let offset = parse_imm(&text[index + 1..])?;
        Some((reg, offset))
    } else {
        parse_reg(text).map(|reg| (reg, 0))
    }
}

/// Parses the long form of load_imm_and_jump_indirect:
/// `tmp = {base}, {dst} = {value}, jump [tmp + {offset}]`, where `dest == base` is allowed
fn parse_load_imm_and_jump_indirect_with_tmp(line: &str) -> Option<(Reg, Reg, i32, i32)> {
    let line = line.trim().strip_prefix("tmp")?;
    if !line.starts_with('=') && line.trim_start() == line {
        return None;
    }
    let line = line.trim().strip_prefix('=')?;

    let index = line.find(',')?;
    let base = parse_reg(line[..index].trim())?;
    let line = line[index + 1..].trim();

    let index = line.find('=')?;
    let dst = parse_reg(line[..index].trim())?;
    let line = line[index + 1..].trim();

    let index = line.find(',')?;
    let value = parse_imm(line[..index].trim())?;
    let line = line[index + 1..].trim().strip_prefix("jump")?;
    let text = line.trim().strip_prefix('[')?.strip_suffix(']')?;

    if let Some(index) = text.find('+') {
        if text[..index].trim() != "tmp" {
            return None;
        }
        let offset = parse_imm(&text[index + 1..])?;
        Some((dst, base, value, offset))
    } else {
        if text.trim() != "tmp" {
            return None;
        }
        Some((dst, base, value, 0))
    }
}

#[derive(Copy, Clone)]
pub enum LoadKind {
    I8,
    I16,
    U32,
    U8,
    U16,
}

#[derive(Copy, Clone)]
pub enum StoreKind {
    U8,
    U16,
    U32,
}

#[derive(Copy, Clone)]
enum ConditionKind {
    Eq,
    NotEq,
    LessSigned,
    LessUnsigned,
    LessOrEqualSigned,
    LessOrEqualUnsigned,
    GreaterSigned,
    GreaterUnsigned,
    GreaterOrEqualSigned,
    GreaterOrEqualUnsigned,
}

impl ConditionKind {
    fn reverse_operands(self) -> Self {
        match self {
            Self::Eq => Self::Eq,
            Self::NotEq => Self::NotEq,
            Self::LessSigned => Self::GreaterSigned,
            Self::LessUnsigned => Self::GreaterUnsigned,
            Self::LessOrEqualSigned => Self::GreaterOrEqualSigned,
            Self::LessOrEqualUnsigned => Self::GreaterOrEqualUnsigned,
            Self::GreaterSigned => Self::LessSigned,
            Self::GreaterUnsigned => Self::LessUnsigned,
            Self::GreaterOrEqualSigned => Self::LessOrEqualSigned,
            Self::GreaterOrEqualUnsigned => Self::LessOrEqualUnsigned,
        }
    }
}

#[derive(Copy, Clone)]
enum RegImm {
    Reg(Reg),
    Imm(i32),
}

#[derive(Copy, Clone)]
struct Condition {
    kind: ConditionKind,
    lhs: RegImm,
    rhs: RegImm,
}

fn parse_condition(text: &str) -> Option<Condition> {
    let text = text.trim();
    let (lhs, text) = split(text, " ")?;
    let lhs = parse_reg_or_imm(lhs)?;
    let (kind, text) = split(text, " ")?;
    let kind = match kind {
        "<u" => ConditionKind::LessUnsigned,
        "<s" => ConditionKind::LessSigned,
        "<=u" => ConditionKind::LessOrEqualUnsigned,
        "<=s" => ConditionKind::LessOrEqualSigned,
        ">u" => ConditionKind::GreaterUnsigned,
        ">s" => ConditionKind::GreaterSigned,
        ">=u" => ConditionKind::GreaterOrEqualUnsigned,
        ">=s" => ConditionKind::GreaterOrEqualSigned,
        "==" => ConditionKind::Eq,
        "!=" => ConditionKind::NotEq,
        _ => return None,
    };

    let rhs = parse_reg_or_imm(text)?;
    Some(Condition { kind, lhs, rhs })
}

pub fn assemble(code: &str) -> Result<Vec<u8>, String> {
    enum MaybeInstruction {
        Instruction(Instruction),
        Jump(String),
        Branch(String, ConditionKind, Reg, Reg),
        BranchImm(String, ConditionKind, Reg, i32),
        LoadLabelAddress(Reg, String),
        LoadImmAndJump(Reg, i32, String),
    }

    impl MaybeInstruction {
        fn starts_new_basic_block(&self) -> bool {
            match self {
                MaybeInstruction::Instruction(instruction) => instruction.starts_new_basic_block(),
                MaybeInstruction::Jump(..)
                | MaybeInstruction::Branch(..)
                | MaybeInstruction::BranchImm(..)
                | MaybeInstruction::LoadImmAndJump(..) => true,
                MaybeInstruction::LoadLabelAddress(..) => false,
            }
        }
    }

    impl From<Instruction> for MaybeInstruction {
        fn from(inst: Instruction) -> Self {
            MaybeInstruction::Instruction(inst)
        }
    }

    let mut instructions: Vec<MaybeInstruction> = Vec::new();
    let mut label_to_index = BTreeMap::new();
    let mut at_block_start = true;
    let mut current_basic_block = 0;
    let mut exports = BTreeMap::new();
    let mut ro_data = Vec::new();
    let mut rw_data = Vec::new();
    let mut ro_data_size = 0;
    let mut rw_data_size = 0;
    let mut stack_size = 0;

    macro_rules! emit_and_continue {
        ($instruction:expr) => {{
            let instruction: MaybeInstruction = $instruction.into();
            at_block_start = instruction.starts_new_basic_block();
            if at_block_start {
                current_basic_block += 1;
            }

            instructions.push(instruction);
            continue;
        }};
    }

    for (nth_line, line) in code.lines().enumerate() {
        let nth_line = nth_line + 1; // Line counter for error messages starts as 1.
        let line = line.trim();
        let original_line = line;

        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        if let Some(line) = line.strip_prefix("%ro_data_size = ") {
            let line = line.trim();
            let Ok(size) = line.parse::<u32>() else {
                return Err(format!("cannot parse line {nth_line}"));
            };
            ro_data_size = size;
            continue;
        }

        if let Some(line) = line.strip_prefix("%rw_data_size = ") {
            let line = line.trim();
            let Ok(size) = line.parse::<u32>() else {
                return Err(format!("cannot parse line {nth_line}"));
            };
            rw_data_size = size;
            continue;
        }

        if let Some(line) = line.strip_prefix("%stack_size = ") {
            let line = line.trim();
            let Ok(size) = line.parse::<u32>() else {
                return Err(format!("cannot parse line {nth_line}"));
            };
            stack_size = size;
            continue;
        }

        fn parse_slice(text: &str) -> Option<Vec<u8>> {
            let text = text.trim().replace(' ', "");
            if text.bytes().len() % 2 != 0 {
                return None;
            }

            let mut output = Vec::new();
            for chunk in text.as_bytes().chunks(2) {
                let chunk = core::str::from_utf8(chunk).ok()?;
                let chunk = u8::from_str_radix(chunk, 16).ok()?;
                output.push(chunk);
            }

            Some(output)
        }

        if let Some(line) = line.strip_prefix("%ro_data = ") {
            let Some(value) = parse_slice(line) else {
                return Err(format!("cannot parse line {nth_line}"));
            };

            ro_data = value;
            continue;
        }

        if let Some(line) = line.strip_prefix("%rw_data = ") {
            let Some(value) = parse_slice(line) else {
                return Err(format!("cannot parse line {nth_line}"));
            };

            rw_data = value;
            continue;
        }

        if let Some((is_export, line)) = line
            .strip_prefix("pub @")
            .map(|line| (true, line))
            .or_else(|| line.strip_prefix('@').map(|line| (false, line)))
        {
            if let Some(label) = line.strip_suffix(':') {
                if !at_block_start {
                    instructions.push(Instruction::fallthrough.into());
                    at_block_start = true;
                    current_basic_block += 1;
                }

                if label_to_index.insert(label, current_basic_block).is_some() {
                    return Err(format!("duplicate label \"{label}\" on line {nth_line}"));
                }

                if is_export {
                    exports.insert(label, current_basic_block);
                }

                continue;
            }
        }

        if line == "trap" {
            emit_and_continue!(Instruction::trap);
        }

        if line == "fallthrough" {
            emit_and_continue!(Instruction::fallthrough);
        }

        if line == "ret" {
            emit_and_continue!(Instruction::jump_indirect(Reg::RA.into(), 0));
        }

        if line == "nop" {
            emit_and_continue!(Instruction::move_reg(Reg::RA.into(), Reg::RA.into()));
        }

        if let Some(line) = line.strip_prefix("ecalli ") {
            let line = line.trim();
            if let Ok(index) = line.parse::<u32>() {
                emit_and_continue!(Instruction::ecalli(index));
            }
        }

        if let Some(line) = line.strip_prefix("jump ") {
            let line = line.trim();
            if let Some(line) = line.strip_prefix('@') {
                if let Some(index) = line.find(' ') {
                    let label = &line[..index];
                    let line = &line[index + 1..].trim();
                    let Some(line) = line.strip_prefix("if ") else {
                        return Err(format!("cannot parse line {nth_line}: \"{original_line}\""));
                    };

                    let line = line.trim();
                    let Some(condition) = parse_condition(line) else {
                        return Err(format!("cannot parse line {nth_line}: invalid condition"));
                    };

                    let (kind, lhs, rhs) = match (condition.lhs, condition.rhs) {
                        (RegImm::Reg(lhs), RegImm::Reg(rhs)) => {
                            emit_and_continue!(MaybeInstruction::Branch(label.to_owned(), condition.kind, lhs, rhs));
                        }
                        (RegImm::Reg(lhs), RegImm::Imm(rhs)) => (condition.kind, lhs, rhs),
                        (RegImm::Imm(lhs), RegImm::Reg(rhs)) => (condition.kind.reverse_operands(), rhs, lhs),
                        (RegImm::Imm(_), RegImm::Imm(_)) => {
                            return Err(format!("cannot parse line {nth_line}: both arguments cannot be immediates"));
                        }
                    };

                    emit_and_continue!(MaybeInstruction::BranchImm(label.to_owned(), kind, lhs, rhs));
                }

                emit_and_continue!(MaybeInstruction::Jump(line.to_owned()));
            }

            if let Some((base, offset)) = parse_indirect_memory_access(line) {
                emit_and_continue!(Instruction::jump_indirect(base.into(), offset as u32));
            }
        }

        if let Some((dst, base, value, offset)) = parse_load_imm_and_jump_indirect_with_tmp(line) {
            emit_and_continue!(Instruction::load_imm_and_jump_indirect(
                dst.into(),
                base.into(),
                value as u32,
                offset as u32
            ));
        }

        if let Some(index) = line.find('=') {
            let lhs = line[..index].trim();
            let rhs = line[index + 1..].trim();

            if let Some(dst) = parse_reg(lhs) {
                if let Some(index) = rhs.find(',') {
                    if let Some(value) = parse_imm(&rhs[..index]) {
                        if let Some(line) = rhs[index + 1..].trim().strip_prefix("jump") {
                            if let Some(label) = line.trim().strip_prefix('@') {
                                emit_and_continue!(MaybeInstruction::LoadImmAndJump(dst, value, label.to_owned()));
                            }
                            if let Some((base, offset)) = parse_indirect_memory_access(line) {
                                let instruction =
                                    Instruction::load_imm_and_jump_indirect(dst.into(), base.into(), value as u32, offset as u32);

                                if dst == base {
                                    return Err(format!("cannot parse line {nth_line}, expected: \"{instruction}\""));
                                }

                                emit_and_continue!(instruction);
                            }
                        }
                    }
                }

                if let Some(index) = rhs.find("if ") {
                    if let Some(src) = parse_reg_or_imm(&rhs[..index]) {
                        if let Some(condition) = parse_condition(&rhs[index + 3..]) {
                            if let (RegImm::Reg(cond), RegImm::Imm(0)) = (condition.lhs, condition.rhs) {
                                let inst = match (src, condition.kind) {
                                    (RegImm::Reg(src), ConditionKind::Eq) => {
                                        Some(Instruction::cmov_if_zero(dst.into(), src.into(), cond.into()))
                                    }
                                    (RegImm::Reg(src), ConditionKind::NotEq) => {
                                        Some(Instruction::cmov_if_zero(dst.into(), src.into(), cond.into()))
                                    }
                                    (RegImm::Imm(src), ConditionKind::Eq) => {
                                        Some(Instruction::cmov_if_zero_imm(dst.into(), cond.into(), src as u32))
                                    }
                                    (RegImm::Imm(src), ConditionKind::NotEq) => {
                                        Some(Instruction::cmov_if_zero_imm(dst.into(), cond.into(), src as u32))
                                    }
                                    _ => None,
                                };

                                if let Some(inst) = inst {
                                    emit_and_continue!(inst);
                                }
                            }
                        }
                    }
                }

                if let Some(src) = parse_reg(rhs) {
                    emit_and_continue!(Instruction::move_reg(dst.into(), src.into()));
                }

                if let Some(imm) = parse_imm(rhs) {
                    emit_and_continue!(Instruction::load_imm(dst.into(), imm as u32));
                }

                if let Some(label) = rhs.strip_prefix('@') {
                    emit_and_continue!(MaybeInstruction::LoadLabelAddress(dst, label.to_owned()));
                }

                enum Op {
                    Add,
                    Sub,
                    And,
                    Xor,
                    Or,
                    Mul,
                    DivUnsigned,
                    DivSigned,
                    RemUnsigned,
                    RemSigned,
                    LessUnsigned,
                    LessSigned,
                    GreaterUnsigned,
                    GreaterSigned,
                    ShiftLeft,
                    ShiftRight,
                    ShiftArithmeticRight,
                }

                #[allow(clippy::manual_map)]
                let operation = if let Some(index) = rhs.find('+') {
                    Some((index, 1, Op::Add))
                } else if let Some(index) = rhs.find('&') {
                    Some((index, 1, Op::And))
                } else if let Some(index) = rhs.find('|') {
                    Some((index, 1, Op::Or))
                } else if let Some(index) = rhs.find('^') {
                    Some((index, 1, Op::Xor))
                } else if let Some(index) = rhs.find('*') {
                    Some((index, 1, Op::Mul))
                } else if let Some(index) = rhs.find("/u") {
                    Some((index, 2, Op::DivUnsigned))
                } else if let Some(index) = rhs.find("/s") {
                    Some((index, 2, Op::DivSigned))
                } else if let Some(index) = rhs.find("%u") {
                    Some((index, 2, Op::RemUnsigned))
                } else if let Some(index) = rhs.find("%s") {
                    Some((index, 2, Op::RemSigned))
                } else if let Some(index) = rhs.find(">>a") {
                    Some((index, 3, Op::ShiftArithmeticRight))
                } else if let Some(index) = rhs.find("<<") {
                    Some((index, 2, Op::ShiftLeft))
                } else if let Some(index) = rhs.find(">>") {
                    Some((index, 2, Op::ShiftRight))
                } else if let Some(index) = rhs.find("<u") {
                    Some((index, 2, Op::LessUnsigned))
                } else if let Some(index) = rhs.find("<s") {
                    Some((index, 2, Op::LessSigned))
                } else if let Some(index) = rhs.find(">u") {
                    Some((index, 2, Op::GreaterUnsigned))
                } else if let Some(index) = rhs.find(">s") {
                    Some((index, 2, Op::GreaterSigned))
                } else if let Some(index) = rhs.find('-') {
                    // Needs to be last.
                    Some((index, 1, Op::Sub))
                } else {
                    None
                };

                if let Some((index, op_len, op)) = operation {
                    let src1 = rhs[..index].trim();
                    let src2 = rhs[index + op_len..].trim();

                    if let Some(src1) = parse_reg(src1) {
                        if let Some(src2) = parse_reg(src2) {
                            let dst = dst.into();
                            let src1 = src1.into();
                            let src2 = src2.into();
                            emit_and_continue!(match op {
                                Op::Add => Instruction::add(dst, src1, src2),
                                Op::Sub => Instruction::sub(dst, src1, src2),
                                Op::And => Instruction::and(dst, src1, src2),
                                Op::Xor => Instruction::xor(dst, src1, src2),
                                Op::Or => Instruction::or(dst, src1, src2),
                                Op::Mul => Instruction::mul(dst, src1, src2),
                                Op::DivUnsigned => Instruction::div_unsigned(dst, src1, src2),
                                Op::DivSigned => Instruction::div_signed(dst, src1, src2),
                                Op::RemUnsigned => Instruction::rem_unsigned(dst, src1, src2),
                                Op::RemSigned => Instruction::rem_signed(dst, src1, src2),
                                Op::LessUnsigned => Instruction::set_less_than_unsigned(dst, src1, src2),
                                Op::LessSigned => Instruction::set_less_than_signed(dst, src1, src2),
                                Op::GreaterUnsigned => Instruction::set_less_than_unsigned(dst, src2, src1),
                                Op::GreaterSigned => Instruction::set_less_than_signed(dst, src2, src1),
                                Op::ShiftLeft => Instruction::shift_logical_left(dst, src1, src2),
                                Op::ShiftRight => Instruction::shift_logical_right(dst, src1, src2),
                                Op::ShiftArithmeticRight => Instruction::shift_arithmetic_right(dst, src1, src2),
                            });
                        } else if let Some(src2) = parse_imm(src2) {
                            let dst = dst.into();
                            let src1 = src1.into();
                            let src2 = src2 as u32;
                            emit_and_continue!(match op {
                                Op::Add => Instruction::add_imm(dst, src1, src2),
                                Op::Sub => Instruction::add_imm(dst, src1, (-(src2 as i32)) as u32),
                                Op::And => Instruction::and_imm(dst, src1, src2),
                                Op::Xor => Instruction::xor_imm(dst, src1, src2),
                                Op::Or => Instruction::or_imm(dst, src1, src2),
                                Op::Mul => Instruction::mul_imm(dst, src1, src2),
                                Op::DivUnsigned | Op::DivSigned => {
                                    return Err(format!("cannot parse line {nth_line}: division is not supported for immediates"));
                                }
                                Op::RemUnsigned | Op::RemSigned => {
                                    return Err(format!("cannot parse line {nth_line}: modulo is not supported for immediates"));
                                }
                                Op::LessUnsigned => Instruction::set_less_than_unsigned_imm(dst, src1, src2),
                                Op::LessSigned => Instruction::set_less_than_signed_imm(dst, src1, src2),
                                Op::GreaterUnsigned => Instruction::set_greater_than_unsigned_imm(dst, src1, src2),
                                Op::GreaterSigned => Instruction::set_greater_than_signed_imm(dst, src1, src2),
                                Op::ShiftLeft => Instruction::shift_logical_left_imm(dst, src1, src2),
                                Op::ShiftRight => Instruction::shift_logical_right_imm(dst, src1, src2),
                                Op::ShiftArithmeticRight => Instruction::shift_arithmetic_right_imm(dst, src1, src2),
                            });
                        }
                    } else if let Some(src1) = parse_imm(src1) {
                        if let Some(src2) = parse_reg(src2) {
                            let dst = dst.into();
                            let src1 = src1 as u32;
                            let src2 = src2.into();
                            emit_and_continue!(match op {
                                Op::Add => Instruction::add_imm(dst, src2, src1),
                                Op::Sub => Instruction::negate_and_add_imm(dst, src2, src1),
                                Op::And => Instruction::and_imm(dst, src2, src1),
                                Op::Xor => Instruction::xor_imm(dst, src2, src1),
                                Op::Or => Instruction::or_imm(dst, src2, src1),
                                Op::Mul => Instruction::mul_imm(dst, src2, src1),
                                Op::DivUnsigned | Op::DivSigned => {
                                    return Err(format!("cannot parse line {nth_line}: division is not supported for immediates"));
                                }
                                Op::RemUnsigned | Op::RemSigned => {
                                    return Err(format!("cannot parse line {nth_line}: modulo is not supported for immediates"));
                                }
                                Op::LessUnsigned => Instruction::set_greater_than_unsigned_imm(dst, src2, src1),
                                Op::LessSigned => Instruction::set_greater_than_signed_imm(dst, src2, src1),
                                Op::GreaterUnsigned => Instruction::set_less_than_unsigned_imm(dst, src2, src1),
                                Op::GreaterSigned => Instruction::set_less_than_signed_imm(dst, src2, src1),
                                Op::ShiftLeft => Instruction::shift_logical_left_imm_alt(dst, src2, src1),
                                Op::ShiftRight => Instruction::shift_logical_right_imm_alt(dst, src2, src1),
                                Op::ShiftArithmeticRight => Instruction::shift_arithmetic_right_imm_alt(dst, src2, src1),
                            });
                        }
                    }
                }

                #[allow(clippy::manual_map)]
                let load_kind = if let Some(rhs) = rhs.strip_prefix("u8") {
                    Some((LoadKind::U8, rhs))
                } else if let Some(rhs) = rhs.strip_prefix("u16") {
                    Some((LoadKind::U16, rhs))
                } else if let Some(rhs) = rhs.strip_prefix("u32") {
                    Some((LoadKind::U32, rhs))
                } else if let Some(rhs) = rhs.strip_prefix("i8") {
                    Some((LoadKind::I8, rhs))
                } else if let Some(rhs) = rhs.strip_prefix("i16") {
                    Some((LoadKind::I16, rhs))
                } else {
                    None
                };

                if let Some((kind, rhs)) = load_kind {
                    if let Some((base, offset)) = parse_indirect_memory_access(rhs) {
                        let dst = dst.into();
                        let base = base.into();
                        let offset = offset as u32;
                        emit_and_continue!(match kind {
                            LoadKind::I8 => Instruction::load_indirect_i8(dst, base, offset),
                            LoadKind::I16 => Instruction::load_indirect_i16(dst, base, offset),
                            LoadKind::U32 => Instruction::load_indirect_u32(dst, base, offset),
                            LoadKind::U8 => Instruction::load_indirect_u8(dst, base, offset),
                            LoadKind::U16 => Instruction::load_indirect_u16(dst, base, offset),
                        });
                    } else if let Some(offset) = parse_absolute_memory_access(rhs) {
                        let dst = dst.into();
                        let offset = offset as u32;
                        emit_and_continue!(match kind {
                            LoadKind::I8 => Instruction::load_i8(dst, offset),
                            LoadKind::I16 => Instruction::load_i16(dst, offset),
                            LoadKind::U32 => Instruction::load_u32(dst, offset),
                            LoadKind::U8 => Instruction::load_u8(dst, offset),
                            LoadKind::U16 => Instruction::load_u16(dst, offset),
                        });
                    }
                }
            }

            #[allow(clippy::manual_map)]
            let store_kind = if let Some(lhs) = lhs.strip_prefix("u8") {
                Some((StoreKind::U8, lhs))
            } else if let Some(lhs) = lhs.strip_prefix("u16") {
                Some((StoreKind::U16, lhs))
            } else if let Some(lhs) = lhs.strip_prefix("u32") {
                Some((StoreKind::U32, lhs))
            } else {
                None
            };

            if let Some((kind, lhs)) = store_kind {
                if let Some(offset) = parse_absolute_memory_access(lhs) {
                    let offset = offset as u32;
                    if let Some(rhs) = parse_reg(rhs) {
                        let rhs = rhs.into();
                        emit_and_continue!(match kind {
                            StoreKind::U8 => Instruction::store_u8(rhs, offset),
                            StoreKind::U16 => Instruction::store_u16(rhs, offset),
                            StoreKind::U32 => Instruction::store_u32(rhs, offset),
                        });
                    } else if let Some(rhs) = parse_imm(rhs) {
                        let rhs = rhs as u32;
                        emit_and_continue!(match kind {
                            StoreKind::U8 => match u8::try_from(rhs) {
                                Ok(_) => Instruction::store_imm_u8(offset, rhs),
                                Err(_) => return Err(format!("cannot parse line {nth_line}: immediate larger than u8")),
                            },
                            StoreKind::U16 => match u16::try_from(rhs) {
                                Ok(_) => Instruction::store_imm_u16(offset, rhs),
                                Err(_) => return Err(format!("cannot parse line {nth_line}: immediate larger than u16")),
                            },
                            StoreKind::U32 => Instruction::store_imm_u32(offset, rhs),
                        });
                    }
                } else if let Some((base, offset)) = parse_indirect_memory_access(lhs) {
                    let base = base.into();
                    let offset = offset as u32;
                    if let Some(rhs) = parse_reg(rhs) {
                        let rhs = rhs.into();
                        emit_and_continue!(match kind {
                            StoreKind::U8 => Instruction::store_indirect_u8(rhs, base, offset),
                            StoreKind::U16 => Instruction::store_indirect_u16(rhs, base, offset),
                            StoreKind::U32 => Instruction::store_indirect_u32(rhs, base, offset),
                        });
                    } else if let Some(rhs) = parse_imm(rhs) {
                        let rhs = rhs as u32;
                        emit_and_continue!(match kind {
                            StoreKind::U8 => match u8::try_from(rhs) {
                                Ok(_) => Instruction::store_imm_indirect_u8(base, offset, rhs),
                                Err(_) => return Err(format!("cannot parse line {nth_line}: immediate larger than u8")),
                            },
                            StoreKind::U16 => match u16::try_from(rhs) {
                                Ok(_) => Instruction::store_imm_indirect_u16(base, offset, rhs),
                                Err(_) => return Err(format!("cannot parse line {nth_line}: immediate larger than u16")),
                            },
                            StoreKind::U32 => Instruction::store_imm_indirect_u32(base, offset, rhs),
                        });
                    }
                }
            }
        }

        return Err(format!("cannot parse line {nth_line}: \"{original_line}\""));
    }

    let mut code = Vec::new();
    let mut jump_table = Vec::new();
    for instruction in instructions {
        match instruction {
            MaybeInstruction::Instruction(instruction) => {
                code.push(instruction);
            }
            MaybeInstruction::LoadLabelAddress(dst, label) => {
                let Some(&target_index) = label_to_index.get(&*label) else {
                    return Err(format!("label is not defined: \"{label}\""));
                };

                jump_table.push(target_index);
                code.push(Instruction::load_imm(
                    dst.into(),
                    (jump_table.len() as u32) * crate::abi::VM_CODE_ADDRESS_ALIGNMENT,
                ));
            }
            MaybeInstruction::LoadImmAndJump(dst, value, label) => {
                let Some(&target_index) = label_to_index.get(&*label) else {
                    return Err(format!("label is not defined: \"{label}\""));
                };

                code.push(Instruction::load_imm_and_jump(dst.into(), value as u32, target_index));
            }
            MaybeInstruction::Jump(label) => {
                let Some(&target_index) = label_to_index.get(&*label) else {
                    return Err(format!("label is not defined: \"{label}\""));
                };
                code.push(Instruction::jump(target_index));
            }
            MaybeInstruction::Branch(label, kind, lhs, rhs) => {
                let Some(&target_index) = label_to_index.get(&*label) else {
                    return Err(format!("label is not defined: \"{label}\""));
                };

                let lhs = lhs.into();
                let rhs = rhs.into();
                let instruction = match kind {
                    ConditionKind::Eq => Instruction::branch_eq(lhs, rhs, target_index),
                    ConditionKind::NotEq => Instruction::branch_not_eq(lhs, rhs, target_index),
                    ConditionKind::LessSigned => Instruction::branch_less_signed(lhs, rhs, target_index),
                    ConditionKind::LessUnsigned => Instruction::branch_less_unsigned(lhs, rhs, target_index),
                    ConditionKind::GreaterOrEqualSigned => Instruction::branch_greater_or_equal_signed(lhs, rhs, target_index),
                    ConditionKind::GreaterOrEqualUnsigned => Instruction::branch_greater_or_equal_unsigned(lhs, rhs, target_index),

                    ConditionKind::LessOrEqualSigned => Instruction::branch_greater_or_equal_signed(rhs, lhs, target_index),
                    ConditionKind::LessOrEqualUnsigned => Instruction::branch_greater_or_equal_unsigned(rhs, lhs, target_index),
                    ConditionKind::GreaterSigned => Instruction::branch_less_signed(rhs, lhs, target_index),
                    ConditionKind::GreaterUnsigned => Instruction::branch_less_unsigned(rhs, lhs, target_index),
                };
                code.push(instruction);
            }
            MaybeInstruction::BranchImm(label, kind, lhs, rhs) => {
                let Some(&target_index) = label_to_index.get(&*label) else {
                    return Err(format!("label is not defined: \"{label}\""));
                };

                let lhs = lhs.into();
                let rhs = rhs as u32;
                let instruction = match kind {
                    ConditionKind::Eq => Instruction::branch_eq_imm(lhs, rhs, target_index),
                    ConditionKind::NotEq => Instruction::branch_not_eq_imm(lhs, rhs, target_index),
                    ConditionKind::LessSigned => Instruction::branch_less_signed_imm(lhs, rhs, target_index),
                    ConditionKind::LessUnsigned => Instruction::branch_less_unsigned_imm(lhs, rhs, target_index),
                    ConditionKind::GreaterOrEqualSigned => Instruction::branch_greater_or_equal_signed_imm(lhs, rhs, target_index),
                    ConditionKind::GreaterOrEqualUnsigned => Instruction::branch_greater_or_equal_unsigned_imm(lhs, rhs, target_index),
                    ConditionKind::LessOrEqualSigned => Instruction::branch_less_or_equal_signed_imm(lhs, rhs, target_index),
                    ConditionKind::LessOrEqualUnsigned => Instruction::branch_less_or_equal_unsigned_imm(lhs, rhs, target_index),
                    ConditionKind::GreaterSigned => Instruction::branch_greater_signed_imm(lhs, rhs, target_index),
                    ConditionKind::GreaterUnsigned => Instruction::branch_greater_unsigned_imm(lhs, rhs, target_index),
                };
                code.push(instruction);
            }
        };
    }

    let mut builder = crate::writer::ProgramBlobBuilder::new();
    builder.set_ro_data(ro_data);
    builder.set_ro_data_size(ro_data_size);
    builder.set_rw_data(rw_data);
    builder.set_rw_data_size(rw_data_size);
    builder.set_stack_size(stack_size);
    builder.set_code(&code, &jump_table);
    for (label, target_index) in exports {
        builder.add_export_by_basic_block(target_index, label.as_bytes());
    }

    Ok(builder.to_vec())
}

#[cfg(test)]
#[track_caller]
fn assert_assembler(input: &str, expected_output: &str) {
    use alloc::string::ToString;

    let expected_output_clean: Vec<_> = expected_output.trim().split('\n').map(|line| line.trim()).collect();
    let expected_output_clean = expected_output_clean.join("\n");

    let blob = assemble(input).expect("failed to assemble");
    let program = crate::program::ProgramBlob::parse(blob.into()).unwrap();
    let output: Vec<_> = program
        .instructions(crate::program::DefaultInstructionSet::default())
        .take_while(|inst| (inst.offset.0 as usize) < program.code().len())
        .map(|inst| inst.kind.to_string())
        .collect();
    let output = output.join("\n");
    assert_eq!(output, expected_output_clean);
}

#[test]
fn test_assembler_basics() {
    assert_assembler(
        "
        // This is a comment.
        a0 = a1 + a2
        a3 = a4 + a5
        // This is another comment.
    ",
        "
        a0 = a1 + a2
        a3 = a4 + a5
    ",
    );

    assert_assembler(
        "
        jump @label
        a0 = 1
        @label:
        a0 = 2
    ",
        "
        jump 6
        a0 = 0x1
        fallthrough
        a0 = 0x2
    ",
    );
}
