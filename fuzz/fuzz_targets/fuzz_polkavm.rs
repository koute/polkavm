#![no_main]

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use polkavm::Engine;
use polkavm::InterruptKind;
use polkavm::ModuleConfig;
use polkavm::ProgramCounter;
use polkavm::SetCacheSizeLimitArgs;

use polkavm_common::program::{asm, Instruction, InstructionSetKind, ProgramBlob, Reg};
use polkavm_common::writer::ProgramBlobBuilder;

use polkavm::RETURN_TO_HOST;

#[derive(Arbitrary, Debug)]
struct CacheSizeConfig {
    max_cache_size_bytes: usize,
    max_block_size: u32,
}

#[derive(Arbitrary, Debug)]
enum ArglessKind {
    Trap,
    Fallthrough,
    Memset,
}

#[derive(Arbitrary, Debug)]
enum RegImmKind {
    JumpIndirect,
    LoadImmediate,
    LoadUnsigned8,
    LoadSigned8,
    LoadUnsigned16,
    LoadSigned16,
    LoadUnsigned32,
    LoadSigned32,
    LoadUnsigned64,
    StoreUnsigned8,
    StoreUnsigned16,
    StoreUnsigned32,
    StoreUnsigned64,
}

#[derive(Arbitrary, Debug)]
enum RegOffsetKind {
    BranchEqualImmediate,
    BranchNotEqualImmediate,
    BranchLessThanUnsignedImmediate,
    BranchLessThanSignedImmediate,
    BranchGreaterThanOrEqualUnsignedImmediate,
    BranchGreaterThanOrEqualSignedImmediate,
    BranchLessThanOrEqualSignedImmediate,
    BranchLessThanOrEqualUnsignedImmediate,
    BranchGreaterThanSignedImmediate,
    BranchGreaterThanUnsignedImmediate,
}

#[derive(Arbitrary, Debug)]
enum RegImmImmKind {
    StoreIndirectUnsigned8,
    StoreIndirectUnsigned16,
    StoreIndirectUnsigned32,
    StoreIndirectUnsigned64,
}

#[derive(Arbitrary, Debug)]
enum RegRegImmKind {
    StoreIndirectUnsigned8,
    StoreIndirectUnsigned16,
    StoreIndirectUnsigned32,
    StoreIndirectUnsigned64,
    LoadIndirectUnsigned8,
    LoadIndirectSigned8,
    LoadIndirectUnsigned16,
    LoadIndirectSigned16,
    LoadIndirectUnsigned32,
    LoadIndirectSigned32,
    LoadIndirectUnsigned64,
    Add32,
    Add64,
    And,
    Xor,
    Or,
    Mul32,
    Mul64,
    SetLessThanUnsigned,
    SetLessThanSigned,
    ShiftLogicalLeft32,
    ShiftLogicalLeft64,
    ShiftLogicalRight32,
    ShiftLogicalRight64,
    ShiftArithmeticRight32,
    ShiftArithmeticRight64,
    Sub32,
    Sub64,
    SetGreaterThanUnsigned,
    SetGreaterThanSigned,
    ShiftLogicalLeftAlt32,
    ShiftLogicalLeftAlt64,
    ShiftLogicalRightAlt32,
    ShiftLogicalRightAlt64,
    ShiftArithmeticRightAlt32,
    ShiftArithmeticRightAlt64,
    CMovIfZero,
    CMovIfNotZero,
    RotateRight32,
    RotateRight64,
    RotateRightAlt32,
    RotateRightAlt64,
}

#[derive(Arbitrary, Debug)]
enum RegRegOffsetKind {
    BranchEqual,
    BranchNotEqual,
    BranchLessThanUnsigned,
    BranchLessThanSigned,
    BranchGreaterThanOrEqualUnsigned,
    BranchGreaterThanOrEqualSigned,
}

#[derive(Arbitrary, Debug)]
enum RegRegRegKind {
    Add32,
    Add64,
    Sub32,
    Sub64,
    And,
    Xor,
    Or,
    Mul32,
    Mul64,
    MulUpperSignedSigned,
    MulUpperUnsignedUnsigned,
    MulUpperSignedUnsigned,
    SetLessThanUnsigned,
    SetLessThanSigned,
    ShiftLogicalLeft32,
    ShiftLogicalLeft64,
    ShiftLogicalRight32,
    ShiftLogicalRight64,
    ShiftArithmeticRight32,
    ShiftArithmeticRight64,
    DivUnsigned32,
    DivUnsigned64,
    DivSigned32,
    DivSigned64,
    RemUnsigned32,
    RemUnsigned64,
    RemSigned32,
    RemSigned64,
    CMovIfZero,
    CMovIfNotZero,
    AndInverted,
    OrInverted,
    Xnor,
    Maximum,
    MaximumUnsigned,
    Minimum,
    MinimumUnsigned,
    RotateLeft32,
    RotateLeft64,
    RotateRight32,
    RotateRight64,
}

#[derive(Arbitrary, Debug)]
enum ImmImmKind {
    StoreUnsigned8,
    StoreUnsigned16,
    StoreUnsigned32,
    StoreUnsigned64,
}

#[derive(Arbitrary, Debug)]
enum RegRegKind {
    Move,
    CountLeadingZeroBits32,
    CountLeadingZeroBits64,
    CountTrailingZeroBits32,
    CountTrailingZeroBits64,
    CountSetBits32,
    CountSetBits64,
    SignExtend8,
    SignExtend16,
    ZeroExtend16,
    ReverseByte,
}

#[derive(Arbitrary, Debug)]
enum OperationReg {
    RA = 0,
    SP = 1,
    T0 = 2,
    T1 = 3,
    T2 = 4,
    S0 = 5,
    S1 = 6,
    A0 = 7,
    A1 = 8,
    A2 = 9,
    A3 = 10,
    A4 = 11,
    A5 = 12,
}

impl From<OperationReg> for Reg {
    fn from(reg: OperationReg) -> Self {
        match reg {
            OperationReg::RA => Reg::RA,
            OperationReg::SP => Reg::SP,
            OperationReg::T0 => Reg::T0,
            OperationReg::T1 => Reg::T1,
            OperationReg::T2 => Reg::T2,
            OperationReg::S0 => Reg::S0,
            OperationReg::S1 => Reg::S1,
            OperationReg::A0 => Reg::A0,
            OperationReg::A1 => Reg::A1,
            OperationReg::A2 => Reg::A2,
            OperationReg::A3 => Reg::A3,
            OperationReg::A4 => Reg::A4,
            OperationReg::A5 => Reg::A5,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum OperationKind {
    Argless {
        kind: ArglessKind,
    },
    RegImmArgs {
        kind: RegImmKind,
        reg: OperationReg,
        imm: i32,
    },
    RegOffsetArgs {
        kind: RegOffsetKind,
        reg: OperationReg,
    },
    RegImmImmArgs {
        kind: RegImmImmKind,
        reg: OperationReg,
        imm1: i32,
        imm2: i32,
    },
    RegRegImmArgs {
        kind: RegRegImmKind,
        reg1: OperationReg,
        reg2: OperationReg,
        imm: i32,
    },
    RegRegOffsetArgs {
        kind: RegRegOffsetKind,
        reg1: OperationReg,
        reg2: OperationReg,
    },
    RegRegRegArgs {
        kind: RegRegRegKind,
        reg1: OperationReg,
        reg2: OperationReg,
        reg3: OperationReg,
    },
    ImmImmArgs {
        kind: ImmImmKind,
        imm1: i32,
        imm2: i32,
    },
    RegRegArgs {
        kind: RegRegKind,
        reg1: OperationReg,
        reg2: OperationReg,
    },
    RegImm64Args {
        reg: OperationReg,
        imm: u64,
    },
    RegImmOffsetArgs {
        reg: OperationReg,
        imm: i32,
    },
}

fn transform_code(data: Vec<OperationKind>) -> Vec<Instruction> {
    macro_rules! codegen {
        (
            args = $args:tt,
            kind = $kind:expr,
            {
                $($p:pat => $inst:ident,)+
            }
        ) => {
            match $kind {
                $(
                    $p => asm::$inst $args
                ),+
            }
        }
    }

    let mut buffer = Vec::new();
    buffer.push(asm::fallthrough());

    for op in data {
        let op = match op {
            OperationKind::Argless { kind } => {
                codegen! {
                    args = (),
                    kind = kind,
                    {
                        ArglessKind::Trap => trap,
                        ArglessKind::Fallthrough => fallthrough,
                        ArglessKind::Memset => memset,
                    }
                }
            }
            OperationKind::RegImmArgs { kind, reg, imm } => {
                codegen! {
                    args = (reg.into(), imm),
                    kind = kind,
                    {
                        RegImmKind::JumpIndirect => jump_indirect,
                        RegImmKind::LoadImmediate => load_imm,
                        RegImmKind::LoadUnsigned8 => load_u8,
                        RegImmKind::LoadSigned8 => load_i8,
                        RegImmKind::LoadUnsigned16 => load_u16,
                        RegImmKind::LoadSigned16 => load_i16,
                        RegImmKind::LoadUnsigned32 => load_u32,
                        RegImmKind::LoadSigned32 => load_i32,
                        RegImmKind::LoadUnsigned64 => load_u64,
                        RegImmKind::StoreUnsigned8 => store_u8,
                        RegImmKind::StoreUnsigned16 => store_u16,
                        RegImmKind::StoreUnsigned32 => store_u32,
                        RegImmKind::StoreUnsigned64 => store_u64,
                    }
                }
            }
            OperationKind::RegOffsetArgs { kind, reg } => {
                codegen! {
                    args = (reg.into(), 0, 0),
                    kind = kind,
                    {
                        RegOffsetKind::BranchEqualImmediate => branch_eq_imm,
                        RegOffsetKind::BranchNotEqualImmediate => branch_not_eq_imm,
                        RegOffsetKind::BranchLessThanUnsignedImmediate => branch_less_unsigned_imm,
                        RegOffsetKind::BranchLessThanSignedImmediate => branch_less_signed_imm,
                        RegOffsetKind::BranchGreaterThanOrEqualUnsignedImmediate => branch_greater_or_equal_unsigned_imm,
                        RegOffsetKind::BranchGreaterThanOrEqualSignedImmediate => branch_greater_or_equal_signed_imm,
                        RegOffsetKind::BranchLessThanOrEqualSignedImmediate => branch_less_or_equal_signed_imm,
                        RegOffsetKind::BranchLessThanOrEqualUnsignedImmediate => branch_less_or_equal_unsigned_imm,
                        RegOffsetKind::BranchGreaterThanSignedImmediate => branch_greater_signed_imm,
                        RegOffsetKind::BranchGreaterThanUnsignedImmediate => branch_greater_unsigned_imm,
                    }
                }
            }
            OperationKind::RegImmImmArgs { kind, reg, imm1, imm2 } => {
                codegen! {
                    args = (reg.into(), imm1, imm2),
                    kind = kind,
                    {
                        RegImmImmKind::StoreIndirectUnsigned8 => store_imm_indirect_u8,
                        RegImmImmKind::StoreIndirectUnsigned16 => store_imm_indirect_u16,
                        RegImmImmKind::StoreIndirectUnsigned32 => store_imm_indirect_u32,
                        RegImmImmKind::StoreIndirectUnsigned64 => store_imm_indirect_u64,
                    }
                }
            }
            OperationKind::RegRegImmArgs { kind, reg1, reg2, imm } => {
                codegen! {
                    args = (reg1.into(), reg2.into(), imm),
                    kind = kind,
                    {
                        RegRegImmKind::StoreIndirectUnsigned8 => store_indirect_u8,
                        RegRegImmKind::StoreIndirectUnsigned16 => store_indirect_u16,
                        RegRegImmKind::StoreIndirectUnsigned32 => store_indirect_u32,
                        RegRegImmKind::StoreIndirectUnsigned64 => store_indirect_u64,
                        RegRegImmKind::LoadIndirectUnsigned8 => load_indirect_u8,
                        RegRegImmKind::LoadIndirectSigned8 => load_indirect_i8,
                        RegRegImmKind::LoadIndirectUnsigned16 => load_indirect_u16,
                        RegRegImmKind::LoadIndirectSigned16 => load_indirect_i16,
                        RegRegImmKind::LoadIndirectUnsigned32 => load_indirect_u32,
                        RegRegImmKind::LoadIndirectSigned32 => load_indirect_i32,
                        RegRegImmKind::LoadIndirectUnsigned64 => load_indirect_u64,
                        RegRegImmKind::Add32 => add_imm_32,
                        RegRegImmKind::Add64 => add_imm_64,
                        RegRegImmKind::And => and_imm,
                        RegRegImmKind::Xor => xor_imm,
                        RegRegImmKind::Or => or_imm,
                        RegRegImmKind::Mul32 => mul_imm_32,
                        RegRegImmKind::Mul64 => mul_imm_64,
                        RegRegImmKind::SetLessThanUnsigned => set_less_than_unsigned_imm,
                        RegRegImmKind::SetLessThanSigned => set_less_than_signed_imm,
                        RegRegImmKind::ShiftLogicalLeft32 => shift_logical_left_imm_32,
                        RegRegImmKind::ShiftLogicalLeft64 => shift_logical_left_imm_64,
                        RegRegImmKind::ShiftLogicalRight32 => shift_logical_right_imm_32,
                        RegRegImmKind::ShiftLogicalRight64 => shift_logical_right_imm_64,
                        RegRegImmKind::ShiftArithmeticRight32 => shift_arithmetic_right_imm_32,
                        RegRegImmKind::ShiftArithmeticRight64 => shift_arithmetic_right_imm_64,
                        RegRegImmKind::Sub32 => negate_and_add_imm_32,
                        RegRegImmKind::Sub64 => negate_and_add_imm_64,
                        RegRegImmKind::SetGreaterThanUnsigned => set_greater_than_unsigned_imm,
                        RegRegImmKind::SetGreaterThanSigned => set_greater_than_signed_imm,
                        RegRegImmKind::ShiftLogicalLeftAlt32 => shift_logical_left_imm_alt_32,
                        RegRegImmKind::ShiftLogicalLeftAlt64 => shift_logical_left_imm_alt_64,
                        RegRegImmKind::ShiftLogicalRightAlt32 => shift_logical_right_imm_alt_32,
                        RegRegImmKind::ShiftLogicalRightAlt64 => shift_logical_right_imm_alt_64,
                        RegRegImmKind::ShiftArithmeticRightAlt32 => shift_arithmetic_right_imm_alt_32,
                        RegRegImmKind::ShiftArithmeticRightAlt64 => shift_arithmetic_right_imm_alt_64,
                        RegRegImmKind::CMovIfZero => cmov_if_zero_imm,
                        RegRegImmKind::CMovIfNotZero => cmov_if_not_zero_imm,
                        RegRegImmKind::RotateRight32 => rotate_right_imm_32,
                        RegRegImmKind::RotateRight64 => rotate_right_imm_64,
                        RegRegImmKind::RotateRightAlt32 => rotate_right_imm_alt_32,
                        RegRegImmKind::RotateRightAlt64 => rotate_right_imm_alt_64,
                    }
                }
            }
            OperationKind::RegRegOffsetArgs { kind, reg1, reg2 } => {
                codegen! {
                    args = (reg1.into(), reg2.into(), 0),
                    kind = kind,
                    {
                        RegRegOffsetKind::BranchEqual => branch_eq,
                        RegRegOffsetKind::BranchNotEqual => branch_not_eq,
                        RegRegOffsetKind::BranchLessThanUnsigned => branch_less_unsigned,
                        RegRegOffsetKind::BranchLessThanSigned => branch_less_signed,
                        RegRegOffsetKind::BranchGreaterThanOrEqualUnsigned => branch_greater_or_equal_unsigned,
                        RegRegOffsetKind::BranchGreaterThanOrEqualSigned => branch_greater_or_equal_signed,
                    }
                }
            }
            OperationKind::RegRegRegArgs { kind, reg1, reg2, reg3 } => {
                codegen! {
                    args = (reg1.into(), reg2.into(), reg3.into()),
                    kind = kind,
                    {
                        RegRegRegKind::Add32 => add_32,
                        RegRegRegKind::Add64 => add_64,
                        RegRegRegKind::Sub32 => sub_32,
                        RegRegRegKind::Sub64 => sub_64,
                        RegRegRegKind::And => and,
                        RegRegRegKind::Xor => xor,
                        RegRegRegKind::Or => or,
                        RegRegRegKind::Mul32 => mul_32,
                        RegRegRegKind::Mul64 => mul_64,
                        RegRegRegKind::MulUpperSignedSigned => mul_upper_signed_signed,
                        RegRegRegKind::MulUpperUnsignedUnsigned => mul_upper_unsigned_unsigned,
                        RegRegRegKind::MulUpperSignedUnsigned => mul_upper_signed_unsigned,
                        RegRegRegKind::SetLessThanUnsigned => set_less_than_unsigned,
                        RegRegRegKind::SetLessThanSigned => set_less_than_signed,
                        RegRegRegKind::ShiftLogicalLeft32 => shift_logical_left_32,
                        RegRegRegKind::ShiftLogicalLeft64 => shift_logical_left_64,
                        RegRegRegKind::ShiftLogicalRight32 => shift_logical_right_32,
                        RegRegRegKind::ShiftLogicalRight64 => shift_logical_right_64,
                        RegRegRegKind::ShiftArithmeticRight32 => shift_arithmetic_right_32,
                        RegRegRegKind::ShiftArithmeticRight64 => shift_arithmetic_right_64,
                        RegRegRegKind::DivUnsigned32 => div_unsigned_32,
                        RegRegRegKind::DivUnsigned64 => div_unsigned_64,
                        RegRegRegKind::DivSigned32 => div_signed_32,
                        RegRegRegKind::DivSigned64 => div_signed_64,
                        RegRegRegKind::RemUnsigned32 => rem_unsigned_32,
                        RegRegRegKind::RemUnsigned64 => rem_unsigned_64,
                        RegRegRegKind::RemSigned32 => rem_signed_32,
                        RegRegRegKind::RemSigned64 => rem_signed_64,
                        RegRegRegKind::CMovIfZero => cmov_if_zero,
                        RegRegRegKind::CMovIfNotZero => cmov_if_not_zero,
                        RegRegRegKind::AndInverted => and_inverted,
                        RegRegRegKind::OrInverted => or_inverted,
                        RegRegRegKind::Xnor => xnor,
                        RegRegRegKind::Maximum => maximum,
                        RegRegRegKind::MaximumUnsigned => maximum_unsigned,
                        RegRegRegKind::Minimum => minimum,
                        RegRegRegKind::MinimumUnsigned => minimum_unsigned,
                        RegRegRegKind::RotateLeft32 => rotate_left_32,
                        RegRegRegKind::RotateLeft64 => rotate_left_64,
                        RegRegRegKind::RotateRight32 => rotate_right_32,
                        RegRegRegKind::RotateRight64 => rotate_right_64,
                    }
                }
            }
            OperationKind::ImmImmArgs { kind, imm1, imm2 } => {
                codegen! {
                    args = (imm1, imm2),
                    kind = kind,
                    {
                        ImmImmKind::StoreUnsigned8 => store_imm_u8,
                        ImmImmKind::StoreUnsigned16 => store_imm_u16,
                        ImmImmKind::StoreUnsigned32 => store_imm_u32,
                        ImmImmKind::StoreUnsigned64 => store_imm_u64,
                    }
                }
            }
            OperationKind::RegRegArgs { kind, reg1, reg2 } => {
                codegen! {
                    args = (reg1.into(), reg2.into()),
                    kind = kind,
                    {
                        RegRegKind::Move => move_reg,
                        RegRegKind::CountLeadingZeroBits32 => count_leading_zero_bits_32,
                        RegRegKind::CountLeadingZeroBits64 => count_leading_zero_bits_64,
                        RegRegKind::CountTrailingZeroBits32 => count_trailing_zero_bits_32,
                        RegRegKind::CountTrailingZeroBits64 => count_trailing_zero_bits_64,
                        RegRegKind::CountSetBits32 => count_set_bits_32,
                        RegRegKind::CountSetBits64 => count_set_bits_64,
                        RegRegKind::SignExtend8 => sign_extend_8,
                        RegRegKind::SignExtend16 => sign_extend_16,
                        RegRegKind::ZeroExtend16 => zero_extend_16,
                        RegRegKind::ReverseByte => reverse_byte,
                    }
                }
            }
            OperationKind::RegImm64Args { reg, imm } => asm::load_imm64(reg.into(), imm),
            OperationKind::RegImmOffsetArgs { reg, imm } => asm::load_imm_and_jump(reg.into(), imm, 0),
        };

        buffer.push(op);
    }
    buffer
}

fn build_program_blob(data: Vec<OperationKind>) -> ProgramBlob {
    let code = transform_code(data);

    let mut builder = ProgramBlobBuilder::new(InstructionSetKind::Latest64);
    builder.add_export_by_basic_block(0, b"main");
    builder.set_code(&code, &[]);
    ProgramBlob::parse(builder.into_vec().unwrap().into()).unwrap()
}

fn engine(backend: polkavm::BackendKind) -> &'static Engine {
    static INTERPRETER: OnceLock<Engine> = OnceLock::new();
    static COMPILER: OnceLock<Engine> = OnceLock::new();

    let lazy_engine = match backend {
        polkavm::BackendKind::Interpreter => &INTERPRETER,
        polkavm::BackendKind::Compiler => &COMPILER,
    };

    lazy_engine.get_or_init(|| {
        let mut config = polkavm::Config::new();
        config.set_backend(Some(backend));
        Engine::new(&config).unwrap()
    })
}

fn interpreter_fuzzer_harness(data: Vec<OperationKind>, cache_config: Option<CacheSizeConfig>) {
    let blob = build_program_blob(data);

    let mut module_config = ModuleConfig::default();
    module_config.set_strict(true);
    module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));

    let module = polkavm::Module::from_blob(engine(polkavm::BackendKind::Interpreter), &module_config, blob).unwrap();
    let mut instance = module.instantiate().unwrap();

    if let Some(config) = cache_config {
        let _ = instance.set_interpreter_cache_size_limit(Some(SetCacheSizeLimitArgs {
            max_cache_size_bytes: config.max_cache_size_bytes,
            max_block_size: config.max_block_size,
        }));
    }

    instance.set_gas(1000000);
    instance.set_next_program_counter(ProgramCounter(0));

    instance.run().unwrap();
}

fn correctness_fuzzer_harness(data: Vec<OperationKind>) {
    let blob = build_program_blob(data);

    let mut instance_interpreter = {
        let mut module_config = ModuleConfig::default();
        module_config.set_strict(false);
        module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));

        let module = polkavm::Module::from_blob(engine(polkavm::BackendKind::Interpreter), &module_config, blob.clone()).unwrap();
        let mut instance = module.instantiate().unwrap();
        instance.set_gas(10000);
        instance.set_next_program_counter(ProgramCounter(0));
        instance.set_reg(Reg::RA, RETURN_TO_HOST);

        instance
    };

    let mut instance_recompiler = {
        let mut module_config = ModuleConfig::default();
        module_config.set_strict(false);
        module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));

        let module = polkavm::Module::from_blob(engine(polkavm::BackendKind::Compiler), &module_config, blob.clone()).unwrap();
        let mut instance = module.instantiate().unwrap();
        instance.set_gas(10000);
        instance.set_next_program_counter(ProgramCounter(0));
        instance.set_reg(Reg::RA, RETURN_TO_HOST);

        instance
    };

    loop {
        let interrupt_interpreter = instance_interpreter.run().unwrap();
        let interrupt_recompiler = instance_recompiler.run().unwrap();

        if interrupt_interpreter != interrupt_recompiler {
            panic!(
                "interrupt code mismatch (interpreter: {:?}, recompiler: {:?})",
                interrupt_interpreter, interrupt_recompiler
            );
        }

        if instance_interpreter.program_counter() != instance_recompiler.program_counter() {
            panic!(
                "program counter mismatch (interpreter: {:?}, recompiler: {:?})",
                instance_interpreter.program_counter(),
                instance_recompiler.program_counter()
            );
        }

        //
        // Compare the registers.
        //

        for reg in Reg::ALL {
            let reg_interpreter = instance_interpreter.reg(reg);
            let reg_recompiler = instance_recompiler.reg(reg);

            assert_eq!(
                reg_interpreter, reg_recompiler,
                "register comparison failed for {:?} (interpreter: {:?}, recompiler: {:?})",
                reg, reg_interpreter, reg_recompiler
            );
        }

        //
        // Compare interrupt code.
        //

        match interrupt_interpreter.clone() {
            InterruptKind::Finished | InterruptKind::NotEnoughGas | InterruptKind::Trap => {
                break;
            }
            polkavm::InterruptKind::Ecalli(_) => {
                continue;
            }
            _ => panic!("unexpected interrupt code {:?}", interrupt_interpreter),
        }
    }
}

fuzz_target!(|data: (Vec<OperationKind>, Option<CacheSizeConfig>)| {
    if std::env::var("CORRECTNESS_FUZZER").is_ok() {
        correctness_fuzzer_harness(data.0);
    } else {
        interpreter_fuzzer_harness(data.0, data.1);
    }
});
