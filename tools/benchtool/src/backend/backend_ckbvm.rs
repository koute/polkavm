use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub enum CkbvmBackend {
    Asm,
    NonAsm,
}

#[derive(Copy, Clone)]
pub struct Ckbvm(pub CkbvmBackend);

enum CkbvmInstanceKind {
    Asm(ckb_vm::machine::asm::AsmMachine),
    NonAsm(ckb_vm::DefaultMachine<ckb_vm::DefaultCoreMachine<u64, ckb_vm::SparseMemory<u64>>>),
}

pub struct CkbvmInstance {
    pc: u64,
    sp: u64,
    kind: CkbvmInstanceKind,
}

impl CkbvmInstance {
    fn run(&mut self, a0: u64) {
        use ckb_vm::CoreMachine;

        match self.kind {
            CkbvmInstanceKind::Asm(ref mut machine) => {
                machine.machine.set_register(ckb_vm::registers::SP, self.sp);
                machine.machine.set_register(ckb_vm::registers::A0, a0);
                machine.machine.update_pc(self.pc);
                machine.machine.commit_pc();
                machine.run().unwrap();
            }
            CkbvmInstanceKind::NonAsm(ref mut machine) => {
                machine.set_register(ckb_vm::registers::SP, self.sp);
                machine.set_register(ckb_vm::registers::A0, a0);
                machine.update_pc(self.pc);
                machine.commit_pc();
                machine.run().unwrap();
            }
        }
    }
}

impl Backend for Ckbvm {
    type Engine = ();
    type Blob = Vec<u8>;
    type Module = Vec<u8>;
    type Instance = CkbvmInstance;

    fn name(&self) -> &'static str {
        match self.0 {
            CkbvmBackend::Asm => "ckbvm_asm",
            CkbvmBackend::NonAsm => "ckbvm_non_asm",
        }
    }

    fn create(&self, _args: CreateArgs) -> Self::Engine {}

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, _engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        blob.clone()
    }

    fn spawn(&self, _engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        struct SyscallHandler;

        impl<Mac: ckb_vm::SupportMachine> ckb_vm::Syscalls<Mac> for SyscallHandler {
            fn initialize(&mut self, _machine: &mut Mac) -> Result<(), ckb_vm::error::Error> {
                Ok(())
            }

            fn ecall(&mut self, machine: &mut Mac) -> Result<bool, ckb_vm::error::Error> {
                machine.set_running(false);
                Ok(true)
            }
        }

        use ckb_vm::CoreMachine;

        match self.0 {
            CkbvmBackend::Asm => {
                let core_machine = ckb_vm::machine::asm::AsmCoreMachine::new(
                    ckb_vm::ISA_IMC | ckb_vm::ISA_A | ckb_vm::ISA_B | ckb_vm::ISA_MOP,
                    ckb_vm::machine::VERSION2,
                    u64::max_value(),
                );

                let core = ckb_vm::DefaultMachineBuilder::new(core_machine)
                    .instruction_cycle_func(Box::new(ckb_vm::cost_model::estimate_cycles))
                    .syscall(Box::new(SyscallHandler))
                    .build();

                let mut machine = ckb_vm::machine::asm::AsmMachine::new(core);
                machine.load_program(&module.clone().into(), &[]).unwrap();

                CkbvmInstance {
                    pc: *machine.machine.pc(),
                    sp: machine.machine.registers()[ckb_vm::registers::SP],
                    kind: CkbvmInstanceKind::Asm(machine),
                }
            }
            CkbvmBackend::NonAsm => {
                let core_machine = ckb_vm::DefaultCoreMachine::<u64, ckb_vm::SparseMemory<u64>>::new(
                    ckb_vm::ISA_IMC | ckb_vm::ISA_A | ckb_vm::ISA_B | ckb_vm::ISA_MOP,
                    ckb_vm::machine::VERSION2,
                    u64::MAX,
                );

                let mut machine = ckb_vm::DefaultMachineBuilder::new(core_machine)
                    .instruction_cycle_func(Box::new(ckb_vm::cost_model::estimate_cycles))
                    .syscall(Box::new(SyscallHandler))
                    .build();

                machine.load_program(&module.clone().into(), &[]).unwrap();

                CkbvmInstance {
                    pc: *machine.pc(),
                    sp: machine.registers()[ckb_vm::registers::SP],
                    kind: CkbvmInstanceKind::NonAsm(machine),
                }
            }
        }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        instance.run(0);
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance.run(1);
    }

    fn is_slow(&self) -> bool {
        match self.0 {
            CkbvmBackend::Asm => false,
            CkbvmBackend::NonAsm => true,
        }
    }
}
