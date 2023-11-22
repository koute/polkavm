use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub struct Ckbvm();
pub struct CkbvmInstance {
    pc: u64,
    sp: u64,
    machine: ckb_vm::machine::asm::AsmMachine,
}

impl CkbvmInstance {
    fn run(&mut self, a0: u64) {
        use ckb_vm::CoreMachine;
        self.machine.machine.set_register(ckb_vm::registers::SP, self.sp);
        self.machine.machine.set_register(ckb_vm::registers::A0, a0);
        self.machine.machine.update_pc(self.pc);
        self.machine.machine.commit_pc();
        self.machine.machine.run().unwrap();
    }
}

impl Backend for Ckbvm {
    type Engine = ();
    type Blob = Vec<u8>;
    type Module = Vec<u8>;
    type Instance = CkbvmInstance;

    fn name(&self) -> &'static str {
        "ckbvm"
    }

    fn create(&self) -> Self::Engine {}

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, _engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        blob.clone()
    }

    fn spawn(&self, _engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        use ckb_vm::CoreMachine;

        let core_machine = ckb_vm::machine::asm::AsmCoreMachine::new(
            ckb_vm::ISA_IMC | ckb_vm::ISA_A | ckb_vm::ISA_B | ckb_vm::ISA_MOP,
            ckb_vm::machine::VERSION2,
            u64::max_value(),
        );

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

        let core = ckb_vm::DefaultMachineBuilder::new(core_machine)
            .instruction_cycle_func(Box::new(ckb_vm::cost_model::estimate_cycles))
            .syscall(Box::new(SyscallHandler))
            .build();

        let mut machine = ckb_vm::machine::asm::AsmMachine::new(core);
        machine.load_program(&module.clone().into(), &[]).unwrap();

        CkbvmInstance {
            pc: *machine.machine.pc(),
            sp: machine.machine.registers()[ckb_vm::registers::SP],
            machine,
        }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        instance.run(0);
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance.run(1);
    }

    fn is_slow(&self) -> bool {
        true
    }
}
