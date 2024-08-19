use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub struct PolkaVM(pub polkavm::BackendKind, pub Option<polkavm::GasMeteringKind>);

pub struct Instance {
    ext_initialize: polkavm::ProgramCounter,
    ext_run: polkavm::ProgramCounter,
    instance: polkavm::Instance<()>,
}

impl Backend for PolkaVM {
    type Engine = polkavm::Engine;
    type Blob = polkavm::ArcBytes;
    type Module = polkavm::Module;
    type Instance = Instance;

    fn name(&self) -> &'static str {
        match (self.0, self.1) {
            (polkavm::BackendKind::Compiler, None) => "polkavm_compiler_no_gas",
            (polkavm::BackendKind::Compiler, Some(polkavm::GasMeteringKind::Async)) => "polkavm_compiler_async_gas",
            (polkavm::BackendKind::Compiler, Some(polkavm::GasMeteringKind::Sync)) => "polkavm_compiler_sync_gas",
            (polkavm::BackendKind::Interpreter, _) => "polkavm_interpreter",
        }
    }

    fn create(&self, args: CreateArgs) -> Self::Engine {
        let mut config = polkavm::Config::from_env().unwrap();
        config.set_backend(Some(self.0));
        if args.is_compile_only {
            config.set_worker_count(0);
        }
        polkavm::Engine::new(&config).unwrap()
    }

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap().into()
    }

    fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        let blob = polkavm::ProgramBlob::parse(blob.clone()).unwrap();
        let mut config = polkavm::ModuleConfig::default();
        config.set_gas_metering(self.1);
        polkavm::Module::from_blob(engine, &config, blob).unwrap()
    }

    fn spawn(&self, _engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        let linker = polkavm::Linker::<()>::new();
        let instance_pre = linker.instantiate_pre(module).unwrap();
        let instance = instance_pre.instantiate().unwrap();
        let ext_initialize = module.exports().find(|export| export == "initialize").unwrap().program_counter();
        let ext_run = module.exports().find(|export| export == "run").unwrap().program_counter();
        Instance {
            ext_initialize,
            ext_run,
            instance,
        }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        if self.1.is_some() {
            instance.instance.set_gas(polkavm::Gas::MAX);
        }

        instance
            .instance
            .call_typed(&mut (), instance.ext_initialize, ())
            .unwrap();
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance
            .instance
            .call_typed(&mut (), instance.ext_run, ())
            .unwrap();
    }

    fn pid(&self, instance: &Self::Instance) -> Option<u32> {
        instance.instance.pid()
    }

    fn is_compiled(&self) -> bool {
        true
    }

    fn is_slow(&self) -> bool {
        // The interpreter is currently way too slow.
        matches!(self.0, polkavm::BackendKind::Interpreter)
    }
}
