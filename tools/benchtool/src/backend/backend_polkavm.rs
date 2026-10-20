use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub enum CostModel {
    Simple,
    Full,
}

#[derive(Copy, Clone)]
pub struct PolkaVM(
    pub polkavm::BackendKind,
    pub Option<polkavm::GasMeteringKind>,
    pub bool,
    pub CostModel,
);

pub struct Instance {
    ext_initialize: polkavm::ProgramCounter,
    ext_run: polkavm::ProgramCounter,
    ext_set_size: Option<polkavm::ProgramCounter>,
    instance: polkavm::Instance<()>,
}

impl Backend for PolkaVM {
    type Engine = polkavm::Engine;
    type Blob = polkavm::ArcBytes;
    type Module = polkavm::Module;
    type Instance = Instance;

    fn name(&self) -> &'static str {
        match (self.0, self.1, self.2, self.3) {
            (polkavm::BackendKind::Compiler, None, false, CostModel::Simple) => "polkavm32_compiler_no_gas",
            (polkavm::BackendKind::Compiler, Some(polkavm::GasMeteringKind::Async), false, CostModel::Simple) => {
                "polkavm32_compiler_async_gas"
            }
            (polkavm::BackendKind::Compiler, Some(polkavm::GasMeteringKind::Sync), false, CostModel::Simple) => {
                "polkavm32_compiler_sync_gas"
            }
            (polkavm::BackendKind::Interpreter, _, false, CostModel::Simple) => "polkavm32_interpreter",
            (polkavm::BackendKind::Compiler, None, true, CostModel::Simple) => "polkavm64_compiler_no_gas",
            (polkavm::BackendKind::Compiler, Some(polkavm::GasMeteringKind::Async), true, CostModel::Simple) => {
                "polkavm64_compiler_async_gas"
            }
            (polkavm::BackendKind::Compiler, Some(polkavm::GasMeteringKind::Sync), true, CostModel::Simple) => {
                "polkavm64_compiler_sync_gas"
            }
            (polkavm::BackendKind::Interpreter, _, true, CostModel::Simple) => "polkavm64_interpreter",
            (polkavm::BackendKind::Compiler, Some(polkavm::GasMeteringKind::Sync), true, CostModel::Full) => {
                "polkavm64_compiler_full_model_sync_gas"
            }
            _ => unreachable!(),
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
        assert_eq!(blob.is_64_bit(), self.2);

        let mut config = polkavm::ModuleConfig::default();
        config.set_gas_metering(self.1);
        let cost_model = match self.3 {
            CostModel::Simple => polkavm::CostModelKind::Simple(polkavm::CostModel::naive_ref()),
            CostModel::Full => polkavm::CostModelKind::Full(polkavm::CacheModel::L2Hit),
        };
        config.set_cost_model(Some(cost_model));
        polkavm::Module::from_blob(engine, &config, blob).unwrap()
    }

    fn spawn(&self, _engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        let linker = polkavm::Linker::<()>::new();
        let instance_pre = linker.instantiate_pre(module).unwrap();
        let instance = instance_pre.instantiate().unwrap();
        let ext_initialize = module.exports().find(|export| export == "initialize").unwrap().program_counter();
        let ext_run = module.exports().find(|export| export == "run").unwrap().program_counter();
        let ext_set_size = module
            .exports()
            .find(|export| export == "benchmark_set_size")
            .map(|export| export.program_counter());
        Instance {
            ext_initialize,
            ext_run,
            ext_set_size,
            instance,
        }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        if self.1.is_some() {
            instance.instance.set_gas(polkavm::Gas::MAX);
        }

        instance.instance.call_typed(&mut (), instance.ext_initialize, ()).unwrap();
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance.instance.call_typed(&mut (), instance.ext_run, ()).unwrap();
    }

    fn set_size(&self, instance: &mut Self::Instance, size: u64) -> bool {
        let Some(ext_set_size) = instance.ext_set_size else { return false };
        instance.instance.call_typed(&mut (), ext_set_size, (size,)).unwrap();
        true
    }

    fn supports_set_size(&self) -> bool {
        true
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
