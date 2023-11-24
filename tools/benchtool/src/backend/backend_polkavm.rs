use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub struct PolkaVM(pub Option<polkavm::GasMeteringKind>);

#[cfg(target_arch = "x86_64")]
impl Backend for PolkaVM {
    type Engine = polkavm::Engine;
    type Blob = Vec<u8>;
    type Module = polkavm::Module;
    type Instance = (polkavm::TypedFunc<(), (), ()>, polkavm::TypedFunc<(), (), ()>, Option<u32>);

    fn name(&self) -> &'static str {
        match self.0 {
            None => "polkavm_no_gas",
            Some(polkavm::GasMeteringKind::Async) => "polkavm_async_gas",
            Some(polkavm::GasMeteringKind::Sync) => "polkavm_sync_gas",
        }
    }

    fn create(&self) -> Self::Engine {
        let config = polkavm::Config::default();
        polkavm::Engine::new(&config).unwrap()
    }

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        let blob = polkavm::ProgramBlob::parse(&**blob).unwrap();
        let mut config = polkavm::ModuleConfig::default();
        config.set_gas_metering(self.0);
        polkavm::Module::from_blob(engine, &config, &blob).unwrap()
    }

    fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        let linker = polkavm::Linker::<()>::new(engine);
        let instance_pre = linker.instantiate_pre(module).unwrap();
        let instance = instance_pre.instantiate().unwrap();
        let ext_initialize = instance.get_typed_func::<(), ()>("initialize").unwrap();
        let ext_run = instance.get_typed_func::<(), ()>("run").unwrap();
        (ext_initialize, ext_run, instance.pid())
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        let mut config = polkavm::ExecutionConfig::default();
        if self.0.is_some() {
            config.set_gas(polkavm::Gas::MAX);
        }

        instance.0.call_ex(&mut (), (), config).unwrap();
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance.1.call(&mut (), ()).unwrap();
    }

    fn pid(&self, instance: &Self::Instance) -> Option<u32> {
        instance.2
    }

    fn is_compiled(&self) -> bool {
        true
    }
}
