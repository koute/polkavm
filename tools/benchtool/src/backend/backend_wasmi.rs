use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub struct Wasmi(pub wasmi::EngineBackend);

pub struct WasmiInstance {
    store: wasmi::Store<()>,
    initialize: wasmi::TypedFunc<(), ()>,
    run: wasmi::TypedFunc<(), ()>,
}

impl Backend for Wasmi {
    type Engine = wasmi::Engine;
    type Blob = Vec<u8>;
    type Module = wasmi::Module;
    type Instance = WasmiInstance;

    fn name(&self) -> &'static str {
        match self.0 {
            wasmi::EngineBackend::StackMachine => "wasmi_stack",
            wasmi::EngineBackend::RegisterMachine => "wasmi_register",
        }
    }

    fn create(&self) -> Self::Engine {
        let mut config = wasmi::Config::default();
        config.set_engine_backend(self.0);
        wasmi::Engine::new(&config)
    }

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        wasmi::Module::new(engine, &**blob).unwrap()
    }

    fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        let mut store = wasmi::Store::new(engine, ());
        let linker = wasmi::Linker::new(engine);
        let instance = linker.instantiate(&mut store, module).unwrap();
        let instance = instance.ensure_no_start(&mut store).unwrap();
        let initialize = instance.get_typed_func::<(), ()>(&mut store, "initialize").unwrap();
        let run = instance.get_typed_func::<(), ()>(&mut store, "run").unwrap();
        WasmiInstance { store, initialize, run }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        instance.initialize.call(&mut instance.store, ()).unwrap();
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance.run.call(&mut instance.store, ()).unwrap();
    }

    fn is_compiled(&self) -> bool {
        true
    }
}
