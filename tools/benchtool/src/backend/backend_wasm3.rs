use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub struct Wasm3();

pub struct Wasm3Instance {
    initialize: wasm3::Function<'static, (), ()>,
    run: wasm3::Function<'static, (), ()>,
    _runtime: wasm3::Runtime,
}

impl Backend for Wasm3 {
    type Engine = wasm3::Environment;
    type Blob = Vec<u8>;
    type Module = Vec<u8>;
    type Instance = Wasm3Instance;

    fn name(&self) -> &'static str {
        "wasm3"
    }

    fn create(&self, _args: CreateArgs) -> Self::Engine {
        wasm3::Environment::new().unwrap()
    }

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, _engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        blob.clone()
    }

    fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        let runtime = engine.create_runtime(4096).unwrap();
        let module = wasm3::Module::parse(engine, &**module).unwrap();
        runtime.load_module(module).unwrap();

        let initialize: wasm3::Function<(), ()> = runtime.find_function::<(), ()>("initialize").unwrap();
        let run: wasm3::Function<(), ()> = runtime.find_function::<(), ()>("run").unwrap();
        Wasm3Instance {
            initialize: unsafe { core::mem::transmute(initialize) },
            run: unsafe { core::mem::transmute(run) },
            _runtime: runtime,
        }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        instance.initialize.call().unwrap();
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance.run.call().unwrap();
    }
}
