use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub struct Wasmer();

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub struct WasmerInstance {
    store: wasmer::Store,
    initialize: wasmer::TypedFunction<(), ()>,
    run: wasmer::TypedFunction<(), ()>,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl Backend for Wasmer {
    type Engine = wasmer::Engine;
    type Blob = Vec<u8>;
    type Module = wasmer::Module;
    type Instance = WasmerInstance;

    fn name(&self) -> &'static str {
        "wasmer"
    }

    fn create(&self, _args: CreateArgs) -> Self::Engine {
        let config = Box::new(wasmer::Singlepass::new());
        <wasmer::Engine as wasmer::NativeEngineExt>::new(config, wasmer::Target::default(), wasmer::sys::Features::default())
    }

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        wasmer::Module::new(engine, blob).unwrap()
    }

    fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        let mut store = wasmer::Store::new(engine.clone());
        let import_object = wasmer::imports! {};
        let instance = wasmer::Instance::new(&mut store, module, &import_object).unwrap();
        let initialize: wasmer::TypedFunction<(), ()> = instance.exports.get_function("initialize").unwrap().typed(&store).unwrap();
        let run: wasmer::TypedFunction<(), ()> = instance.exports.get_function("run").unwrap().typed(&store).unwrap();
        WasmerInstance { store, initialize, run }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        instance.initialize.call(&mut instance.store).unwrap();
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance.run.call(&mut instance.store).unwrap();
    }

    fn is_compiled(&self) -> bool {
        true
    }
}
