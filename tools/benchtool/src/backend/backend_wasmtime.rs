use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub enum Metering {
    None,
    ConsumeFuel,
    EpochInterruption,
}

#[cfg(all(feature = "wasmtime", any(target_arch = "x86_64", target_arch = "aarch64")))]
#[derive(Copy, Clone)]
pub struct Wasmtime(pub wasmtime::Strategy, pub Metering);

#[cfg(all(feature = "wasmtime", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub struct WasmtimeInstance {
    store: wasmtime::Store<()>,
    initialize: wasmtime::TypedFunc<(), ()>,
    run: wasmtime::TypedFunc<(), ()>,
}

#[cfg(all(feature = "wasmtime", any(target_arch = "x86_64", target_arch = "aarch64")))]
impl Backend for Wasmtime {
    type Engine = wasmtime::Engine;
    type Blob = Vec<u8>;
    type Module = wasmtime::Module;
    type Instance = WasmtimeInstance;

    fn name(&self) -> &'static str {
        match (self.0, self.1) {
            (wasmtime::Strategy::Cranelift, Metering::None) => "wasmtime_cranelift_default",
            (wasmtime::Strategy::Cranelift, Metering::ConsumeFuel) => "wasmtime_cranelift_with_fuel",
            (wasmtime::Strategy::Cranelift, Metering::EpochInterruption) => "wasmtime_cranelift_with_epoch",
            (wasmtime::Strategy::Winch, Metering::None) => "wasmtime_winch",
            _ => unimplemented!(),
        }
    }

    fn create(&self, _args: CreateArgs) -> Self::Engine {
        let mut config = wasmtime::Config::default();
        config.strategy(self.0);
        match self.1 {
            Metering::None => {}
            Metering::ConsumeFuel => {
                config.consume_fuel(true);
            }
            Metering::EpochInterruption => {
                config.epoch_interruption(true);
            }
        }
        wasmtime::Engine::new(&config).unwrap()
    }

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        wasmtime::Module::new(engine, blob).unwrap()
    }

    fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        let mut store = wasmtime::Store::new(engine, ());
        match self.1 {
            Metering::None => {}
            Metering::ConsumeFuel => {
                store.set_fuel(u64::MAX).unwrap();
            }
            Metering::EpochInterruption => {
                store.set_epoch_deadline(u64::MAX);
            }
        }

        let instance = wasmtime::Instance::new(&mut store, module, &[]).unwrap();
        let initialize = instance.get_typed_func::<(), ()>(&mut store, "initialize").unwrap();
        let run = instance.get_typed_func::<(), ()>(&mut store, "run").unwrap();
        WasmtimeInstance { store, initialize, run }
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
