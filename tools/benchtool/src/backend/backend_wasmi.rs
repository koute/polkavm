use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub struct Wasmi(pub WasmiConfig);

#[derive(Debug, Copy, Clone)]
pub enum WasmiConfig {
    Eager,
    Lazy,
    LazyUnchecked,
    LazyTranslation,
}

impl WasmiConfig {
    fn compilation_mode(&self) -> wasmi::CompilationMode {
        match self {
            Self::Eager => wasmi::CompilationMode::Eager,
            Self::Lazy | Self::LazyUnchecked => wasmi::CompilationMode::Lazy,
            Self::LazyTranslation => wasmi::CompilationMode::LazyTranslation,
        }
    }

    fn validation(&self) -> Validation {
        match self {
            Self::Eager | Self::Lazy | Self::LazyTranslation => Validation::Checked,
            Self::LazyUnchecked => Validation::Unchecked,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Validation {
    Checked,
    Unchecked,
}

pub struct WasmiInstance {
    store: wasmi::Store<()>,
    initialize: wasmi::TypedFunc<(), ()>,
    run: wasmi::TypedFunc<(), ()>,
    set_size: Option<wasmi::TypedFunc<u64, ()>>,
}

impl Backend for Wasmi {
    type Engine = wasmi::Engine;
    type Blob = Vec<u8>;
    type Module = wasmi::Module;
    type Instance = WasmiInstance;

    fn name(&self) -> &'static str {
        use wasmi::CompilationMode;
        match (self.0.compilation_mode(), self.0.validation()) {
            (CompilationMode::Eager, Validation::Checked) => "wasmi_eager_checked",
            (CompilationMode::Eager, Validation::Unchecked) => "wasmi_eager_unchecked",
            (CompilationMode::Lazy, Validation::Checked) => "wasmi_lazy_checked",
            (CompilationMode::Lazy, Validation::Unchecked) => "wasmi_lazy_unchecked",
            (CompilationMode::LazyTranslation, Validation::Checked) => "wasmi_lazy_translation_checked",
            (CompilationMode::LazyTranslation, Validation::Unchecked) => "wasmi_lazy_translation_unchecked",
        }
    }

    fn create(&self, _args: CreateArgs) -> Self::Engine {
        let mut config = wasmi::Config::default();
        config.compilation_mode(self.0.compilation_mode());
        wasmi::Engine::new(&config)
    }

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        match self.0.validation() {
            Validation::Checked => wasmi::Module::new(engine, blob).unwrap(),
            Validation::Unchecked => {
                // SAFETY: All benchmark inputs are known to be valid.
                unsafe { wasmi::Module::new_unchecked(engine, blob).unwrap() }
            }
        }
    }

    fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        let mut store = wasmi::Store::new(engine, ());
        let linker = wasmi::Linker::new(engine);
        let instance = linker.instantiate(&mut store, module).unwrap();
        let instance = instance.ensure_no_start(&mut store).unwrap();
        let initialize = instance.get_typed_func::<(), ()>(&mut store, "initialize").unwrap();
        let run = instance.get_typed_func::<(), ()>(&mut store, "run").unwrap();
        let set_size = instance.get_typed_func::<u64, ()>(&mut store, "benchmark_set_size").ok();
        WasmiInstance {
            store,
            initialize,
            run,
            set_size,
        }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        instance.initialize.call(&mut instance.store, ()).unwrap();
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance.run.call(&mut instance.store, ()).unwrap();
    }

    fn set_size(&self, instance: &mut Self::Instance, size: u64) -> bool {
        let Some(ref set_size) = instance.set_size else { return false };
        set_size.call(&mut instance.store, size).unwrap();
        true
    }

    fn supports_set_size(&self) -> bool {
        true
    }

    fn is_compiled(&self) -> bool {
        true
    }
}
