use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub struct Native();
pub struct NativeInstance {
    initialize: libloading::Symbol<'static, unsafe extern "C" fn()>,
    run: libloading::Symbol<'static, unsafe extern "C" fn()>,
    set_size: Option<libloading::Symbol<'static, unsafe extern "C" fn(u64)>>,
    _library: libloading::Library,
}

impl Backend for Native {
    type Engine = ();
    type Blob = PathBuf;
    type Module = PathBuf;
    type Instance = NativeInstance;

    fn name(&self) -> &'static str {
        "native"
    }

    fn create(&self, _args: CreateArgs) -> Self::Engine {}

    fn load(&self, path: &Path) -> Self::Blob {
        path.to_owned()
    }

    fn compile(&self, _engine: &mut Self::Engine, path: &Self::Blob) -> Self::Module {
        path.clone()
    }

    fn spawn(&self, _engine: &mut Self::Engine, path: &Self::Module) -> Self::Instance {
        unsafe {
            let library = libloading::Library::new(path).unwrap();
            let initialize: libloading::Symbol<unsafe extern "C" fn()> = library.get(b"initialize").unwrap();
            let initialize: libloading::Symbol<unsafe extern "C" fn()> = core::mem::transmute(initialize);
            let run: libloading::Symbol<unsafe extern "C" fn()> = library.get(b"run").unwrap();
            let run: libloading::Symbol<unsafe extern "C" fn()> = core::mem::transmute(run);
            let set_size: Option<libloading::Symbol<unsafe extern "C" fn(u64)>> = library.get(b"benchmark_set_size").ok();
            let set_size: Option<libloading::Symbol<'static, unsafe extern "C" fn(u64)>> = core::mem::transmute(set_size);
            NativeInstance {
                initialize,
                run,
                set_size,
                _library: library,
            }
        }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        unsafe {
            (instance.initialize)();
        }
    }

    fn run(&self, instance: &mut Self::Instance) {
        unsafe {
            (instance.run)();
        }
    }

    fn set_size(&self, instance: &mut Self::Instance, size: u64) -> bool {
        let Some(ref set_size) = instance.set_size else { return false };
        unsafe {
            set_size(size);
        }
        true
    }

    fn supports_set_size(&self) -> bool {
        true
    }
}
