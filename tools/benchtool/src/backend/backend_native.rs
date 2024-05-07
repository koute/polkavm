use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub struct Native();
pub struct NativeInstance {
    initialize: libloading::Symbol<'static, unsafe extern "C" fn()>,
    run: libloading::Symbol<'static, unsafe extern "C" fn()>,
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
            NativeInstance {
                initialize,
                run,
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
}
