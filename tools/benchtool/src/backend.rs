use crate::BenchmarkKind;
use std::path::{Path, PathBuf};

pub trait Backend: Copy + Clone {
    type Engine;
    type Blob;
    type Module;
    type Instance;

    fn create(&self) -> Self::Engine;
    fn load(&self, path: &Path) -> Self::Blob;
    fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module;
    fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance;
    fn initialize(&self, instance: &mut Self::Instance);
    fn run(&self, instance: &mut Self::Instance);
    fn pid(&self, _instance: &Self::Instance) -> Option<u32> {
        None
    }
}

#[derive(Copy, Clone, Default)]
pub struct Unimplemented;

impl Backend for Unimplemented {
    type Engine = ();
    type Blob = ();
    type Module = ();
    type Instance = ();

    fn create(&self) -> Self::Engine {
        unimplemented!();
    }

    fn load(&self, _path: &Path) -> Self::Blob {
        unimplemented!();
    }

    fn compile(&self, _engine: &mut Self::Engine, _blob: &Self::Blob) -> Self::Module {
        unimplemented!();
    }

    fn spawn(&self, _engine: &mut Self::Engine, _module: &Self::Module) -> Self::Instance {
        unimplemented!();
    }

    fn initialize(&self, _instance: &mut Self::Instance) {
        unimplemented!();
    }

    fn run(&self, _instance: &mut Self::Instance) {
        unimplemented!();
    }
}

#[derive(Copy, Clone, Default)]
pub struct PolkaVM;

impl Backend for PolkaVM {
    type Engine = polkavm::Engine;
    type Blob = Vec<u8>;
    type Module = polkavm::Module;
    type Instance = (polkavm::TypedFunc<(), (), ()>, polkavm::TypedFunc<(), (), ()>, Option<u32>);

    fn create(&self) -> Self::Engine {
        let config = polkavm::Config::default();
        polkavm::Engine::new(&config).unwrap()
    }

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        let blob = polkavm::ProgramBlob::parse(&**blob).unwrap();
        polkavm::Module::from_blob(engine, &Default::default(), &blob).unwrap()
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
        instance.0.call(&mut (), ()).unwrap();
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance.1.call(&mut (), ()).unwrap();
    }

    fn pid(&self, instance: &Self::Instance) -> Option<u32> {
        instance.2
    }
}

#[cfg(not(all(feature = "wasmtime", not(target_arch = "x86"))))]
pub type Wasmtime = Unimplemented;

#[cfg(all(feature = "wasmtime", not(target_arch = "x86")))]
#[derive(Copy, Clone, Default)]
pub struct Wasmtime;

#[cfg(all(feature = "wasmtime", not(target_arch = "x86")))]
pub struct WasmtimeInstance {
    store: wasmtime::Store<()>,
    initialize: wasmtime::TypedFunc<(), ()>,
    run: wasmtime::TypedFunc<(), ()>,
}

#[cfg(all(feature = "wasmtime", not(target_arch = "x86")))]
impl Backend for Wasmtime {
    type Engine = wasmtime::Engine;
    type Blob = Vec<u8>;
    type Module = wasmtime::Module;
    type Instance = WasmtimeInstance;

    fn create(&self) -> Self::Engine {
        let config = wasmtime::Config::default();
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
}

#[derive(Copy, Clone, Default)]
pub struct Wasmer;
pub struct WasmerInstance {
    store: wasmer::Store,
    initialize: wasmer::TypedFunction<(), ()>,
    run: wasmer::TypedFunction<(), ()>,
}

impl Backend for Wasmer {
    type Engine = wasmer::Engine;
    type Blob = Vec<u8>;
    type Module = wasmer::Module;
    type Instance = WasmerInstance;

    fn create(&self) -> Self::Engine {
        let config = Box::new(wasmer::Singlepass::new());
        <wasmer::Engine as wasmer::NativeEngineExt>::new(config, wasmer::Target::default(), wasmer::Features::default())
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
}

#[derive(Copy, Clone, Default)]
pub struct Native;
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

    fn create(&self) -> Self::Engine {}

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

struct WaZeroSo(libloading::Library);
struct WaZeroInterface<'a> {
    engine_new: libloading::Symbol<'a, unsafe extern "C" fn() -> u64>,
    engine_drop: libloading::Symbol<'a, unsafe extern "C" fn(u64)>,
    module_new: libloading::Symbol<'a, unsafe extern "C" fn(u64, *const u8, core::ffi::c_int) -> u64>,
    module_drop: libloading::Symbol<'a, unsafe extern "C" fn(u64)>,
    instance_new: libloading::Symbol<'a, unsafe extern "C" fn(u64, u64) -> u64>,
    instance_initialize: libloading::Symbol<'a, unsafe extern "C" fn(u64)>,
    instance_run: libloading::Symbol<'a, unsafe extern "C" fn(u64)>,
    instance_drop: libloading::Symbol<'a, unsafe extern "C" fn(u64)>,
}

impl WaZeroSo {
    fn new() -> Option<Self> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("wazero/libwazero.so");
        unsafe {
            let library = libloading::Library::new(path).ok()?;
            Some(WaZeroSo(library))
        }
    }

    fn get(&'_ self) -> WaZeroInterface<'_> {
        unsafe {
            let engine_new = self.0.get(b"Engine_new").unwrap();
            let engine_drop = self.0.get(b"Engine_drop").unwrap();
            let module_new = self.0.get(b"Module_new").unwrap();
            let module_drop = self.0.get(b"Module_drop").unwrap();
            let instance_new = self.0.get(b"Instance_new").unwrap();
            let instance_initialize = self.0.get(b"Instance_initialize").unwrap();
            let instance_run = self.0.get(b"Instance_run").unwrap();
            let instance_drop = self.0.get(b"Instance_drop").unwrap();
            WaZeroInterface {
                engine_new,
                engine_drop,
                module_new,
                module_drop,
                instance_new,
                instance_initialize,
                instance_run,
                instance_drop,
            }
        }
    }
}

struct WaZeroInterfaceStatic {
    initialized: bool,
    interface: Option<WaZeroInterface<'static>>,
}

static mut WA_ZERO_SO: Option<WaZeroSo> = None;
static mut WA_ZERO_INTERFACE: WaZeroInterfaceStatic = WaZeroInterfaceStatic {
    initialized: false,
    interface: None,
};

static mut WA_ZERO_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

#[cold]
fn get_wazero_slow() -> Option<&'static WaZeroInterface<'static>> {
    unsafe {
        let _lock = WA_ZERO_LOCK.write().unwrap();
        if WA_ZERO_INTERFACE.initialized {
            return WA_ZERO_INTERFACE.interface.as_ref();
        }

        WA_ZERO_INTERFACE.initialized = true;
        WA_ZERO_SO = Some(WaZeroSo::new()?);
        WA_ZERO_INTERFACE.interface = Some(WA_ZERO_SO.as_ref().unwrap().get());
        WA_ZERO_INTERFACE.interface.as_ref()
    }
}

fn get_wazero() -> Option<&'static WaZeroInterface<'static>> {
    unsafe {
        let _lock = WA_ZERO_LOCK.read().unwrap();
        if WA_ZERO_INTERFACE.initialized {
            return WA_ZERO_INTERFACE.interface.as_ref();
        }

        core::mem::drop(_lock);
        get_wazero_slow()
    }
}

#[derive(Copy, Clone, Default)]
pub struct WaZero;
pub struct WaZeroEngine(u64);
pub struct WaZeroModule(u64);
pub struct WaZeroInstance(u64);

impl Drop for WaZeroEngine {
    fn drop(&mut self) {
        unsafe {
            (get_wazero().unwrap().engine_drop)(self.0);
        }
    }
}

impl Drop for WaZeroModule {
    fn drop(&mut self) {
        unsafe {
            (get_wazero().unwrap().module_drop)(self.0);
        }
    }
}

impl Drop for WaZeroInstance {
    fn drop(&mut self) {
        unsafe {
            (get_wazero().unwrap().instance_drop)(self.0);
        }
    }
}

impl Backend for WaZero {
    type Engine = WaZeroEngine;
    type Blob = Vec<u8>;
    type Module = WaZeroModule;
    type Instance = WaZeroInstance;

    fn create(&self) -> Self::Engine {
        unsafe { WaZeroEngine((get_wazero().unwrap().engine_new)()) }
    }

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        unsafe { WaZeroModule((get_wazero().unwrap().module_new)(engine.0, blob.as_ptr().cast(), blob.len() as _)) }
    }

    fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        unsafe { WaZeroInstance((get_wazero().unwrap().instance_new)(engine.0, module.0)) }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        unsafe { (get_wazero().unwrap().instance_initialize)(instance.0) }
    }

    fn run(&self, instance: &mut Self::Instance) {
        unsafe { (get_wazero().unwrap().instance_run)(instance.0) }
    }
}

#[derive(Copy, Clone, Default)]
pub struct PvfExecutor;

impl Backend for PvfExecutor {
    type Engine = ();
    type Blob = Vec<u8>;
    type Module = pvf_executor::PreparedPvf;
    type Instance = pvf_executor::PvfInstance;

    fn create(&self) -> Self::Engine {}

    fn load(&self, path: &Path) -> Self::Blob {
        std::fs::read(path).unwrap()
    }

    fn compile(&self, _engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        let blob = pvf_executor::RawPvf::from_bytes(blob);
        let mut ir = blob.translate().unwrap();
        ir.optimize();

        let mut codegen = pvf_executor::IntelX64Compiler::new();
        ir.compile(&mut codegen)
    }

    fn spawn(&self, _engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        pvf_executor::PvfInstance::instantiate(module, None)
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        unsafe { instance.call::<_, _, ()>("initialize", ()) }.unwrap();
    }

    fn run(&self, instance: &mut Self::Instance) {
        unsafe { instance.call::<_, _, ()>("run", ()) }.unwrap();
    }
}

macro_rules! define_backends {
    ($($backend:ident => $name:expr),+) => {
        #[derive(Copy, Clone)]
        pub enum BackendKind {
            $($backend),+
        }

        pub enum AnyEngine {
            $($backend(<$backend as Backend>::Engine)),+
        }

        pub enum AnyBlob {
            $($backend(<$backend as Backend>::Blob)),+
        }

        #[allow(clippy::large_enum_variant)]
        pub enum AnyModule {
            $($backend(<$backend as Backend>::Module)),+
        }

        pub enum AnyInstance {
            $($backend(<$backend as Backend>::Instance)),+
        }

        impl BackendKind {
            pub fn name(self) -> &'static str {
                match self {
                    $(
                        BackendKind::$backend => $name,
                    )+
                }
            }
        }

        impl Backend for BackendKind {
            type Engine = AnyEngine;
            type Blob = AnyBlob;
            type Module = AnyModule;
            type Instance = AnyInstance;

            fn create(&self) -> Self::Engine {
                match self {
                    $(
                        Self::$backend => AnyEngine::$backend($backend::default().create()),
                    )+
                }
            }

            fn load(&self, path: &Path) -> Self::Blob {
                match self {
                    $(
                        Self::$backend => AnyBlob::$backend($backend::default().load(path)),
                    )+
                }
            }

            fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
                match self {
                    $(
                        Self::$backend => {
                            let AnyEngine::$backend(engine) = engine else { unreachable!() };
                            let AnyBlob::$backend(blob) = blob else { unreachable!() };
                            AnyModule::$backend($backend::default().compile(engine, blob))
                        },
                    )+
                }
            }

            fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
                match self {
                    $(
                        Self::$backend => {
                            let AnyEngine::$backend(engine) = engine else { unreachable!() };
                            let AnyModule::$backend(module) = module else { unreachable!() };
                            AnyInstance::$backend($backend::default().spawn(engine, module))
                        },
                    )+
                }
            }

            fn initialize(&self, instance: &mut Self::Instance) {
                match self {
                    $(
                        Self::$backend => {
                            let AnyInstance::$backend(instance) = instance else { unreachable!() };
                            $backend::default().initialize(instance)
                        },
                    )+
                }
            }

            fn run(&self, instance: &mut Self::Instance) {
                match self {
                    $(
                        Self::$backend => {
                            let AnyInstance::$backend(instance) = instance else { unreachable!() };
                            $backend::default().run(instance)
                        },
                    )+
                }
            }

            fn pid(&self, instance: &Self::Instance) -> Option<u32> {
                match self {
                    $(
                        Self::$backend => {
                            let AnyInstance::$backend(instance) = instance else { unreachable!() };
                            $backend::default().pid(instance)
                        },
                    )+
                }
            }
        }
    };
}

define_backends! {
    PolkaVM => "polkavm",
    Wasmtime => "wasmtime",
    Wasmer => "wasmer",
    WaZero => "wazero",
    PvfExecutor => "pvfexecutor",
    Native => "native"
}

impl BenchmarkKind {
    pub fn matching_backends(self) -> Vec<BackendKind> {
        match self {
            BenchmarkKind::PolkaVM => vec![BackendKind::PolkaVM],
            BenchmarkKind::WebAssembly => {
                let mut output = vec![BackendKind::Wasmer];

                if get_wazero().is_some() {
                    output.push(BackendKind::WaZero);
                }

                #[cfg(not(target_arch = "x86"))]
                {
                    #[cfg(feature = "wasmtime")]
                    output.push(BackendKind::Wasmtime);
                    output.push(BackendKind::PvfExecutor);
                }

                output
            }
            BenchmarkKind::Native => vec![BackendKind::Native],
        }
    }
}
