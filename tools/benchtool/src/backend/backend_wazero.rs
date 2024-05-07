use super::backend_prelude::*;

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

pub fn is_available() -> bool {
    get_wazero().is_some()
}

#[derive(Copy, Clone)]
pub struct WaZero();
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

    fn name(&self) -> &'static str {
        "wazero"
    }

    fn create(&self, _args: CreateArgs) -> Self::Engine {
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

    fn is_compiled(&self) -> bool {
        true
    }
}
