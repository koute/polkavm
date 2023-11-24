use crate::BenchmarkKind;
use std::path::Path;

mod backend_prelude {
    pub use super::Backend;
    pub use std::path::{Path, PathBuf};
}

pub trait Backend: Copy + Clone {
    type Engine;
    type Blob;
    type Module;
    type Instance;

    fn name(&self) -> &'static str;
    fn create(&self) -> Self::Engine;
    fn load(&self, path: &Path) -> Self::Blob;
    fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module;
    fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance;
    fn initialize(&self, instance: &mut Self::Instance);
    fn run(&self, instance: &mut Self::Instance);
    fn pid(&self, _instance: &Self::Instance) -> Option<u32> {
        None
    }

    fn is_slow(&self) -> bool {
        false
    }

    fn is_compiled(&self) -> bool {
        false
    }
}

#[cfg(target_arch = "x86_64")]
mod backend_polkavm;

#[cfg(target_arch = "x86_64")]
mod backend_pvfexecutor;

#[cfg(all(feature = "ckb-vm", target_arch = "x86_64"))]
mod backend_ckbvm;

#[cfg(target_arch = "x86_64")]
mod backend_wasm3;

#[cfg(all(feature = "wasmtime", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod backend_wasmtime;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod backend_wasmer;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod backend_wazero;

mod backend_native;
mod backend_wasmi;

macro_rules! define_backends {
    ($(
        #[cfg($($cfg:tt)*)]
        $backend:ident => $module:ident::$struct:ident($($ctor_args:tt)*)
    ),+) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone)]
        pub enum BackendKind {
            $(
                #[cfg($($cfg)*)]
                $backend
            ),+
        }

        #[allow(non_camel_case_types)]
        pub enum AnyEngine {
            $(
                #[cfg($($cfg)*)]
                $backend(<self::$module::$struct as Backend>::Engine)
            ),+
        }

        #[allow(non_camel_case_types)]
        pub enum AnyBlob {
            $(
                #[cfg($($cfg)*)]
                $backend(<self::$module::$struct as Backend>::Blob)
            ),+
        }

        #[allow(non_camel_case_types)]
        #[allow(clippy::large_enum_variant)]
        pub enum AnyModule {
            $(
                #[cfg($($cfg)*)]
                $backend(<self::$module::$struct as Backend>::Module)
            ),+
        }

        #[allow(non_camel_case_types)]
        pub enum AnyInstance {
            $(
                #[cfg($($cfg)*)]
                $backend(<self::$module::$struct as Backend>::Instance)
            ),+
        }

        impl Backend for BackendKind {
            type Engine = AnyEngine;
            type Blob = AnyBlob;
            type Module = AnyModule;
            type Instance = AnyInstance;

            fn name(&self) -> &'static str {
                match self {
                    $(
                        #[cfg($($cfg)*)]
                        Self::$backend => self::$module::$struct($($ctor_args)*).name(),
                    )+
                }
            }

            fn create(&self) -> Self::Engine {
                match self {
                    $(
                        #[cfg($($cfg)*)]
                        Self::$backend => AnyEngine::$backend(self::$module::$struct($($ctor_args)*).create()),
                    )+
                }
            }

            fn load(&self, path: &Path) -> Self::Blob {
                match self {
                    $(
                        #[cfg($($cfg)*)]
                        Self::$backend => AnyBlob::$backend(self::$module::$struct($($ctor_args)*).load(path)),
                    )+
                }
            }

            fn compile(&self, engine: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
                match self {
                    $(
                        #[cfg($($cfg)*)]
                        Self::$backend => {
                            let AnyEngine::$backend(engine) = engine else { unreachable!() };
                            let AnyBlob::$backend(blob) = blob else { unreachable!() };
                            AnyModule::$backend(self::$module::$struct($($ctor_args)*).compile(engine, blob))
                        },
                    )+
                }
            }

            fn spawn(&self, engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
                match self {
                    $(
                        #[cfg($($cfg)*)]
                        Self::$backend => {
                            let AnyEngine::$backend(engine) = engine else { unreachable!() };
                            let AnyModule::$backend(module) = module else { unreachable!() };
                            AnyInstance::$backend(self::$module::$struct($($ctor_args)*).spawn(engine, module))
                        },
                    )+
                }
            }

            fn initialize(&self, instance: &mut Self::Instance) {
                match self {
                    $(
                        #[cfg($($cfg)*)]
                        Self::$backend => {
                            let AnyInstance::$backend(instance) = instance else { unreachable!() };
                            self::$module::$struct($($ctor_args)*).initialize(instance)
                        },
                    )+
                }
            }

            fn run(&self, instance: &mut Self::Instance) {
                match self {
                    $(
                        #[cfg($($cfg)*)]
                        Self::$backend => {
                            let AnyInstance::$backend(instance) = instance else { unreachable!() };
                            self::$module::$struct($($ctor_args)*).run(instance)
                        },
                    )+
                }
            }

            fn pid(&self, instance: &Self::Instance) -> Option<u32> {
                match self {
                    $(
                        #[cfg($($cfg)*)]
                        Self::$backend => {
                            let AnyInstance::$backend(instance) = instance else { unreachable!() };
                            self::$module::$struct($($ctor_args)*).pid(instance)
                        },
                    )+
                }
            }

            fn is_slow(&self) -> bool {
                match self {
                    $(
                        #[cfg($($cfg)*)]
                        Self::$backend => self::$module::$struct($($ctor_args)*).is_slow(),
                    )+
                }
            }

            fn is_compiled(&self) -> bool {
                match self {
                    $(
                        #[cfg($($cfg)*)]
                        Self::$backend => self::$module::$struct($($ctor_args)*).is_compiled(),
                    )+
                }
            }
        }
    };
}

define_backends! {
    #[cfg(target_arch = "x86_64")]
    PolkaVM_NoGas => backend_polkavm::PolkaVM(None),
    #[cfg(target_arch = "x86_64")]
    PolkaVM_AsyncGas => backend_polkavm::PolkaVM(Some(polkavm::GasMeteringKind::Async)),
    #[cfg(target_arch = "x86_64")]
    PolkaVM_SyncGas => backend_polkavm::PolkaVM(Some(polkavm::GasMeteringKind::Sync)),

    #[cfg(all(feature = "wasmtime", any(target_arch = "x86_64", target_arch = "aarch64")))]
    Wasmtime_Cranelift =>
        backend_wasmtime::Wasmtime(wasmtime::Strategy::Cranelift, backend_wasmtime::Metering::None),

    #[cfg(all(feature = "wasmtime", any(target_arch = "x86_64", target_arch = "aarch64")))]
    Wasmtime_CraneliftConsumeFuel =>
        backend_wasmtime::Wasmtime(wasmtime::Strategy::Cranelift, backend_wasmtime::Metering::ConsumeFuel),

    #[cfg(all(feature = "wasmtime", any(target_arch = "x86_64", target_arch = "aarch64")))]
    Wasmtime_CraneliftEpochInterruption =>
        backend_wasmtime::Wasmtime(wasmtime::Strategy::Cranelift, backend_wasmtime::Metering::EpochInterruption),

    #[cfg(all(feature = "wasmtime", any(target_arch = "x86_64", target_arch = "aarch64")))]
    Wasmtime_Winch =>
        backend_wasmtime::Wasmtime(wasmtime::Strategy::Winch, backend_wasmtime::Metering::None),

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    Wasmer => backend_wasmer::Wasmer(),

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    WaZero => backend_wazero::WaZero(),

    #[cfg(target_arch = "x86_64")]
    PvfExecutor => backend_pvfexecutor::PvfExecutor(),

    #[cfg(all(feature = "ckb-vm", target_arch = "x86_64"))]
    Ckbvm_Asm => backend_ckbvm::Ckbvm(backend_ckbvm::CkbvmBackend::Asm),

    #[cfg(all(feature = "ckb-vm", target_arch = "x86_64"))]
    Ckbvm_NonAsm => backend_ckbvm::Ckbvm(backend_ckbvm::CkbvmBackend::NonAsm),

    #[cfg(target_arch = "x86_64")]
    Wasm3 => backend_wasm3::Wasm3(),

    #[cfg(not(_dummy))]
    Wasmi_StackMachine => backend_wasmi::Wasmi(wasmi::EngineBackend::StackMachine),
    #[cfg(not(_dummy))]
    Wasmi_RegisterMachine => backend_wasmi::Wasmi(wasmi::EngineBackend::RegisterMachine),

    #[cfg(not(_dummy))]
    Native => backend_native::Native()
}

impl BenchmarkKind {
    pub fn matching_backends(self) -> Vec<BackendKind> {
        let mut output = Vec::new();
        match self {
            BenchmarkKind::PolkaVM => {
                #[cfg(target_arch = "x86_64")]
                {
                    output.extend([
                        BackendKind::PolkaVM_NoGas,
                        BackendKind::PolkaVM_AsyncGas,
                        BackendKind::PolkaVM_SyncGas,
                    ]);
                }
            }
            BenchmarkKind::WebAssembly => {
                output.push(BackendKind::Wasmi_StackMachine);
                output.push(BackendKind::Wasmi_RegisterMachine);

                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                {
                    #[cfg(feature = "wasmtime")]
                    {
                        output.extend([
                            BackendKind::Wasmtime_Cranelift,
                            BackendKind::Wasmtime_CraneliftConsumeFuel,
                            BackendKind::Wasmtime_CraneliftEpochInterruption,
                            // TODO: Enable once it doesn't crash with a 'not yet implemented' error.
                            // BackendKind::Wasmtime_Winch,
                        ]);
                    }

                    output.push(BackendKind::Wasmer);

                    if backend_wazero::is_available() {
                        output.push(BackendKind::WaZero);
                    }
                }

                #[cfg(target_arch = "x86_64")]
                {
                    output.push(BackendKind::PvfExecutor);
                    output.push(BackendKind::Wasm3);
                }
            }
            BenchmarkKind::Ckbvm => {
                #[cfg(all(feature = "ckb-vm", target_arch = "x86_64"))]
                {
                    output.push(BackendKind::Ckbvm_Asm);
                    output.push(BackendKind::Ckbvm_NonAsm);
                }
            }
            BenchmarkKind::Native => {
                output.push(BackendKind::Native);
            }
        }

        output
    }
}
