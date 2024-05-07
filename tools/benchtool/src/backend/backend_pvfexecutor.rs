use super::backend_prelude::*;

#[derive(Copy, Clone)]
pub struct PvfExecutor();

impl Backend for PvfExecutor {
    type Engine = ();
    type Blob = Vec<u8>;
    type Module = pvf_executor::PreparedPvf;
    type Instance = pvf_executor::PvfInstance;

    fn name(&self) -> &'static str {
        "pvfexecutor"
    }

    fn create(&self, _args: CreateArgs) -> Self::Engine {}

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

    fn is_compiled(&self) -> bool {
        true
    }
}
