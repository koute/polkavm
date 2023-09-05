#![forbid(unused_must_use)]
#![forbid(clippy::missing_safety_doc)]
#![forbid(clippy::undocumented_unsafe_blocks)]

mod error;

mod api;
mod caller;
mod config;
mod interpreter;
mod source_cache;
mod tracer;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod compiler;

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
mod compiler_dummy;

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
use compiler_dummy as compiler;

pub use polkavm_common::{
    error::{ExecutionError, Trap},
    program::{ProgramBlob, Reg},
    utils::AsUninitSliceMut,
};

pub use crate::api::{Engine, Func, FuncType, Instance, InstancePre, IntoExternFn, Linker, Module, TypedFunc, Val, ValType};
pub use crate::caller::{Caller, CallerRef};
pub use crate::config::Config;
pub use crate::error::Error;

#[cfg(test)]
mod tests {
    use crate::{Caller, CallerRef, Config, Engine, Linker, Module, ProgramBlob, Reg, Trap};
    use std::cell::RefCell;
    use std::rc::Rc;

    // TODO: Add a dedicated test blob.
    const RAW_BLOB: &[u8] = include_bytes!("../../../examples/hosts/hello-world/src/guest.polkavm");

    #[test]
    fn caller_and_caller_ref_work() {
        let blob = ProgramBlob::parse(RAW_BLOB).unwrap();
        let config = Config::default();
        let engine = Engine::new(&config).unwrap();
        let module = Module::from_blob(&engine, &blob).unwrap();
        let mut linker = Linker::new(&engine);

        #[derive(Default)]
        struct State {
            illegal_contraband: Rc<RefCell<Option<CallerRef<State>>>>,
        }

        linker
            .func_wrap("get_third_number", move |caller: Caller<State>| -> Result<u32, Trap> {
                {
                    let value = caller.read_u32(polkavm_common::abi::VM_ADDR_USER_STACK_HIGH - 4)?;
                    assert_eq!(value, polkavm_common::abi::VM_ADDR_RETURN_TO_HOST);
                }
                {
                    let caller = caller.into_ref();
                    let value = caller.read_u32(polkavm_common::abi::VM_ADDR_USER_STACK_HIGH - 4)?;
                    assert_eq!(value, polkavm_common::abi::VM_ADDR_RETURN_TO_HOST);

                    let illegal_contraband = caller.data().illegal_contraband.clone();
                    *illegal_contraband.borrow_mut() = Some(caller);
                }

                Ok(100)
            })
            .unwrap();

        let instance_pre = linker.instantiate_pre(&module).unwrap();
        let instance = instance_pre.instantiate().unwrap();
        let mut state = State::default();
        let result = instance
            .get_typed_func::<(u32, u32), u32>("add_numbers")
            .unwrap()
            .call(&mut state, (1, 10))
            .unwrap();

        assert_eq!(result, 111);

        let caller = state.illegal_contraband.borrow_mut().take().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| caller.get_reg(Reg::A0)));
        assert!(result.is_err());
    }
}
