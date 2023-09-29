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

#[cfg(all(target_arch = "x86_64", target_os = "linux", not(miri)))]
mod compiler;

#[cfg(not(all(target_arch = "x86_64", target_os = "linux", not(miri))))]
mod compiler_dummy;

#[cfg(not(all(target_arch = "x86_64", target_os = "linux", not(miri))))]
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
    use crate::{Caller, CallerRef, Config, Engine, ExecutionError, Linker, Module, ProgramBlob, Reg, Trap, Val};
    use std::cell::RefCell;
    use std::rc::Rc;

    // TODO: Add a dedicated test blob.
    const RAW_BLOB: &[u8] = include_bytes!("../../../examples/hosts/hello-world/src/guest.polkavm");

    #[test]
    fn caller_and_caller_ref_work() {
        let _ = env_logger::try_init();
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

    #[test]
    fn trapping_from_hostcall_handler_works() {
        let _ = env_logger::try_init();
        let blob = ProgramBlob::parse(RAW_BLOB).unwrap();
        let config = Config::default();
        let engine = Engine::new(&config).unwrap();
        let module = Module::from_blob(&engine, &blob).unwrap();
        let mut linker = Linker::new(&engine);

        enum Kind {
            Ok,
            Trap,
        }

        linker
            .func_wrap("get_third_number", move |caller: Caller<Kind>| -> Result<u32, Trap> {
                match *caller.data() {
                    Kind::Ok => Ok(100),
                    Kind::Trap => Err(Trap::default()),
                }
            })
            .unwrap();

        let instance_pre = linker.instantiate_pre(&module).unwrap();
        let instance = instance_pre.instantiate().unwrap();

        let result = instance
            .get_typed_func::<(u32, u32), u32>("add_numbers")
            .unwrap()
            .call(&mut Kind::Ok, (1, 10));
        assert!(matches!(result, Ok(111)));

        let result = instance
            .get_typed_func::<(u32, u32), u32>("add_numbers")
            .unwrap()
            .call(&mut Kind::Trap, (1, 10));
        assert!(matches!(result, Err(ExecutionError::Trap(..))));

        let result = instance
            .get_func("add_numbers")
            .unwrap()
            .call(&mut Kind::Ok, &[Val::from(1), Val::from(10)]);
        assert!(matches!(result, Ok(Some(Val::I32(111)))));

        let result = instance
            .get_func("add_numbers")
            .unwrap()
            .call(&mut Kind::Trap, &[Val::from(1), Val::from(10)]);
        assert!(matches!(result, Err(ExecutionError::Trap(..))));
    }
}
