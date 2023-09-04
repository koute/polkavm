use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use polkavm_common::abi::{
    GuestMemoryConfig, VM_MAXIMUM_EXPORT_COUNT, VM_MAXIMUM_EXTERN_ARG_COUNT, VM_MAXIMUM_IMPORT_COUNT, VM_MAXIMUM_INSTRUCTION_COUNT,
    VM_MAXIMUM_JUMP_TARGET,
};
use polkavm_common::error::Trap;
use polkavm_common::init::GuestProgramInit;
use polkavm_common::program::{ExternFnPrototype, ExternTy, ProgramBlob, ProgramExport, ProgramImport};
use polkavm_common::program::{Opcode, RawInstruction, Reg};
use polkavm_common::utils::{Access, AsUninitSliceMut};

use crate::compiler::{CompiledAccess, CompiledInstance, CompiledModule};
use crate::config::{Backend, Config};
use crate::error::{bail, Error, ExecutionError};
use crate::interpreter::{InterpretedAccess, InterpretedInstance, InterpretedModule};
use crate::tracer::Tracer;

struct DisplayFn<'a, Args> {
    name: &'a str,
    args: Args,
    return_ty: Option<ExternTy>,
}

impl<'a, Args> core::fmt::Display for DisplayFn<'a, Args>
where
    Args: Clone + Iterator<Item = ExternTy>,
{
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self.name)?;
        fmt.write_str("(")?;
        for (index, ty) in self.args.clone().enumerate() {
            if index > 0 {
                fmt.write_str(", ")?;
            }
            ty.fmt(fmt)?;
        }
        fmt.write_str(")")?;
        if let Some(return_ty) = self.return_ty {
            fmt.write_str(" -> ")?;
            return_ty.fmt(fmt)?;
        }

        Ok(())
    }
}

pub(crate) type OnHostcall<'a> = &'a mut dyn for<'r> FnMut(u64, BackendAccess<'r>) -> Result<(), Trap>;

pub struct Engine {
    config: Config,
}

impl Engine {
    pub fn new(config: &Config) -> Result<Self, Error> {
        if let Some(backend) = config.backend {
            if !backend.is_supported() {
                bail!("the '{backend}' backend is not supported on this platform")
            }
        }

        #[allow(clippy::collapsible_if)]
        if !config.allow_insecure {
            if config.trace_execution {
                bail!("cannot enable trace execution: `set_allow_insecure`/`POLKAVM_ALLOW_INSECURE` is not enabled");
            }
        }

        Ok(Engine { config: config.clone() })
    }
}

struct ModulePrivate {
    debug_trace_execution: bool,
    exports: Vec<ProgramExport<'static>>,
    imports: BTreeMap<u32, ProgramImport<'static>>,
    export_index_by_name: HashMap<String, usize>,
    instructions: Vec<RawInstruction>,
    jump_target_to_instruction: HashMap<u32, u32>,

    blob: Option<ProgramBlob<'static>>,
    compiled_module: Option<CompiledModule>,
    interpreted_module: Option<InterpretedModule>,
}

/// A compiled PolkaVM program module.
#[derive(Clone)]
pub struct Module(Arc<ModulePrivate>);

impl Module {
    pub(crate) fn is_debug_trace_execution_enabled(&self) -> bool {
        self.0.debug_trace_execution
    }

    pub(crate) fn instructions(&self) -> &[RawInstruction] {
        &self.0.instructions
    }

    pub(crate) fn compiled_module(&self) -> Option<&CompiledModule> {
        self.0.compiled_module.as_ref()
    }

    pub(crate) fn interpreted_module(&self) -> Option<&InterpretedModule> {
        self.0.interpreted_module.as_ref()
    }

    pub(crate) fn blob(&self) -> Option<&ProgramBlob<'static>> {
        self.0.blob.as_ref()
    }

    pub(crate) fn get_export(&self, export_index: usize) -> Option<&ProgramExport> {
        self.0.exports.get(export_index)
    }

    pub(crate) fn instruction_by_jump_target(&self, target: u32) -> Option<u32> {
        self.0.jump_target_to_instruction.get(&target).copied()
    }

    /// Creates a new module by deserializing the program from the given `bytes`.
    pub fn new(engine: &Engine, bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let blob = match ProgramBlob::parse(bytes.as_ref()) {
            Ok(blob) => blob,
            Err(error) => {
                bail!("failed to parse blob: {}", error);
            }
        };

        Self::from_blob(engine, &blob)
    }

    /// Creates a new module from a deserialized program `blob`.
    pub fn from_blob(engine: &Engine, blob: &ProgramBlob) -> Result<Self, Error> {
        log::trace!("Parsing imports...");
        let mut imports = BTreeMap::new();
        for import in blob.imports() {
            let import = import.map_err(Error::from_display)?;
            if imports.insert(import.index(), import).is_some() {
                bail!("duplicate import index");
            }

            if imports.len() > VM_MAXIMUM_IMPORT_COUNT as usize {
                bail!(
                    "too many imports; the program contains more than {} imports",
                    VM_MAXIMUM_IMPORT_COUNT
                );
            }
        }

        log::trace!("Parsing code...");
        let (instructions, jump_target_to_instruction) = {
            let mut jump_target_to_instruction = HashMap::with_capacity(blob.code().len() / 64);
            let mut instructions = Vec::with_capacity(blob.code().len() / 4);
            for (nth_instruction, instruction) in blob.instructions().enumerate() {
                let instruction = instruction.map_err(Error::from_display)?;
                match instruction.op() {
                    Opcode::jump_target => {
                        let target = instruction.raw_imm_or_reg();
                        if target > VM_MAXIMUM_JUMP_TARGET {
                            bail!("program has too big jump target");
                        }

                        if jump_target_to_instruction
                            .insert(instruction.raw_imm_or_reg(), nth_instruction as u32)
                            .is_some()
                        {
                            bail!("duplicate jump target");
                        }
                    }
                    Opcode::ecalli => {
                        let nr = instruction.raw_imm_or_reg();
                        if imports.get(&nr).is_none() {
                            bail!("found an unrecognized ecall number: {nr:}");
                        }
                    }
                    // TODO: Check jump/branch target validity.
                    _ => {}
                }
                instructions.push(instruction);
            }

            if instructions.len() > VM_MAXIMUM_INSTRUCTION_COUNT as usize {
                bail!(
                    "too many instructions; the program contains more than {} instructions",
                    VM_MAXIMUM_INSTRUCTION_COUNT
                );
            }

            (instructions, jump_target_to_instruction)
        };

        log::trace!("Parsing exports...");
        let exports = {
            let mut exports = Vec::with_capacity(1);
            for export in blob.exports() {
                let export = export.map_err(Error::from_display)?;
                if !jump_target_to_instruction.contains_key(&export.address()) {
                    bail!(
                        "address of export '{}' (0x{:x}) doesn't point to a jump target instruction",
                        export.prototype().name(),
                        export.address()
                    );
                }

                exports.push(export);

                if exports.len() > VM_MAXIMUM_EXPORT_COUNT as usize {
                    bail!(
                        "too many exports; the program contains more than {} exports",
                        VM_MAXIMUM_EXPORT_COUNT
                    );
                }
            }
            exports
        };

        log::trace!("Parsing finished!");

        // Do an early check for memory config validity.
        GuestMemoryConfig::new(
            blob.ro_data().len() as u64,
            blob.rw_data().len() as u64,
            blob.bss_size() as u64,
            blob.stack_size() as u64,
        )
        .map_err(Error::from_static_str)?;

        let debug_trace_execution = engine.config.trace_execution;
        let init = GuestProgramInit::new()
            .with_ro_data(blob.ro_data())
            .with_rw_data(blob.rw_data())
            .with_bss(blob.bss_size())
            .with_stack(blob.stack_size());

        let default_backend = if Backend::Compiler.is_supported() {
            Backend::Compiler
        } else {
            Backend::Interpreter
        };
        let selected_backend = engine.config.backend.unwrap_or(default_backend);

        let compiler_enabled = selected_backend == Backend::Compiler;
        let interpreter_enabled = debug_trace_execution || selected_backend == Backend::Interpreter;

        // TODO: Don't always initialize both.
        let compiled_module = if compiler_enabled {
            Some(CompiledModule::new(&instructions, &exports, init, debug_trace_execution)?)
        } else {
            None
        };

        let interpreted_module = if interpreter_enabled {
            Some(InterpretedModule::new(init)?)
        } else {
            None
        };

        assert!(compiled_module.is_some() || interpreted_module.is_some());

        let export_index_by_name = exports
            .iter()
            .enumerate()
            .map(|(index, export)| (export.prototype().name().to_owned(), index))
            .collect();
        let exports = exports.into_iter().map(|export| export.into_owned()).collect();
        let imports = imports.into_iter().map(|(index, import)| (index, import.into_owned())).collect();

        Ok(Module(Arc::new(ModulePrivate {
            debug_trace_execution,
            instructions,
            exports,
            imports,
            export_index_by_name,
            jump_target_to_instruction,

            blob: if debug_trace_execution {
                Some(blob.clone().into_owned())
            } else {
                None
            },
            compiled_module,
            interpreted_module,
        })))
    }
}

/// A handle used to access the execution context.
pub struct Caller<'a, 'b, T> {
    user_data: &'a mut T,
    access: &'a mut BackendAccess<'b>,
    tracer: Option<&'a mut Tracer>,
}

impl<'a, 'b, T> Caller<'a, 'b, T> {
    pub fn data(&self) -> &T {
        self.user_data
    }

    pub fn data_mut(&mut self) -> &mut T {
        self.user_data
    }

    pub fn get_reg(&self, reg: Reg) -> u32 {
        let value = self.access.get_reg(reg);
        log::trace!("Getting register (during hostcall): {reg} = 0x{value:x}");
        value
    }

    pub fn set_reg(&mut self, reg: Reg, value: u32) {
        log::trace!("Setting register (during hostcall): {reg} = 0x{value:x}");
        self.access.set_reg(reg, value);
        if let Some(ref mut tracer) = self.tracer {
            tracer.on_set_reg_in_hostcall(reg, value);
        }
    }

    pub fn read_memory_into_slice<'slice, B>(&self, address: u32, buffer: &'slice mut B) -> Result<&'slice mut [u8], Trap>
    where
        B: ?Sized + AsUninitSliceMut,
    {
        log::trace!(
            "Reading memory (during hostcall): 0x{:x}-0x{:x} ({} bytes)",
            address,
            (address as usize + buffer.as_uninit_slice_mut().len()) as u32,
            buffer.as_uninit_slice_mut().len()
        );
        self.access.read_memory_into_slice(address, buffer)
    }

    pub fn read_memory_into_new_vec(&self, address: u32, length: u32) -> Result<Vec<u8>, Trap> {
        log::trace!(
            "Reading memory (during hostcall): 0x{:x}-0x{:x} ({} bytes)",
            address,
            address.wrapping_add(length),
            length
        );
        self.access.read_memory_into_new_vec(address, length)
    }

    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Trap> {
        log::trace!(
            "Writing memory (during hostcall): 0x{:x}-0x{:x} ({} bytes)",
            address,
            (address as usize + data.len()) as u32,
            data.len()
        );
        let result = self.access.write_memory(address, data);
        if let Some(ref mut tracer) = self.tracer {
            tracer.on_memory_write_in_hostcall(address, data, result.is_ok())?;
        }

        result
    }
}

#[derive(Clone)]
pub enum ValType {
    I32,
    I64,
}

#[derive(Clone, Debug)]
pub enum Val {
    I32(i32),
    I64(i64),
}

impl core::fmt::Display for Val {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Val::I32(value) => value.fmt(fmt),
            Val::I64(value) => value.fmt(fmt),
        }
    }
}

impl From<i32> for Val {
    fn from(value: i32) -> Val {
        Val::I32(value)
    }
}

impl From<u32> for Val {
    fn from(value: u32) -> Val {
        Val::I32(value as i32)
    }
}

impl ValType {
    fn extern_ty(&self) -> ExternTy {
        match self {
            ValType::I32 => ExternTy::I32,
            ValType::I64 => ExternTy::I64,
        }
    }
}

impl Val {
    fn extern_ty(&self) -> ExternTy {
        match self {
            Val::I32(_) => ExternTy::I32,
            Val::I64(_) => ExternTy::I64,
        }
    }

    pub fn i32(&self) -> Option<i32> {
        match self {
            Val::I32(value) => Some(*value),
            Val::I64(_) => None,
        }
    }

    pub fn u32(&self) -> Option<u32> {
        self.i32().map(|value| value as u32)
    }
}

impl From<ExternTy> for ValType {
    fn from(ty: ExternTy) -> Self {
        match ty {
            ExternTy::I32 => ValType::I32,
            ExternTy::I64 => ValType::I64,
        }
    }
}

pub struct FuncType {
    args: Vec<ExternTy>,
    return_ty: Option<ExternTy>,
}

impl FuncType {
    pub fn new(params: impl IntoIterator<Item = ValType>, return_ty: Option<ValType>) -> Self {
        FuncType {
            args: params.into_iter().map(|ty| ty.extern_ty()).collect(),
            return_ty: return_ty.map(|ty| ty.extern_ty()),
        }
    }

    pub fn params(&'_ self) -> impl ExactSizeIterator<Item = ValType> + '_ {
        self.args.iter().map(|&ty| ValType::from(ty))
    }

    pub fn return_ty(&self) -> Option<ValType> {
        self.return_ty.map(ValType::from)
    }
}

trait ExternFn<T> {
    fn call(&self, user_data: &mut T, access: BackendAccess, tracer: Option<&mut Tracer>) -> Result<(), Trap>;
    fn typecheck(&self, prototype: &ExternFnPrototype) -> Result<(), Error>;
}

#[repr(transparent)]
pub struct ExternFnArc<T>(Arc<dyn ExternFn<T>>);

impl<T> Clone for ExternFnArc<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub trait IntoExternFn<T, Params, Result>: Send + Sync + 'static {
    #[doc(hidden)]
    fn _into_extern_fn(self) -> ExternFnArc<T>;
}

/// A type which can be marshalled through the VM's FFI boundary.
pub trait AbiTy: Sized + Send + 'static {
    #[doc(hidden)]
    const _PRIVATE_EXTERN_TY: ExternTy;

    #[doc(hidden)]
    const _REGS_REQUIRED: usize;

    #[doc(hidden)]
    fn _get(get_reg: impl FnMut() -> u32) -> Self;

    #[doc(hidden)]
    fn _set(self, set_reg: impl FnMut(u32));
}

impl AbiTy for u32 {
    const _PRIVATE_EXTERN_TY: ExternTy = ExternTy::I32;
    const _REGS_REQUIRED: usize = 1;

    fn _get(mut get_reg: impl FnMut() -> u32) -> Self {
        get_reg()
    }

    fn _set(self, mut set_reg: impl FnMut(u32)) {
        set_reg(self)
    }
}

impl AbiTy for i32 {
    const _PRIVATE_EXTERN_TY: ExternTy = <u32 as AbiTy>::_PRIVATE_EXTERN_TY;
    const _REGS_REQUIRED: usize = <u32 as AbiTy>::_REGS_REQUIRED;

    fn _get(get_reg: impl FnMut() -> u32) -> Self {
        <u32 as AbiTy>::_get(get_reg) as i32
    }

    fn _set(self, set_reg: impl FnMut(u32)) {
        (self as u32)._set(set_reg)
    }
}

impl AbiTy for u64 {
    const _PRIVATE_EXTERN_TY: ExternTy = ExternTy::I64;
    const _REGS_REQUIRED: usize = 2;

    fn _get(mut get_reg: impl FnMut() -> u32) -> Self {
        let value_lo = get_reg();
        let value_hi = get_reg();
        (value_lo as u64) | ((value_hi as u64) << 32)
    }

    fn _set(self, mut set_reg: impl FnMut(u32)) {
        set_reg(self as u32);
        set_reg((self >> 32) as u32);
    }
}

impl AbiTy for i64 {
    const _PRIVATE_EXTERN_TY: ExternTy = <u64 as AbiTy>::_PRIVATE_EXTERN_TY;
    const _REGS_REQUIRED: usize = <u64 as AbiTy>::_REGS_REQUIRED;

    fn _get(get_reg: impl FnMut() -> u32) -> Self {
        <u64 as AbiTy>::_get(get_reg) as i64
    }

    fn _set(self, set_reg: impl FnMut(u32)) {
        (self as u64)._set(set_reg)
    }
}

// `AbiTy` is deliberately not implemented for `usize`.

/// A type which can be returned from a host function.
pub trait ReturnTy: Sized + Send + 'static {
    #[doc(hidden)]
    const _PRIVATE_EXTERN_TY: ExternTy;
    fn _handle_return(self, set_reg: impl FnMut(u32)) -> Result<(), Trap>;
}

impl<T> ReturnTy for T
where
    T: AbiTy,
{
    const _PRIVATE_EXTERN_TY: ExternTy = T::_PRIVATE_EXTERN_TY;
    fn _handle_return(self, set_reg: impl FnMut(u32)) -> Result<(), Trap> {
        self._set(set_reg);
        Ok(())
    }
}

impl<T> ReturnTy for Result<T, Trap>
where
    T: AbiTy,
{
    const _PRIVATE_EXTERN_TY: ExternTy = T::_PRIVATE_EXTERN_TY;
    fn _handle_return(self, set_reg: impl FnMut(u32)) -> Result<(), Trap> {
        self?._set(set_reg);
        Ok(())
    }
}

pub trait FuncArgs: Send {
    // #[doc(hidden)]
    // const _PRIVATE_ARG_COUNT: usize;

    #[doc(hidden)]
    const _PRIVATE_EXTERN_TY: &'static [ExternTy];

    #[doc(hidden)]
    fn _set(self, set_reg: impl FnMut(u32));
}

pub trait FuncResult: Send {
    #[doc(hidden)]
    const _PRIVATE_EXTERN_TY: Option<ExternTy>;

    #[doc(hidden)]
    fn _get(get_reg: impl FnMut() -> u32) -> Self;
}

impl FuncResult for () {
    const _PRIVATE_EXTERN_TY: Option<ExternTy> = None;

    fn _get(_: impl FnMut() -> u32) -> Self {}
}

impl<T> FuncResult for T
where
    T: AbiTy,
{
    const _PRIVATE_EXTERN_TY: Option<ExternTy> = Some(<T as AbiTy>::_PRIVATE_EXTERN_TY);

    fn _get(get_reg: impl FnMut() -> u32) -> Self {
        <T as AbiTy>::_get(get_reg)
    }
}

macro_rules! impl_into_extern_fn {
    (@check_reg_count $regs_required:expr) => {
        if $regs_required > Reg::ARG_REGS.len() {
            // TODO: We should probably print out which exact function it is.
            log::error!("External call failed: too many registers required for arguments!");
            return Err(Trap::default());
        }
    };

    (@call $caller:expr, $callback:expr, ) => {{
        catch_hostcall_panic(|| ($callback)($caller))
    }};

    (@get_reg $caller:expr) => {{
        let mut reg_index = 0;
        let access = &mut *$caller.access;
        move || -> u32 {
            let value = access.get_reg(Reg::ARG_REGS[reg_index]);
            reg_index += 1;
            value
        }
    }};

    (@call $caller:expr, $callback:expr, $a0:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED);

        let cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0))
    }};

    (@call $caller:expr, $callback:expr, $a0:ident, $a1:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED + $a1::_REGS_REQUIRED);

        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(&mut cb);
        let a1 = $a1::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0, a1))
    }};

    (@call $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED + $a1::_REGS_REQUIRED + $a2::_REGS_REQUIRED);

        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(&mut cb);
        let a1 = $a1::_get(&mut cb);
        let a2 = $a2::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0, a1, a2))
    }};

    (@call $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident, $a3:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED + $a1::_REGS_REQUIRED + $a2::_REGS_REQUIRED + $a3::_REGS_REQUIRED);

        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(&mut cb);
        let a1 = $a1::_get(&mut cb);
        let a2 = $a2::_get(&mut cb);
        let a3 = $a3::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0, a1, a2, a3))
    }};

    (@call $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident, $a3:ident, $a4:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED + $a1::_REGS_REQUIRED + $a2::_REGS_REQUIRED + $a3::_REGS_REQUIRED + $a4::_REGS_REQUIRED);

        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(&mut cb);
        let a1 = $a1::_get(&mut cb);
        let a2 = $a2::_get(&mut cb);
        let a3 = $a3::_get(&mut cb);
        let a4 = $a4::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0, a1, a2, a3, a4))
    }};

    (@call $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident, $a3:ident, $a4:ident, $a5:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED + $a1::_REGS_REQUIRED + $a2::_REGS_REQUIRED + $a3::_REGS_REQUIRED + $a4::_REGS_REQUIRED + $a5::_REGS_REQUIRED);

        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(&mut cb);
        let a1 = $a1::_get(&mut cb);
        let a2 = $a2::_get(&mut cb);
        let a3 = $a3::_get(&mut cb);
        let a4 = $a4::_get(&mut cb);
        let a5 = $a5::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0, a1, a2, a3, a4, a5))
    }};

    ($arg_count:tt $($args:ident)*) => {
        impl<T, F, $($args,)* R> ExternFn<T> for (F, core::marker::PhantomData<(R, $($args),*)>)
            where
            F: Fn(Caller<'_, '_, T>, $($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy,
        {
            fn call(&self, user_data: &mut T, mut access: BackendAccess, mut tracer: Option<&mut Tracer>) -> Result<(), Trap> {
                let caller = Caller {
                    user_data,
                    access: &mut access,
                    tracer: tracer.as_deref_mut(),
                };

                let result = impl_into_extern_fn!(@call caller, self.0, $($args),*)?;

                let set_reg = {
                    let tracer = &mut tracer;
                    let mut reg_index = 0;
                    move |value: u32| {
                        let reg = Reg::ARG_REGS[reg_index];
                        access.set_reg(reg, value);

                        if let Some(tracer) = tracer {
                            tracer.on_set_reg_in_hostcall(reg, value as u32);
                        }

                        reg_index += 1;
                    }
                };
                result._handle_return(set_reg)
            }

            fn typecheck(&self, prototype: &ExternFnPrototype) -> Result<(), Error> {
                let args: [ExternTy; $arg_count] = [$($args::_PRIVATE_EXTERN_TY,)*];
                if args.len() != prototype.args().len() || args.into_iter().zip(prototype.args()).any(|(lhs, rhs)| lhs != rhs) || Some(R::_PRIVATE_EXTERN_TY) != prototype.return_ty() {
                    bail!(
                        "failed to instantiate module: the module wanted to import function '{}', while the function that was registered was '{}'",
                        DisplayFn { name: prototype.name(), args: prototype.args(), return_ty: prototype.return_ty() },
                        DisplayFn { name: prototype.name(), args: args.into_iter(), return_ty: Some(R::_PRIVATE_EXTERN_TY) },
                    );
                }

                Ok(())
            }
        }

        impl<T, F, $($args,)* R> IntoExternFn<T, ($($args,)*), R> for F
        where
            F: Fn($($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy,
        {
            fn _into_extern_fn(self) -> ExternFnArc<T> {
                #[allow(non_snake_case)]
                let callback = move |_caller: Caller<T>, $($args: $args),*| -> R {
                    self($($args),*)
                };
                ExternFnArc(Arc::new((callback, core::marker::PhantomData::<(R, $($args),*)>)))
            }
        }

        impl<T, F, $($args,)* R> IntoExternFn<T, (Caller<'_, '_, T>, $($args,)*), R> for F
        where
            F: Fn(Caller<'_, '_, T>, $($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy,
        {
            fn _into_extern_fn(self) -> ExternFnArc<T> {
                ExternFnArc(Arc::new((self, core::marker::PhantomData::<(R, $($args),*)>)))
            }
        }

        impl<$($args: Send + AbiTy,)*> FuncArgs for ($($args,)*) {
            const _PRIVATE_EXTERN_TY: &'static [ExternTy] = &[
                $(<$args as AbiTy>::_PRIVATE_EXTERN_TY,)*
            ];

            #[allow(unused_mut)]
            #[allow(unused_variables)]
            #[allow(non_snake_case)]
            fn _set(self, mut set_reg: impl FnMut(u32)) {
                let ($($args,)*) = self;
                $($args._set(&mut set_reg);)*
            }
        }
    };
}

impl_into_extern_fn!(0);
impl_into_extern_fn!(1 A0);
impl_into_extern_fn!(2 A0 A1);
impl_into_extern_fn!(3 A0 A1 A2);
impl_into_extern_fn!(4 A0 A1 A2 A3);
impl_into_extern_fn!(5 A0 A1 A2 A3 A4);
impl_into_extern_fn!(6 A0 A1 A2 A3 A4 A5);

struct DynamicFn<T, F> {
    args: Vec<ExternTy>,
    return_ty: Option<ExternTy>,
    callback: F,
    _phantom: core::marker::PhantomData<T>,
}

polkavm_common::static_assert!(Reg::ARG_REGS.len() == VM_MAXIMUM_EXTERN_ARG_COUNT);

fn catch_hostcall_panic<R>(callback: impl FnOnce() -> R) -> Result<R, Trap> {
    std::panic::catch_unwind(core::panic::AssertUnwindSafe(callback)).map_err(|panic| {
        if let Some(message) = panic.downcast_ref::<&str>() {
            log::error!("Hostcall panicked: {message}");
        } else if let Some(message) = panic.downcast_ref::<String>() {
            log::error!("Hostcall panicked: {message}");
        } else {
            log::error!("Hostcall panicked");
        }

        Trap::default()
    })
}

impl<T, F> ExternFn<T> for DynamicFn<T, F>
where
    F: Fn(Caller<'_, '_, T>, &[Val], Option<&mut Val>) -> Result<(), Trap> + Send + Sync + 'static,
    T: 'static,
{
    fn call(&self, user_data: &mut T, mut access: BackendAccess, mut tracer: Option<&mut Tracer>) -> Result<(), Trap> {
        const DEFAULT: Val = Val::I64(0);
        let mut args = [DEFAULT; VM_MAXIMUM_EXTERN_ARG_COUNT];
        let args = &mut args[..self.args.len()];

        let mut arg_regs = Reg::ARG_REGS.into_iter();
        for (&arg_ty, arg) in self.args.iter().zip(args.iter_mut()) {
            match arg_ty {
                ExternTy::I32 => {
                    let Some(reg) = arg_regs.next() else {
                        log::error!("dynamic host call called with too many arguments");
                        return Err(Trap::default());
                    };

                    *arg = Val::I32(access.get_reg(reg) as i32);
                }
                ExternTy::I64 => {
                    let Some(reg_1) = arg_regs.next() else {
                        log::error!("dynamic host call called with too many arguments");
                        return Err(Trap::default());
                    };

                    let Some(reg_2) = arg_regs.next() else {
                        log::error!("dynamic host call called with too many arguments");
                        return Err(Trap::default());
                    };

                    let lo = access.get_reg(reg_1);
                    let hi = access.get_reg(reg_2);
                    *arg = Val::I64((lo as u64 | ((hi as u64) << 32)) as i64);
                }
            }
        }

        let mut return_value = match self.return_ty.unwrap_or(ExternTy::I32) {
            ExternTy::I32 => Val::I32(0),
            ExternTy::I64 => Val::I64(0),
        };

        let caller = Caller {
            user_data,
            access: &mut access,
            tracer: tracer.as_deref_mut(),
        };

        catch_hostcall_panic(|| (self.callback)(caller, args, self.return_ty.map(|_| &mut return_value)))??;

        if let Some(return_ty) = self.return_ty {
            match return_value {
                Val::I32(value) => {
                    if return_ty != ExternTy::I32 {
                        // TODO: Print out the name of the hostcall.
                        log::error!(
                            "Hostcall return type mismatch: expected a hostcall to return '{}', but it returned 'i32'",
                            return_ty
                        );
                        return Err(Trap::default());
                    }

                    access.set_reg(Reg::A0, value as u32);
                    if let Some(tracer) = tracer {
                        tracer.on_set_reg_in_hostcall(Reg::A0, value as u32);
                    }
                }
                Val::I64(value) => {
                    if return_ty != ExternTy::I64 {
                        log::error!(
                            "Hostcall return type mismatch: expected a hostcall to return '{}', but it returned 'i64'",
                            return_ty
                        );
                        return Err(Trap::default());
                    }

                    let value = value as u64;
                    access.set_reg(Reg::A0, value as u32);
                    access.set_reg(Reg::A1, (value >> 32) as u32);

                    if let Some(tracer) = tracer {
                        tracer.on_set_reg_in_hostcall(Reg::A0, value as u32);
                        tracer.on_set_reg_in_hostcall(Reg::A1, (value >> 32) as u32);
                    }
                }
            }
        }

        Ok(())
    }

    fn typecheck(&self, prototype: &ExternFnPrototype) -> Result<(), Error> {
        if self.args.len() != prototype.args().len()
            || self.args.iter().zip(prototype.args()).any(|(lhs, rhs)| *lhs != rhs)
            || self.return_ty != prototype.return_ty()
        {
            bail!(
                "failed to instantiate module: the module wanted to import function '{}', while the function that was registered was '{}'",
                DisplayFn {
                    name: prototype.name(),
                    args: prototype.args(),
                    return_ty: prototype.return_ty()
                },
                DisplayFn {
                    name: prototype.name(),
                    args: self.args.iter().copied(),
                    return_ty: self.return_ty
                },
            );
        }

        Ok(())
    }
}

type FallbackHandlerArc<T> = Arc<dyn Fn(Caller<'_, '_, T>, u32) -> Result<(), Trap> + Send + Sync + 'static>;

pub struct Linker<T> {
    host_functions: HashMap<String, ExternFnArc<T>>,
    #[allow(clippy::type_complexity)]
    fallback_handler: Option<FallbackHandlerArc<T>>,
    phantom: core::marker::PhantomData<T>,
}

impl<T> Linker<T> {
    pub fn new(_engine: &Engine) -> Self {
        Self {
            host_functions: Default::default(),
            fallback_handler: None,
            phantom: core::marker::PhantomData,
        }
    }

    /// Defines a fallback external call handler, in case no other registered functions match.
    pub fn func_fallback(&mut self, func: impl Fn(Caller<'_, '_, T>, u32) -> Result<(), Trap> + Send + Sync + 'static) {
        self.fallback_handler = Some(Arc::new(func));
    }

    /// Defines a new dynamically typed handler for external calls with a given name.
    pub fn func_new(
        &mut self,
        name: &str,
        ty: FuncType,
        func: impl Fn(Caller<'_, '_, T>, &[Val], Option<&mut Val>) -> Result<(), Trap> + Send + Sync + 'static,
    ) -> Result<&mut Self, Error>
    where
        T: 'static,
    {
        if self.host_functions.contains_key(name) {
            bail!("cannot register host function: host function was already registered: '{}'", name);
        }

        self.host_functions.insert(
            name.to_owned(),
            ExternFnArc(Arc::new(DynamicFn {
                args: ty.args,
                return_ty: ty.return_ty,
                callback: func,
                _phantom: core::marker::PhantomData,
            })),
        );

        Ok(self)
    }

    /// Defines a new statically typed handler for external calls with a given name.
    pub fn func_wrap<Params, Args>(&mut self, name: &str, func: impl IntoExternFn<T, Params, Args>) -> Result<&mut Self, Error> {
        if self.host_functions.contains_key(name) {
            bail!("cannot register host function: host function was already registered: '{}'", name);
        }

        self.host_functions.insert(name.to_owned(), func._into_extern_fn());
        Ok(self)
    }

    /// Pre-instantiates a new module, linking it with the external functions previously defined on this object.
    pub fn instantiate_pre(&self, module: &Module) -> Result<InstancePre<T>, Error> {
        let mut host_functions: Vec<ExternFnArc<T>> = Vec::new();
        host_functions.reserve_exact(module.0.imports.len());

        for import in module.0.imports.values() {
            let prototype = import.prototype();
            let host_fn = match self.host_functions.get(prototype.name()) {
                Some(host_fn) => host_fn,
                None => {
                    if self.fallback_handler.is_some() {
                        continue;
                    }

                    bail!("failed to instantiate module: missing host function: '{}'", prototype.name());
                }
            };

            host_fn.0.typecheck(prototype)?;
            host_functions.push(host_fn.clone());
        }

        Ok(InstancePre(Arc::new(InstancePrePrivate {
            module: module.clone(),
            host_functions,
            fallback_handler: self.fallback_handler.clone(),
            _private: core::marker::PhantomData,
        })))
    }
}

struct InstancePrePrivate<T> {
    module: Module,
    host_functions: Vec<ExternFnArc<T>>,
    fallback_handler: Option<FallbackHandlerArc<T>>,
    _private: core::marker::PhantomData<T>,
}

pub struct InstancePre<T>(Arc<InstancePrePrivate<T>>);

impl<T> Clone for InstancePre<T> {
    fn clone(&self) -> Self {
        InstancePre(self.0.clone())
    }
}

impl<T> InstancePre<T> {
    /// Instantiates a new module.
    pub fn instantiate(&self) -> Result<Instance<T>, Error> {
        let backend = if self.0.module.0.compiled_module.is_some() {
            let compiled_instance = CompiledInstance::new(self.0.module.clone())?;
            InstanceBackend::Compiled(compiled_instance)
        } else {
            let interpreted_instance = InterpretedInstance::new(self.0.module.clone())?;
            InstanceBackend::Interpreted(interpreted_instance)
        };

        let tracer = if self.0.module.0.debug_trace_execution {
            Some(Tracer::new(self.0.module.clone()))
        } else {
            None
        };

        Ok(Instance(Arc::new(InstancePrivate {
            instance_pre: self.clone(),
            mutable: Mutex::new(InstancePrivateMut { backend, tracer }),
        })))
    }
}

enum InstanceBackend {
    Compiled(CompiledInstance),
    Interpreted(InterpretedInstance),
}

impl InstanceBackend {
    fn call(
        &mut self,
        export_index: usize,
        on_hostcall: OnHostcall,
        args: &[u32],
        reset_memory_after_execution: bool,
    ) -> Result<(), ExecutionError> {
        match self {
            InstanceBackend::Compiled(ref mut backend) => backend.call(export_index, on_hostcall, args, reset_memory_after_execution),
            InstanceBackend::Interpreted(ref mut backend) => backend.call(export_index, on_hostcall, args, reset_memory_after_execution),
        }
    }

    fn access(&mut self) -> BackendAccess {
        match self {
            InstanceBackend::Compiled(ref mut backend) => BackendAccess::Compiled(backend.access()),
            InstanceBackend::Interpreted(ref mut backend) => BackendAccess::Interpreted(backend.access()),
        }
    }
}

pub enum BackendAccess<'a> {
    #[allow(dead_code)]
    Compiled(CompiledAccess<'a>),
    Interpreted(InterpretedAccess<'a>),
}

impl<'a> Access<'a> for BackendAccess<'a> {
    type Error = Trap;

    fn get_reg(&self, reg: Reg) -> u32 {
        match self {
            BackendAccess::Compiled(access) => access.get_reg(reg),
            BackendAccess::Interpreted(access) => access.get_reg(reg),
        }
    }

    fn set_reg(&mut self, reg: Reg, value: u32) {
        match self {
            BackendAccess::Compiled(access) => access.set_reg(reg, value),
            BackendAccess::Interpreted(access) => access.set_reg(reg, value),
        }
    }

    fn read_memory_into_slice<'slice, B>(&self, address: u32, buffer: &'slice mut B) -> Result<&'slice mut [u8], Self::Error>
    where
        B: ?Sized + AsUninitSliceMut,
    {
        match self {
            BackendAccess::Compiled(access) => Ok(access.read_memory_into_slice(address, buffer)?),
            BackendAccess::Interpreted(access) => Ok(access.read_memory_into_slice(address, buffer)?),
        }
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
        match self {
            BackendAccess::Compiled(access) => Ok(access.write_memory(address, data)?),
            BackendAccess::Interpreted(access) => Ok(access.write_memory(address, data)?),
        }
    }

    fn program_counter(&self) -> Option<u32> {
        match self {
            BackendAccess::Compiled(access) => access.program_counter(),
            BackendAccess::Interpreted(access) => access.program_counter(),
        }
    }

    fn native_program_counter(&self) -> Option<u64> {
        match self {
            BackendAccess::Compiled(access) => access.native_program_counter(),
            BackendAccess::Interpreted(access) => access.native_program_counter(),
        }
    }
}

struct InstancePrivateMut {
    backend: InstanceBackend,
    tracer: Option<Tracer>,
}

struct InstancePrivate<T> {
    instance_pre: InstancePre<T>,
    mutable: Mutex<InstancePrivateMut>,
}

pub struct Instance<T>(Arc<InstancePrivate<T>>);

impl<T> Clone for Instance<T> {
    fn clone(&self) -> Self {
        Instance(self.0.clone())
    }
}

impl<T> Instance<T> {
    /// Returns a handle to a function of a given name exported by the module.
    pub fn get_func(&self, name: &str) -> Option<Func<T>> {
        let export_index = *self.0.instance_pre.0.module.0.export_index_by_name.get(name)?;
        Some(Func {
            instance: self.clone(),
            export_index,
        })
    }

    /// Returns a handle to a function of a given name exported by the module.
    pub fn get_typed_func<FnArgs, FnResult>(&self, name: &str) -> Result<TypedFunc<T, FnArgs, FnResult>, Error>
    where
        FnArgs: FuncArgs,
        FnResult: FuncResult,
    {
        let Some(&export_index) = self.0.instance_pre.0.module.0.export_index_by_name.get(name) else {
            return Err(Error::from(format!(
                "failed to get function '{}': no such function is exported",
                name
            )));
        };

        let export = &self.0.instance_pre.0.module.0.exports[export_index];
        let prototype = export.prototype();

        let return_ty = FnResult::_PRIVATE_EXTERN_TY;
        let args = FnArgs::_PRIVATE_EXTERN_TY;

        if args.len() != prototype.args().len()
            || args.iter().copied().zip(prototype.args()).any(|(lhs, rhs)| lhs != rhs)
            || return_ty != prototype.return_ty()
        {
            let error = format!(
                "failed to get function: wanted to get function '{}', while the function that was exported was '{}'",
                DisplayFn {
                    name: prototype.name(),
                    args: args.iter().copied(),
                    return_ty
                },
                DisplayFn {
                    name: prototype.name(),
                    args: prototype.args(),
                    return_ty: prototype.return_ty()
                },
            );

            return Err(error.into());
        }

        Ok(TypedFunc {
            instance: self.clone(),
            export_index,
            _phantom: core::marker::PhantomData,
        })
    }
}

pub struct Func<T> {
    instance: Instance<T>,
    export_index: usize,
}

impl<T> Clone for Func<T> {
    fn clone(&self) -> Self {
        Self {
            instance: self.instance.clone(),
            export_index: self.export_index,
        }
    }
}

fn on_hostcall<'a, T>(
    user_data: &'a mut T,
    host_functions: &'a [ExternFnArc<T>],
    fallback_handler: Option<&'a FallbackHandlerArc<T>>,
    mut tracer: Option<&'a mut Tracer>,
) -> impl for<'r> FnMut(u64, BackendAccess<'r>) -> Result<(), Trap> + 'a {
    move |hostcall: u64, mut access: BackendAccess| -> Result<(), Trap> {
        if hostcall > u32::MAX as u64 {
            if hostcall == polkavm_common::zygote::HOSTCALL_TRACE {
                if let Some(tracer) = tracer.as_mut() {
                    return tracer.on_trace(&mut access);
                }

                log::error!("trace hostcall called but no tracer is set");
                return Err(Trap::default());
            }

            log::error!("unknown special hostcall triggered: {}", hostcall);
            return Err(Trap::default());
        }

        let host_fn = match host_functions.get(hostcall as usize) {
            Some(host_fn) => host_fn,
            None => {
                if let Some(fallback_handler) = fallback_handler {
                    let caller = Caller {
                        user_data,
                        access: &mut access,
                        tracer: tracer.as_deref_mut(),
                    };

                    return fallback_handler(caller, hostcall as u32);
                }

                // This should never happen.
                log::error!("hostcall to a function which doesn't exist: {}", hostcall);
                return Err(Trap::default());
            }
        };

        if let Err(trap) = host_fn.0.call(user_data, access, tracer.as_deref_mut()) {
            log::debug!("hostcall failed: {}", trap);
            return Err(trap);
        }

        Ok(())
    }
}

impl<T> Func<T> {
    /// Calls the function. Doesn't reset the memory after the call.
    pub fn call(&self, user_data: &mut T, args: &[Val]) -> Result<Option<Val>, ExecutionError> {
        self.call_impl(user_data, args, false)
    }

    /// Calls the function. Will reset the memory after the call.
    pub fn call_and_reset_memory(&self, user_data: &mut T, args: &[Val]) -> Result<Option<Val>, ExecutionError> {
        self.call_impl(user_data, args, true)
    }

    fn call_impl(&self, user_data: &mut T, args: &[Val], reset_memory_after_execution: bool) -> Result<Option<Val>, ExecutionError> {
        let instance_pre = &self.instance.0.instance_pre;
        let export = &instance_pre.0.module.0.exports[self.export_index];
        let prototype = export.prototype();

        if args.len() != prototype.args().len()
            || args
                .iter()
                .map(|value| value.extern_ty())
                .zip(prototype.args())
                .any(|(lhs, rhs)| lhs != rhs)
        {
            let error = format!(
                "failed to call function: wanted to call function '{}', while the function that was exported was '{}'",
                DisplayFn {
                    name: prototype.name(),
                    args: args.iter().map(|value| value.extern_ty()),
                    return_ty: prototype.return_ty()
                },
                DisplayFn {
                    name: prototype.name(),
                    args: prototype.args(),
                    return_ty: prototype.return_ty()
                },
            );

            return Err(ExecutionError::Error(error.into()));
        }

        let mut arg_regs: [u32; VM_MAXIMUM_EXTERN_ARG_COUNT] = [0; VM_MAXIMUM_EXTERN_ARG_COUNT];
        let mut input_count = 0;
        if prototype.args().len() > 0 {
            let required_count = args
                .iter()
                .map(|arg| match arg {
                    Val::I32(..) => i32::_REGS_REQUIRED,
                    Val::I64(..) => i64::_REGS_REQUIRED,
                })
                .sum::<usize>();

            if required_count > Reg::ARG_REGS.len() {
                return Err(ExecutionError::Error(
                    format!("failed to call function '{}': too many arguments", prototype.name()).into(),
                ));
            }

            let mut cb = |value: u32| {
                arg_regs[input_count] = value;
                input_count += 1;
            };

            for arg in args {
                match arg {
                    Val::I32(value) => i32::_set(*value, &mut cb),
                    Val::I64(value) => i64::_set(*value, &mut cb),
                }
            }
        }
        let arg_regs = &arg_regs[..input_count];

        let mutable = &self.instance.0.mutable;
        let mut mutable = match mutable.lock() {
            Ok(mutable) => mutable,
            Err(poison) => poison.into_inner(),
        };

        let mutable = &mut *mutable;
        let mut tracer = mutable.tracer.as_mut();
        if let Some(ref mut tracer) = tracer {
            tracer.on_before_call(self.export_index, export, arg_regs, reset_memory_after_execution);
        }

        let mut on_hostcall = on_hostcall(
            user_data,
            &instance_pre.0.host_functions,
            instance_pre.0.fallback_handler.as_ref(),
            tracer.as_deref_mut(),
        );

        let result = mutable
            .backend
            .call(self.export_index, &mut on_hostcall, arg_regs, reset_memory_after_execution);
        core::mem::drop(on_hostcall);

        if let Some(ref mut tracer) = tracer {
            tracer.on_after_call();
        }

        match result {
            Ok(()) => {}
            Err(ExecutionError::Error(error)) => {
                return Err(ExecutionError::Error(
                    format!("failed to call function '{}': {}", export.prototype().name(), error).into(),
                ));
            }
            Err(ExecutionError::Trap(trap)) => {
                return Err(ExecutionError::Error(
                    format!("execution trapped while calling '{}': {}", export.prototype().name(), trap).into(),
                ));
            }
        }

        if let Some(return_ty) = prototype.return_ty() {
            let mut output_count = 0;
            let get = || {
                let value = mutable.backend.access().get_reg(Reg::ARG_REGS[output_count]);
                output_count += 1;
                value
            };

            match return_ty {
                ExternTy::I32 => {
                    let value = <i32 as AbiTy>::_get(get);
                    Ok(Some(Val::I32(value)))
                }
                ExternTy::I64 => {
                    let value = <i64 as AbiTy>::_get(get);
                    Ok(Some(Val::I64(value)))
                }
            }
        } else {
            Ok(None)
        }
    }
}

pub struct TypedFunc<T, FnArgs, FnResult> {
    instance: Instance<T>,
    export_index: usize,
    _phantom: core::marker::PhantomData<(FnArgs, FnResult)>,
}

impl<T, FnArgs, FnResult> TypedFunc<T, FnArgs, FnResult>
where
    FnArgs: FuncArgs,
    FnResult: FuncResult,
{
    /// Calls the function. Doesn't reset the memory after the call.
    pub fn call(&self, user_data: &mut T, args: FnArgs) -> Result<FnResult, ExecutionError> {
        self.call_impl(user_data, args, false)
    }

    /// Calls the function. Will reset the memory after the call.
    pub fn call_and_reset_memory(&self, user_data: &mut T, args: FnArgs) -> Result<FnResult, ExecutionError> {
        self.call_impl(user_data, args, true)
    }

    fn call_impl(&self, user_data: &mut T, args: FnArgs, reset_memory_after_execution: bool) -> Result<FnResult, ExecutionError> {
        let instance_pre = &self.instance.0.instance_pre;
        let export = &instance_pre.0.module.0.exports[self.export_index];

        let mut arg_regs: [u32; VM_MAXIMUM_EXTERN_ARG_COUNT] = [0; VM_MAXIMUM_EXTERN_ARG_COUNT];
        let mut input_count = 0;
        args._set(|value| {
            arg_regs[input_count] = value;
            input_count += 1;
        });
        let arg_regs = &arg_regs[..input_count];

        let mutable = &self.instance.0.mutable;
        let mut mutable = match mutable.lock() {
            Ok(mutable) => mutable,
            Err(poison) => poison.into_inner(),
        };

        let mutable = &mut *mutable;
        let mut tracer = mutable.tracer.as_mut();
        if let Some(ref mut tracer) = tracer {
            tracer.on_before_call(self.export_index, export, arg_regs, reset_memory_after_execution);
        }

        let mut on_hostcall = on_hostcall(
            user_data,
            &instance_pre.0.host_functions,
            instance_pre.0.fallback_handler.as_ref(),
            tracer.as_deref_mut(),
        );

        let result = mutable
            .backend
            .call(self.export_index, &mut on_hostcall, arg_regs, reset_memory_after_execution);
        core::mem::drop(on_hostcall);

        if let Some(ref mut tracer) = tracer {
            tracer.on_after_call();
        }

        match result {
            Ok(()) => {}
            Err(ExecutionError::Error(error)) => {
                return Err(ExecutionError::Error(
                    format!("failed to call function '{}': {}", export.prototype().name(), error).into(),
                ));
            }
            Err(ExecutionError::Trap(trap)) => {
                return Err(ExecutionError::Error(
                    format!("execution trapped while calling '{}': {}", export.prototype().name(), trap).into(),
                ));
            }
        }

        let mut output_count = 0;
        let result = FnResult::_get(|| {
            let access = mutable.backend.access();
            let value = access.get_reg(Reg::ARG_REGS[output_count]);
            output_count += 1;
            value
        });

        Ok(result)
    }
}
