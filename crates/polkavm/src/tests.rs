use crate::{
    CallArgs, Caller, CallerRef, Config, Engine, ExecutionError, Gas, GasMeteringKind, Linker, MemoryMap, Module, ModuleConfig,
    ProgramBlob, Reg, StateArgs, Trap,
};
use core::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Mutex;

use polkavm_common::program::asm;
use polkavm_common::program::Reg::*;
use polkavm_common::program::{ProgramExport, ProgramImport};
use polkavm_common::utils::align_to_next_page_u32;
use polkavm_common::writer::ProgramBlobBuilder;

macro_rules! run_tests {
    ($($test_name:ident)+) => {
        if_compiler_is_supported! {
            mod compiler {
                #[cfg(target_os = "linux")]
                mod linux {
                    $(
                        #[test]
                        fn $test_name() {
                            let mut config = crate::Config::default();
                            config.set_backend(Some(crate::BackendKind::Compiler));
                            config.set_sandbox(Some(crate::SandboxKind::Linux));
                            super::super::$test_name(config);
                        }
                    )+
                }

                #[cfg(target_os = "linux")]
                mod linux_tracing {
                    $(
                        #[test]
                        fn $test_name() {
                            let mut config = crate::Config::default();
                            config.set_backend(Some(crate::BackendKind::Compiler));
                            config.set_sandbox(Some(crate::SandboxKind::Linux));
                            config.set_allow_insecure(true);
                            config.set_trace_execution(true);
                            super::super::$test_name(config);
                        }
                    )+
                }

                mod generic {
                    $(
                        #[test]
                        fn $test_name() {
                            let mut config = crate::Config::default();
                            config.set_backend(Some(crate::BackendKind::Compiler));
                            config.set_sandbox(Some(crate::SandboxKind::Generic));
                            config.set_allow_insecure(true);
                            super::super::$test_name(config);
                        }
                    )+
                }

                mod generic_tracing {
                    $(
                        #[test]
                        fn $test_name() {
                            let mut config = crate::Config::default();
                            config.set_backend(Some(crate::BackendKind::Compiler));
                            config.set_sandbox(Some(crate::SandboxKind::Generic));
                            config.set_allow_insecure(true);
                            config.set_trace_execution(true);
                            super::super::$test_name(config);
                        }
                    )+
                }
            }
        }

        mod interpreter {
            $(
                #[test]
                fn $test_name() {
                    let mut config = crate::Config::default();
                    config.set_backend(Some(crate::BackendKind::Interpreter));
                    super::$test_name(config);
                }
            )+
        }
    }
}

fn basic_test_blob() -> ProgramBlob<'static> {
    let memory_map = MemoryMap::new(0x4000, 0, 0x4000, 0).unwrap();
    let mut builder = ProgramBlobBuilder::new();
    builder.set_rw_data_size(0x4000);
    builder.add_export(ProgramExport::new(0, "main".into()));
    builder.add_import(ProgramImport::new("hostcall".into()));
    builder.set_code(&[
        asm::store_imm_u32(0x12345678, memory_map.rw_data_address()),
        asm::add(S0, A0, A1),
        asm::ecalli(0),
        asm::add(A0, A0, S0),
        asm::ret(),
    ]);
    ProgramBlob::parse(builder.into_vec()).unwrap()
}

fn caller_and_caller_ref_work(config: Config) {
    let _ = env_logger::try_init();
    let blob = basic_test_blob();
    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &Default::default(), &blob).unwrap();
    let mut linker = Linker::new(&engine);

    #[derive(Default)]
    struct State {
        illegal_contraband: Rc<RefCell<Option<CallerRef<State>>>>,
    }

    let address = module.memory_map().rw_data_address();
    linker
        .func_wrap("hostcall", move |caller: Caller<State>| -> Result<u32, Trap> {
            {
                let value = caller.read_u32(address)?;
                assert_eq!(value, 0x12345678);
            }
            {
                let caller = caller.into_ref();
                let value = caller.read_u32(address)?;
                assert_eq!(value, 0x12345678);

                let illegal_contraband = Rc::clone(&caller.data().illegal_contraband);
                *illegal_contraband.borrow_mut() = Some(caller);
            }

            Ok(100)
        })
        .unwrap();

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let instance = instance_pre.instantiate().unwrap();
    let mut state = State::default();
    let result = instance.call_typed::<(u32, u32), u32>(&mut state, "main", (1, 10)).unwrap();

    assert_eq!(result, 111);

    let caller = state.illegal_contraband.borrow_mut().take().unwrap();
    let result = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| caller.get_reg(Reg::A0)));
    assert!(result.is_err());
}

fn caller_split_works(config: Config) {
    let _ = env_logger::try_init();
    let blob = basic_test_blob();
    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &Default::default(), &blob).unwrap();
    let mut linker = Linker::new(&engine);

    #[derive(Default)]
    struct State {
        value: u32,
    }

    let address = module.memory_map().rw_data_address();
    linker
        .func_wrap("hostcall", move |caller: Caller<State>| -> Result<u32, Trap> {
            {
                let value = caller.read_u32(address)?;
                assert_eq!(value, 0x12345678);
            }
            {
                let (caller, state) = caller.split();
                state.value = caller.read_u32(address)?;
            }

            Ok(100)
        })
        .unwrap();

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let instance = instance_pre.instantiate().unwrap();
    let mut state = State::default();
    let result = instance.call_typed::<(u32, u32), u32>(&mut state, "main", (1, 10)).unwrap();

    assert_eq!(result, 111);
    assert_eq!(state.value, 0x12345678);
}

fn trapping_from_hostcall_handler_works(config: Config) {
    let _ = env_logger::try_init();
    let blob = basic_test_blob();
    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &Default::default(), &blob).unwrap();
    let mut linker = Linker::new(&engine);

    enum Kind {
        Ok,
        Trap,
    }

    linker
        .func_wrap("hostcall", move |caller: Caller<Kind>| -> Result<u32, Trap> {
            match *caller.data() {
                Kind::Ok => Ok(100),
                Kind::Trap => Err(Trap::default()),
            }
        })
        .unwrap();

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let instance = instance_pre.instantiate().unwrap();

    let result = instance.call_typed::<(u32, u32), u32>(&mut Kind::Ok, "main", (1, 10));
    assert!(matches!(result, Ok(111)));

    let result = instance.call_typed::<(u32, u32), u32>(&mut Kind::Trap, "main", (1, 10));
    assert!(matches!(result, Err(ExecutionError::Trap(..))));
}

fn fallback_hostcall_handler_works(config: Config) {
    let _ = env_logger::try_init();
    let blob = basic_test_blob();
    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &Default::default(), &blob).unwrap();
    let mut linker = Linker::new(&engine);

    linker.func_fallback(move |mut caller: Caller<()>, symbol: &[u8]| -> Result<(), Trap> {
        assert_eq!(symbol, b"hostcall");
        caller.set_reg(Reg::A0, 100);
        Ok(())
    });

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let instance = instance_pre.instantiate().unwrap();
    let result = instance.call_typed::<(u32, u32), u32>(&mut (), "main", (1, 10)).unwrap();

    assert_eq!(result, 111);
}

fn decompress_zstd(mut bytes: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut output = Vec::new();
    ruzstd::streaming_decoder::StreamingDecoder::new(&mut bytes)
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    output
}

static BLOB_MAP: Mutex<Option<HashMap<&'static [u8], ProgramBlob>>> = Mutex::new(None);

fn get_blob(elf: &'static [u8]) -> ProgramBlob {
    let mut blob_map = match BLOB_MAP.lock() {
        Ok(blob_map) => blob_map,
        Err(error) => error.into_inner(),
    };

    let blob_map = blob_map.get_or_insert_with(HashMap::new);
    blob_map
        .entry(elf)
        .or_insert_with(|| {
            // This is slow, so cache it.
            let elf = decompress_zstd(elf);
            let blob = polkavm_linker::program_from_elf(Default::default(), &elf).unwrap();
            blob.into_owned()
        })
        .clone()
}

fn doom(config: Config, elf: &'static [u8]) {
    if config.backend() == Some(crate::BackendKind::Interpreter) || config.trace_execution() {
        // The interpreter is currently too slow to run doom.
        return;
    }

    if cfg!(debug_assertions) {
        // The linker is currently very slow in debug mode.
        return;
    }

    const DOOM_WAD: &[u8] = include_bytes!("../../../examples/doom/roms/doom1.wad");

    let _ = env_logger::try_init();
    let blob = get_blob(elf);
    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &Default::default(), &blob).unwrap();
    let mut linker = Linker::new(&engine);

    struct State {
        frame: Vec<u8>,
        frame_width: u32,
        frame_height: u32,
    }

    linker
        .func_wrap(
            "ext_output_video",
            |caller: Caller<State>, address: u32, width: u32, height: u32| -> Result<(), Trap> {
                let (caller, state) = caller.split();
                let length = width * height * 4;
                state.frame.clear();
                state.frame.reserve(length as usize);
                caller.read_memory_into_slice(address, &mut state.frame.spare_capacity_mut()[..length as usize])?;
                // SAFETY: We've successfully read this many bytes into this Vec.
                unsafe {
                    state.frame.set_len(length as usize);
                }
                state.frame_width = width;
                state.frame_height = height;
                Ok(())
            },
        )
        .unwrap();

    linker
        .func_wrap(
            "ext_output_audio",
            |_caller: Caller<State>, _address: u32, _samples: u32| -> Result<(), Trap> { Ok(()) },
        )
        .unwrap();

    linker
        .func_wrap("ext_rom_size", |_caller: Caller<State>| -> u32 { DOOM_WAD.len() as u32 })
        .unwrap();

    linker
        .func_wrap(
            "ext_rom_read",
            |mut caller: Caller<State>, pointer: u32, offset: u32, length: u32| -> Result<(), Trap> {
                let chunk = DOOM_WAD
                    .get(offset as usize..offset as usize + length as usize)
                    .ok_or_else(Trap::default)?;

                caller.write_memory(pointer, chunk)
            },
        )
        .unwrap();

    linker
        .func_wrap(
            "ext_stdout",
            |_caller: Caller<State>, _buffer: u32, length: u32| -> Result<i32, Trap> { Ok(length as i32) },
        )
        .unwrap();

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let instance = instance_pre.instantiate().unwrap();
    let ext_initialize = instance.module().lookup_export("ext_initialize").unwrap();
    let ext_tick = instance.module().lookup_export("ext_tick").unwrap();

    let mut state = State {
        frame: Vec::new(),
        frame_width: 0,
        frame_height: 0,
    };

    instance
        .call(Default::default(), CallArgs::new(&mut state, ext_initialize))
        .unwrap();
    for nth_frame in 0..=10440 {
        instance.call(Default::default(), CallArgs::new(&mut state, ext_tick)).unwrap();

        let expected_frame_raw = match nth_frame {
            120 => decompress_zstd(include_bytes!("../../../test-data/doom_00120.tga.zst")),
            1320 => decompress_zstd(include_bytes!("../../../test-data/doom_01320.tga.zst")),
            9000 => decompress_zstd(include_bytes!("../../../test-data/doom_09000.tga.zst")),
            10440 => decompress_zstd(include_bytes!("../../../test-data/doom_10440.tga.zst")),
            _ => continue,
        };

        for pixel in state.frame.chunks_exact_mut(4) {
            pixel.swap(0, 2);
            pixel[3] = 0xff;
        }

        let expected_frame = image::load_from_memory_with_format(&expected_frame_raw, image::ImageFormat::Tga)
            .unwrap()
            .to_rgba8();

        if state.frame != *expected_frame.as_raw() {
            panic!("frame {nth_frame:05} doesn't match!");
        }
    }

    // Generate frames to pick:
    // for nth_frame in 0..20000 {
    //     ext_tick.call(&mut state, ()).unwrap();
    //     if nth_frame % 120 == 0 {
    //         for pixel in state.frame.chunks_exact_mut(4) {
    //             pixel.swap(0, 2);
    //             pixel[3] = 0xff;
    //         }
    //         let filename = format!("/tmp/doom-frames/doom_{:05}.tga", nth_frame);
    //         image::save_buffer(filename, &state.frame, state.frame_width, state.frame_height, image::ColorType::Rgba8).unwrap();
    //     }
    // }
}

fn doom_o3_dwarf5(config: Config) {
    doom(config, include_bytes!("../../../test-data/doom_O3_dwarf5.elf.zst"));
}

fn doom_o1_dwarf5(config: Config) {
    doom(config, include_bytes!("../../../test-data/doom_O1_dwarf5.elf.zst"));
}

fn doom_o3_dwarf2(config: Config) {
    doom(config, include_bytes!("../../../test-data/doom_O3_dwarf2.elf.zst"));
}

fn pinky(config: Config) {
    if config.backend() == Some(crate::BackendKind::Interpreter) || config.trace_execution() {
        // The interpreter is currently too slow to run this.
        return;
    }

    let _ = env_logger::try_init();
    let blob = get_blob(include_bytes!("../../../test-data/bench-pinky.elf.zst"));

    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &Default::default(), &blob).unwrap();
    let linker = Linker::new(&engine);
    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let instance = instance_pre.instantiate().unwrap();
    let ext_initialize = instance.module().lookup_export("initialize").unwrap();
    let ext_run = instance.module().lookup_export("run").unwrap();
    let ext_get_framebuffer = instance.module().lookup_export("get_framebuffer").unwrap();

    instance.call(Default::default(), CallArgs::new(&mut (), ext_initialize)).unwrap();
    for _ in 0..256 {
        instance.call(Default::default(), CallArgs::new(&mut (), ext_run)).unwrap();
    }

    instance
        .call(Default::default(), CallArgs::new(&mut (), ext_get_framebuffer))
        .unwrap();
    let address = instance.get_result_typed::<u32>();
    let framebuffer = instance.read_memory_into_new_vec(address, 256 * 240 * 4).unwrap();

    let expected_frame_raw = decompress_zstd(include_bytes!("../../../test-data/pinky_00256.tga.zst"));
    let expected_frame = image::load_from_memory_with_format(&expected_frame_raw, image::ImageFormat::Tga)
        .unwrap()
        .to_rgba8();

    if framebuffer != *expected_frame.as_raw() {
        panic!("frames doesn't match!");
    }
}

struct TestInstance {
    module: crate::Module,
    instance: crate::Instance<()>,
}

impl TestInstance {
    fn new(config: &Config) -> Self {
        let _ = env_logger::try_init();
        let blob = get_blob(include_bytes!("../../../test-data/test-blob.elf.zst"));

        let engine = Engine::new(config).unwrap();
        let module = Module::from_blob(&engine, &Default::default(), &blob).unwrap();
        let mut linker = Linker::new(&engine);
        linker
            .func_wrap("multiply_by_2", |_caller: Caller<()>, value: u32| -> Result<u32, Trap> {
                Ok(value * 2)
            })
            .unwrap();

        linker
            .func_wrap("identity", |_caller: Caller<()>, value: u32| -> u32 { value })
            .unwrap();

        linker
            .func_new("multiply_all_input_registers", |mut caller: Caller<()>| -> Result<(), Trap> {
                let mut value = 1;

                use Reg as R;
                for reg in [R::A0, R::A1, R::A2, R::A3, R::A4, R::A5, R::T0, R::T1, R::T2] {
                    value *= caller.get_reg(reg);
                }

                caller.set_reg(Reg::A0, value);
                Ok(())
            })
            .unwrap();

        linker
            .func_wrap("call_sbrk_indirectly_impl", |mut caller: Caller<()>, size: u32| -> u32 {
                caller.sbrk(size).unwrap_or(0)
            })
            .unwrap();

        let instance_pre = linker.instantiate_pre(&module).unwrap();
        let instance = instance_pre.instantiate().unwrap();

        TestInstance { module, instance }
    }

    pub fn call<FnArgs, FnResult>(&self, name: &str, args: FnArgs) -> Result<FnResult, crate::ExecutionError<crate::Error>>
    where
        FnArgs: crate::api::FuncArgs,
        FnResult: crate::api::FuncResult,
    {
        self.instance.call_typed::<FnArgs, FnResult>(&mut (), name, args)?;
        Ok(self.instance.get_result_typed::<FnResult>())
    }
}

fn test_blob_basic_test(config: Config) {
    let i = TestInstance::new(&config);
    assert_eq!(i.call::<(), u32>("push_one_to_global_vec", ()).unwrap(), 1);
    assert_eq!(i.call::<(), u32>("push_one_to_global_vec", ()).unwrap(), 2);
    assert_eq!(i.call::<(), u32>("push_one_to_global_vec", ()).unwrap(), 3);
}

fn test_blob_atomic_fetch_add(config: Config) {
    let i = TestInstance::new(&config);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (1,)).unwrap(), 0);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (1,)).unwrap(), 1);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (1,)).unwrap(), 2);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (0,)).unwrap(), 3);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (0,)).unwrap(), 3);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (2,)).unwrap(), 3);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (0,)).unwrap(), 5);
}

fn test_blob_atomic_fetch_swap(config: Config) {
    let i = TestInstance::new(&config);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_swap", (10,)).unwrap(), 0);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_swap", (100,)).unwrap(), 10);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_swap", (1000,)).unwrap(), 100);
}

fn test_blob_atomic_fetch_minmax(config: Config) {
    use core::cmp::{max, min};

    fn maxu(a: i32, b: i32) -> i32 {
        max(a as u32, b as u32) as i32
    }

    fn minu(a: i32, b: i32) -> i32 {
        min(a as u32, b as u32) as i32
    }

    #[allow(clippy::type_complexity)]
    let list: [(&str, fn(i32, i32) -> i32); 4] = [
        ("atomic_fetch_max_signed", max),
        ("atomic_fetch_min_signed", min),
        ("atomic_fetch_max_unsigned", maxu),
        ("atomic_fetch_min_unsigned", minu),
    ];

    let i = TestInstance::new(&config);
    for (name, cb) in list {
        for a in [-10, 0, 10] {
            for b in [-10, 0, 10] {
                let new_value = cb(a, b);
                i.call::<(i32,), ()>("set_global", (a,)).unwrap();
                assert_eq!(i.call::<(i32,), i32>(name, (b,)).unwrap(), a);
                assert_eq!(i.call::<(), i32>("get_global", ()).unwrap(), new_value);
            }
        }
    }
}

fn test_blob_hostcall(config: Config) {
    let i = TestInstance::new(&config);
    assert_eq!(i.call::<(u32,), u32>("test_multiply_by_6", (10,)).unwrap(), 60);
}

fn test_blob_define_abi(config: Config) {
    let i = TestInstance::new(&config);
    assert!(i.call::<(), ()>("test_define_abi", ()).is_ok());
}

fn test_blob_input_registers(config: Config) {
    let i = TestInstance::new(&config);
    assert!(i.call::<(), ()>("test_input_registers", ()).is_ok());
}

fn test_blob_call_sbrk_from_guest(config: Config) {
    test_blob_call_sbrk_impl(config, |i, size| i.call::<(u32,), u32>("call_sbrk", (size,)).unwrap())
}

fn test_blob_call_sbrk_from_host_instance(config: Config) {
    test_blob_call_sbrk_impl(config, |i, size| i.instance.sbrk(size).unwrap().unwrap_or(0))
}

fn test_blob_call_sbrk_from_host_function(config: Config) {
    test_blob_call_sbrk_impl(config, |i, size| i.call::<(u32,), u32>("call_sbrk_indirectly", (size,)).unwrap())
}

fn test_blob_program_memory_can_be_reused_and_cleared(config: Config) {
    let i = TestInstance::new(&config);
    let address = i.call::<(), u32>("get_global_address", ()).unwrap();

    assert_eq!(i.instance.read_memory_into_new_vec(address, 4).unwrap(), [0x00, 0x00, 0x00, 0x00]);

    i.call::<(), ()>("increment_global", ()).unwrap();
    assert_eq!(i.instance.read_memory_into_new_vec(address, 4).unwrap(), [0x01, 0x00, 0x00, 0x00]);

    i.call::<(), ()>("increment_global", ()).unwrap();
    assert_eq!(i.instance.read_memory_into_new_vec(address, 4).unwrap(), [0x02, 0x00, 0x00, 0x00]);

    let ext_increment_global = i.instance.module().lookup_export("increment_global").unwrap();
    {
        let mut state = ();
        let mut call_args = CallArgs::new(&mut state, ext_increment_global);
        call_args.reset_memory_after_call(true);
        i.instance.call(Default::default(), call_args).unwrap();
    }
    assert_eq!(i.instance.read_memory_into_new_vec(address, 4).unwrap(), [0x00, 0x00, 0x00, 0x00]);

    i.call::<(), ()>("increment_global", ()).unwrap();
    assert_eq!(i.instance.read_memory_into_new_vec(address, 4).unwrap(), [0x01, 0x00, 0x00, 0x00]);

    i.call::<(), ()>("increment_global", ()).unwrap();
    assert_eq!(i.instance.read_memory_into_new_vec(address, 4).unwrap(), [0x02, 0x00, 0x00, 0x00]);

    {
        let mut state_args = StateArgs::new();
        state_args.reset_memory(true);
        i.instance.call(state_args, CallArgs::new(&mut (), ext_increment_global)).unwrap();
    }
    assert_eq!(i.instance.read_memory_into_new_vec(address, 4).unwrap(), [0x01, 0x00, 0x00, 0x00]);
}

fn test_blob_out_of_bounds_memory_access_generates_a_trap(config: Config) {
    let i = TestInstance::new(&config);
    let address = i.call::<(), u32>("get_global_address", ()).unwrap();
    assert_eq!(i.call::<(u32,), u32>("read_u32", (address,)).unwrap(), 0);
    i.call::<(), ()>("increment_global", ()).unwrap();
    assert_eq!(i.call::<(u32,), u32>("read_u32", (address,)).unwrap(), 1);
    assert!(matches!(i.call::<(u32,), u32>("read_u32", (4,)), Err(ExecutionError::Trap(..))));

    assert_eq!(i.call::<(u32,), u32>("read_u32", (address,)).unwrap(), 1);
    i.call::<(), ()>("increment_global", ()).unwrap();
    assert_eq!(i.call::<(u32,), u32>("read_u32", (address,)).unwrap(), 2);
}

fn test_blob_call_sbrk_impl(config: Config, mut call_sbrk: impl FnMut(&mut TestInstance, u32) -> u32) {
    let mut i = TestInstance::new(&config);
    let memory_map = i.module.memory_map().clone();
    let heap_base = memory_map.heap_base();
    let page_size = memory_map.page_size();

    assert_eq!(
        i.instance.read_memory_into_new_vec(memory_map.rw_data_range().end - 1, 1).unwrap(),
        vec![0]
    );
    assert!(i.instance.read_memory_into_new_vec(memory_map.rw_data_range().end, 1).is_err());
    assert!(i
        .instance
        .read_memory_into_new_vec(heap_base, memory_map.rw_data_range().end - heap_base)
        .unwrap()
        .iter()
        .all(|&byte| byte == 0));
    assert_eq!(i.instance.heap_size(), 0);

    log::error!("AAA");
    assert_eq!(call_sbrk(&mut i, 0), heap_base);
    log::error!("BBB");
    assert_eq!(i.instance.heap_size(), 0);
    assert_eq!(call_sbrk(&mut i, 0), heap_base);
    assert_eq!(call_sbrk(&mut i, 1), heap_base + 1);
    assert_eq!(i.instance.heap_size(), 1);
    assert_eq!(call_sbrk(&mut i, 0), heap_base + 1);
    assert_eq!(call_sbrk(&mut i, 0xffffffff), 0);
    assert_eq!(call_sbrk(&mut i, 0), heap_base + 1);

    i.instance.write_memory(heap_base, &[0x33]).unwrap();
    assert_eq!(i.instance.read_memory_into_new_vec(heap_base, 1).unwrap(), vec![0x33]);

    let new_origin = align_to_next_page_u32(memory_map.page_size(), heap_base + i.instance.heap_size()).unwrap();
    {
        let until_next_page = new_origin - (heap_base + i.instance.heap_size());
        assert_eq!(call_sbrk(&mut i, until_next_page), new_origin);
    }

    assert_eq!(i.instance.read_memory_into_new_vec(new_origin - 1, 1).unwrap(), vec![0]);
    assert!(i.instance.read_memory_into_new_vec(new_origin, 1).is_err());
    assert!(i.instance.write_memory(new_origin, &[0x34]).is_err());

    assert_eq!(call_sbrk(&mut i, 1), new_origin + 1);
    assert_eq!(
        i.instance.read_memory_into_new_vec(new_origin, page_size).unwrap().len(),
        page_size as usize
    );
    assert!(i.instance.read_memory_into_new_vec(new_origin, page_size + 1).is_err());
    assert!(i.instance.write_memory(new_origin, &[0x35]).is_ok());

    assert_eq!(call_sbrk(&mut i, page_size - 1), new_origin + page_size);
    assert!(i.instance.read_memory_into_new_vec(new_origin, page_size + 1).is_err());

    i.instance.reset_memory().unwrap();
    assert_eq!(call_sbrk(&mut i, 0), heap_base);
    assert_eq!(i.instance.heap_size(), 0);
    assert!(i.instance.read_memory_into_new_vec(memory_map.rw_data_range().end, 1).is_err());

    assert_eq!(call_sbrk(&mut i, 1), heap_base + 1);
    assert_eq!(i.instance.read_memory_into_new_vec(heap_base, 1).unwrap(), vec![0]);
}

fn basic_gas_metering(config: Config, gas_metering_kind: GasMeteringKind) {
    let _ = env_logger::try_init();

    let mut builder = ProgramBlobBuilder::new();
    builder.add_export(ProgramExport::new(0, "main".into()));
    builder.set_code(&[asm::add_imm(A0, A0, 666), asm::ret()]);

    let blob = ProgramBlob::parse(builder.into_vec()).unwrap();
    let engine = Engine::new(&config).unwrap();
    let mut module_config = ModuleConfig::default();
    module_config.set_gas_metering(Some(gas_metering_kind));

    let module = Module::from_blob(&engine, &module_config, &blob).unwrap();
    let linker = Linker::new(&engine);
    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let instance = instance_pre.instantiate().unwrap();
    let ext_main = instance.module().lookup_export("main").unwrap();

    {
        let mut state_args = StateArgs::default();
        state_args.set_gas(Gas::new(2).unwrap());

        instance.call(state_args, CallArgs::new(&mut (), ext_main)).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(0).unwrap());
    }

    {
        let mut state_args = StateArgs::default();
        state_args.set_gas(Gas::new(1).unwrap());

        let result = instance.call(state_args, CallArgs::new(&mut (), ext_main));
        assert!(matches!(result, Err(ExecutionError::OutOfGas)), "unexpected result: {result:?}");
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(0).unwrap());
    }

    {
        let mut state_args = StateArgs::default();
        state_args.set_gas(Gas::new(4).unwrap());

        instance.call(state_args, CallArgs::new(&mut (), ext_main)).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(2).unwrap());

        instance.call(StateArgs::default(), CallArgs::new(&mut (), ext_main)).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(0).unwrap());

        let result = instance.call(StateArgs::default(), CallArgs::new(&mut (), ext_main));
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(0).unwrap());
        assert!(matches!(result, Err(ExecutionError::OutOfGas)), "unexpected result: {result:?}");
    }

    {
        core::mem::drop(instance);
        let instance = instance_pre.instantiate().unwrap();
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(0).unwrap());

        let result = instance.call(StateArgs::default(), CallArgs::new(&mut (), ext_main));
        assert!(matches!(result, Err(ExecutionError::OutOfGas)), "unexpected result: {result:?}");
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(0).unwrap());
    }
}

fn basic_gas_metering_sync(config: Config) {
    basic_gas_metering(config, GasMeteringKind::Sync);
}

fn basic_gas_metering_async(config: Config) {
    basic_gas_metering(config, GasMeteringKind::Async);
}

fn consume_gas_in_host_function(config: Config, gas_metering_kind: GasMeteringKind) {
    let _ = env_logger::try_init();

    let mut builder = ProgramBlobBuilder::new();
    builder.add_export(ProgramExport::new(0, "main".into()));
    builder.add_import(ProgramImport::new("hostfn".into()));
    builder.set_code(&[asm::ecalli(0), asm::ret()]);

    let blob = ProgramBlob::parse(builder.into_vec()).unwrap();
    let engine = Engine::new(&config).unwrap();
    let mut module_config = ModuleConfig::default();
    module_config.set_gas_metering(Some(gas_metering_kind));

    let module = Module::from_blob(&engine, &module_config, &blob).unwrap();
    let mut linker = Linker::new(&engine);
    linker
        .func_wrap("hostfn", |mut caller: Caller<u64>| -> u32 {
            assert_eq!(caller.gas_remaining().unwrap().get(), 1);
            caller.consume_gas(*caller.data());
            666
        })
        .unwrap();

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let instance = instance_pre.instantiate().unwrap();
    let ext_main = instance.module().lookup_export("main").unwrap();

    {
        let mut state_args = StateArgs::default();
        state_args.set_gas(Gas::new(3).unwrap());

        instance.call(state_args, CallArgs::new(&mut 0, ext_main)).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(1).unwrap());
    }

    {
        let mut state_args = StateArgs::default();
        state_args.set_gas(Gas::new(3).unwrap());

        instance.call(state_args, CallArgs::new(&mut 1, ext_main)).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(0).unwrap());
    }

    {
        let mut state_args = StateArgs::default();
        state_args.set_gas(Gas::new(3).unwrap());

        let result = instance.call(state_args, CallArgs::new(&mut 2, ext_main));
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(0).unwrap());
        assert!(matches!(result, Err(ExecutionError::OutOfGas)), "unexpected result: {result:?}");
    }
}

fn consume_gas_in_host_function_sync(config: Config) {
    consume_gas_in_host_function(config, GasMeteringKind::Sync);
}

fn consume_gas_in_host_function_async(config: Config) {
    consume_gas_in_host_function(config, GasMeteringKind::Async);
}

fn gas_metering_with_more_than_one_basic_block(config: Config) {
    let _ = env_logger::try_init();

    let mut builder = ProgramBlobBuilder::new();
    builder.add_export(ProgramExport::new(0, "export_1".into()));
    builder.add_export(ProgramExport::new(1, "export_2".into()));
    builder.set_code(&[
        asm::add_imm(A0, A0, 666),
        asm::ret(),
        asm::add_imm(A0, A0, 666),
        asm::add_imm(A0, A0, 100),
        asm::ret(),
    ]);

    let blob = ProgramBlob::parse(builder.into_vec()).unwrap();
    let engine = Engine::new(&config).unwrap();
    let mut module_config = ModuleConfig::default();
    module_config.set_gas_metering(Some(GasMeteringKind::Sync));

    let module = Module::from_blob(&engine, &module_config, &blob).unwrap();
    let linker = Linker::new(&engine);
    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let instance = instance_pre.instantiate().unwrap();
    let ext_1 = instance.module().lookup_export("export_1").unwrap();
    let ext_2 = instance.module().lookup_export("export_2").unwrap();

    {
        let mut state_args = StateArgs::default();
        state_args.set_gas(Gas::new(10).unwrap());

        instance.call(state_args, CallArgs::new(&mut (), ext_1)).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(8).unwrap());
    }

    {
        let mut state_args = StateArgs::default();
        state_args.set_gas(Gas::new(10).unwrap());

        instance.call(state_args, CallArgs::new(&mut (), ext_2)).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 766);
        assert_eq!(instance.gas_remaining().unwrap(), Gas::new(7).unwrap());
    }
}

fn spawn_stress_test(mut config: Config) {
    let _ = env_logger::try_init();

    let mut builder = ProgramBlobBuilder::new();
    builder.add_export(ProgramExport::new(0, "main".into()));
    builder.set_ro_data_size(1);
    builder.set_rw_data_size(1);
    builder.set_ro_data(vec![0x00]);
    builder.set_code(&[asm::ret()]);

    let blob = ProgramBlob::parse(builder.into_vec()).unwrap();

    for worker_count in [0, 1] {
        config.set_worker_count(worker_count);
        let engine = Engine::new(&config).unwrap();

        let module = Module::from_blob(&engine, &ModuleConfig::default(), &blob).unwrap();
        let ext_main = module.lookup_export("main").unwrap();
        let linker = Linker::new(&engine);
        let instance_pre = linker.instantiate_pre(&module).unwrap();

        const THREAD_COUNT: usize = 32;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREAD_COUNT));

        let mut threads = Vec::new();
        for _ in 0..THREAD_COUNT {
            let instance_pre = instance_pre.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let thread = std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..64 {
                    let instance = instance_pre.instantiate().unwrap();
                    instance.call(Default::default(), CallArgs::new(&mut (), ext_main)).unwrap();
                }
            });
            threads.push(thread);
        }

        let mut results = Vec::new();
        for thread in threads {
            results.push(thread.join());
        }

        for result in results {
            result.unwrap();
        }
    }
}

run_tests! {
    caller_and_caller_ref_work
    caller_split_works
    trapping_from_hostcall_handler_works
    fallback_hostcall_handler_works
    doom_o3_dwarf5
    doom_o1_dwarf5
    doom_o3_dwarf2
    pinky

    test_blob_basic_test
    test_blob_atomic_fetch_add
    test_blob_atomic_fetch_swap
    test_blob_atomic_fetch_minmax
    test_blob_hostcall
    test_blob_define_abi
    test_blob_input_registers
    test_blob_call_sbrk_from_guest
    test_blob_call_sbrk_from_host_instance
    test_blob_call_sbrk_from_host_function
    test_blob_program_memory_can_be_reused_and_cleared
    test_blob_out_of_bounds_memory_access_generates_a_trap

    basic_gas_metering_sync
    basic_gas_metering_async
    consume_gas_in_host_function_sync
    consume_gas_in_host_function_async
    gas_metering_with_more_than_one_basic_block

    spawn_stress_test
}

// Source: https://users.rust-lang.org/t/a-macro-to-assert-that-a-type-does-not-implement-trait-bounds/31179
macro_rules! assert_not_impl {
    ($x:ty, $($t:path),+ $(,)*) => {
        const _: fn() -> () = || {
            struct Check<T: ?Sized>(T);
            trait AmbiguousIfImpl<A> { fn some_item() { } }

            impl<T: ?Sized> AmbiguousIfImpl<()> for Check<T> { }
            impl<T: ?Sized $(+ $t)*> AmbiguousIfImpl<u8> for Check<T> { }

            <Check::<$x> as AmbiguousIfImpl<_>>::some_item()
        };
    };
}

macro_rules! assert_impl {
    ($x:ty, $($t:path),+ $(,)*) => {
        const _: fn() -> () = || {
            struct Check where $x: $($t),+;
        };
    };
}

macro_rules! assert_send_sync {
    ($($x: ty,)+) => {
        $(
            assert_impl!($x, Send);
            assert_impl!($x, Sync);
        )+
    }
}

assert_send_sync! {
    crate::CallArgs<'static, ()>,
    crate::Config,
    crate::Engine,
    crate::Error,
    crate::Gas,
    crate::Instance<()>,
    crate::InstancePre<()>,
    crate::Linker<()>,
    crate::Module,
    crate::ModuleConfig,
    crate::ProgramBlob<'static>,
    crate::StateArgs,
    crate::Trap,
}

assert_not_impl!(crate::Caller<'static, ()>, Send);
assert_not_impl!(crate::Caller<'static, ()>, Sync);
assert_not_impl!(crate::CallerRef<()>, Send);
assert_not_impl!(crate::CallerRef<()>, Sync);
