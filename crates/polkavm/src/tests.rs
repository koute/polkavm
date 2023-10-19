use crate::{Caller, CallerRef, Config, Engine, ExecutionError, Linker, Module, ProgramBlob, Reg, Trap, Val};
use std::cell::RefCell;
use std::rc::Rc;

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

// TODO: Add a dedicated test blob.
const RAW_BLOB: &[u8] = include_bytes!("../../../guest-programs/output/example-hello-world.polkavm");

fn caller_and_caller_ref_work(config: Config) {
    let _ = env_logger::try_init();
    let blob = ProgramBlob::parse(RAW_BLOB).unwrap();
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

fn caller_split_works(config: Config) {
    let _ = env_logger::try_init();
    let blob = ProgramBlob::parse(RAW_BLOB).unwrap();
    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &blob).unwrap();
    let mut linker = Linker::new(&engine);

    #[derive(Default)]
    struct State {
        value: u32,
    }

    linker
        .func_wrap("get_third_number", move |caller: Caller<State>| -> Result<u32, Trap> {
            {
                let value = caller.read_u32(polkavm_common::abi::VM_ADDR_USER_STACK_HIGH - 4)?;
                assert_eq!(value, polkavm_common::abi::VM_ADDR_RETURN_TO_HOST);
            }
            {
                let (caller, state) = caller.split();
                state.value = caller.read_u32(polkavm_common::abi::VM_ADDR_USER_STACK_HIGH - 4)?;
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
    assert_eq!(state.value, polkavm_common::abi::VM_ADDR_RETURN_TO_HOST);
}

fn trapping_from_hostcall_handler_works(config: Config) {
    let _ = env_logger::try_init();
    let blob = ProgramBlob::parse(RAW_BLOB).unwrap();
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

fn doom(config: Config, elf: &'static [u8]) {
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn decompress_zstd(mut bytes: &[u8]) -> Vec<u8> {
        use std::io::Read;
        let mut output = Vec::new();
        ruzstd::streaming_decoder::StreamingDecoder::new(&mut bytes)
            .unwrap()
            .read_to_end(&mut output)
            .unwrap();
        output
    }

    if config.backend() == Some(crate::BackendKind::Interpreter) || config.trace_execution() {
        // The interpreter is currently too slow to run doom.
        return;
    }

    if cfg!(debug_assertions) {
        // The linker is currently very slow in debug mode.
        return;
    }

    const DOOM_WAD: &[u8] = include_bytes!("../../../examples/doom/roms/doom1.wad");
    static DOOM_BLOB_MAP: Mutex<Option<HashMap<&'static [u8], ProgramBlob>>> = Mutex::new(None);

    let _ = env_logger::try_init();
    let mut blob_map = match DOOM_BLOB_MAP.lock() {
        Ok(blob_map) => blob_map,
        Err(error) => error.into_inner(),
    };

    let blob_map = blob_map.get_or_insert_with(HashMap::new);
    let blob = blob_map.entry(elf).or_insert_with(|| {
        // This is slow, so cache it.
        let elf = decompress_zstd(elf);
        let blob = polkavm_linker::program_from_elf(Default::default(), &elf).unwrap();
        blob.into_owned()
    });

    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, blob).unwrap();
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
    let ext_initialize = instance.get_typed_func::<(), ()>("ext_initialize").unwrap();
    let ext_tick = instance.get_typed_func::<(), ()>("ext_tick").unwrap();

    let mut state = State {
        frame: Vec::new(),
        frame_width: 0,
        frame_height: 0,
    };

    ext_initialize.call(&mut state, ()).unwrap();
    for nth_frame in 0..=10440 {
        ext_tick.call(&mut state, ()).unwrap();

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

run_tests! {
    caller_and_caller_ref_work
    caller_split_works
    trapping_from_hostcall_handler_works
    doom_o3_dwarf5
    doom_o1_dwarf5
    doom_o3_dwarf2
}
