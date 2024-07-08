use crate::mutex::Mutex;
use crate::{
    Caller, Config, Engine, CallError, GasMeteringKind, Linker, MemoryMap, Module, ModuleConfig,
    ProgramBlob, Reg, Trap, MemoryAccessError,
};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use polkavm_common::program::asm;
use polkavm_common::program::Reg::*;
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

fn basic_test_blob() -> ProgramBlob {
    let memory_map = MemoryMap::new(0x4000, 0, 0x4000, 0).unwrap();
    let mut builder = ProgramBlobBuilder::new();
    builder.set_rw_data_size(0x4000);
    builder.add_export_by_basic_block(0, b"main");
    builder.add_import(b"hostcall");
    builder.set_code(
        &[
            asm::store_imm_u32(memory_map.rw_data_address(), 0x12345678),
            asm::add(S0, A0, A1),
            asm::ecalli(0),
            asm::add(A0, A0, S0),
            asm::ret(),
        ],
        &[],
    );
    ProgramBlob::parse(builder.into_vec().into()).unwrap()
}

fn basic_test(config: Config) {
    let _ = env_logger::try_init();
    let blob = basic_test_blob();
    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &Default::default(), blob).unwrap();
    let mut linker: Linker<State, MemoryAccessError> = Linker::new();

    #[derive(Default)]
    struct State {}

    let address = module.memory_map().rw_data_address();
    linker
        .define_typed("hostcall", move |caller: Caller<State>| -> Result<u32, MemoryAccessError> {
            let value = caller.instance.read_u32(address)?;
            assert_eq!(value, 0x12345678);

            Ok(100)
        })
        .unwrap();

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let mut instance = instance_pre.instantiate().unwrap();
    let mut state = State::default();
    let result = instance.call_typed_and_get_result::<u32, (u32, u32)>(&mut state, "main", (1, 10)).unwrap();

    assert_eq!(result, 111);
}

fn fallback_hostcall_handler_works(config: Config) {
    let _ = env_logger::try_init();
    let blob = basic_test_blob();
    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &Default::default(), blob).unwrap();
    let mut linker = Linker::new();

    linker.define_fallback(move |caller: Caller<()>, num: u32| -> Result<(), Trap> {
        assert_eq!(num, 0);
        caller.instance.set_reg(Reg::A0, 100);
        Ok(())
    });

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let mut instance = instance_pre.instantiate().unwrap();
    let result = instance.call_typed_and_get_result::<u32, (u32, u32)>(&mut (), "main", (1, 10)).unwrap();

    assert_eq!(result, 111);
}

fn decompress_zstd(mut bytes: &[u8]) -> Vec<u8> {
    use ruzstd::io::Read;
    let mut output = Vec::new();
    let mut fp = ruzstd::streaming_decoder::StreamingDecoder::new(&mut bytes).unwrap();

    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let count = fp.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }

        output.extend_from_slice(&buffer);
    }

    output
}

static BLOB_MAP: Mutex<Option<BTreeMap<&'static [u8], ProgramBlob>>> = Mutex::new(None);

fn get_blob(elf: &'static [u8]) -> ProgramBlob {
    let mut blob_map = BLOB_MAP.lock();
    let blob_map = blob_map.get_or_insert_with(BTreeMap::new);
    blob_map
        .entry(elf)
        .or_insert_with(|| {
            // This is slow, so cache it.
            let elf = decompress_zstd(elf);
            let bytes = polkavm_linker::program_from_elf(Default::default(), &elf).unwrap();
            ProgramBlob::parse(bytes.into()).unwrap()
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
    let mut module_config = ModuleConfig::default();
    module_config.set_page_size(16 * 1024); // TODO: Also test with other page sizes.
    let module = Module::from_blob(&engine, &module_config, blob).unwrap();
    let mut linker: Linker<State, String> = Linker::new();

    struct State {
        frame: Vec<u8>,
        frame_width: u32,
        frame_height: u32,
    }

    linker
        .define_typed(
            "ext_output_video",
            |caller: Caller<State>, address: u32, width: u32, height: u32| -> Result<(), String> {
                let length = width * height * 4;
                caller.user_data.frame.clear();
                caller.user_data.frame.reserve(length as usize);
                caller.instance.read_memory_into(address, &mut caller.user_data.frame.spare_capacity_mut()[..length as usize]).map_err(|err| err.to_string())?;
                // SAFETY: We've successfully read this many bytes into this Vec.
                unsafe {
                    caller.user_data.frame.set_len(length as usize);
                }
                caller.user_data.frame_width = width;
                caller.user_data.frame_height = height;
                Ok(())
            },
        )
        .unwrap();

    linker
        .define_typed(
            "ext_output_audio",
            |_caller: Caller<State>, _address: u32, _samples: u32| {},
        )
        .unwrap();

    linker
        .define_typed("ext_rom_size", |_caller: Caller<State>| -> u32 { DOOM_WAD.len() as u32 })
        .unwrap();

    linker
        .define_typed(
            "ext_rom_read",
            |caller: Caller<State>, pointer: u32, offset: u32, length: u32| -> Result<(), String> {
                let chunk = DOOM_WAD
                    .get(offset as usize..offset as usize + length as usize)
                    .ok_or_else(|| format!("invalid ROM read: offset = 0x{offset:x}, length = {length}"))?;

                caller.instance.write_memory(pointer, chunk).map_err(|err| err.to_string())
            },
        )
        .unwrap();

    linker
        .define_typed(
            "ext_stdout",
            |_caller: Caller<State>, _buffer: u32, length: u32| -> i32 { length as i32 },
        )
        .unwrap();

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let mut instance = instance_pre.instantiate().unwrap();

    let mut state = State {
        frame: Vec::new(),
        frame_width: 0,
        frame_height: 0,
    };

    instance.call_typed(&mut state, "ext_initialize", ()).unwrap();
    for nth_frame in 0..=10440 {
        instance.call_typed(&mut state, "ext_tick", ()).unwrap();

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
    let module = Module::from_blob(&engine, &Default::default(), blob).unwrap();
    let linker: Linker = Linker::new();
    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let mut instance = instance_pre.instantiate().unwrap();

    instance.call_typed(&mut (), "initialize", ()).unwrap();
    for _ in 0..256 {
        instance.call_typed(&mut (), "run", ()).unwrap();
    }

    let address: u32 = instance.call_typed_and_get_result(&mut (), "get_framebuffer", ()).unwrap();
    let framebuffer = instance.read_memory(address, 256 * 240 * 4).unwrap();

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
    instance: crate::Instance,
}

impl TestInstance {
    fn new(config: &Config) -> Self {
        let _ = env_logger::try_init();
        let blob = get_blob(include_bytes!("../../../test-data/test-blob.elf.zst"));

        let engine = Engine::new(config).unwrap();
        let module = Module::from_blob(&engine, &Default::default(), blob).unwrap();
        let mut linker = Linker::new();
        linker
            .define_typed("multiply_by_2", |_caller: Caller<()>, value: u32| -> u32 {
                value * 2
            })
            .unwrap();

        linker
            .define_typed("identity", |_caller: Caller<()>, value: u32| -> u32 { value })
            .unwrap();

        linker
            .define_untyped("multiply_all_input_registers", |caller: Caller<()>| {
                let mut value = 1;

                use Reg as R;
                for reg in [R::A0, R::A1, R::A2, R::A3, R::A4, R::A5, R::T0, R::T1, R::T2] {
                    value *= caller.instance.reg(reg);
                }

                caller.instance.set_reg(Reg::A0, value);
                Ok(())
            })
            .unwrap();

        linker
            .define_typed("call_sbrk_indirectly_impl", |caller: Caller<()>, size: u32| -> u32 {
                caller.instance.sbrk(size).unwrap_or(0)
            })
            .unwrap();

        let instance_pre = linker.instantiate_pre(&module).unwrap();
        let instance = instance_pre.instantiate().unwrap();

        TestInstance { module, instance }
    }

    pub fn call<FnArgs, FnResult>(&mut self, name: &str, args: FnArgs) -> Result<FnResult, crate::CallError>
    where
        FnArgs: crate::linker::FuncArgs,
        FnResult: crate::linker::FuncResult,
    {
        self.instance.call_typed_and_get_result::<FnResult, FnArgs>(&mut (), name, args)
    }
}

fn test_blob_basic_test(config: Config) {
    let mut i = TestInstance::new(&config);
    assert_eq!(i.call::<(), u32>("push_one_to_global_vec", ()).unwrap(), 1);
    assert_eq!(i.call::<(), u32>("push_one_to_global_vec", ()).unwrap(), 2);
    assert_eq!(i.call::<(), u32>("push_one_to_global_vec", ()).unwrap(), 3);
}

fn test_blob_atomic_fetch_add(config: Config) {
    let mut i = TestInstance::new(&config);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (1,)).unwrap(), 0);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (1,)).unwrap(), 1);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (1,)).unwrap(), 2);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (0,)).unwrap(), 3);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (0,)).unwrap(), 3);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (2,)).unwrap(), 3);
    assert_eq!(i.call::<(u32,), u32>("atomic_fetch_add", (0,)).unwrap(), 5);
}

fn test_blob_atomic_fetch_swap(config: Config) {
    let mut i = TestInstance::new(&config);
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

    let mut i = TestInstance::new(&config);
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
    let mut i = TestInstance::new(&config);
    assert_eq!(i.call::<(u32,), u32>("test_multiply_by_6", (10,)).unwrap(), 60);
}

fn test_blob_define_abi(config: Config) {
    let mut i = TestInstance::new(&config);
    assert!(i.call::<(), ()>("test_define_abi", ()).is_ok());
}

fn test_blob_input_registers(config: Config) {
    let mut i = TestInstance::new(&config);
    assert!(i.call::<(), ()>("test_input_registers", ()).is_ok());
}

fn test_blob_call_sbrk_from_guest(config: Config) {
    test_blob_call_sbrk_impl(config, |i, size| i.call::<(u32,), u32>("call_sbrk", (size,)).unwrap())
}

fn test_blob_call_sbrk_from_host_instance(config: Config) {
    test_blob_call_sbrk_impl(config, |i, size| i.instance.sbrk(size).unwrap_or(0))
}

fn test_blob_call_sbrk_from_host_function(config: Config) {
    test_blob_call_sbrk_impl(config, |i, size| i.call::<(u32,), u32>("call_sbrk_indirectly", (size,)).unwrap())
}

fn test_blob_program_memory_can_be_reused_and_cleared(config: Config) {
    let mut i = TestInstance::new(&config);
    let address = i.call::<(), u32>("get_global_address", ()).unwrap();

    assert_eq!(i.instance.read_memory(address, 4).unwrap(), [0x00, 0x00, 0x00, 0x00]);

    i.call::<(), ()>("increment_global", ()).unwrap();
    assert_eq!(i.instance.read_memory(address, 4).unwrap(), [0x01, 0x00, 0x00, 0x00]);

    i.call::<(), ()>("increment_global", ()).unwrap();
    assert_eq!(i.instance.read_memory(address, 4).unwrap(), [0x02, 0x00, 0x00, 0x00]);

    i.instance.reset_memory();
    assert_eq!(i.instance.read_memory(address, 4).unwrap(), [0x00, 0x00, 0x00, 0x00]);

    i.call::<(), ()>("increment_global", ()).unwrap();
    assert_eq!(i.instance.read_memory(address, 4).unwrap(), [0x01, 0x00, 0x00, 0x00]);
}

fn test_blob_out_of_bounds_memory_access_generates_a_trap(config: Config) {
    let mut i = TestInstance::new(&config);
    let address = i.call::<(), u32>("get_global_address", ()).unwrap();
    assert_eq!(i.call::<(u32,), u32>("read_u32", (address,)).unwrap(), 0);
    i.call::<(), ()>("increment_global", ()).unwrap();
    assert_eq!(i.call::<(u32,), u32>("read_u32", (address,)).unwrap(), 1);
    assert!(matches!(i.call::<(u32,), u32>("read_u32", (4,)), Err(CallError::Trap)));

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
        i.instance.read_memory(memory_map.rw_data_range().end - 1, 1).unwrap(),
        vec![0]
    );
    assert!(i.instance.read_memory(memory_map.rw_data_range().end, 1).is_err());
    assert!(i
        .instance
        .read_memory(heap_base, memory_map.rw_data_range().end - heap_base)
        .unwrap()
        .iter()
        .all(|&byte| byte == 0));
    assert_eq!(i.instance.heap_size(), 0);

    assert_eq!(call_sbrk(&mut i, 0), heap_base);
    assert_eq!(i.instance.heap_size(), 0);
    assert_eq!(call_sbrk(&mut i, 0), heap_base);
    assert_eq!(call_sbrk(&mut i, 1), heap_base + 1);
    assert_eq!(i.instance.heap_size(), 1);
    assert_eq!(call_sbrk(&mut i, 0), heap_base + 1);
    assert_eq!(call_sbrk(&mut i, 0xffffffff), 0);
    assert_eq!(call_sbrk(&mut i, 0), heap_base + 1);

    i.instance.write_memory(heap_base, &[0x33]).unwrap();
    assert_eq!(i.instance.read_memory(heap_base, 1).unwrap(), vec![0x33]);

    let new_origin = align_to_next_page_u32(memory_map.page_size(), heap_base + i.instance.heap_size()).unwrap();
    {
        let until_next_page = new_origin - (heap_base + i.instance.heap_size());
        assert_eq!(call_sbrk(&mut i, until_next_page), new_origin);
    }

    assert_eq!(i.instance.read_memory(new_origin - 1, 1).unwrap(), vec![0]);
    assert!(i.instance.read_memory(new_origin, 1).is_err());
    assert!(i.instance.write_memory(new_origin, &[0x34]).is_err());

    assert_eq!(call_sbrk(&mut i, 1), new_origin + 1);
    assert_eq!(
        i.instance.read_memory(new_origin, page_size).unwrap().len(),
        page_size as usize
    );
    assert!(i.instance.read_memory(new_origin, page_size + 1).is_err());
    assert!(i.instance.write_memory(new_origin, &[0x35]).is_ok());

    assert_eq!(call_sbrk(&mut i, page_size - 1), new_origin + page_size);
    assert!(i.instance.read_memory(new_origin, page_size + 1).is_err());

    i.instance.reset_memory();
    assert_eq!(call_sbrk(&mut i, 0), heap_base);
    assert_eq!(i.instance.heap_size(), 0);
    assert!(i.instance.read_memory(memory_map.rw_data_range().end, 1).is_err());

    assert_eq!(call_sbrk(&mut i, 1), heap_base + 1);
    assert_eq!(i.instance.read_memory(heap_base, 1).unwrap(), vec![0]);
}

fn basic_gas_metering(config: Config, gas_metering_kind: GasMeteringKind) {
    let _ = env_logger::try_init();

    let mut builder = ProgramBlobBuilder::new();
    builder.add_export_by_basic_block(0, b"main");
    builder.set_code(&[asm::add_imm(A0, A0, 666), asm::ret()], &[]);

    let blob = ProgramBlob::parse(builder.into_vec().into()).unwrap();
    let engine = Engine::new(&config).unwrap();
    let mut module_config = ModuleConfig::default();
    module_config.set_gas_metering(Some(gas_metering_kind));

    let module = Module::from_blob(&engine, &module_config, blob).unwrap();
    let linker: Linker = Linker::new();
    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let mut instance = instance_pre.instantiate().unwrap();

    {
        instance.set_gas(2);
        instance.call_typed(&mut (), "main", ()).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas(), 0);
    }

    {
        instance.set_gas(1);
        let result = instance.call_typed(&mut (), "main", ());
        assert!(matches!(result, Err(CallError::NotEnoughGas)), "unexpected result: {result:?}");
        assert_eq!(instance.gas(), -1);

        let result = instance.call_typed(&mut (), "main", ());
        assert!(matches!(result, Err(CallError::NotEnoughGas)), "unexpected result: {result:?}");
        assert_eq!(instance.gas(), -1);
    }

    {
        instance.set_gas(4);
        instance.call_typed(&mut (), "main", ()).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas(), 2);

        instance.call_typed(&mut (), "main", ()).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas(), 0);

        let result = instance.call_typed(&mut (), "main", ());
        assert_eq!(instance.gas(), -2);
        assert!(matches!(result, Err(CallError::NotEnoughGas)), "unexpected result: {result:?}");
    }

    {
        core::mem::drop(instance);
        let mut instance = instance_pre.instantiate().unwrap();
        assert_eq!(instance.gas(), 0);

        let result = instance.call_typed(&mut (), "main", ());
        assert!(matches!(result, Err(CallError::NotEnoughGas)), "unexpected result: {result:?}");
        assert_eq!(instance.gas(), -2);
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
    builder.add_export_by_basic_block(0, b"main");
    builder.add_import(b"hostfn");
    builder.set_code(&[asm::ecalli(0), asm::ret()], &[]);

    let blob = ProgramBlob::parse(builder.into_vec().into()).unwrap();
    let engine = Engine::new(&config).unwrap();
    let mut module_config = ModuleConfig::default();
    module_config.set_gas_metering(Some(gas_metering_kind));

    let module = Module::from_blob(&engine, &module_config, blob).unwrap();
    let mut linker: Linker<i64, core::convert::Infallible> = Linker::new();
    linker
        .define_typed("hostfn", |caller: Caller<i64>| -> u32 {
            assert_eq!(caller.instance.gas(), 1);
            caller.instance.set_gas(1 - *caller.user_data);
            666
        })
        .unwrap();

    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let mut instance = instance_pre.instantiate().unwrap();

    {
        instance.set_gas(3);
        instance.call_typed(&mut 0, "main", ()).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas(), 1);
    }

    {
        instance.set_gas(3);
        instance.call_typed(&mut 1, "main", ()).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas(), 0);
    }

    {
        instance.set_gas(3);
        let result = instance.call_typed(&mut 2, "main", ());
        assert_eq!(instance.gas(), -1);
        assert!(matches!(result, Err(CallError::NotEnoughGas)), "unexpected result: {result:?}");
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
    builder.add_export_by_basic_block(0, b"export_1");
    builder.add_export_by_basic_block(1, b"export_2");
    builder.set_code(
        &[
            asm::add_imm(A0, A0, 666),
            asm::ret(),
            asm::add_imm(A0, A0, 666),
            asm::add_imm(A0, A0, 100),
            asm::ret(),
        ],
        &[],
    );

    let blob = ProgramBlob::parse(builder.into_vec().into()).unwrap();
    let engine = Engine::new(&config).unwrap();
    let mut module_config = ModuleConfig::default();
    module_config.set_gas_metering(Some(GasMeteringKind::Sync));

    let module = Module::from_blob(&engine, &module_config, blob).unwrap();
    let linker: Linker = Linker::new();
    let instance_pre = linker.instantiate_pre(&module).unwrap();
    let mut instance = instance_pre.instantiate().unwrap();

    {
        instance.set_gas(10);
        instance.call_typed(&mut (), "export_1", ()).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 666);
        assert_eq!(instance.gas(), 8);
    }

    {
        instance.set_gas(10);
        instance.call_typed(&mut (), "export_2", ()).unwrap();
        assert_eq!(instance.get_result_typed::<i32>(), 766);
        assert_eq!(instance.gas(), 7);
    }
}

#[cfg(not(feature = "std"))]
fn spawn_stress_test(_config: Config) {}

#[cfg(feature = "std")]
fn spawn_stress_test(mut config: Config) {
    let _ = env_logger::try_init();

    let mut builder = ProgramBlobBuilder::new();
    builder.add_export_by_basic_block(0, b"main");
    builder.set_ro_data_size(1);
    builder.set_rw_data_size(1);
    builder.set_ro_data(vec![0x00]);
    builder.set_code(&[asm::ret()], &[]);

    let blob = ProgramBlob::parse(builder.into_vec().into()).unwrap();

    for worker_count in [0, 1] {
        config.set_worker_count(worker_count);
        let engine = Engine::new(&config).unwrap();

        let module = Module::from_blob(&engine, &ModuleConfig::default(), blob.clone()).unwrap();
        let linker: Linker = Linker::new();
        let instance_pre = linker.instantiate_pre(&module).unwrap();

        const THREAD_COUNT: usize = 32;
        let barrier = alloc::sync::Arc::new(std::sync::Barrier::new(THREAD_COUNT));

        let mut threads = Vec::new();
        for _ in 0..THREAD_COUNT {
            let instance_pre = instance_pre.clone();
            let barrier = alloc::sync::Arc::clone(&barrier);
            let thread = std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..64 {
                    let mut instance = instance_pre.instantiate().unwrap();
                    instance.call_typed(&mut (), "main", ()).unwrap();
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
    basic_test
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
    crate::Config,
    crate::Engine,
    crate::Error,
    crate::Gas,
    crate::Instance<(), ()>,
    crate::InstancePre<(), ()>,
    crate::Linker<(), ()>,
    crate::Module,
    crate::ModuleConfig,
    crate::ProgramBlob,
    crate::Trap,
}
