use super::backend_prelude::*;
use object::{Object, ObjectSection};

use solana_rbpf::{
    aligned_memory::AlignedMemory,
    ebpf,
    elf::Executable,
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    vm::{Config, ContextObject, EbpfVm},
};
use std::sync::Arc;

pub const fn align_to_next_page_size(value: usize) -> usize {
    const PAGE_SIZE: usize = 4096;
    if value & (PAGE_SIZE - 1) == 0 {
        value
    } else if value <= usize::MAX - PAGE_SIZE {
        (value + PAGE_SIZE) & !(PAGE_SIZE - 1)
    } else {
        unreachable!()
    }
}

pub struct Ctx;

fn static_ctx() -> &'static mut Ctx {
    static mut CTX: Ctx = Ctx;
    unsafe { &mut *core::ptr::addr_of_mut!(CTX) }
}

impl ContextObject for Ctx {
    fn trace(&mut self, _state: [u64; 12]) {}
    fn consume(&mut self, _amount: u64) {}
    fn get_remaining(&self) -> u64 {
        u64::MAX
    }
}

#[derive(Copy, Clone)]
pub struct SolanaRbpf();

pub struct SolanaBlob {
    elf: Vec<u8>,
    data_size: u64,
}

pub struct SolanaModule {
    data_size: u64,
    executable: Arc<Executable<Ctx>>,
}

pub struct SolanaInstance {
    vm: EbpfVm<'static, Ctx>,
    executable: Arc<Executable<Ctx>>,
    _stack: AlignedMemory<{ ebpf::HOST_ALIGN }>,
    _heap: AlignedMemory<{ ebpf::HOST_ALIGN }>,
    _input: AlignedMemory<{ ebpf::HOST_ALIGN }>,
}

impl Backend for SolanaRbpf {
    type Engine = Arc<BuiltinProgram<Ctx>>;
    type Blob = SolanaBlob;
    type Module = SolanaModule;
    type Instance = SolanaInstance;

    fn name(&self) -> &'static str {
        "solana_rbpf"
    }

    fn create(&self, _args: CreateArgs) -> Self::Engine {
        let config = Config {
            enable_instruction_meter: false,
            ..Config::default()
        };
        let registry = FunctionRegistry::default();
        Arc::new(BuiltinProgram::<Ctx>::new_loader(config, registry))
    }

    fn load(&self, path: &Path) -> Self::Blob {
        let elf = std::fs::read(path).unwrap();
        let obj = object::File::parse(&*elf).unwrap();

        let mut data_size = 0;
        if let Some(section) = obj.section_by_name(".heap_size") {
            let xs = section.data().unwrap();
            data_size = u64::from_le_bytes([xs[0], xs[1], xs[2], xs[3], xs[4], xs[5], xs[6], xs[7]]);
        }

        SolanaBlob { elf, data_size }
    }

    fn compile(&self, loader: &mut Self::Engine, blob: &Self::Blob) -> Self::Module {
        let mut executable = Executable::load(&blob.elf, loader.clone()).unwrap();
        executable.verify::<solana_rbpf::verifier::RequisiteVerifier>().unwrap();
        executable.jit_compile().unwrap();

        SolanaModule {
            data_size: blob.data_size,
            executable: Arc::new(executable),
        }
    }

    fn spawn(&self, _engine: &mut Self::Engine, module: &Self::Module) -> Self::Instance {
        let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(module.executable.get_config().stack_size());
        let stack_len = stack.len();
        let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(align_to_next_page_size(module.data_size as usize));
        let mut input = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(align_to_next_page_size(1));

        let regions: Vec<MemoryRegion> = vec![
            module.executable.get_ro_region(),
            MemoryRegion::new_writable(stack.as_slice_mut(), ebpf::MM_STACK_START),
            MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
            MemoryRegion::new_writable(input.as_slice_mut(), ebpf::MM_INPUT_START),
        ];

        let config: &Config = module.executable.get_config();
        let sbpf_version: &SBPFVersion = module.executable.get_sbpf_version();

        // For some inexplicable reason these are stored in `EbpfVm` by reference (even though they could have easily been `Clone`d), so let's fake a 'static lifetime here.
        let config: &Config = unsafe { core::mem::transmute(config) };
        let sbpf_version: &SBPFVersion = unsafe { core::mem::transmute(sbpf_version) };

        let memory_mapping = MemoryMapping::new(regions, config, sbpf_version).unwrap();
        let vm = EbpfVm::new(
            module.executable.get_loader().clone(),
            module.executable.get_sbpf_version(),
            static_ctx(),
            memory_mapping,
            stack_len,
        );

        SolanaInstance {
            vm,
            executable: module.executable.clone(),

            // ...and these must be kept alive, because the `EbpfVm` stores a reference to the memory these own while ignoring their lifetimes,
            // so if we drop them we'll get a segfault (in 100% safe Rust code, nice!).
            _stack: stack,
            _heap: heap,
            _input: input,
        }
    }

    fn initialize(&self, instance: &mut Self::Instance) {
        instance.vm.memory_mapping.store(0_u8, ebpf::MM_INPUT_START);
        let (_, result) = instance.vm.execute_program(&instance.executable, false);
        if let solana_rbpf::error::StableResult::Err(error) = result {
            panic!("failed to initialize benchmark: {error:?}");
        }
    }

    fn run(&self, instance: &mut Self::Instance) {
        instance.vm.memory_mapping.store(1_u8, ebpf::MM_INPUT_START);
        let (_, result) = instance.vm.execute_program(&instance.executable, false);
        assert!(result.is_ok());
    }

    fn is_compiled(&self) -> bool {
        true
    }
}
