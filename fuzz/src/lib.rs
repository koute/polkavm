use std::collections::BTreeSet;
use std::sync::OnceLock;

use arbitrary::{Result, Unstructured};
use polkavm::{
    BackendKind, CacheModel, Config, CostModel, CostModelKind, Engine, GasMeteringKind, InterruptKind, MemoryProtection, Module,
    ModuleConfig, ProgramCounter, RawInstance, Segfault, SetCacheSizeLimitArgs, RETURN_TO_HOST,
};
use polkavm_common::abi::{MemoryMap, MemoryMapBuilder, VM_ADDR_RETURN_TO_HOST, VM_CODE_ADDRESS_ALIGNMENT};
use polkavm_common::program::{Instruction, InstructionSet, InstructionSetKind, Opcode, ProgramBlob, ProgramParts, Reg};
use polkavm_common::writer::ProgramBlobBuilder;

pub const ISAS: [InstructionSetKind; 2] = [InstructionSetKind::ReviveV1, InstructionSetKind::Latest64];
const PAGE_SIZES: [u32; 5] = [0x1000, 0x2000, 0x4000, 0x8000, 0x10000];
const MAX_INSTRUCTIONS: u32 = 512;
const MAX_JUMP_TABLE_ENTRIES: u32 = 16;
const MAX_INTERRUPTS: usize = 1024;
const MAX_GAS: i64 = 100_000;
const TOP_PAGE_END: u64 = 0x100000000;
const MAX_REUSES: usize = 2;
pub const SETUP_LENGTH: usize = 64;
pub const RAW_CONTAINER_FLAG: u8 = 0x80;

fn arbitrary_bytes(u: &mut Unstructured, max_length: u32) -> Result<Vec<u8>> {
    let length = (u.int_in_range(0..=max_length)? as usize).min(u.len());
    Ok(u.bytes(length)?.to_vec())
}

pub fn is_in_scope(isa: InstructionSetKind, opcode: Opcode) -> bool {
    isa.supports_opcode(opcode) && !matches!(opcode, Opcode::memset | Opcode::sbrk)
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    Crosscheck,
    Pair,
}

#[derive(Copy, Clone, Debug)]
pub enum CostModelChoice {
    Naive,
    Full(u8),
}

impl CostModelChoice {
    fn to_cost_model(self) -> CostModelKind {
        match self {
            CostModelChoice::Naive => CostModelKind::Simple(CostModel::naive_ref()),
            CostModelChoice::Full(0) => CostModelKind::Full(CacheModel::L1Hit),
            CostModelChoice::Full(1) => CostModelKind::Full(CacheModel::L2Hit),
            CostModelChoice::Full(_) => CostModelKind::Full(CacheModel::L3Hit),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Setup {
    pub isa: InstructionSetKind,
    pub mode: Mode,
    pub dynamic_paging: bool,
    pub page_size: u32,
    pub gas_metering: Option<GasMeteringKind>,
    pub cost_model: CostModelChoice,
    pub cache_limit: Option<(usize, u32)>,
    pub ro_data_size: u32,
    pub ro_data: Vec<u8>,
    pub rw_data_size: u32,
    pub rw_data: Vec<u8>,
    pub stack_size: u32,
    pub aux_data_size: u32,
    pub accessible_aux_size: u32,
    pub is_strict: bool,
}

impl Setup {
    pub fn arbitrary(u: &mut Unstructured) -> Result<Self> {
        let isa = *u.choose(&ISAS)?;
        let gas_metering = match u.int_in_range(0..=15)? {
            0..=12 => Some(GasMeteringKind::Sync),
            _ => None,
        };

        let mode = if u.arbitrary()? { Mode::Crosscheck } else { Mode::Pair };

        let dynamic_paging = u.arbitrary()?;
        let page_size = *u.choose(&PAGE_SIZES)?;
        let page_size = if dynamic_paging { PAGE_SIZES[0] } else { page_size };
        let cost_model = match u.int_in_range(0..=3)? {
            0 => CostModelChoice::Naive,
            index => CostModelChoice::Full(index - 1),
        };

        let has_cache_limit = u.arbitrary::<u8>()? >= 170;
        let is_cache_small = u.arbitrary::<bool>()?;
        let max_cache_size_bytes: usize = u.int_in_range(0..=0x100000)?;
        let max_cache_size_bytes = if is_cache_small {
            max_cache_size_bytes % 0x4001
        } else {
            max_cache_size_bytes
        };
        let extra_block_size = u.int_in_range(0..=1000)?;
        let cache_limit = has_cache_limit.then_some((max_cache_size_bytes, extra_block_size));

        let ro_data_size = u.int_in_range(0..=0x4000)?;
        let rw_data_size = u.int_in_range(0..=0x4000)?;
        let stack_size = u.int_in_range(0..=0x10000)?;
        let aux_data_size = u.int_in_range(0..=0x10000)?;
        let aux_data_size = if dynamic_paging { 0 } else { aux_data_size };
        let accessible_aux_size = u.int_in_range(0..=0x10000)? % (aux_data_size + 1);
        let is_strict = u.arbitrary()?;
        let ro_data = arbitrary_bytes(u, ro_data_size.min(256))?;
        let rw_data = arbitrary_bytes(u, rw_data_size.min(256))?;

        Ok(Setup {
            isa,
            mode,
            dynamic_paging,
            page_size,
            gas_metering,
            cost_model,
            cache_limit,
            ro_data_size,
            ro_data,
            rw_data_size,
            rw_data,
            stack_size,
            aux_data_size,
            accessible_aux_size,
            is_strict,
        })
    }

    fn memory_map_builder(&self) -> MemoryMapBuilder {
        let mut builder = MemoryMapBuilder::new(self.page_size);
        builder
            .ro_data_size(self.ro_data_size)
            .rw_data_size(self.rw_data_size)
            .stack_size(self.stack_size)
            .aux_data_size(self.aux_data_size);
        builder
    }

    pub fn memory_map(&self) -> MemoryMap {
        self.memory_map_builder()
            .build()
            .expect("the generated memory configuration is invalid")
    }

    fn module_config(&self) -> ModuleConfig {
        let mut config = ModuleConfig::new();
        config.set_page_size(self.page_size);
        config.set_gas_metering(self.gas_metering);
        config.set_dynamic_paging(self.dynamic_paging);
        config.set_aux_data_size(self.aux_data_size);
        config.set_cost_model(Some(self.cost_model.to_cost_model()));
        config.set_strict(self.is_strict);
        config
    }
}

struct Addresses {
    map: MemoryMap,
    pages: Vec<u32>,
    jump_table_length: u32,
}

impl Addresses {
    fn new(u: &mut Unstructured, setup: &Setup, jump_table_length: u32) -> Result<Self> {
        let map = setup.memory_map();
        let mut pages = vec![map.ro_data_address(), map.rw_data_address(), map.stack_address_low()];
        for _ in 0..u.int_in_range(0..=4)? {
            pages.push(0x10000 + setup.page_size * u.int_in_range(0..=0xfffe_0000 / setup.page_size)?);
        }

        Ok(Addresses {
            map,
            pages,
            jump_table_length,
        })
    }

    fn memory_address(&self, u: &mut Unstructured) -> Result<u32> {
        let page_size = self.map.page_size();
        let offset = u.int_in_range(0..=page_size + 8)?;
        let address = match u.int_in_range(0..=9)? {
            0 => self.map.ro_data_address().wrapping_add(offset),
            1 => self.map.rw_data_address().wrapping_add(offset),
            2 => self
                .map
                .heap_base()
                .wrapping_add(self.map.rw_data_size())
                .wrapping_sub(u.int_in_range(1..=8)?),
            3 => self.map.stack_address_high().wrapping_sub(offset),
            4 => self.map.stack_address_low().wrapping_add(offset),
            5 => self.map.aux_data_address().wrapping_add(offset),
            6 => u.choose(&self.pages)?.wrapping_add(page_size).wrapping_sub(u.int_in_range(1..=8)?),
            7 => u.choose(&self.pages)?.wrapping_add(offset),
            8 => u.int_in_range(0..=0xffff)?,
            _ => u.arbitrary()?,
        };

        Ok(address)
    }

    fn jump_address(&self, u: &mut Unstructured) -> Result<u32> {
        let length = self.jump_table_length;
        let valid = (u.int_in_range(0..=length.saturating_sub(1))? + 1) * VM_CODE_ADDRESS_ALIGNMENT;
        let address = match u.int_in_range(0..=6)? {
            0..=2 => valid,
            3 => 0,
            4 => valid + 1,
            5 => (length + 1 + u.int_in_range(0..=2)?) * VM_CODE_ADDRESS_ALIGNMENT,
            _ => VM_ADDR_RETURN_TO_HOST + u.int_in_range(0..=4)? * VM_CODE_ADDRESS_ALIGNMENT,
        };

        Ok(address)
    }

    fn value(&self, u: &mut Unstructured) -> Result<u64> {
        let value = match u.int_in_range(0..=3)? {
            0 => u64::from(self.memory_address(u)?),
            1 => u64::from(self.jump_address(u)?),
            2 => 0,
            _ => u.arbitrary()?,
        };

        Ok(value)
    }

    fn small_offset(u: &mut Unstructured) -> Result<i32> {
        u.int_in_range(-16..=16)
    }

    fn fix_up(&self, u: &mut Unstructured, instruction: &mut Instruction) -> Result<()> {
        use Instruction as I;
        if !u.ratio(3, 4)? {
            return Ok(());
        }

        match instruction {
            I::load_u8(_, address)
            | I::load_i8(_, address)
            | I::load_u16(_, address)
            | I::load_i16(_, address)
            | I::load_u32(_, address)
            | I::load_i32(_, address)
            | I::load_u64(_, address)
            | I::store_u8(_, address)
            | I::store_u16(_, address)
            | I::store_u32(_, address)
            | I::store_u64(_, address)
            | I::store_imm_u8(address, _)
            | I::store_imm_u16(address, _)
            | I::store_imm_u32(address, _)
            | I::store_imm_u64(address, _) => *address = self.memory_address(u)? as i32,
            I::load_indirect_u8(_, _, offset)
            | I::load_indirect_i8(_, _, offset)
            | I::load_indirect_u16(_, _, offset)
            | I::load_indirect_i16(_, _, offset)
            | I::load_indirect_u32(_, _, offset)
            | I::load_indirect_i32(_, _, offset)
            | I::load_indirect_u64(_, _, offset)
            | I::store_indirect_u8(_, _, offset)
            | I::store_indirect_u16(_, _, offset)
            | I::store_indirect_u32(_, _, offset)
            | I::store_indirect_u64(_, _, offset)
            | I::store_imm_indirect_u8(_, offset, _)
            | I::store_imm_indirect_u16(_, offset, _)
            | I::store_imm_indirect_u32(_, offset, _)
            | I::store_imm_indirect_u64(_, offset, _)
            | I::jump_indirect(_, offset) => *offset = Self::small_offset(u)?,
            I::load_imm(_, value) => *value = self.value(u)? as i32,
            I::load_imm64(_, value) => *value = self.value(u)?,
            I::load_imm_and_jump(_, value, _) => *value = self.jump_address(u)? as i32,
            I::load_imm_and_jump_indirect(_, _, value, offset) => {
                *value = self.jump_address(u)? as i32;
                *offset = Self::small_offset(u)?;
            }
            _ => {}
        }

        Ok(())
    }
}

pub struct ProgramCode {
    pub code: Vec<Instruction>,
    pub jump_table: Vec<u32>,
    pub regs: [u64; Reg::ALL.len()],
}

pub struct Program {
    pub blob: ProgramBlob,
    pub code: Vec<Instruction>,
    pub entry: ProgramCounter,
    pub regs: [u64; Reg::ALL.len()],
}

pub fn max_block_size(blob: &ProgramBlob) -> u32 {
    let mut max_block_size = 0;
    let mut block_size = 0;
    for instruction in blob.instructions() {
        block_size += 1;
        if instruction.kind.opcode().starts_new_basic_block() {
            max_block_size = max_block_size.max(block_size);
            block_size = 0;
        }
    }

    max_block_size.max(block_size)
}

fn block_index_of_each_instruction(code: &[Instruction]) -> Vec<u32> {
    let mut block = 0;
    code.iter()
        .map(|instruction| {
            let current = block;
            block += u32::from(instruction.opcode().starts_new_basic_block());
            current
        })
        .collect()
}

impl ProgramCode {
    pub fn arbitrary(u: &mut Unstructured, setup: &Setup, is_acyclic: bool) -> Result<Self> {
        let mut code = Vec::new();
        for _ in 0..u.int_in_range(1..=MAX_INSTRUCTIONS)? {
            let instruction = match u.arbitrary()? {
                Instruction::invalid => Instruction::trap,
                instruction => instruction,
            };

            if is_in_scope(setup.isa, instruction.opcode()) {
                code.push(instruction);
            }
        }

        if is_acyclic || !code.last().is_some_and(|instruction| instruction.opcode().starts_new_basic_block()) {
            code.push(Instruction::trap);
        }

        let block_count = block_index_of_each_instruction(&code).last().copied().unwrap_or(0) + 1;
        let jump_table_length = u.int_in_range(0..=MAX_JUMP_TABLE_ENTRIES)?;
        let mut jump_table = Vec::with_capacity(jump_table_length as usize);
        for _ in 0..jump_table_length {
            jump_table.push(if is_acyclic {
                block_count - 1
            } else {
                u.int_in_range(0..=block_count - 1)?
            });
        }

        let addresses = Addresses::new(u, setup, jump_table_length)?;
        let blocks = block_index_of_each_instruction(&code);
        for (instruction, &block) in code.iter_mut().zip(blocks.iter()) {
            if let Some(target) = instruction.target_mut() {
                *target = if is_acyclic {
                    block + 1 + *target % (block_count - block - 1).max(1)
                } else {
                    *target % block_count
                };
            }

            addresses.fix_up(u, instruction)?;
        }

        let mut regs = [0; Reg::ALL.len()];
        for (reg, value) in Reg::ALL.into_iter().zip(regs.iter_mut()) {
            *value = if reg == Reg::RA && u.ratio(7, 8)? {
                RETURN_TO_HOST
            } else {
                addresses.value(u)?
            };
        }

        Ok(ProgramCode { code, jump_table, regs })
    }

    pub fn to_bytes(&self, setup: &Setup) -> Vec<u8> {
        let mut builder = ProgramBlobBuilder::new(setup.isa);
        builder.set_ro_data_size(setup.ro_data_size);
        builder.set_ro_data(setup.ro_data.clone());
        builder.set_rw_data_size(setup.rw_data_size);
        builder.set_rw_data(setup.rw_data.clone());
        builder.set_stack_size(setup.stack_size);
        builder.add_export_by_basic_block(0, b"main");
        builder.set_code(&self.code, &self.jump_table);
        builder.into_vec().expect("failed to build a program from in-scope instructions")
    }

    pub fn build(self, setup: &Setup) -> Program {
        let blob = ProgramBlob::parse(self.to_bytes(setup).into()).expect("failed to parse a program built by the writer");
        let entry = blob.exports().next().expect("the program has no exports").program_counter();
        let ProgramCode { code, regs, .. } = self;
        Program { blob, code, entry, regs }
    }
}

#[derive(Copy, Clone)]
enum EngineKind {
    Crosscheck,
    Compiler,
    Interpreter,
}

fn engine(kind: EngineKind) -> &'static Engine {
    static ENGINES: [OnceLock<Engine>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
    ENGINES[kind as usize].get_or_init(|| {
        let mut config = Config::new();
        config.set_allow_experimental(true);
        config.set_allow_dynamic_paging(true);
        match kind {
            EngineKind::Crosscheck => {
                config.set_backend(Some(BackendKind::Compiler));
                config.set_crosscheck(true);
            }
            EngineKind::Compiler => {
                config.set_backend(Some(BackendKind::Compiler));
            }
            EngineKind::Interpreter => {
                config.set_backend(Some(BackendKind::Interpreter));
            }
        }

        Engine::new(&config).expect("failed to create an engine")
    })
}

fn engines(mode: Mode) -> Vec<&'static Engine> {
    if !BackendKind::Compiler.is_supported() {
        if cfg!(target_arch = "x86_64") {
            panic!("the recompiler is not supported on this AMD64 host; the differential would silently test nothing");
        }

        return vec![engine(EngineKind::Interpreter), engine(EngineKind::Interpreter)];
    }

    match mode {
        Mode::Crosscheck => vec![engine(EngineKind::Crosscheck)],
        Mode::Pair => vec![engine(EngineKind::Compiler), engine(EngineKind::Interpreter)],
    }
}

pub fn first_block_cost(setup: &Setup, blob: &ProgramBlob, entry: ProgramCounter) -> Option<i64> {
    setup.gas_metering?;
    let mut config = setup.module_config();
    config.set_step_tracing(true);
    let module = Module::from_blob(engine(EngineKind::Interpreter), &config, blob.clone()).ok()?;
    let mut instance = module.instantiate().ok()?;
    instance.set_gas(MAX_GAS);
    instance.set_next_program_counter(entry);
    while instance.gas() == MAX_GAS {
        if !matches!(instance.run().ok()?, InterruptKind::Step) {
            break;
        }
    }

    Some(MAX_GAS - instance.gas())
}

pub fn arbitrary_gas(u: &mut Unstructured, block_cost: Option<i64>, is_acyclic: bool) -> Result<i64> {
    let gas = match (u.int_in_range(0..=6)?, block_cost) {
        (0, _) => 0,
        (1, _) => 1,
        (2, Some(cost)) => cost - 1,
        (3, Some(cost)) => cost,
        (4, Some(cost)) => cost + 1,
        (5, _) if is_acyclic => i64::MAX,
        _ => u.int_in_range(0..=MAX_GAS)?,
    };

    Ok(gas)
}

fn enter(instance: &mut RawInstance, entry: ProgramCounter, regs: &[u64; Reg::ALL.len()], call_arguments: Option<usize>) {
    match call_arguments {
        Some(count) => {
            let arguments: Vec<u64> = Reg::ARG_REGS[..count].iter().map(|reg| regs[reg.to_usize()]).collect();
            instance.prepare_call_untyped(entry, &arguments);
        }
        None => {
            for (reg, &value) in Reg::ALL.into_iter().zip(regs.iter()) {
                instance.set_reg(reg, value);
            }

            instance.set_next_program_counter(entry);
        }
    }
}

pub struct Vm<'a> {
    setup: &'a Setup,
    instances: Vec<RawInstance>,
    pages: BTreeSet<u32>,
    entry: ProgramCounter,
    regs: [u64; Reg::ALL.len()],
    call_arguments: Option<usize>,
    gas: i64,
    accessible_aux_size: u32,
    reuses: usize,
    is_program_counter_stale: bool,
    is_verbose: bool,
}

impl<'a> Vm<'a> {
    pub fn new(
        setup: &'a Setup,
        blob: &ProgramBlob,
        entry: ProgramCounter,
        regs: &[u64; Reg::ALL.len()],
        call_arguments: Option<usize>,
        gas: i64,
    ) -> Option<Self> {
        let config = setup.module_config();
        let modules: Vec<_> = engines(setup.mode)
            .into_iter()
            .map(|engine| Module::from_blob(engine, &config, blob.clone()))
            .collect();

        if modules.iter().all(|module| module.is_err()) {
            return None;
        }

        let modules: Vec<Module> = modules
            .into_iter()
            .map(|module| module.expect("the backends disagree on whether the module is valid"))
            .collect();

        let mut instances: Vec<RawInstance> = modules
            .iter()
            .map(|module| module.instantiate().expect("failed to instantiate the module"))
            .collect();

        for instance in &mut instances {
            enter(instance, entry, regs, call_arguments);
            instance.set_gas(gas);
            if !setup.dynamic_paging {
                instance
                    .set_accessible_aux_size(setup.accessible_aux_size)
                    .expect("failed to set the accessible aux size");
            }
        }

        if let Some((max_cache_size_bytes, extra_block_size)) = setup.cache_limit {
            let _ = instances
                .last_mut()
                .unwrap()
                .set_interpreter_cache_size_limit(Some(SetCacheSizeLimitArgs {
                    max_block_size: max_block_size(blob) + extra_block_size,
                    max_cache_size_bytes,
                }));
        }

        Some(Vm {
            setup,
            instances,
            pages: BTreeSet::new(),
            entry,
            regs: *regs,
            call_arguments,
            gas,
            accessible_aux_size: setup.accessible_aux_size,
            reuses: 0,
            is_program_counter_stale: false,
            is_verbose: std::env::var_os("POLKAVM_FUZZ_VERBOSE").is_some(),
        })
    }

    fn compare<T: core::fmt::Debug + PartialEq>(&self, name: &str, mut results: Vec<T>) -> T {
        if self.is_verbose {
            let states: Vec<_> = self
                .instances
                .iter()
                .map(|instance| (instance.program_counter(), instance.next_program_counter(), instance.gas()))
                .collect();
            eprintln!("  {name}: {results:?}, (pc, next_pc, gas) = {states:?}");
        }

        let first = results.remove(0);
        for result in results {
            assert_eq!(first, result, "{name}: backends disagree");
        }

        first
    }

    fn each<T: core::fmt::Debug + PartialEq>(&mut self, name: &str, callback: impl FnMut(&mut RawInstance) -> T) -> T {
        let results = self.instances.iter_mut().map(callback).collect();
        self.compare(name, results)
    }

    fn each_ok<T, E>(&mut self, name: &str, mut callback: impl FnMut(&mut RawInstance) -> core::result::Result<T, E>) -> bool {
        self.each(name, |instance| callback(instance).is_ok())
    }

    fn run(&mut self) -> InterruptKind {
        let interrupt = self.each("run", |instance| instance.run().expect("failed to run the instance"));
        if !core::mem::take(&mut self.is_program_counter_stale) {
            self.each("program counter", |instance| instance.program_counter());
        }
        self.each("next program counter", |instance| instance.next_program_counter());
        self.each("gas", |instance| instance.gas());
        for reg in Reg::ALL {
            self.each(&format!("register {reg}"), |instance| instance.reg(reg));
        }

        self.compare_memory();
        interrupt
    }

    fn compare_memory(&mut self) {
        let mut regions = Vec::new();
        if self.setup.dynamic_paging {
            let page_size = self.setup.page_size;
            for page in self.pages.clone() {
                for protection in [MemoryProtection::Read, MemoryProtection::ReadWrite] {
                    self.each("page protection", |instance| {
                        instance.is_memory_accessible(page, page_size, protection)
                    });
                }

                regions.push((page, page_size));
            }
        } else {
            let map = self.instances[0].module().memory_map().clone();
            let heap_size = self.each("heap size", |instance| instance.heap_size());
            let heap_top = (map.heap_base() + heap_size).next_multiple_of(self.setup.page_size);
            regions.extend([
                (map.ro_data_address(), map.ro_data_size()),
                (map.rw_data_address(), heap_top - map.rw_data_address()),
                (map.stack_address_low(), map.stack_address_high() - map.stack_address_low()),
                (map.aux_data_address(), self.accessible_aux_size),
            ]);
        }

        for (address, length) in regions {
            if length != 0 {
                self.each("memory contents", |instance| instance.read_memory(address, length).ok());
            }
        }
    }

    fn map_pages(&mut self, address: u32, length: u32, protection: MemoryProtection) {
        if self.each_ok("zero_memory_with_memory_protection", |instance| {
            instance.zero_memory_with_memory_protection(address, length, protection)
        }) {
            self.pages
                .extend((address..address + length).step_by(self.setup.page_size as usize));
        }
    }

    fn host_paging_operation(&mut self, u: &mut Unstructured, fault: Option<&Segfault>) -> Result<bool> {
        let page_size = self.setup.page_size;
        let page = match fault {
            Some(fault) => fault.page_address,
            None if self.pages.is_empty() => return Ok(true),
            None => *u.choose(&self.pages.iter().copied().collect::<Vec<_>>())?,
        };

        if u64::from(page) + u64::from(page_size) >= TOP_PAGE_END {
            return Ok(false);
        }

        match u.int_in_range(0..=7)? {
            0 | 1 => self.map_pages(page, page_size, MemoryProtection::ReadWrite),
            2 => self.map_pages(page, page_size, MemoryProtection::Read),
            3 => {
                self.map_pages(page, page_size, MemoryProtection::ReadWrite);
                let contents = arbitrary_bytes(u, page_size.min(64))?;
                let offset = u.int_in_range(0..=page_size - contents.len() as u32)?;
                self.each_ok("write_memory", |instance| instance.write_memory(page + offset, &contents));
                if u.arbitrary()? {
                    self.each_ok("protect_memory", |instance| instance.protect_memory(page, page_size));
                }
            }
            4 => {
                self.each_ok("unprotect_memory", |instance| instance.unprotect_memory(page, page_size));
            }
            5 => {
                let length = page_size * u.int_in_range(1..=2)?;
                let length = if u64::from(page) + u64::from(length) >= TOP_PAGE_END - u64::from(page_size) {
                    page_size
                } else {
                    length
                };
                self.each_ok("protect_memory", |instance| instance.protect_memory(page, length));
            }
            6 => {
                let victim = *u.choose(&self.pages.iter().copied().chain([page]).collect::<Vec<_>>())?;
                if self.each_ok("free_pages", |instance| instance.free_pages(victim, page_size)) {
                    self.pages.remove(&victim);
                }

                if fault.is_some() {
                    self.map_pages(page, page_size, MemoryProtection::ReadWrite);
                }
            }
            _ => {
                let span = page_size * u.int_in_range(3..=4)?;
                if u64::from(page) + u64::from(span) >= TOP_PAGE_END - u64::from(page_size) {
                    return Ok(true);
                }

                if u.arbitrary()? {
                    self.map_pages(page, span, MemoryProtection::ReadWrite);
                }

                let address = page + u.int_in_range(0..=page_size - 1)?;
                let length = page + span - u.int_in_range(0..=page_size - 1)? - address;
                match u.int_in_range(0..=2)? {
                    0 => {
                        self.each("read_memory", |instance| instance.read_memory(address, length).ok());
                    }
                    1 => {
                        let seed = u.arbitrary::<u8>()?;
                        let data: Vec<u8> = (0..length).map(|offset| (offset as u8).wrapping_mul(31) ^ seed).collect();
                        self.each_ok("write_memory", |instance| instance.write_memory(address, &data));
                    }
                    _ => {
                        self.each_ok("zero_memory", |instance| instance.zero_memory(address, length));
                    }
                }
            }
        }

        Ok(true)
    }

    fn static_address(u: &mut Unstructured, map: &MemoryMap) -> Result<u32> {
        let offset = u.int_in_range(0..=map.page_size() + 8)?;
        let address = match u.int_in_range(0..=5)? {
            0 => map.ro_data_address().wrapping_add(offset),
            1 => map.rw_data_address().wrapping_add(offset),
            2 => map.stack_address_low().wrapping_add(offset),
            3 => map.stack_address_high().wrapping_sub(offset),
            4 => map.aux_data_address().wrapping_add(u.int_in_range(0..=map.aux_data_size())?),
            _ => u.arbitrary()?,
        };

        Ok(address)
    }

    fn reset_memory(&mut self) {
        self.each_ok("reset_memory", |instance| instance.reset_memory());
        self.is_program_counter_stale = true;
        self.accessible_aux_size = self.setup.aux_data_size;
        self.pages.clear();
    }

    fn host_static_operation(&mut self, u: &mut Unstructured) -> Result<()> {
        let map = self.setup.memory_map();
        let max_length = map.page_size() + 16;
        match u.int_in_range(0..=4)? {
            0 => {
                let address = Self::static_address(u, &map)?;
                let data = arbitrary_bytes(u, 64)?;
                self.each_ok("write_memory", |instance| instance.write_memory(address, &data));
            }
            1 => {
                let address = Self::static_address(u, &map)?;
                let length = u.int_in_range(0..=max_length)?;
                self.each("read_memory", |instance| instance.read_memory(address, length).ok());
            }
            2 => {
                let address = Self::static_address(u, &map)?;
                let length = u.int_in_range(0..=max_length)?;
                self.each_ok("zero_memory", |instance| instance.zero_memory(address, length));
                self.is_program_counter_stale = true;
            }
            3 if self.setup.aux_data_size > 0 => {
                if self.accessible_aux_size > 0 {
                    let offset = u.int_in_range(0..=self.accessible_aux_size - 1)?;
                    let data = arbitrary_bytes(u, 64)?;
                    let address = map.aux_data_address() + offset;
                    self.each_ok("write_memory", |instance| instance.write_memory(address, &data));
                }

                let shrunk = if u.arbitrary()? {
                    0
                } else {
                    u.int_in_range(0..=self.accessible_aux_size)?
                };
                let grown = u.int_in_range(shrunk..=self.setup.aux_data_size)?;
                for size in [shrunk, grown] {
                    if self.each_ok("set_accessible_aux_size", |instance| instance.set_accessible_aux_size(size)) {
                        self.accessible_aux_size = size;
                    }
                }

                self.is_program_counter_stale = true;
            }
            _ => self.reset_memory(),
        }

        Ok(())
    }

    fn maybe_reset_interpreter_cache(&mut self, u: &mut Unstructured) -> Result<()> {
        if u.arbitrary::<u8>()? >= 192 {
            self.each("reset_interpreter_cache", |instance| instance.reset_interpreter_cache());
        }

        Ok(())
    }

    fn reuse(&mut self) {
        self.reset_memory();
        let (regs, gas, entry, call_arguments) = (self.regs, self.gas, self.entry, self.call_arguments);
        self.each("reuse", |instance| {
            enter(instance, entry, &regs, call_arguments);
            instance.set_gas(gas);
        });
        self.reuses += 1;
    }

    pub fn execute(&mut self, u: &mut Unstructured) -> Result<()> {
        for _ in 0..MAX_INTERRUPTS {
            match self.run() {
                InterruptKind::Finished | InterruptKind::Trap | InterruptKind::NotEnoughGas => {
                    if !self.setup.dynamic_paging && u.arbitrary::<u8>()? >= 64 {
                        for _ in 0..u.int_in_range(1..=4)? {
                            self.host_static_operation(u)?;
                        }

                        self.compare_memory();
                    }

                    if self.reuses == MAX_REUSES || u.arbitrary::<u8>()? < 192 {
                        break;
                    }

                    self.maybe_reset_interpreter_cache(u)?;
                    self.reuse();
                }
                InterruptKind::Ecalli(hostcall) => {
                    let result = u64::from(hostcall).wrapping_mul(0x9e3779b97f4a7c15);
                    self.each("set_reg", |instance| instance.set_reg(Reg::A0, result));
                    if self.setup.gas_metering.is_some() {
                        self.each("set_gas", |instance| instance.set_gas(instance.gas() - i64::from(hostcall % 64)));
                    }

                    self.maybe_reset_interpreter_cache(u)?;
                    if self.setup.dynamic_paging {
                        if u.arbitrary::<u8>()? >= 192 {
                            self.host_paging_operation(u, None)?;
                        }
                    } else if u.arbitrary::<u8>()? >= 128 {
                        self.host_static_operation(u)?;
                    }
                }
                InterruptKind::Segfault(segfault) => {
                    if !self.setup.dynamic_paging {
                        break;
                    }

                    if !self.host_paging_operation(u, Some(&segfault))? {
                        break;
                    }
                }
                InterruptKind::Step => {}
            }
        }

        self.compare_memory();
        Ok(())
    }
}

fn execute(
    u: &mut Unstructured,
    setup: &Setup,
    blob: &ProgramBlob,
    entry: ProgramCounter,
    regs: &[u64; Reg::ALL.len()],
    is_acyclic: bool,
) -> Result<()> {
    let block_cost = first_block_cost(setup, blob, entry);
    let gas = arbitrary_gas(u, block_cost, is_acyclic)?.min(if is_acyclic { i64::MAX } else { MAX_GAS });
    let call_arguments = if u.arbitrary::<u8>()? >= 128 {
        Some(u.int_in_range(0..=Reg::ARG_REGS.len())?)
    } else {
        None
    };

    if std::env::var_os("POLKAVM_FUZZ_VERBOSE").is_some() {
        eprintln!(
            "{setup:#?}\nfirst block cost = {block_cost:?}, gas = {gas}, entry = {entry}, regs = {regs:x?}, prepare_call_untyped arguments = {call_arguments:?}"
        );
        for instruction in blob.instructions() {
            eprintln!("  {}: {:?}", instruction.offset, instruction.kind);
        }
    }

    if let Some(mut vm) = Vm::new(setup, blob, entry, regs, call_arguments, gas) {
        vm.execute(u)?;
    }

    Ok(())
}

pub fn generate_structured_code(u: &mut Unstructured) -> Result<(Setup, ProgramCode, bool)> {
    let setup = Setup::arbitrary(&mut Unstructured::new(u.bytes(SETUP_LENGTH.min(u.len()))?))?;
    let is_acyclic = u.ratio(1, 8)? || setup.gas_metering.is_none();
    let code = ProgramCode::arbitrary(u, &setup, is_acyclic)?;
    Ok((setup, code, is_acyclic))
}

pub fn generate_structured(u: &mut Unstructured) -> Result<(Setup, Program, bool)> {
    let (setup, code, is_acyclic) = generate_structured_code(u)?;
    let program = code.build(&setup);
    Ok((setup, program, is_acyclic))
}

fn arbitrary_structured_entry(u: &mut Unstructured, program: &Program) -> Result<ProgramCounter> {
    let instructions: Vec<_> = program.blob.instructions().collect();
    let entry = match u.int_in_range(0..=7)? {
        0 => u.choose(&instructions)?.offset,
        1 => {
            let terminators: Vec<_> = instructions
                .iter()
                .filter(|instruction| instruction.kind.opcode().starts_new_basic_block())
                .collect();
            u.choose(&terminators)?.offset
        }
        _ => program.entry,
    };

    Ok(entry)
}

pub fn run_structured(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let (setup, program, is_acyclic) = generate_structured(&mut u)?;
    let entry = arbitrary_structured_entry(&mut u, &program)?;
    execute(&mut u, &setup, &program.blob, entry, &program.regs, is_acyclic)
}

pub struct RawProgram {
    pub isa: InstructionSetKind,
    pub jump_table: Vec<u32>,
    pub code: Vec<u8>,
    pub bitmask: Vec<u8>,
}

impl RawProgram {
    pub fn decode(data: &[u8]) -> Self {
        let mut reader = data.get(SETUP_LENGTH + 1..).unwrap_or(&[]);
        let mut take = |length: usize| {
            let (head, tail) = reader.split_at(length.min(reader.len()));
            reader = tail;
            head
        };

        let jump_table_length = usize::from(take(1).first().copied().unwrap_or(0));
        let jump_table = take(jump_table_length * 4)
            .chunks(4)
            .map(|chunk| {
                let mut bytes = [0; 4];
                bytes[..chunk.len()].copy_from_slice(chunk);
                u32::from_le_bytes(bytes)
            })
            .collect();

        let mut length = [0; 4];
        let head = take(4);
        length[..head.len()].copy_from_slice(head);
        let code = take(u32::from_le_bytes(length) as usize).to_vec();
        let bitmask = take(usize::MAX).to_vec();
        let isa = ISAS[usize::from(data.first().copied().unwrap_or(0) & !RAW_CONTAINER_FLAG) % ISAS.len()];

        RawProgram {
            isa,
            jump_table,
            code,
            bitmask,
        }
    }

    pub fn encode(&self, setup: &[u8; SETUP_LENGTH]) -> Vec<u8> {
        let mut output = Vec::new();
        output.push(ISAS.iter().position(|&isa| isa == self.isa).unwrap() as u8);
        output.extend_from_slice(setup);
        let jump_table = &self.jump_table[..self.jump_table.len().min(usize::from(u8::MAX))];
        output.push(jump_table.len() as u8);
        for entry in jump_table {
            output.extend_from_slice(&entry.to_le_bytes());
        }

        output.extend_from_slice(&(self.code.len() as u32).to_le_bytes());
        output.extend_from_slice(&self.code);
        output.extend_from_slice(&self.bitmask);
        output
    }

    pub fn code_and_jump_table(&self) -> Vec<u8> {
        let mut output = Vec::new();
        let mut varint = [0; 5];
        let length = polkavm_common::varint::write_varint(self.jump_table.len() as u32, &mut varint);
        output.extend_from_slice(&varint[..length]);
        output.push(4);
        if self.isa.is_legacy() {
            let length = polkavm_common::varint::write_varint(self.code.len() as u32, &mut varint);
            output.extend_from_slice(&varint[..length]);
        }

        for entry in &self.jump_table {
            output.extend_from_slice(&entry.to_le_bytes());
        }

        output.extend_from_slice(&self.code);
        if self.isa.is_legacy() {
            let mut bitmask = self.bitmask.clone();
            bitmask.resize(self.code.len().div_ceil(8), 0);
            if self.code.len() % 8 != 0 {
                *bitmask.last_mut().unwrap() &= (1 << (self.code.len() % 8)) - 1;
            }

            output.extend_from_slice(&bitmask);
        }

        output
    }

    pub fn to_blob(&self, setup: &Setup) -> Option<ProgramBlob> {
        let mut parts = ProgramParts::empty(self.isa);
        parts.ro_data_size = setup.ro_data_size;
        parts.ro_data = setup.ro_data.clone().into();
        parts.rw_data_size = setup.rw_data_size;
        parts.rw_data = setup.rw_data.clone().into();
        parts.stack_size = setup.stack_size;
        parts.code_and_jump_table = self.code_and_jump_table().into();
        ProgramBlob::from_parts(parts).ok()
    }
}

pub fn encode_raw_container(isa: InstructionSetKind, setup: &[u8; SETUP_LENGTH], blob: &[u8]) -> Vec<u8> {
    let mut output = vec![ISAS.iter().position(|&kind| kind == isa).unwrap() as u8 | RAW_CONTAINER_FLAG];
    output.extend_from_slice(setup);
    output.extend_from_slice(blob);
    output
}

fn container_to_blob(setup: &mut Setup, data: &[u8]) -> Option<ProgramBlob> {
    let blob = ProgramBlob::parse(data.get(SETUP_LENGTH + 1..).unwrap_or(&[]).to_vec().into()).ok()?;
    if !ISAS.contains(&blob.isa()) {
        return None;
    }

    setup.isa = blob.isa();
    setup.ro_data_size = blob.ro_data_size();
    setup.ro_data = blob.ro_data().to_vec();
    setup.rw_data_size = blob.rw_data_size();
    setup.rw_data = blob.rw_data().to_vec();
    setup.stack_size = blob.stack_size();
    setup.memory_map_builder().build().ok()?;
    Some(blob)
}

pub fn decode_raw(u: &mut Unstructured, data: &[u8]) -> Result<Option<(Setup, ProgramBlob)>> {
    let mut setup = Setup::arbitrary(u)?;
    setup.gas_metering = Some(GasMeteringKind::Sync);
    let blob = if data.first().is_some_and(|byte| byte & RAW_CONTAINER_FLAG != 0) {
        container_to_blob(&mut setup, data)
    } else {
        let raw = RawProgram::decode(data);
        setup.isa = raw.isa;
        raw.to_blob(&setup)
    };

    let Some(blob) = blob else {
        return Ok(None);
    };

    if blob
        .instructions()
        .any(|instruction| !is_in_scope(setup.isa, instruction.kind.opcode()))
    {
        return Ok(None);
    }

    Ok(Some((setup, blob)))
}

pub fn run_raw(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data.get(1..SETUP_LENGTH + 1).unwrap_or(&[]));
    let Some((setup, blob)) = decode_raw(&mut u, data)? else {
        return Ok(());
    };

    let jump_table: Vec<u32> = blob.jump_table().iter().map(|target| target.0).collect();
    let exports: Vec<u32> = blob.exports().map(|export| export.program_counter().0).collect();
    let entry = match u.int_in_range(0..=3)? {
        0 => 0,
        1 if !jump_table.is_empty() => *u.choose(&jump_table)?,
        2 if !exports.is_empty() => *u.choose(&exports)?,
        _ => u.int_in_range(0..=blob.code().len() as u32)?,
    };

    let addresses = Addresses::new(&mut u, &setup, blob.jump_table().len())?;
    let mut regs = [0; Reg::ALL.len()];
    for (reg, value) in Reg::ALL.into_iter().zip(regs.iter_mut()) {
        *value = if reg == Reg::RA { RETURN_TO_HOST } else { addresses.value(&mut u)? };
    }

    execute(&mut u, &setup, &blob, ProgramCounter(entry), &regs, false)
}
