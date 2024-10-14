#![no_main]

use libfuzzer_sys::fuzz_target;
use polkavm::Engine;
use polkavm::InterruptKind;
use polkavm::ModuleConfig;
use polkavm::ProgramCounter;
use polkavm_common::program::ProgramBlob;

fn harness(data: &[u8]) {
    // configure the polkavm engine
    let mut config = polkavm::Config::new();
    config.set_backend(Some(polkavm::BackendKind::Interpreter));

    let engine = Engine::new(&config).unwrap();

    // configure the polkavm module
    let mut module_config = ModuleConfig::default();
    module_config.set_strict(true);
    module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
    module_config.set_step_tracing(true);

    // create a polkavm program blob (eventually to be filled with the fuzzed data)
    let mut fuzzed_blob = ProgramBlob::default();

    let bitmask = vec![0xff; data.len() / 8 + 1];

    fuzzed_blob.set_code(data.into());
    fuzzed_blob.set_bitmask(bitmask.into());

    // create a polkavm module from the engine, module config, and program blob
    let module = polkavm::Module::from_blob(&engine, &module_config, fuzzed_blob).unwrap();

    let initial_pc = ProgramCounter(0);
    let mut final_pc = initial_pc;

    // instantiate the module and run it
    let mut instance = module.instantiate().unwrap();
    instance.set_gas(1000000);
    instance.set_next_program_counter(initial_pc);

    let expected_status = loop {
        match instance.run().unwrap() {
            InterruptKind::Finished => break "halt",
            InterruptKind::Trap => break "trap",
            InterruptKind::Ecalli(..) => todo!(),
            InterruptKind::NotEnoughGas => break "out-of-gas",
            InterruptKind::Segfault(..) => todo!(),
            InterruptKind::Step => {
                final_pc = instance.program_counter().unwrap();
                continue;
            }
        }
    };
}

fuzz_target!(|data: &[u8]| {
    harness(data);
});
