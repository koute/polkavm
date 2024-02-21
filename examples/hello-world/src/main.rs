use polkavm::{CallArgs, Config, Engine, Linker, Module, ProgramBlob, Reg, StateArgs};

fn main() {
    env_logger::init();

    let raw_blob = include_bytes!("../../../guest-programs/output/example-hello-world.polkavm");
    let blob = ProgramBlob::parse(&raw_blob[..]).unwrap();

    let config = Config::from_env().unwrap();
    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &Default::default(), &blob).unwrap();
    let mut linker = Linker::new(&engine);

    // Define a host function.
    linker.func_wrap("get_third_number", || -> u32 { 100 }).unwrap();

    // Link the host functions with the module.
    let instance_pre = linker.instantiate_pre(&module).unwrap();

    // Instantiate the module.
    let instance = instance_pre.instantiate().unwrap();

    // Grab the function and call it.
    println!("Calling into the guest program (simple):");
    let result = instance.call_typed::<(u32, u32), u32>(&mut (), "add_numbers", (1, 10)).unwrap();
    println!("  1 + 10 + 100 = {}", result);

    println!("Calling into the guest program (full):");
    let export_index = instance.module().lookup_export("add_numbers").unwrap();

    #[allow(clippy::let_unit_value)]
    let mut user_data = ();
    let mut call_args = CallArgs::new(&mut user_data, export_index);
    call_args.args_untyped(&[1, 10]);

    instance.call(StateArgs::new(), call_args).unwrap();
    let return_value = instance.get_reg(Reg::A0);
    println!("  1 + 10 + 100 = {}", return_value);
}
