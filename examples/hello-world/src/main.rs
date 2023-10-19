use polkavm::{Config, Engine, Linker, Module, ProgramBlob, Val};

fn main() {
    env_logger::init();

    let raw_blob = include_bytes!("../../../guest-programs/output/example-hello-world.polkavm");
    let blob = ProgramBlob::parse(&raw_blob[..]).unwrap();

    let config = Config::from_env().unwrap();
    let engine = Engine::new(&config).unwrap();
    let module = Module::from_blob(&engine, &blob).unwrap();
    let mut linker = Linker::new(&engine);

    // Define a host function.
    linker.func_wrap("get_third_number", || -> u32 { 100 }).unwrap();

    // Link the host functions with the module.
    let instance_pre = linker.instantiate_pre(&module).unwrap();

    // Instantiate the module.
    let instance = instance_pre.instantiate().unwrap();

    // Grab the function and call it.
    println!("Calling into the guest program (through typed function):");
    let fn_typed = instance.get_typed_func::<(u32, u32), u32>("add_numbers").unwrap();
    let result = fn_typed.call(&mut (), (1, 10)).unwrap();
    println!("  1 + 10 + 100 = {}", result);

    println!("Calling into the guest program (through untyped function):");
    let fn_untyped = instance.get_func("add_numbers").unwrap();
    let result = fn_untyped.call(&mut (), &[Val::I32(1), Val::I32(10)]).unwrap();
    println!("  1 + 10 + 100 = {}", result.unwrap());
}
