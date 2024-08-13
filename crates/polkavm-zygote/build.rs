fn generate_linker_script() -> String {
    format!(
        r#"
        SECTIONS {{
            /*
                NOTE: If the binary grows too much an 'address range overlaps' error will be generated during linking.
                      If so then this has to be adjusted to move everything further back so that there's no overlap.
            */
            . = 0x{vmctx_address:010x} - 0x9000;

            /* Section for read-only globals. */
            .rodata : {{ *(.rodata) *(.rodata.*) *(.gcc_except_table.*) }} : rodata
            .note.gnu.property : {{ *(.note.gnu.property) }} : rodata

            . = ALIGN(0x1000);
            /* Section for non-zero read-write globals. */
            .data : {{ *(.got) *(.got.*) *(.data.rel.ro) *(.data.rel.ro.*) *(.sdata) *(.sdata.*) *(.data) *(.data.*) }} : data
            /* Section for zeroed read-write globals. */
            .bss : {{ *(.sbss) *(.sbss.*) *(.bss) *(.bss.*) }} : data

            . = ALIGN(0x1000);
            /* Section for code. */
            .text : {{ *(.text_hot) *(.text .text.*) }} : text

            /* Global virtual machine context. Must be located at a statically known address. */
            . = 0x{vmctx_address:010x};
            .vmctx : {{ KEEP(*(.vmctx)) }} : vmctx

            .address_table (INFO) : {{ KEEP(*(.address_table)) }}
            .ext_table (INFO) : {{ KEEP(*(.ext_table)) }}

            /* Strip away junk we don't need. */
            /DISCARD/ : {{ *(.comment) *(.eh_frame) *(.eh_frame_hdr) }}
        }}

        PHDRS
        {{
            rodata PT_LOAD FLAGS(4);
            data PT_LOAD FLAGS(6);
            text PT_LOAD FLAGS(5);
            vmctx PT_LOAD FLAGS(0);
            gnustack PT_GNU_STACK FLAGS(6);
        }}

        ENTRY(_start)
    "#,
        vmctx_address = polkavm_common::zygote::VM_ADDR_VMCTX
    )
}

#[allow(non_upper_case_globals)]
fn generate_assembly() -> String {
    // Duplicate these here to avoid depending on `polkavm-linux-raw`.
    const SYS_rt_sigreturn: u32 = 15;
    const SYS_mmap: u32 = 9;
    const PROT_READ: u32 = 1;
    const PROT_WRITE: u32 = 2;
    const MAP_FIXED: u32 = 16;
    const MAP_PRIVATE: u32 = 2;
    const MAP_ANONYMOUS: u32 = 32;

    let template = include_str!("src/global_asm.s");
    template
        .replace("{native_stack_low}", &polkavm_common::zygote::VM_ADDR_NATIVE_STACK_LOW.to_string())
        .replace(
            "{native_stack_high}",
            &polkavm_common::zygote::VM_ADDR_NATIVE_STACK_HIGH.to_string(),
        )
        .replace(
            "{native_stack_size}",
            &polkavm_common::zygote::VM_ADDR_NATIVE_STACK_SIZE.to_string(),
        )
        .replace("{SYS_rt_sigreturn}", &SYS_rt_sigreturn.to_string())
        .replace("{SYS_mmap}", &SYS_mmap.to_string())
        .replace("{stack_mmap_protection}", &(PROT_READ | PROT_WRITE).to_string())
        .replace("{stack_mmap_flags}", &(MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS).to_string())
}

fn write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    if path.exists() {
        let old_data = std::fs::read(path)?;
        if old_data == data {
            return Ok(());
        }
    }

    std::fs::write(path, data)
}

fn main() {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let linker_script_path = out_dir.join("memory.ld");
    write(&linker_script_path, generate_linker_script().as_bytes()).unwrap();

    let assembly_path = out_dir.join("global_asm.s");
    write(&assembly_path, generate_assembly().as_bytes()).unwrap();

    println!("cargo:rustc-link-arg=-T{}", linker_script_path.to_str().unwrap());
    println!("cargo:rerun-if-changed=src/global_asm.s");
}
