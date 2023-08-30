fn generate_linker_script() -> String {
    format!(
        r#"
        SECTIONS {{
            /*
                NOTE: If the binary grows too much an 'address range overlaps' error will be generated during linking.
                      If so then this has to be adjusted to move everything further back so that there's no overlap.
            */
            . = 0x{vmctx_address:010x} - 0x6000;

            /* Section for read-only globals. */
            .rodata : {{ *(.rodata) *(.rodata.*) }}
            .note.gnu.property : {{ *(.note.gnu.property) }}

            . = ALIGN(0x1000);
            /* Section for non-zero read-write globals. */
            .data : {{ *(.got) *(.got.*) *(.data.rel.ro) *(.data.rel.ro.*) *(.sdata) *(.sdata.*) *(.data) *(.data.*) }}
            /* Section for zeroed read-write globals. */
            .bss : {{ *(.sbss) *(.sbss.*) *(.bss) *(.bss.*) }}

            . = 0x{text_address:010x};
            /* Section for code. */
            .text : {{ KEEP(*(.text_syscall)) *(.text_hot) *(.text .text.*) }}

            /* Global virtual machine context. Must be located at a statically known address. */
            . = 0x{vmctx_address:010x};
            .vmctx : {{ KEEP(*(.vmctx)) }}

            /* Strip away junk we don't need. */
            /DISCARD/ : {{ *(.comment) *(.eh_frame) *(.eh_frame_hdr) }}
        }}

        ENTRY(_start)
    "#,
        text_address = polkavm_common::zygote::VM_ADDR_SYSCALL,
        vmctx_address = polkavm_common::zygote::VM_ADDR_VMCTX
    )
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

    println!("cargo:rustc-link-arg=-T{}", linker_script_path.to_str().unwrap());
}
