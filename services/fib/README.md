
# JAM Service: Fib

This is a test Rust-based JAM service named "jam-service-fib" with refine/accumulate/on_transfer/is_authorized entrypoints:

* `refine` (entry point 5) imports a 12-byte segment with [n, fib(n), f(n-1)] and exports the next segment in the same way [n+1, fib(n+1), fib(n)]
* `accumulate` (entry point 10) reads a 12-byte segment and writes to service storage key "0"
* `is_authorized` (entry point 0) and `on_transfer` (entry point 15) are just stubs right now

It uses 3 polka_import macros for import/export/write but attempts to set up all 23 or so and a few others.  These are just stubs at present, have not been checked or tested.

### Step 1: Set Up the Toolchain

1. **Extract and Move the Toolchain**  
   Extract the toolchain file using `tar` with zstd compression and move it to the Rustup toolchain directory:
   ```bash
   tar --zstd -xf rust-rve-nightly-2024-01-05-x86_64-unknown-linux-gnu.tar.zst
   mv rve-nightly ~/.rustup/toolchains/
   ```

2. **Verify Toolchain Installation**  
   Check if the toolchain was successfully installed by listing the contents of the `toolchains` directory:
   ```bash
   ls ~/.rustup/toolchains/
   ```
   Ensure that `rve-nightly` appears among the other installed toolchains.

3. **Set the Toolchain as the Default**  
   Set `rve-nightly` as the default toolchain using the following commands:
   ```bash
   echo "export RUSTUP_TOOLCHAIN=rve-nightly" >> ~/.bashrc
   source ~/.bashrc
   ```

---

### Step 2: Build the JAM Service

1. **Navigate to the `fib` Service Directory**  
   Change to the directory containing the `fib` JAM service:
   ```bash
   cd ./jamservices/services/fib
   ```

2. **Build the JAM Service**  
   Build the service in release mode using Cargo:
   ```bash
   cargo build --release --target-dir ./target
   ```

---

### Step 3: Build the Polkatool

1. **Move to the `polkatool` Directory**  
   Change to the `polkatool` tool directory:
   ```bash
   cd ./jamservices/tools/polkatool
   ```

2. **Build the Polkatool**  
   Build the tool in release mode:
   ```bash
   cargo build --release --target-dir ./target
   ```

---

### Step 4: Generate the Service and Blob

1. **Create the JAM Service and Blob from the Compiled `fib` Binary**  
   Use `polkatool` to generate the JAM service and blob:
   ```bash
   cargo run -p polkatool jam-service services/fib/target/riscv32ema-unknown-none-elf/release/fib -o services/fib/jam_service.pvm -d services/fib/blob.pvm
   ```

   After running this command, two output files will be generated:
   - `jam_service.pvm`: A JAM-ready top-level service blob, as defined in equation 259 of A.7 in GP v0.4.1. Currently, this cannot be disassembled using `polkatool`.
   - `blob.pvm`: This can be disassembled using `polkatool`, and the disassembly result is provided below.

---

### Step 5: Disassemble the Blob

1. **Disassemble the Blob File and Optionally Show the Raw Bytes**  
   Disassemble the generated blob to view the instructions and raw bytes:
   ```bash
   cargo run -p polkatool disassemble services/fib/blob.pvm --show-raw-bytes
   ```

2. **Disassembly Result**  
   Below is the output of the disassembled `blob.pvm` file:

```
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 4096 bytes
// Jump table entry point size = 0 bytes
// RO data = []
// RW data = []
// Instructions = 54
// Code size = 144 bytes

      :                          @0
     0: 05 11 00 00 00           jump @4
      :                          @1
     5: 05 10 00 00 00           jump @5
      :                          @2
    10: 05 5a 00 00 00           jump @10
      :                          @3
    15: 05 7d                    jump @11
      :                          @4 [export #0: 'is_authorized']
    17: 04 07                    a0 = 0x0
    19: 13 00                    ret
      :                          @5 [export #1: 'refine']
    21: 02 11 f0                 sp = sp - 16
    24: 03 10 0c                 u32 [sp + 12] = ra
    27: 0d 11 08                 u32 [sp + 8] = 0
    30: 0d 11 04                 u32 [sp + 4] = 0
    33: 0d 01                    u32 [sp + 0] = 0
    35: 52 18                    a1 = sp
    37: 04 09 0c                 a2 = 0xc
    40: 04 07                    a0 = 0x0
    42: 4e 10                    ecalli 16 // 'import'
    44: 11                       fallthrough
      :                          @6
    45: 07 07 0f                 jump @8 if a0 == 0
      :                          @7
    48: 0d 11 08                 u32 [sp + 8] = 0
    51: 0d 11 04 01              u32 [sp + 4] = 1
    55: 0d 01 01                 u32 [sp + 0] = 1
    58: 05 19                    jump @9
      :                          @8
    60: 01 17 04                 a0 = u32 [sp + 4]
    63: 01 18 08                 a1 = u32 [sp + 8]
    66: 01 19                    a2 = u32 [sp]
    68: 08 78 08                 a1 = a1 + a0
    71: 02 99 01                 a2 = a2 + 0x1
    74: 03 19                    u32 [sp] = a2
    76: 03 18 04                 u32 [sp + 4] = a1
    79: 03 17 08                 u32 [sp + 8] = a0
    82: 11                       fallthrough
      :                          @9
    83: 52 17                    a0 = sp
    85: 04 08 0c                 a1 = 0xc
    88: 4e 11                    ecalli 17 // 'export'
    90: 04 07                    a0 = 0x0
    92: 01 10 0c                 ra = u32 [sp + 12]
    95: 02 11 10                 sp = sp + 0x10
    98: 13 00                    ret
      :                          @10 [export #2: 'accumulate']
   100: 02 11 ec                 sp = sp - 20
   103: 03 10 10                 u32 [sp + 16] = ra
   106: 0d 11 08                 u32 [sp + 8] = 0
   109: 0d 11 04                 u32 [sp + 4] = 0
   112: 0d 01                    u32 [sp + 0] = 0
   114: 1a 11 0f                 u8 [sp + 15] = 0
   117: 02 17 0f                 a0 = sp + 0xf
   120: 04 08 01                 a1 = 0x1
   123: 52 19                    a2 = sp
   125: 04 0a 0c                 a3 = 0xc
   128: 4e 03                    ecalli 3 // 'write'
   130: 04 07                    a0 = 0x0
   132: 01 10 10                 ra = u32 [sp + 16]
   135: 02 11 14                 sp = sp + 0x14
   138: 13 00                    ret
      :                          @11 [export #3: 'on_transfer']
   140: 04 07                    a0 = 0x0
   142: 13 00                    ret
```