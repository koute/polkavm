
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
// RW data = 0/4128 bytes
// Stack size = 4096 bytes
// Jump table entry point size = 2 bytes
// RO data = []
// RW data = []
// Instructions = 419
// Code size = 1187 bytes

      :                          @0
     0: 05 f0 01 00 00           jump @52
      :                          @1
     5: 05 ef 01 00 00           jump @53
      :                          @2
    10: 05 b1 03 00 00           jump @78
      :                          @3
    15: 05 d4 03                 jump @79
      :                          @4
    18: 02 11 e4                 sp = sp - 28
    21: 03 10 18                 u32 [sp + 24] = ra
    24: 03 15 14                 u32 [sp + 20] = s0
    27: 03 16 10                 u32 [sp + 16] = s1
    30: 52 96                    s1 = a2
    32: 52 75                    s0 = a0
    34: 07 08 a0 00              jump @20 if a1 == 0
      :                          @5
    38: 20 06 a8 00              jump @21 if s1 <s 0
      :                          @6
    42: 01 a7 04                 a0 = u32 [a3 + 4]
    45: 07 07 aa 00              jump @22 if a0 == 0
      :                          @7
    49: 01 a9 08                 a2 = u32 [a3 + 8]
    52: 07 09 d8 00              jump @29 if a2 == 0
      :                          @8
    56: 01 a8                    a1 = u32 [a3]
    58: 04 07 00 10              a0 = 0x1000
    62: 04 04 10 00 02           t2 = 0x20010
    67: 04 03 10 10 02           t1 = 0x21010
    72: 11                       fallthrough
      :                          @9
    73: 0a 0a 10 10 02           a3 = u32 [0x21010]
    78: 08 6a 02                 t0 = a3 + s1
    81: 2f a2 fc 00              jump @35 if t0 <u a3
      :                          @10
    85: 02 2b 01                 a4 = t0 + 0x1
    88: 1b bc 01                 a5 = a4 <u 0x1
    91: 27 bb 00 10              a4 = a4 >u 0x1000
    95: 0c bc 0b                 a4 = a5 | a4
    98: 0f 0b eb 00              jump @35 if a4 != 0
      :                          @11
   102: 0a 0b 10 10 02           a4 = u32 [0x21010]
   107: 1e ab de                 jump @9 if a4 != a3
      :                          @12
   110: 16 02 10 10 02           u32 [0x21010] = t0
   115: 04 0c                    a5 = 0x0
   117: 14 24 07                 a0 = t2 - t0
   120: 02 77 00 10              a0 = a0 + 0x1000
   124: 03 17 08                 u32 [sp + 8] = a0
   127: 03 18 04                 u32 [sp + 4] = a1
   130: 03 19 0c                 u32 [sp + 12] = a2
   133: 03 14                    u32 [sp] = t2
   135: 06 10 02 6a 03           ra = 2, jump @82
      :                          @13 [@dyn 1]
   140: 01 1c 0c                 a5 = u32 [sp + 12]
   143: 32 2c 00 10 25           jump @19 if a5 >u 4096
      :                          @14
   148: 01 18                    a1 = u32 [sp]
   150: 02 87 00 10              a0 = a1 + 0x1000
   154: 01 12 04                 t0 = u32 [sp + 4]
   157: 11                       fallthrough
      :                          @15
   158: 01 78                    a1 = u32 [a0]
   160: 14 87 09                 a2 = a0 - a1
   163: 1e 29 11                 jump @19 if a2 != t0
      :                          @16
   166: 14 c8 09                 a2 = a1 - a5
   169: 11                       fallthrough
      :                          @17
   170: 01 7a                    a3 = u32 [a0]
   172: 1e 8a f2                 jump @15 if a3 != a1
      :                          @18
   175: 03 79                    u32 [a0] = a2
   177: 04 0b                    a4 = 0x0
   179: 11                       fallthrough
      :                          @19
   180: 01 18 08                 a1 = u32 [sp + 8]
   183: 04 07                    a0 = 0x0
   185: 03 58 04                 u32 [s0 + 4] = a1
   188: 03 56 08                 u32 [s0 + 8] = s1
   191: 05 98 00                 jump @36
      :                          @20
   194: 0d 15 04                 u32 [s0 + 4] = 0
   197: 03 56 08                 u32 [s0 + 8] = s1
   200: 04 07 01                 a0 = 0x1
   203: 05 8c 00                 jump @36
      :                          @21
   206: 0d 15 04                 u32 [s0 + 4] = 0
   209: 04 07 01                 a0 = 0x1
   212: 05 83 00                 jump @36
      :                          @22
   215: 04 07 00 10              a0 = 0x1000
   219: 04 08 10 00 02           a1 = 0x20010
   224: 04 09 10 10 02           a2 = 0x21010
   229: 11                       fallthrough
      :                          @23
   230: 01 9b                    a4 = u32 [a2]
   232: 08 6b 0a                 a3 = a4 + s1
   235: 2f ba 62                 jump @35 if a3 <u a4
      :                          @24
   238: 02 ac 01                 a5 = a3 + 0x1
   241: 1b c2 01                 t0 = a5 <u 0x1
   244: 24 c7 0c                 a5 = a0 <u a5
   247: 0c c2 0c                 a5 = t0 | a5
   250: 0f 0c 53                 jump @35 if a5 != 0
      :                          @25
   253: 01 9c                    a5 = u32 [a2]
   255: 1e bc e7                 jump @23 if a5 != a4
      :                          @26
   258: 03 9a                    u32 [a2] = a3
   260: 04 02                    t0 = 0x0
   262: 11                       fallthrough
      :                          @27
   263: 1e bc df                 jump @23 if a5 != a4
      :                          @28
   266: 05 32                    jump @34
      :                          @29
   268: 04 07 00 10              a0 = 0x1000
   272: 04 08 10 00 02           a1 = 0x20010
   277: 04 09 10 10 02           a2 = 0x21010
   282: 11                       fallthrough
      :                          @30
   283: 01 9b                    a4 = u32 [a2]
   285: 08 6b 0a                 a3 = a4 + s1
   288: 2f ba 2d                 jump @35 if a3 <u a4
      :                          @31
   291: 02 ac 01                 a5 = a3 + 0x1
   294: 1b c2 01                 t0 = a5 <u 0x1
   297: 24 c7 0c                 a5 = a0 <u a5
   300: 0c c2 0c                 a5 = t0 | a5
   303: 0f 0c 1e                 jump @35 if a5 != 0
      :                          @32
   306: 01 9c                    a5 = u32 [a2]
   308: 1e bc e7                 jump @30 if a5 != a4
      :                          @33
   311: 03 9a                    u32 [a2] = a3
   313: 04 02                    t0 = 0x0
   315: 11                       fallthrough
      :                          @34
   316: 14 a8 08                 a1 = a1 - a3
   319: 02 88 00 10              a1 = a1 + 0x1000
   323: 04 07                    a0 = 0x0
   325: 03 58 04                 u32 [s0 + 4] = a1
   328: 03 56 08                 u32 [s0 + 8] = s1
   331: 05 0c                    jump @36
      :                          @35
   333: 04 07 01                 a0 = 0x1
   336: 03 57 04                 u32 [s0 + 4] = a0
   339: 03 56 08                 u32 [s0 + 8] = s1
   342: 11                       fallthrough
      :                          @36
   343: 03 57                    u32 [s0] = a0
   345: 01 10 18                 ra = u32 [sp + 24]
   348: 01 15 14                 s0 = u32 [sp + 20]
   351: 01 16 10                 s1 = u32 [sp + 16]
   354: 02 11 1c                 sp = sp + 0x1c
   357: 13 00                    ret
      :                          @37
   359: 02 11 dc                 sp = sp - 36
   362: 03 10 20                 u32 [sp + 32] = ra
   365: 03 15 1c                 u32 [sp + 28] = s0
   368: 03 16 18                 u32 [sp + 24] = s1
   371: 08 98 09                 a2 = a1 + a2
   374: 2f 89 5d                 jump @49 if a2 <u a1
      :                          @38
   377: 52 75                    s0 = a0
   379: 01 77                    a0 = u32 [a0]
   381: 09 76 01                 s1 = a0 << 1
   384: 29 69 1f                 jump @42 if a2 >=u s1
      :                          @39
   387: 3b 16 08 22              jump @43 if s1 <=u 8
      :                          @40
   391: 1f 68 ff                 a1 = s1 ^ 0xffffffff
   394: 0e 88 1f                 a1 = a1 >> 31
   397: 07 07 21                 jump @44 if a0 == 0
      :                          @41
   400: 01 59 04                 a2 = u32 [s0 + 4]
   403: 03 19 0c                 u32 [sp + 12] = a2
   406: 0d 11 10 01              u32 [sp + 16] = 1
   410: 03 17 14                 u32 [sp + 20] = a0
   413: 05 15                    jump @45
      :                          @42
   415: 52 96                    s1 = a2
   417: 32 19 08 e6              jump @40 if a2 >u 8
      :                          @43
   421: 04 06 08                 s1 = 0x8
   424: 04 08 01                 a1 = 0x1
   427: 0f 07 e5                 jump @41 if a0 != 0
      :                          @44
   430: 0d 11 10                 u32 [sp + 16] = 0
   433: 11                       fallthrough
      :                          @45
   434: 52 17                    a0 = sp
   436: 02 1a 0c                 a3 = sp + 0xc
   439: 52 69                    a2 = s1
   441: 06 10 04 59 fe           ra = 4, jump @4
      :                          @46 [@dyn 2]
   446: 01 18                    a1 = u32 [sp]
   448: 01 17 04                 a0 = u32 [sp + 4]
   451: 07 08 19                 jump @50 if a1 == 0
      :                          @47
   454: 04 08 01 00 00 80        a1 = 0x80000001
   460: 18 87 16                 jump @51 if a0 == a1
      :                          @48
   463: 0f 07 18 02              jump @80 if a0 != 0
      :                          @49
   467: 04 00 06                 ra = 0x6
   470: 02 11 fc                 sp = sp - 4
   473: 03 10                    u32 [sp] = ra
   475: 00                       trap
      :                          @50 [@dyn 3]
   476: 03 57 04                 u32 [s0 + 4] = a0
   479: 03 56                    u32 [s0] = s1
   481: 11                       fallthrough
      :                          @51
   482: 01 10 20                 ra = u32 [sp + 32]
   485: 01 15 1c                 s0 = u32 [sp + 28]
   488: 01 16 18                 s1 = u32 [sp + 24]
   491: 02 11 24                 sp = sp + 0x24
   494: 13 00                    ret
      :                          @52 [export #0: 'is_authorized']
   496: 04 07                    a0 = 0x0
   498: 13 00                    ret
      :                          @53 [export #1: 'refine']
   500: 02 11 c0                 sp = sp - 64
   503: 03 10 3c                 u32 [sp + 60] = ra
   506: 03 15 38                 u32 [sp + 56] = s0
   509: 03 16 34                 u32 [sp + 52] = s1
   512: 0d 11 18                 u32 [sp + 24] = 0
   515: 0d 11 14                 u32 [sp + 20] = 0
   518: 0d 11 10                 u32 [sp + 16] = 0
   521: 02 18 10                 a1 = sp + 0x10
   524: 04 09 0c                 a2 = 0xc
   527: 04 07                    a0 = 0x0
   529: 4e 10                    ecalli 16 // 'import'
   531: 11                       fallthrough
      :                          @54
   532: 07 07 1a                 jump @56 if a0 == 0
      :                          @55
   535: 0d 11 10 01              u32 [sp + 16] = 1
   539: 0d 11 14 01              u32 [sp + 20] = 1
   543: 1a 11 18                 u8 [sp + 24] = 0
   546: 1a 11 19                 u8 [sp + 25] = 0
   549: 1a 11 1a                 u8 [sp + 26] = 0
   552: 1a 11 1b                 u8 [sp + 27] = 0
   555: 05 6e 01                 jump @75
      :                          @56
   558: 01 17 14                 a0 = u32 [sp + 20]
   561: 01 18 18                 a1 = u32 [sp + 24]
   564: 01 19 10                 a2 = u32 [sp + 16]
   567: 08 78 0a                 a3 = a1 + a0
   570: 02 98 01                 a1 = a2 + 0x1
   573: 03 18 1c                 u32 [sp + 28] = a1
   576: 02 14 20                 t2 = sp + 0x20
   579: 03 1a 20                 u32 [sp + 32] = a3
   582: 03 17 24                 u32 [sp + 36] = a0
   585: 02 10 1d                 ra = sp + 0x1d
   588: 04 07 00 10              a0 = 0x1000
   592: 04 03 10 00 02           t1 = 0x20010
   597: 04 09 10 10 02           a2 = 0x21010
   602: 11                       fallthrough
      :                          @57
   603: 01 9b                    a4 = u32 [a2]
   605: 02 ba 08                 a3 = a4 + 0x8
   608: 2f ba 87 01              jump @80 if a3 <u a4
      :                          @58
   612: 02 ac 01                 a5 = a3 + 0x1
   615: 1b c2 01                 t0 = a5 <u 0x1
   618: 24 c7 0c                 a5 = a0 <u a5
   621: 0c c2 0c                 a5 = t0 | a5
   624: 0f 0c 77 01              jump @80 if a5 != 0
      :                          @59
   628: 01 9c                    a5 = u32 [a2]
   630: 1e bc e5                 jump @57 if a5 != a4
      :                          @60
   633: 03 9a                    u32 [a2] = a3
   635: 04 02                    t0 = 0x0
   637: 03 13                    u32 [sp] = t1
   639: 14 a3 07                 a0 = t1 - a3
   642: 04 09 00 10              a2 = 0x1000
   646: 08 97 07                 a0 = a0 + a2
   649: 10 78                    u8 [a0] = a1
   651: 04 08 08                 a1 = 0x8
   654: 03 18 28                 u32 [sp + 40] = a1
   657: 03 17 2c                 u32 [sp + 44] = a0
   660: 04 05 01                 s0 = 0x1
   663: 03 15 30                 u32 [sp + 48] = s0
   666: 02 1a 1c                 a3 = sp + 0x1c
   669: 04 0b 03                 a4 = 0x3
   672: 04 0c 01                 a5 = 0x1
   675: 05 19                    jump @63
      :                          @61
   677: 01 19 28                 a2 = u32 [sp + 40]
   680: 0b 06                    s1 = u8 [ra]
   682: 02 00 01                 ra = ra + 0x1
   685: 18 95 26                 jump @66 if s0 == a2
      :                          @62
   688: 08 57 08                 a1 = a0 + s0
   691: 10 86                    u8 [a1] = s1
   693: 02 55 01                 s0 = s0 + 0x1
   696: 03 15 30                 u32 [sp + 48] = s0
   699: 11                       fallthrough
      :                          @63
   700: 1e 40 e9                 jump @61 if ra != t2
      :                          @64
   703: 18 bc 49                 jump @68 if a5 == a4
      :                          @65
   706: 09 c8 02                 a1 = a5 << 2
   709: 08 8a 00                 ra = a3 + a1
   712: 02 cc 01                 a5 = a5 + 0x1
   715: 09 c8 02                 a1 = a5 << 2
   718: 08 8a 04                 t2 = a3 + a1
   721: 05 d4                    jump @61
      :                          @66
   723: 14 04 07                 a0 = t2 - ra
   726: 02 77 01                 a0 = a0 + 0x1
   729: 27 78                    a1 = a0 >u 0x0
   731: 02 88 ff                 a1 = a1 - 1
   734: 0c 78 09                 a2 = a1 | a0
   737: 02 17 28                 a0 = sp + 0x28
   740: 52 58                    a1 = s0
   742: 03 14 0c                 u32 [sp + 12] = t2
   745: 03 10 08                 u32 [sp + 8] = ra
   748: 03 1c 04                 u32 [sp + 4] = a5
   751: 06 10 08 78 fe           ra = 8, jump @37
      :                          @67 [@dyn 4]
   756: 01 1c 04                 a5 = u32 [sp + 4]
   759: 04 0b 03                 a4 = 0x3
   762: 02 1a 1c                 a3 = sp + 0x1c
   765: 01 10 08                 ra = u32 [sp + 8]
   768: 01 14 0c                 t2 = u32 [sp + 12]
   771: 01 17 2c                 a0 = u32 [sp + 44]
   774: 05 aa                    jump @62
      :                          @68
   776: 0f 15 0c a9 00           jump @76 if s0 != 12
      :                          @69
   781: 01 17 2c                 a0 = u32 [sp + 44]
   784: 0b 78 09                 a1 = u8 [a0 + 9]
   787: 0b 79 08                 a2 = u8 [a0 + 8]
   790: 0b 7a 0a                 a3 = u8 [a0 + 10]
   793: 0b 7b 0b                 a4 = u8 [a0 + 11]
   796: 09 88 08                 a1 = a1 << 8
   799: 0c 98 08                 a1 = a1 | a2
   802: 09 aa 10                 a3 = a3 << 16
   805: 09 bb 18                 a4 = a4 << 24
   808: 0c ab 0a                 a3 = a4 | a3
   811: 0c 8a 08                 a1 = a3 | a1
   814: 03 18 18                 u32 [sp + 24] = a1
   817: 0b 78 05                 a1 = u8 [a0 + 5]
   820: 0b 79 04                 a2 = u8 [a0 + 4]
   823: 0b 7a 06                 a3 = u8 [a0 + 6]
   826: 0b 7b 07                 a4 = u8 [a0 + 7]
   829: 09 88 08                 a1 = a1 << 8
   832: 0c 98 08                 a1 = a1 | a2
   835: 09 aa 10                 a3 = a3 << 16
   838: 09 bb 18                 a4 = a4 << 24
   841: 0c ab 0a                 a3 = a4 | a3
   844: 0c 8a 08                 a1 = a3 | a1
   847: 03 18 14                 u32 [sp + 20] = a1
   850: 0b 78 01                 a1 = u8 [a0 + 1]
   853: 0b 79                    a2 = u8 [a0]
   855: 09 88 08                 a1 = a1 << 8
   858: 0b 7a 02                 a3 = u8 [a0 + 2]
   861: 0b 7b 03                 a4 = u8 [a0 + 3]
   864: 0c 98 09                 a2 = a1 | a2
   867: 01 18 28                 a1 = u32 [sp + 40]
   870: 09 aa 10                 a3 = a3 << 16
   873: 09 bb 18                 a4 = a4 << 24
   876: 0c ab 0a                 a3 = a4 | a3
   879: 0c 9a 09                 a2 = a3 | a2
   882: 02 8b ff ef              a4 = a1 + 0xffffefff
   886: 03 19 10                 u32 [sp + 16] = a2
   889: 2c 2b 00 f0 20           jump @75 if a4 <u 4294963200
      :                          @70
   894: 01 1a                    a3 = u32 [sp]
   896: 02 a9 00 10              a2 = a3 + 0x1000
   900: 11                       fallthrough
      :                          @71
   901: 01 9a                    a3 = u32 [a2]
   903: 14 a9 0b                 a4 = a2 - a3
   906: 1e 7b 0f                 jump @75 if a4 != a0
      :                          @72
   909: 14 8a 0b                 a4 = a3 - a1
   912: 11                       fallthrough
      :                          @73
   913: 01 9c                    a5 = u32 [a2]
   915: 1e ac f2                 jump @71 if a5 != a3
      :                          @74
   918: 03 9b                    u32 [a2] = a4
   920: 11                       fallthrough
      :                          @75
   921: 02 17 10                 a0 = sp + 0x10
   924: 04 08 0c                 a1 = 0xc
   927: 4e 11                    ecalli 17 // 'export'
   929: 04 07                    a0 = 0x0
   931: 01 10 3c                 ra = u32 [sp + 60]
   934: 01 15 38                 s0 = u32 [sp + 56]
   937: 01 16 34                 s1 = u32 [sp + 52]
   940: 02 11 40                 sp = sp + 0x40
   943: 13 00                    ret
      :                          @76
   945: 04 00 0a                 ra = 0xa
   948: 02 11 fc                 sp = sp - 4
   951: 03 10                    u32 [sp] = ra
   953: 00                       trap
      :                          @77 [@dyn 5]
   954: 00                       trap
      :                          @78 [export #2: 'accumulate']
   955: 02 11 ec                 sp = sp - 20
   958: 03 10 10                 u32 [sp + 16] = ra
   961: 0d 11 08                 u32 [sp + 8] = 0
   964: 0d 11 04                 u32 [sp + 4] = 0
   967: 0d 01                    u32 [sp + 0] = 0
   969: 1a 11 0f                 u8 [sp + 15] = 0
   972: 02 17 0f                 a0 = sp + 0xf
   975: 04 08 01                 a1 = 0x1
   978: 52 19                    a2 = sp
   980: 04 0a 0c                 a3 = 0xc
   983: 4e 03                    ecalli 3 // 'write'
   985: 04 07                    a0 = 0x0
   987: 01 10 10                 ra = u32 [sp + 16]
   990: 02 11 14                 sp = sp + 0x14
   993: 13 00                    ret
      :                          @79 [export #3: 'on_transfer']
   995: 04 07                    a0 = 0x0
   997: 13 00                    ret
      :                          @80
   999: 04 00 0c                 ra = 0xc
  1002: 02 11 fc                 sp = sp - 4
  1005: 03 10                    u32 [sp] = ra
  1007: 00                       trap
      :                          @81 [@dyn 6]
  1008: 00                       trap
      :                          @82
  1009: 02 11 f0                 sp = sp - 16
  1012: 03 10 0c                 u32 [sp + 12] = ra
  1015: 03 15 08                 u32 [sp + 8] = s0
  1018: 03 16 04                 u32 [sp + 4] = s1
  1021: 2c 19 10 64              jump @91 if a2 <u 16
      :                          @83
  1025: 28 7a                    a3 = -a0
  1027: 12 aa 03                 a3 = a3 & 0x3
  1030: 08 a7 0b                 a4 = a0 + a3
  1033: 07 0a 15                 jump @86 if a3 == 0
      :                          @84
  1036: 52 8c                    a5 = a1
  1038: 52 72                    t0 = a0
  1040: 11                       fallthrough
      :                          @85
  1041: 0b c3                    t1 = u8 [a5]
  1043: 10 23                    u8 [t0] = t1
  1045: 02 22 01                 t0 = t0 + 0x1
  1048: 02 cc 01                 a5 = a5 + 0x1
  1051: 2f b2 f6                 jump @85 if t0 <u a4
      :                          @86
  1054: 08 a8 08                 a1 = a1 + a3
  1057: 14 a9 09                 a2 = a2 - a3
  1060: 12 9c fc                 a5 = a2 & 0xfffffffc
  1063: 12 82 03                 t0 = a1 & 0x3
  1066: 08 cb 0a                 a3 = a4 + a5
  1069: 07 02 3b                 jump @93 if t0 == 0
      :                          @87
  1072: 2e 0c 4b                 jump @96 if a5 <=s 0
      :                          @88
  1075: 09 83 03                 t1 = a1 << 3
  1078: 12 32 18                 t0 = t1 & 0x18
  1081: 12 84 fc                 t2 = a1 & 0xfffffffc
  1084: 01 45                    s0 = u32 [t2]
  1086: 28 33                    t1 = -t1
  1088: 12 33 18                 t1 = t1 & 0x18
  1091: 02 44 04                 t2 = t2 + 0x4
  1094: 11                       fallthrough
      :                          @89
  1095: 01 46                    s1 = u32 [t2]
  1097: 33 25 05                 s0 = s0 >> t0
  1100: 37 36 00                 ra = s1 << t1
  1103: 0c 50 05                 s0 = ra | s0
  1106: 03 b5                    u32 [a4] = s0
  1108: 02 bb 04                 a4 = a4 + 0x4
  1111: 02 44 04                 t2 = t2 + 0x4
  1114: 52 65                    s0 = s1
  1116: 2f ab eb                 jump @89 if a4 <u a3
      :                          @90
  1119: 05 1c                    jump @96
      :                          @91
  1121: 52 7a                    a3 = a0
  1123: 0f 09 21                 jump @97 if a2 != 0
      :                          @92
  1126: 05 2f                    jump @99
      :                          @93
  1128: 2e 0c 13                 jump @96 if a5 <=s 0
      :                          @94
  1131: 52 82                    t0 = a1
  1133: 11                       fallthrough
      :                          @95
  1134: 01 23                    t1 = u32 [t0]
  1136: 03 b3                    u32 [a4] = t1
  1138: 02 bb 04                 a4 = a4 + 0x4
  1141: 02 22 04                 t0 = t0 + 0x4
  1144: 2f ab f6                 jump @95 if a4 <u a3
      :                          @96
  1147: 08 c8 08                 a1 = a1 + a5
  1150: 12 99 03                 a2 = a2 & 0x3
  1153: 07 09 14                 jump @99 if a2 == 0
      :                          @97
  1156: 08 9a 09                 a2 = a3 + a2
  1159: 11                       fallthrough
      :                          @98
  1160: 0b 8b                    a4 = u8 [a1]
  1162: 10 ab                    u8 [a3] = a4
  1164: 02 aa 01                 a3 = a3 + 0x1
  1167: 02 88 01                 a1 = a1 + 0x1
  1170: 2f 9a f6                 jump @98 if a3 <u a2
      :                          @99
  1173: 01 10 0c                 ra = u32 [sp + 12]
  1176: 01 15 08                 s0 = u32 [sp + 8]
  1179: 01 16 04                 s1 = u32 [sp + 4]
  1182: 02 11 10                 sp = sp + 0x10
  1185: 13 00                    ret
```