
# JAM Service: Fib

This is a test Rust-based JAM service named "jam-service-fib" with refine/accumulate/on_transfer/is_authorized entrypoints:

* `refine` (entry point 5) imports a 12-byte segment with [n, fib(n), f(n-1)] and exports the next segment in the same way [n+1, fib(n+1), fib(n)]
* `accumulate` (entry point 10) reads a 12-byte segment and writes to service storage key "0"
* `is_authorized` (entry point 0) and `on_transfer` (entry point 15) are just stubs right now

It uses 3 polka_import macros for import/export/write but attempts to set up all 23 or so and a few others.  These are just stubs at present, have not been checked or tested.


## Setup toolchain

Install this [rustc-rv32e-toolchain](https://github.com/paritytech/rustc-rv32e-toolchain/) -- we found the release build sufficient.

After installation you should have `~/.rustup/toolchains/rve-nightly/`.  Then

```
export RUSTUP_TOOLCHAIN=rve-nightly
```

will make this accessible

## Build Service

```
cargo build --release --target-dir=./target
```

This will generate a 1MB file in `target` here:

```
# ls -l target/riscv32ema-unknown-none-elf/release/jam-service-fib
-rwxr-xr-x 2 root root 1067744 Sep 26 09:37 target/riscv32ema-unknown-none-elf/release/jam-service-fib
```

## Generate PVM Byte code with `polkatool`

You can then use `polkatool` to generate "JAM-ready" PVM byte code and raw code blobs with:
```
# cargo run -p polkatool jam-service guest-programs/jam-service-fib/target/riscv32ema-unknown-none-elf/release/jam-service-fib -o guest-programs/jam-service-fib/jam_service.pvm -d guest-programs/jam-service-fib/blob.pvm
warning: /root/go/src/github.com/colorfulnotion/polkavm/Cargo.toml: unused manifest key: workspace.lints.rust.unexpected_cfgs.check-cfg
    Finished dev [unoptimized + debuginfo] target(s) in 0.08s
     Running `target/debug/polkatool jam-service guest-programs/jam-service-fib/target/riscv32ema-unknown-none-elf/release/jam-service-fib -o guest-programs/jam-service-fib/jam_service.pvm -d guest-programs/jam-service-fib/blob.pvm`
Writing JAM-ready code blob "guest-programs/jam-service-fib/jam_service.pvm"
Writing raw code "guest-programs/jam-service-fib/blob.pvm"
```

## Disassemble

Given the above `blob.pvm`, you can disassemble it with `polkatool`:

```
# cargo run -p polkatool disassemble guest-programs/jam-service-fib/blob.pvm  --show-raw-bytes
// RO data = 0/0 bytes
// RW data = 0/4128 bytes
// Stack size = 4096 bytes

// Instructions = 418
// Code size = 1185 bytes

      :                          @0
     0: 05 ee 01 00 00           jump @52  // is_authorized
      :                          @1
     5: 05 ed 01 00 00           jump @53  // refine
      :                          @2
    10: 05 af 03 00 00           jump @78  // accumulate
      :                          @3
    15: 05 d2 03                 jump @79  // on_transfer
      :                          @4


      :                          @52 [export #0: 'is_authorized']
   494: 04 07                    a0 = 0x0
   496: 13 00                    ret


      :                          @53 [export #1: 'refine']
   498: 02 11 c0                 sp = sp - 64
   501: 03 10 3c                 u32 [sp + 60] = ra
   504: 03 15 38                 u32 [sp + 56] = s0
   507: 03 16 34                 u32 [sp + 52] = s1
   510: 0d 11 18                 u32 [sp + 24] = 0
   513: 0d 11 14                 u32 [sp + 20] = 0
   516: 0d 11 10                 u32 [sp + 16] = 0
   519: 02 18 10                 a1 = sp + 0x10
   522: 04 09 0c                 a2 = 0xc
   525: 04 07                    a0 = 0x0
   527: 4e 10                    ecalli 16 // 'import'
   529: 11                       fallthrough
      :                          @54
   530: 07 07 1a                 jump @56 if a0 == 0
      :                          @55
   533: 0d 11 10 01              u32 [sp + 16] = 1
   537: 0d 11 14 01              u32 [sp + 20] = 1
   541: 1a 11 18                 u8 [sp + 24] = 0
   544: 1a 11 19                 u8 [sp + 25] = 0
   547: 1a 11 1a                 u8 [sp + 26] = 0
   550: 1a 11 1b                 u8 [sp + 27] = 0
   553: 05 6e 01                 jump @75
      :                          @56
   556: 01 17 14                 a0 = u32 [sp + 20]
   559: 01 18 18                 a1 = u32 [sp + 24]
   562: 01 19 10                 a2 = u32 [sp + 16]
   565: 08 78 0a                 a3 = a1 + a0
   568: 02 98 01                 a1 = a2 + 0x1
   571: 03 18 1c                 u32 [sp + 28] = a1
   574: 02 14 20                 t2 = sp + 0x20
   577: 03 1a 20                 u32 [sp + 32] = a3
   580: 03 17 24                 u32 [sp + 36] = a0
   583: 02 10 1d                 ra = sp + 0x1d
   586: 04 07 00 10              a0 = 0x1000
   590: 04 03 10 00 02           t1 = 0x20010
   595: 04 09 10 10 02           a2 = 0x21010
   600: 11                       fallthrough
      :                          @57
   601: 01 9b                    a4 = u32 [a2]
   603: 02 ba 08                 a3 = a4 + 0x8
   606: 2f ba 87 01              jump @80 if a3 <u a4
      :                          @58
   610: 02 ac 01                 a5 = a3 + 0x1
   613: 1b c2 01                 t0 = a5 <u 0x1
   616: 24 c7 0c                 a5 = a0 <u a5
   619: 0c c2 0c                 a5 = t0 | a5
   622: 0f 0c 77 01              jump @80 if a5 != 0
      :                          @59
   626: 01 9c                    a5 = u32 [a2]
   628: 1e bc e5                 jump @57 if a5 != a4
      :                          @60
   631: 03 9a                    u32 [a2] = a3
   633: 04 02                    t0 = 0x0
   635: 03 13                    u32 [sp] = t1
   637: 14 a3 07                 a0 = t1 - a3
   640: 04 09 00 10              a2 = 0x1000
   644: 08 97 07                 a0 = a0 + a2
   647: 10 78                    u8 [a0] = a1
   649: 04 08 08                 a1 = 0x8
   652: 03 18 28                 u32 [sp + 40] = a1
   655: 03 17 2c                 u32 [sp + 44] = a0
   658: 04 05 01                 s0 = 0x1
   661: 03 15 30                 u32 [sp + 48] = s0
   664: 02 1a 1c                 a3 = sp + 0x1c
   667: 04 0b 03                 a4 = 0x3
   670: 04 0c 01                 a5 = 0x1
   673: 05 19                    jump @63
      :                          @61
   675: 01 19 28                 a2 = u32 [sp + 40]
   678: 0b 06                    s1 = u8 [ra]
   680: 02 00 01                 ra = ra + 0x1
   683: 18 95 26                 jump @66 if s0 == a2
      :                          @62
   686: 08 57 08                 a1 = a0 + s0
   689: 10 86                    u8 [a1] = s1
   691: 02 55 01                 s0 = s0 + 0x1
   694: 03 15 30                 u32 [sp + 48] = s0
   697: 11                       fallthrough
      :                          @63
   698: 1e 40 e9                 jump @61 if ra != t2
      :                          @64
   701: 18 bc 49                 jump @68 if a5 == a4
      :                          @65
   704: 09 c8 02                 a1 = a5 << 2
   707: 08 8a 00                 ra = a3 + a1
   710: 02 cc 01                 a5 = a5 + 0x1
   713: 09 c8 02                 a1 = a5 << 2
   716: 08 8a 04                 t2 = a3 + a1
   719: 05 d4                    jump @61
      :                          @66
   721: 14 04 07                 a0 = t2 - ra
   724: 02 77 01                 a0 = a0 + 0x1
   727: 27 78                    a1 = a0 >u 0x0
   729: 02 88 ff                 a1 = a1 - 1
   732: 0c 78 09                 a2 = a1 | a0
   735: 02 17 28                 a0 = sp + 0x28
   738: 52 58                    a1 = s0
   740: 03 14 0c                 u32 [sp + 12] = t2
   743: 03 10 08                 u32 [sp + 8] = ra
   746: 03 1c 04                 u32 [sp + 4] = a5
   749: 06 10 08 78 fe           ra = 8, jump @37
      :                          @67 [@dyn 4]
   754: 01 1c 04                 a5 = u32 [sp + 4]
   757: 04 0b 03                 a4 = 0x3
   760: 02 1a 1c                 a3 = sp + 0x1c
   763: 01 10 08                 ra = u32 [sp + 8]
   766: 01 14 0c                 t2 = u32 [sp + 12]
   769: 01 17 2c                 a0 = u32 [sp + 44]
   772: 05 aa                    jump @62
      :                          @68
   774: 0f 15 0c a9 00           jump @76 if s0 != 12
      :                          @69
   779: 01 17 2c                 a0 = u32 [sp + 44]
   782: 0b 78 09                 a1 = u8 [a0 + 9]
   785: 0b 79 08                 a2 = u8 [a0 + 8]
   788: 0b 7a 0a                 a3 = u8 [a0 + 10]
   791: 0b 7b 0b                 a4 = u8 [a0 + 11]
   794: 09 88 08                 a1 = a1 << 8
   797: 0c 98 08                 a1 = a1 | a2
   800: 09 aa 10                 a3 = a3 << 16
   803: 09 bb 18                 a4 = a4 << 24
   806: 0c ab 0a                 a3 = a4 | a3
   809: 0c 8a 08                 a1 = a3 | a1
   812: 03 18 18                 u32 [sp + 24] = a1
   815: 0b 78 05                 a1 = u8 [a0 + 5]
   818: 0b 79 04                 a2 = u8 [a0 + 4]
   821: 0b 7a 06                 a3 = u8 [a0 + 6]
   824: 0b 7b 07                 a4 = u8 [a0 + 7]
   827: 09 88 08                 a1 = a1 << 8
   830: 0c 98 08                 a1 = a1 | a2
   833: 09 aa 10                 a3 = a3 << 16
   836: 09 bb 18                 a4 = a4 << 24
   839: 0c ab 0a                 a3 = a4 | a3
   842: 0c 8a 08                 a1 = a3 | a1
   845: 03 18 14                 u32 [sp + 20] = a1
   848: 0b 78 01                 a1 = u8 [a0 + 1]
   851: 0b 79                    a2 = u8 [a0]
   853: 09 88 08                 a1 = a1 << 8
   856: 0b 7a 02                 a3 = u8 [a0 + 2]
   859: 0b 7b 03                 a4 = u8 [a0 + 3]
   862: 0c 98 09                 a2 = a1 | a2
   865: 01 18 28                 a1 = u32 [sp + 40]
   868: 09 aa 10                 a3 = a3 << 16
   871: 09 bb 18                 a4 = a4 << 24
   874: 0c ab 0a                 a3 = a4 | a3
   877: 0c 9a 09                 a2 = a3 | a2
   880: 02 8b ff ef              a4 = a1 + 0xffffefff
   884: 03 19 10                 u32 [sp + 16] = a2
   887: 2c 2b 00 f0 20           jump @75 if a4 <u 4294963200
      :                          @70
   892: 01 1a                    a3 = u32 [sp]
   894: 02 a9 00 10              a2 = a3 + 0x1000
   898: 11                       fallthrough
      :                          @71
   899: 01 9a                    a3 = u32 [a2]
   901: 14 a9 0b                 a4 = a2 - a3
   904: 1e 7b 0f                 jump @75 if a4 != a0
      :                          @72
   907: 14 8a 0b                 a4 = a3 - a1
   910: 11                       fallthrough
      :                          @73
   911: 01 9c                    a5 = u32 [a2]
   913: 1e ac f2                 jump @71 if a5 != a3
      :                          @74
   916: 03 9b                    u32 [a2] = a4
   918: 11                       fallthrough
      :                          @75
   919: 02 17 10                 a0 = sp + 0x10
   922: 04 08 0c                 a1 = 0xc
   925: 4e 11                    ecalli 17 // 'export'
   927: 04 07                    a0 = 0x0
   929: 01 10 3c                 ra = u32 [sp + 60]
   932: 01 15 38                 s0 = u32 [sp + 56]
   935: 01 16 34                 s1 = u32 [sp + 52]
   938: 02 11 40                 sp = sp + 0x40
   941: 13 00                    ret
      :                          @76
   943: 04 00 0a                 ra = 0xa
   946: 02 11 fc                 sp = sp - 4
   949: 03 10                    u32 [sp] = ra
   951: 00                       trap
      :                          @77 [@dyn 5]
   952: 00                       trap




      :                          @78 [export #2: 'accumulate']
   953: 02 11 ec                 sp = sp - 20
   956: 03 10 10                 u32 [sp + 16] = ra
   959: 0d 11 08                 u32 [sp + 8] = 0
   962: 0d 11 04                 u32 [sp + 4] = 0
   965: 0d 01                    u32 [sp + 0] = 0
   967: 1a 11 0f                 u8 [sp + 15] = 0
   970: 02 17 0f                 a0 = sp + 0xf
   973: 04 08 01                 a1 = 0x1
   976: 52 19                    a2 = sp
   978: 04 0a 0c                 a3 = 0xc
   981: 4e 03                    ecalli 3 // 'write'
   983: 04 07                    a0 = 0x0
   985: 01 10 10                 ra = u32 [sp + 16]
   988: 02 11 14                 sp = sp + 0x14
   991: 13 00                    ret



      :                          @79 [export #3: 'on_transfer']
   993: 04 07                    a0 = 0x0
   995: 13 00                    ret

...
```