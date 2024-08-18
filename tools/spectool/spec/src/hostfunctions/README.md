## Host function Test Vectors

This directory has test vectors for JAM implementers to implement host functions of Appendix B of GP, all of which read + write registers just like Appendix A of GP but further interact with DA + PMT storage, setup and take down PVMs, and so on.  It is necessary to implement host functions to build elementary meaningful Work Packages / JAM Services (refine, accumulate, transfer, auth PVM) 

This is NOT an official test vector set, but a community contribution from a JAM implementer.  In particular, **Gav cautions**: "to use opcodes which are not yet in use in place of host functions I would caution against it. Opcodes which are not in use should panic as an illegal instruction. If they do anything else then it will fail test vectors."
 
This directory has  host function tests for JAM implementers, covering the 23 host functions described in Appendix B:
 * `read`  = 130 (0x82)
 * `write` = 131 (0x83)
 * `solicit` = 139 (0x8b)
 * `forget` = 140 (0x8c)
 * `import` = 147 (0x93)
 * `export` = 148 (0x94)
 * `historical_lookup` = 141 (0x8d)
 * `lookup` = 129 (0x81)
* `assign` = 149 (0x94)
* `checkpoint` = 135 (0x87)
* `designate` = 134 (0x86)
 * `egas` = 128 (0x80)
* `empower` = 133 (0x85)
* `expunge` = 148 (0x94)
* `info` = 132 (0x84)
* `invoke` = 147 (0x93)
* `machine` = 144 (0x90)
* `new` = 150 (0x96)
* `peek` = 145  (0x91)
* `poke` = 146 (0x92)
* `quit` = 138 (0x8a)
* `transfer` = 137 (0x89)
* `upgrade` = 136 (0x88)

 Each of these host functions are like `fallthrough` in not taking any arguments and result in just one byte in assembled byte code.  To avoid collisions with opcodes in Appendix A, 128 is added.  23 Opcodes (128-150) are used up with this method.  

 
###  Host Function `read`  (0x82) + `write` (0x83)
```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_read_write.txt  -o read_write.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes read_write.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 33
// Code size = 114 bytes
  :                            @0 [export #0: 'main']
 0: 26 02 00 40 2a             u32 [0x4000] = 42
 5: 26 03 00 00 02 78 56 34 12 u32 [0x20000] = 305419896
14: 04 07 00 00 02             a0 = 0x20000
19: 04 08 04                   a1 = 0x4
22: 04 09 00 40                a2 = 0x4000
26: 04 0a 04                   a3 = 0x4
29: 83                         write
30: 04 07 31                   a0 = 0x31
33: 04 08 00 00 02             a1 = 0x20000
38: 04 09 04                   a2 = 0x4
41: 04 0a 00 00 01             a3 = 0x10000
46: 04 0b 04                   a4 = 0x4
49: 82                         read
50: 0a 0a 00 00 01             a3 = u32 [0x10000]
55: 04 07 01                   a0 = 0x1
58: 22 77 09                   a2 = a0 * a0
61: 08 9a 0a                   a3 = a3 + a2
64: 04 07 03                   a0 = 0x3
67: 22 77 09                   a2 = a0 * a0
70: 08 9a 0a                   a3 = a3 + a2
73: 04 07 05                   a0 = 0x5
76: 22 77 09                   a2 = a0 * a0
79: 08 9a 0a                   a3 = a3 + a2
82: 04 07 07                   a0 = 0x7
85: 22 77 09                   a2 = a0 * a0
88: 08 9a 0a                   a3 = a3 + a2
91: 16 0a 00 00 02             u32 [0x20000] = a3
96: 04 07 00 00 03             a0 = 0x30000
101: 04 08 04                  a1 = 0x4
104: 04 09 00 00 02            a2 = 0x20000
109: 04 0a 04                  a3 = 0x4
112: 83                        write
113: 00 trap
```

### Host Function `import`  (0x8e) + `export` (0x8f)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_import_export.txt  -o import_export.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes import_export.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 10
// Code size = 26 bytes
  :                 @0 [export #0: 'main']
 0: 04 07           a0 = 0x0
 2: 04 08 00 30     a1 = 0x3000
 6: 04 09 04        a2 = 0x4
 9: 8e              import
10: 0a 0a 00 30     a3 = u32 [0x3000]
14: 22 aa 0b        a4 = a3 * a3
17: 04 07 00 70     a0 = 0x7000
21: 04 08 04        a1 = 0x4
24: 8f              export
25: 00              trap
```

### Host Function `solicit` (0x8b)
```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_solicit.txt  -o solicit.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes solicit.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 12
// Code size = 73 bytes
  :                          @0 [export #0: 'main']
 0: 04 07 00 40              a0 = 0x4000
 4: 04 08 04                 a1 = 0x4
 7: 26 02 00 40 43 44 7e 26  u32 [0x4000] = 645809219
15: 26 02 04 40 87 38 1a fc  u32 [0x4004] = 4229576839
23: 26 02 08 40 90 10 eb 9f  u32 [0x4008] = 2682982544
31: 26 02 0c 40 89 78 1e af  u32 [0x400c] = 2938009737
39: 26 02 10 40 32 d9 df 56  u32 [0x4010] = 1457510706
47: 26 02 14 40 ba dc cd 04  u32 [0x4014] = 80600250
55: 26 02 18 40 32 6e 8d 81  u32 [0x4018] = 2173529650
63: 26 02 1c 40 35 f3 57 ee  u32 [0x401c] = 3998741301
71: 8b                       solicit
72: 00                       trap
```

### Host Function `forget` (0x8c)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_forget.txt  -o forget.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes forget.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 12
// Code size = 73 bytes
  :                          @0 [export #0: 'main']
 0: 04 07 00 40              a0 = 0x4000
 4: 04 08 04                 a1 = 0x4
 7: 26 02 00 40 43 44 7e 26  u32 [0x4000] = 645809219
15: 26 02 04 40 87 38 1a fc  u32 [0x4004] = 4229576839
23: 26 02 08 40 90 10 eb 9f  u32 [0x4008] = 2682982544
31: 26 02 0c 40 89 78 1e af  u32 [0x400c] = 2938009737
39: 26 02 10 40 32 d9 df 56  u32 [0x4010] = 1457510706
47: 26 02 14 40 ba dc cd 04  u32 [0x4014] = 80600250
55: 26 02 18 40 32 6e 8d 81  u32 [0x4018] = 2173529650
63: 26 02 1c 40 35 f3 57 ee  u32 [0x401c] = 3998741301
71: 8c                       forget
72: 00                       trap
```

### Host Function `historical_lookup` (0x8d)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_historical_lookup.txt  -o historical_lookup.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes historical_lookup.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 14
// Code size = 80 bytes
  :                          @0 [export #0: 'main']
 0: 04 07 31                 a0 = 0x31
 3: 26 02 00 40 78 56 34 12  u32 [0x4000] = 305419896
11: 26 02 04 40 78 56 34 12  u32 [0x4004] = 305419896
19: 26 02 08 40 78 56 34 12  u32 [0x4008] = 305419896
27: 26 02 0c 40 78 56 34 12  u32 [0x400c] = 305419896
35: 26 02 10 40 78 56 34 12  u32 [0x4010] = 305419896
43: 26 02 14 40 78 56 34 12  u32 [0x4014] = 305419896
51: 26 02 18 40 78 56 34 12  u32 [0x4018] = 305419896
59: 26 02 1c 40 78 56 34 12  u32 [0x401c] = 305419896
67: 04 08 00 40              a1 = 0x4000
71: 04 09 00 50              a2 = 0x5000
75: 04 0a 04                 a3 = 0x4
78: 8d                       historical_lookup
79: 00                       trap
```

### Host Function `lookup` (0x81)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_lookup.txt  -o lookup.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes lookup.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 14
// Code size = 80 bytes
  :                          @0 [export #0: 'main']
 0: 04 07 31                 a0 = 0x31
 3: 26 02 00 40 78 56 34 12  u32 [0x4000] = 305419896
11: 26 02 04 40 78 56 34 12  u32 [0x4004] = 305419896
19: 26 02 08 40 78 56 34 12  u32 [0x4008] = 305419896
27: 26 02 0c 40 78 56 34 12  u32 [0x400c] = 305419896
35: 26 02 10 40 78 56 34 12  u32 [0x4010] = 305419896
43: 26 02 14 40 78 56 34 12  u32 [0x4014] = 305419896
51: 26 02 18 40 78 56 34 12  u32 [0x4018] = 305419896
59: 26 02 1c 40 78 56 34 12  u32 [0x401c] = 305419896
67: 04 08 00 40              a1 = 0x4000
71: 04 09 00 50              a2 = 0x5000
75: 04 0a 04                 a3 = 0x4
78: 81                       lookup
79: 00                       trap
```


### Host Function `assign` (0x95)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_assign.txt  -o assign.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes assign.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 4
// Code size = 9 bytes
  :              @0 [export #0: 'main']
 0: 04 07 01     a0 = 0x1
 3: 04 08 00 40  a1 = 0x4000
 7: 95           assign
 8: 00           trap
```

### Host Function `checkpoint` (0x87)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_checkpoint.txt  -o checkpoint.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes checkpoint.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 2
// Code size = 2 bytes
  :     @0 [export #0: 'main']
 0: 87  checkpoint
 1: 00  trap
```

### Host Function `designate` (0x86)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_designate.txt  -o designate.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes designate.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 3
// Code size = 7 bytes
  :                @0 [export #0: 'main']
 0: 04 07 00 00 01 a0 = 0x10000
 5: 86             designate
 6: 00             trap
```

### Host Function `egas` (0x80)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_egas.txt  -o egas.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes egas.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 2
// Code size = 2 bytes
  :            @0 [export #0: 'main']
 0:  80        egas
 1:  00        trap
```

### Host Function `empower` (0x85)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_empower.txt  -o empower.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes empower.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 5
// Code size = 18 bytes
 :  @0 [export #0: 'main']
 0: 04 07 78 56 34 12  a0 = 0x12345678
 6: 04 08 21 43 65 87  a1 = 0x87654321
12: 04 09 00 01.       a2 = 0x100
16: 85                 empower
17: 00                 trap
```

### Host Function `expunge` (0x94)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_expunge.txt  -o expunge.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes expunge.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 3
// Code size = 5 bytes
  :             @0 [export #0: 'main']
 0: 04 07 2b    a0 = 0x2b
 3: 94          expunge
 4: 00          trap
```

### Host Function `info` (0x84)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_info.txt  -o info.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes info.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 4
// Code size = 9 bytes
  :              @0 [export #0: 'main']
 0: 04 07 2a     a0 = 0x2a
 3: 04 08 00 60  a1 = 0x6000
 7: 84           info
 8: 00           trap
```

### Host Function `invoke` (0x93)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_invoke.txt  -o invoke.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes invoke.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 4
// Code size = 9 bytes
  :              @0 [export #0: 'main']
 0: 04 07 2b     a0 = 0x2b
 3: 04 08 00 40  a1 = 0x4000
 7: 93           invoke
 8: 00           trap
```

### Host Function `machine` (0x90)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_machine.txt  -o machine.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes machine.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 5
// Code size = 12 bytes
  :              @0 [export #0: 'main']
 0: 04 07 00 40  a0 = 0x4000
 4: 04 08 40     a1 = 0x40
 7: 04 09 40     a2 = 0x40
10: 90           machine
11: 00           trap
```

### Host Function `new` (0x96)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_new.txt  -o new.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes new.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 8
// Code size = 27 bytes
 :                     @0 [export #0: 'main']
 0: 04 07 00 40        a0 = 0x4000
 4: 04 08 2a           a1 = 0x2a
 7: 04 09 01           a2 = 0x1
10: 04 0a 78 56 34 12  a3 = 0x12345678
16: 04 0b 02           a4 = 0x2
19: 04 0c 21 43 65 87  a5 = 0x87654321
25: 96                 new
26: 00                 trap
```

### Host Function `peek`

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_peek.txt  -o peek.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes peek.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 6
// Code size = 16 bytes
 :               @0 [export #0: 'main']
 0: 04 07 2a     a0 = 0x2a
 3: 04 08 00 30  a1 = 0x3000
 7: 04 09 00 20  a2 = 0x2000
11: 04 0a 04     a3 = 0x4
14: 91           peek
15: 00           trap
```

### Host Function `poke` (0x92)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_poke.txt  -o poke.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes poke.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 6
// Code size = 16 bytes
  :              @0 [export #0: 'main']
 0: 04 07 2a     a0 = 0x2a
 3: 04 08 00 40  a1 = 0x4000
 7: 04 09 00 30  a2 = 0x3000
11: 04 0a 04     a3 = 0x4
14: 92           poke
15: 00           trap
```

### Host Function `quit` (0x8a)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_quit.txt  -o quit.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes quit.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 4
// Code size = 9 bytes
  :              @0 [export #0: 'main']
 0: 04 07 2a     a0 = 0x2a
 3: 04 08 00 40  a1 = 0x4000
 7: 8a           quit
 8: 00           trap
```

### Host Function `transfer` (0x89)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_transfer.txt  -o transfer.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes transfer.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 8
// Code size = 25 bytes
 :               @0 [export #0: 'main']
 0: 04 07 2a     a0 = 0x2a
 3: 04 08 34 12  a1 = 0x1234
 7: 04 09 78 56  a2 = 0x5678
11: 04 0a 23 01  a3 = 0x123
15: 04 0b 67 45  a4 = 0x4567
19: 04 0c 00 40  a5 = 0x4000
23: 89           transfer
24: 00           trap
```

### Host Function `upgrade` (0x88)

```
# cargo run -p polkatool -- assemble  tools/spectool/spec/src/hostfunctions/host_upgrade.txt  -o upgrade.polkavm
# cargo run -p polkatool disassemble --show-raw-bytes upgrade.polkavm
// RO data = 0/0 bytes
// RW data = 0/0 bytes
// Stack size = 0 bytes
// Instructions = 7
// Code size = 24 bytes
  :                    @0 [export #0: 'main']
 0: 04 07 00 40        a0 = 0x4000
 4: 04 08 78 56 34 12  a1 = 0x12345678
10: 04 09 01           a2 = 0x1
13: 04 0a 02           a3 = 0x2
16: 04 0b 21 43 65 87  a4 = 0x87654321
22: 88                 upgrade
23: 00                 trap
```
