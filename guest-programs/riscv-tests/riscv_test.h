#ifndef __RISCV_TEST_H__
#define __RISCV_TEST_H__

#define RVTEST_DATA_BEGIN
#define RVTEST_DATA_END
#define RVTEST_CODE_BEGIN _start:
#define RVTEST_CODE_END
#define RVTEST_RV32U
#define RVTEST_RV64U
#define RVTEST_FAIL unimp
#define RVTEST_PASS j _finish

_finish:
    li ra, 0xffff0000
    ret

.global _start

.pushsection .polkavm_min_stack_size,"",@progbits
    .word 4096
.popsection

.pushsection .metadata,"",@progbits
_entry_point_name:
    .asciz "main"

_metadata:
    .byte 1
    .word 0
    .word 4
    #ifdef __LP64__
    .quad _entry_point_name
    #else
    .word _entry_point_name
    #endif
    .byte 0
    .byte 0
.popsection

.pushsection .polkavm_exports,"R",@note
    .byte 1
    #ifdef __LP64__
    .quad _metadata
    .quad _start
    #else
    .word _metadata
    .word _start
    #endif
.popsection

#endif
