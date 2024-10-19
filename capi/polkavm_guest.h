#ifndef POLKAVM_GUEST_H_
#define POLKAVM_GUEST_H_

#define POLKAVM_JOIN_IMPL(X,Y) X##Y
#define POLKAVM_JOIN(X,Y) POLKAVM_JOIN_IMPL(X, Y)
#define POLKAVM_UNIQUE(X) POLKAVM_JOIN(X, __COUNTER__)

#define POLKAVM_REGS_FOR_TY_void 0
#define POLKAVM_REGS_FOR_TY_i32 1
#ifdef _LP64
    #define POLKAVM_REGS_FOR_TY_i64 1
#else
    #define POLKAVM_REGS_FOR_TY_i64 2
#endif

#define POLKAVM_REGS_FOR_TY_int8_t    POLKAVM_REGS_FOR_TY_i32
#define POLKAVM_REGS_FOR_TY_uint8_t   POLKAVM_REGS_FOR_TY_i32
#define POLKAVM_REGS_FOR_TY_int16_t   POLKAVM_REGS_FOR_TY_i32
#define POLKAVM_REGS_FOR_TY_uint16_t  POLKAVM_REGS_FOR_TY_i32
#define POLKAVM_REGS_FOR_TY_int32_t   POLKAVM_REGS_FOR_TY_i32
#define POLKAVM_REGS_FOR_TY_uint32_t  POLKAVM_REGS_FOR_TY_i32
#define POLKAVM_REGS_FOR_TY_int64_t   POLKAVM_REGS_FOR_TY_i64
#define POLKAVM_REGS_FOR_TY_uint64_t  POLKAVM_REGS_FOR_TY_i64
#define POLKAVM_REGS_FOR_TY_int       POLKAVM_REGS_FOR_TY_i32

#ifdef _LP64
    #define POLKAVM_REGS_FOR_TY_size_t    POLKAVM_REGS_FOR_TY_i64
    #define POLKAVM_REGS_FOR_TY_long      POLKAVM_REGS_FOR_TY_i64
#else
    #define POLKAVM_REGS_FOR_TY_size_t    POLKAVM_REGS_FOR_TY_i32
    #define POLKAVM_REGS_FOR_TY_long      POLKAVM_REGS_FOR_TY_i32
#endif

#define POLKAVM_COUNT_ARGS(...) POLKAVM_COUNT_ARGS_IMPL(0, ## __VA_ARGS__, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define POLKAVM_COUNT_ARGS_IMPL(_0, _1_, _2_, _3_, _4_, _5_, _6_, _7_, _8_, _9_, _10_, _11_, _12_, _13_, _14_, _15_, _16_, _17_, _18_, _19_, _20_, _21_, _22_, _23_, _24_, _25_, _26_, _27_, _28_, _29_, _30_, _31_, _32_, count, ...) count

#define POLKAVM_REGS_FOR_TY(X) POLKAVM_JOIN(POLKAVM_REGS_FOR_TY_, X)

#define POLKAVM_ARG_ASM_4_0()
#define POLKAVM_ARG_ASM_4_1(A) \
    ".byte %[arg_1]\n"
#define POLKAVM_ARG_ASM_4_2(A, B) \
    ".byte %[arg_1]\n" \
    ".byte %[arg_2]\n"
#define POLKAVM_ARG_ASM_4_3(A, B, C) \
    ".byte %[arg_1]\n" \
    ".byte %[arg_2]\n" \
    ".byte %[arg_3]\n"
#define POLKAVM_ARG_ASM_4_4(A, B, C, D) \
    ".byte %[arg_1]\n" \
    ".byte %[arg_2]\n" \
    ".byte %[arg_3]\n" \
    ".byte %[arg_4]\n"
#define POLKAVM_ARG_ASM_4_5(A, B, C, D, E) \
    ".byte %[arg_1]\n" \
    ".byte %[arg_2]\n" \
    ".byte %[arg_3]\n" \
    ".byte %[arg_4]\n" \
    ".byte %[arg_5]\n"
#define POLKAVM_ARG_ASM_4_6(A, B, C, D, E, F) \
    ".byte %[arg_1]\n" \
    ".byte %[arg_2]\n" \
    ".byte %[arg_3]\n" \
    ".byte %[arg_4]\n" \
    ".byte %[arg_5]\n" \
    ".byte %[arg_6]\n"

#define POLKAVM_ARG_ASM_3(N, ...) POLKAVM_ARG_ASM_4_ ## N(__VA_ARGS__)
#define POLKAVM_ARG_ASM_2(N, ...) POLKAVM_ARG_ASM_3(N, ## __VA_ARGS__)
#define POLKAVM_ARG_ASM(...) POLKAVM_ARG_ASM_2(POLKAVM_COUNT_ARGS(__VA_ARGS__), ## __VA_ARGS__)

#define POLKAVM_COUNT_REGS_4_0() \
    0
#define POLKAVM_COUNT_REGS_4_1(A) \
    POLKAVM_REGS_FOR_TY(A)
#define POLKAVM_COUNT_REGS_4_2(A, B) \
    POLKAVM_REGS_FOR_TY(A) + POLKAVM_REGS_FOR_TY(B)
#define POLKAVM_COUNT_REGS_4_3(A, B, C) \
    POLKAVM_REGS_FOR_TY(A) + POLKAVM_REGS_FOR_TY(B) + POLKAVM_REGS_FOR_TY(C)
#define POLKAVM_COUNT_REGS_4_4(A, B, C, D) \
    POLKAVM_REGS_FOR_TY(A) + POLKAVM_REGS_FOR_TY(B) + POLKAVM_REGS_FOR_TY(C) + POLKAVM_REGS_FOR_TY(D)
#define POLKAVM_COUNT_REGS_4_5(A, B, C, D, E) \
    POLKAVM_REGS_FOR_TY(A) + POLKAVM_REGS_FOR_TY(B) + POLKAVM_REGS_FOR_TY(C) + POLKAVM_REGS_FOR_TY(D) + POLKAVM_REGS_FOR_TY(E)
#define POLKAVM_COUNT_REGS_4_6(A, B, C, D, E, F) \
    POLKAVM_REGS_FOR_TY(A) + POLKAVM_REGS_FOR_TY(B) + POLKAVM_REGS_FOR_TY(C) + POLKAVM_REGS_FOR_TY(D) + POLKAVM_REGS_FOR_TY(E) + POLKAVM_REGS_FOR_TY(F)

#define POLKAVM_COUNT_REGS_3(N, ...) POLKAVM_COUNT_REGS_4_ ## N(__VA_ARGS__)
#define POLKAVM_COUNT_REGS_2(N, ...) POLKAVM_COUNT_REGS_3(N, ## __VA_ARGS__)
#define POLKAVM_COUNT_REGS(...) POLKAVM_COUNT_REGS_2(POLKAVM_COUNT_ARGS(__VA_ARGS__), ## __VA_ARGS__)

#define POLKAVM_IMPORT_ARGS_IMPL_4_0()
#define POLKAVM_IMPORT_ARGS_IMPL_4_1(A0) A0 a0
#define POLKAVM_IMPORT_ARGS_IMPL_4_2(A0, A1) A0 a0, A1 a1
#define POLKAVM_IMPORT_ARGS_IMPL_4_3(A0, A1, A2) A0 a0, A1 a1, A2 a2
#define POLKAVM_IMPORT_ARGS_IMPL_4_4(A0, A1, A2, A3) A0 a0, A1 a1, A2 a2, A3 a3
#define POLKAVM_IMPORT_ARGS_IMPL_4_5(A0, A1, A2, A3, A4) A0 a0, A1 a1, A2 a2, A3 a3, A4 a4
#define POLKAVM_IMPORT_ARGS_IMPL_4_6(A0, A1, A2, A3, A4, A5) A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5

#define POLKAVM_IMPORT_ARGS_IMPL_3(N, ...) POLKAVM_IMPORT_ARGS_IMPL_4_ ## N(__VA_ARGS__)
#define POLKAVM_IMPORT_ARGS_IMPL_2(N, ...) POLKAVM_IMPORT_ARGS_IMPL_3(N, ## __VA_ARGS__)
#define POLKAVM_IMPORT_ARGS_IMPL(...) POLKAVM_IMPORT_ARGS_IMPL_2(POLKAVM_COUNT_ARGS(__VA_ARGS__), ## __VA_ARGS__)

struct PolkaVM_Metadata {
    unsigned char version;
    unsigned int flags;
    unsigned int symbol_length;
    const char * symbol;
    unsigned char input_regs;
    unsigned char output_regs;
} __attribute__ ((packed));

#ifdef _LP64
    #define POLKAVM_EXPORT_DEF()  \
        ".quad %[metadata]\n" \
        ".quad %[function]\n"
#else
    #define POLKAVM_EXPORT_DEF()  \
        ".word %[metadata]\n" \
        ".word %[function]\n"
#endif

#ifdef _LP64
    #define POLKAVM_IMPORT_DEF()  \
        ".quad 0x0000000b\n" \
        ".quad %[metadata]\n"
#else
    #define POLKAVM_IMPORT_DEF()  \
        ".word 0x0000000b\n" \
        ".word %[metadata]\n"
#endif

#define POLKAVM_EXPORT(arg_return_ty, fn_name, ...) \
static struct PolkaVM_Metadata POLKAVM_JOIN(fn_name, __EXPORT_METADATA) __attribute__ ((section(".polkavm_metadata"))) = { \
    1, 0, sizeof(#fn_name) - 1, #fn_name, POLKAVM_COUNT_REGS(__VA_ARGS__), POLKAVM_COUNT_REGS(arg_return_ty) \
}; \
static void __attribute__ ((naked, used)) POLKAVM_UNIQUE(polkavm_export_dummy)() { \
    __asm__( \
        ".pushsection .polkavm_exports,\"R\",@note\n" \
        ".byte 1\n" \
        POLKAVM_EXPORT_DEF() \
        ".popsection\n" \
        : \
        : \
          [metadata] "i" (&POLKAVM_JOIN(fn_name, __EXPORT_METADATA)), \
          [function] "i" (fn_name) \
        : "memory" \
    ); \
}

#define POLKAVM_IMPORT(arg_return_ty, fn_name, ...) \
static struct PolkaVM_Metadata POLKAVM_JOIN(fn_name, __IMPORT_METADATA) __attribute__ ((section(".polkavm_metadata"))) = { \
    1, 0, sizeof(#fn_name) - 1, #fn_name, POLKAVM_COUNT_REGS(__VA_ARGS__), POLKAVM_COUNT_REGS(arg_return_ty) \
}; \
static arg_return_ty __attribute__ ((naked)) fn_name(POLKAVM_IMPORT_ARGS_IMPL(__VA_ARGS__)) { \
    __asm__( \
        POLKAVM_IMPORT_DEF() \
        "ret\n" \
        : \
        : \
          [metadata] "i" (&POLKAVM_JOIN(fn_name, __IMPORT_METADATA)) \
        : "memory" \
    ); \
}

#define POLKAVM_MIN_STACK_SIZE(size) \
static void __attribute__ ((naked, used)) POLKAVM_UNIQUE(polkavm_stack_size)() { \
    __asm__( \
        ".pushsection .polkavm_min_stack_size,\"\",@progbits\n" \
        ".word %[value]\n" \
        ".popsection\n" \
        : \
        : \
          [value] "i" (size) \
        : \
    ); \
}

#define POLKAVM_TRAP() \
{ \
    __asm__("unimp\n" :::); \
    __builtin_unreachable(); \
}

#endif
