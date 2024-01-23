.pushsection ".text"

.p2align 4, 0xcc
_start:
.global _start
// Map ourselves a new stack.
mov rax, {SYS_mmap}
mov rdi, {native_stack_low}
mov rsi, {native_stack_size}
mov rdx, {stack_mmap_protection}
mov r10, {stack_mmap_flags}
mov r8, -1
mov r9, 0
syscall
mov rdi, rsp
mov rsp, {native_stack_high}
push rbp
jmp {entry_point}

.p2align 4, 0xcc
zygote_longjmp:
// Restore registers.
mov rbx, [rdi + 8]
mov rsp, [rdi + 16]
mov rbp, [rdi + 24]
mov r12, [rdi + 32]
mov r13, [rdi + 40]
mov r14, [rdi + 48]
mov r15, [rdi + 56]
// Set return value.
mov rax, rsi
// Jump out.
mov rdx, [rdi]
jmp rdx

.p2align 4, 0xcc
zygote_setjmp:
// Save the return address.
mov rax, [rsp]
mov [rdi], rax
// Save the callee-saved registers.
mov [rdi + 8], rbx
lea rax, [rsp + 8] // Get the stack pointer as if it was *after* popping the return address.
mov [rdi + 16], rax
mov [rdi + 24], rbp
mov [rdi + 32], r12
mov [rdi + 40], r13
mov [rdi + 48], r14
mov [rdi + 56], r15
// Return '0'.
xor rax, rax
ret

.p2align 4, 0xcc
zygote_signal_restorer:
mov rax, {SYS_rt_sigreturn}
syscall
ud2

.popsection
