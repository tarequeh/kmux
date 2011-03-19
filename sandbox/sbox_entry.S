#include <asm/asm-offsets.h>
#include <asm/segment.h>
#include <asm/thread_info.h>
#include <linux/linkage.h>

#define SAVE_ALL                            \
    cld;                                    \
    pushl %gs;                              \
    pushl %fs;                              \
    pushl %es;                              \
    pushl %ds;                              \
    pushl %eax;                             \
    pushl %ebp;                             \
    pushl %edi;                             \
    pushl %esi;                             \
    pushl %edx;                             \
    pushl %ecx;                             \
    pushl %ebx;                             \
    movl $(__USER_DS), %edx;                \
    movl %edx, %ds;                         \
    movl %edx, %es;                         \
    movl $(__KERNEL_PERCPU), %edx;          \
    movl %edx, %fs;                         \
    movl $(__KERNEL_STACK_CANARY), %edx;    \
    movl %edx, %gs

#define RESTORE_INT_REGS                    \
    popl %ebx;                              \
    popl %ecx;                              \
    popl %edx;                              \
    popl %esi;                              \
    popl %edi;                              \
    popl %ebp;                              \
    popl %eax

#define RESTORE_REGS                        \
    RESTORE_INT_REGS;                       \
    popl %ds;                               \
    popl %es;                               \
    popl %fs;                               \
    popl %gs

.text
ALIGN
ENTRY(sandbox_sysenter_handler)
    movl TSS_sysenter_sp0(%esp), %esp

    # Create space on stack to receive TSS
    pushl $0
    SAVE_ALL

    movl %esp, %eax
    call sandbox_syscall_handler

    RESTORE_REGS
    # Restore TSS
    movl (%esp), %esp

    # Jump to IP in TSS
    jmp  *0x04(%esp)
