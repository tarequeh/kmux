#include <asm/asm-offsets.h>
#include <asm/segment.h>
#include <asm/errno.h>
#include <asm/thread_info.h>
#include <linux/linkage.h>

#define ASM_PAGE_MASK (~(4096-1))

/* from entry.S */
EBX         = 0x00
ECX         = 0x04
EDX         = 0x08
ESI         = 0x0C
EDI         = 0x10
EBP         = 0x14
EAX         = 0x18
DS          = 0x1C
ES          = 0x20
FS          = 0x24
GS          = 0x28
ORIG_EAX	= 0x2C
EIP         = 0x30
CS          = 0x34
EFLAGS		= 0x38
OLDESP		= 0x3C
OLDSS		= 0x40

CF_MASK		= 0x00000001
TF_MASK		= 0x00000100
IF_MASK		= 0x00000200
DF_MASK		= 0x00000400
NT_MASK		= 0x00004000
VM_MASK		= 0x00020000

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
ENTRY(save_syscall_environment)
    movl TSS_sysenter_sp0(%esp), %esp
    /*
     * Push current_thread_info()->sysenter_return to the stack.
     * A tiny bit of offset fixup is necessary - 4xN means the N words
     * pushed above; +8 corresponds to copy_thread's esp0 setting.
     */
    pushl (TI_sysenter_return-THREAD_SIZE+8+4*0)(%esp)
    # Create space on stack to receive TSS
    pushl $0
    SAVE_ALL

    movl %esp, %eax
    # TODO: Load original %ebp value. Linux stores original %ebp on user stack and then loads user stack address in %ebp
    call kmux_syscall_handler

    RESTORE_REGS

    cmpl %eax, 0
    jl exit_syscall_environment

host_syscall_environment:
    # Restore TSS
    movl (%esp), %esp

    # Jump to IP in TSS containing host kernel or exit address
    jmp  *0x04(%esp)

exit_syscall_environment:
    /*
    # 32 bit exit routine form Linux
        PT_EIP (48) -> User IP
        movl PT_EIP(%esp), %edx

        PT_OLDESP (60) -> User Stack Pointer %ebp
        movl PT_OLDESP(%esp), %ecx
        xorl %ebp,%ebp
        TRACE_IRQS_ON
        PT_FS (36) -> Original %ds
    1:  mov  PT_FS(%esp), %fs
        PTGS_TO_GS
        ENABLE_INTERRUPTS_SYSEXIT
    */
    # Load FS with DS
    movl %ds, %edx
    movl %edx, %fs

    # Load User IP form stack in %edx
    movl 4(%esp), %edx

    # Load User Stack Pointer into %ecx
    movl %ebp, %ecx

    xorl %ebp, %ebp
    sti
    sysexit
