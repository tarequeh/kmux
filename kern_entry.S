#include <asm/asm-offsets.h>
#include <asm/segment.h>
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


.data
.align 16
host_os_esp_storage:
	.long 0
/* The idea is that environment (registers) is saved
 * whenever a syscall is trapped. Then the appropriate
 * kernel handler is loaded in kmux_sysenter_addr and
 * the environment is restored before calling the handler
 */
.text
ALIGN
ENTRY(save_syscall_environment)
    # Save host sysenter address
    movl TSS_sysenter_sp0(%esp), %esp
    # %esp = %esp[TSS_sysenter_sp0]

    pushl $0
	SAVE_ALL

	call kmux_syscall_handler

	RESTORE_REGS
    movl (%esp), %esp
	jmp  *0x04(%esp)
