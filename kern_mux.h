#ifndef KERN_MUX_H
#define KERN_MUX_H

#include <asm/ptrace.h>
#include <linux/ioctl.h>

#define MAX_CPU_SUPPORT 16
#define MAX_KERNEL_SUPPORT 64
#define MAX_THREAD_SUPPORT 16384 // 2^14
#define MAX_KERNEL_NAME_LENGTH 50

#define KMUX_PROC_NAME "kmux"
#define KMUX_PROC_NUMBER 0223

#define KMUX_IOCTL_CMD_REGISTER_THREAD 1
#define KMUX_IOCTL_CMD_UNREGISTER_THREAD 2
#define KMUX_IOCTL_CMD_REGISTER_KERNEL_CPU 3
#define KMUX_IOCTL_CMD_UNREGISTER_KERNEL_CPU 4

#define KMUX_IOCTL_CMD_GET_KERNEL_INDEX 51

#define KMUX_REGISTER_THREAD _IOR(0, KMUX_IOCTL_CMD_REGISTER_THREAD, unsigned long)
#define KMUX_UNREGISTER_THREAD _IOR(0, KMUX_IOCTL_CMD_UNREGISTER_THREAD, unsigned long)
#define KMUX_REGISTER_KERNEL_CPU _IOR(0, KMUX_IOCTL_CMD_REGISTER_KERNEL_CPU, unsigned long)
#define KMUX_UNREGISTER_KERNEL_CPU _IOR(0, KMUX_IOCTL_CMD_UNREGISTER_KERNEL_CPU, unsigned long)

#define KMUX_GET_KERNEL_INDEX _IOR(0, KMUX_IOCTL_CMD_GET_KERNEL_INDEX, unsigned long)

#define KMUX_HOST_KERNEL_CPU 0
#define KMUX_HOST_KERNEL_INDEX 0

#define KMUX_SYSCALL_EXIT_INDEX -1

#define KMUX_DEFAULT_KERNEL_NAME "linux"
#define KMUX_SYSCALL_MUX_KERNEL_NAME "syscallmux"

#define SUCCESS 0

/* Handler array definition */
typedef int (*kmux_kernel_syscall_handler)(struct pt_regs *);

/* Data structures */
// Direct kernel call doesn't return to host OS. Indirect kernel call returns control to host OS
struct kernel_entry {
	char kernel_name[MAX_KERNEL_NAME_LENGTH];
	kmux_kernel_syscall_handler kernel_syscall_handler;
};

typedef struct kernel_entry kernel_entry;

struct thread_entry {
	int kernel_index;
	int pgid;
};

typedef struct thread_entry thread_entry;

struct cpu_entry {
	int kernel_index;
	int idle_pid;
};

typedef struct cpu_entry cpu_entry;

// Structures exclusively used by kmul/ioctl
struct cpu_registration_entry {
	int kernel_index;
	int cpu;
};

typedef struct cpu_registration_entry cpu_registration_entry;

#endif
