#include <linux/ioctl.h>

#define MAX_KERNEL_SUPPORT 50
#define MAX_THREAD_SUPPORT 1000
#define MAX_KERNEL_NAME_LENGTH 50

#define KMUX_PROC_NAME "kmux"
#define KMUX_PROC_NUMBER 0223

#define KMUX_IOCTL_CMD_REGISTER_THREAD 1
#define KMUX_IOCTL_CMD_UNREGISTER_THREAD 2

#define KMUX_REGISTER_THREAD _IOR(0, KMUX_IOCTL_CMD_REGISTER_THREAD, unsigned long)
#define KMUX_UNREGISTER_THREAD _IOR(0, KMUX_IOCTL_CMD_UNREGISTER_THREAD, unsigned long)

#define DEFAULT_KERNEL_NAME "linux"

#define SUCCESS 0

/* Handler array definition */
typedef int (*kmux_kernel_syscall_handler)(void);
typedef int (*kmux_remove_handler)(void);

/* Data structures */
struct kernel_entry {
	char kernel_name[MAX_KERNEL_NAME_LENGTH];
	kmux_kernel_syscall_handler kernel_syscall_handler;
	kmux_remove_handler kernel_removal_handler;
};

typedef struct kernel_entry kernel_entry;

struct thread_register {
	char kernel_name[MAX_KERNEL_NAME_LENGTH];
	unsigned int thread_id;
};

typedef struct thread_register thread_register;
