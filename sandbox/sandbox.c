#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>

#include "../kern_mux.h"

#define MODULE_NAME "sandbox"

extern int register_kernel(char* kernel_name, kmux_kernel_syscall_handler syscall_handler, kmux_kernel_config_handler config_handler);
extern int unregister_kernel(char* kernel_name);
extern int get_kernel_index(char* kernel_name);

#define MAX_SYSCALL 337

int allowed_syscalls[MAX_SYSCALL];
int gnext_kernel_index = KMUX_HOST_KERNEL_INDEX;

int sandbox_syscall_handler(struct pt_regs *regs) {
    printk("sandbox_syscall_handler: Syscall number: %lu executing on %d\n", regs->ax, get_cpu());
    // Add logic to enforce syscall filtering system call

    // If syscall is allowed, return index for syscallmux
    return gnext_kernel_index;
}

static int set_syscall_allowed(int syscall) {
    if (syscall > MAX_SYSCALL) {
        return -EINVAL;
    }

    allowed_syscalls[syscall] = 1;
    return SUCCESS;
}

int sandbox_config_handler(char *config_buffer) {
    printk("Configuring kernel: %s\n", MODULE_NAME);
    // Process buffer
    return SUCCESS;
}

/* Module initialization/ termination */
static int __init sandbox_init(void) {
    printk("Installing module: %s\n", MODULE_NAME);
	register_kernel(MODULE_NAME, &sandbox_syscall_handler, &sandbox_config_handler);
	return 0;
}

static void __exit sandbox_exit(void) {
	printk("Uninstalling the Sandbox kernel\n");
	unregister_kernel(MODULE_NAME);
	return;
}
/* ------------------------- */

module_init(sandbox_init);
module_exit(sandbox_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Sandbox kernel for kmux");
MODULE_LICENSE("GPL");
