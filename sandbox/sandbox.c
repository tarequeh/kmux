#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>

#include "../kern_mux.h"

#define MODULE_NAME "sandbox"

extern int register_kern_syscall_handler(char* kernel_name, kmux_kernel_syscall_handler syscall_handler);
extern int unregister_kern_syscall_handler(char* kernel_name);
extern int get_kernel_index(char* kernel_name);

int sandbox_syscall_handler(struct pt_regs *regs) {
    int next_kernel_index;

    printk("sandbox_syscall_handler: Syscall number: %lu executing on %d\n", regs->ax, get_cpu());
    // Add logic to enforce syscall filtering system call

    // If syscall is allowed, return index for syscallmux
    next_kernel_index = get_kernel_index(KMUX_SYSCALL_MUX_KERNEL_NAME);
    return next_kernel_index;
}

/* Module initialization/ termination */
static int __init sandbox_init(void) {
    printk("Installing module: %s\n", MODULE_NAME);
	register_kern_syscall_handler(MODULE_NAME, &sandbox_syscall_handler);
	return 0;
}

static void __exit sandbox_exit(void) {
	printk("Uninstalling the Sandbox kernel\n");
	unregister_kern_syscall_handler(MODULE_NAME);
	return;
}
/* ------------------------- */

module_init(sandbox_init);
module_exit(sandbox_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Sandbox kernel for kmux");
MODULE_LICENSE("GPL");
