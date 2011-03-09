#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#include "../kern_mux.h"

#define MODULE_NAME "sandbox"

extern int register_kern_syscall_handler(char* kernel_name, kmux_kernel_syscall_handler syscall_handler);
extern int unregister_kern_syscall_handler(char* kernel_name);
extern int chain_kernel(int kernel_index, int kernel_next);
extern int get_kernel_index(char *kernel_name);

int sandbox_syscall_handler(struct pt_regs *regs) {
	// TODO: Restrict all syscalls except for a few resource allocating ones
	return 0;
}

/* Module initialization/ termination */
static int __init sandbox_init(void) {
	printk("Installing module: %s\n", MODULE_NAME);
	register_kern_syscall_handler(MODULE_NAME, &sandbox_syscall_handler);
	chain_kernel(get_kernel_index(MODULE_NAME), KMUX_HOST_KERNEL_INDEX);
	return 0;
}

static void __exit sandbox_exit(void) {
	printk("Uninstalling the Sandbox kernel\n");
	chain_kernel(get_kernel_index(MODULE_NAME), KMUX_UNCHAINED_KERNEL);
	unregister_kern_syscall_handler(MODULE_NAME);
	return;
}
/* ------------------------- */

module_init(sandbox_init);
module_exit(sandbox_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Sandbox kernel for kmux");
MODULE_LICENSE("GPL");
