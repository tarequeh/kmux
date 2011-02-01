#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#include "../kern_mux.h"

#define MODULE_NAME "syscall_printer"

extern int register_kern_syscall_handler(char* kernel_name, kmux_kernel_syscall_handler syscall_handler, kmux_remove_handler removal_handler, int is_direct);
extern int unregister_kern_syscall_handler(char* kernel_name);

int sysprinter_syscall_handler(struct pt_regs regs) {
	printk("Syscall number: %lu\n", regs.ax);
	return 0;
}

/* Module initialization/ termination */
static int __init sysprinter_init(void) {
	printk("Installing module: %s\n", MODULE_NAME);
	register_kern_syscall_handler(MODULE_NAME, &sysprinter_syscall_handler, NULL, 0);
	return 0;
}

static void __exit sysprinter_exit(void) {
	printk("Uninstalling the Syscall Printer kernel\n");
	unregister_kern_syscall_handler(MODULE_NAME);
	return;
}
/* ------------------------- */

module_init(sysprinter_init);
module_exit(sysprinter_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Syscall printing kernel for kmux");
MODULE_LICENSE("GPL");
