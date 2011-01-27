#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

#define MODULE_NAME "syscall_printer"

int sysprinter_syscall_handler(struct pt_regs regs) {
	printk("Syscall number: %lu", regs.ax);
	return 0;
}

/* Module initialization/ termination */
static int sysprinter_init(void) {
	printk("Installing module: %s\n", MODULE_NAME);
	register_kern_syscall_handler(MODULE_NAME, &sysprinter_syscall_handler, NULL, 0);
	return 0;
}

static void sysprinter_exit(void) {
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
