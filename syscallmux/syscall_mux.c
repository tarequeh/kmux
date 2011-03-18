#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#include "../kern_mux.h"

#define MODULE_NAME "syscallmux"

extern int register_kern_syscall_handler(char* kernel_name, kmux_kernel_syscall_handler syscall_handler);
extern int unregister_kern_syscall_handler(char* kernel_name);
extern int get_kernel_index(char *kernel_name);

int syscallmux_syscall_handler(struct pt_regs *regs) {
    int next_kernel_index;

    printk("syscallmux_syscall_handler: Syscall number: %lu executing on %d\n", regs->ax, get_cpu());
    // TODO: Ideally syscallmux would know about all syscall handling kernel installed
    // If kernel is found for handling syscall, return index for that kernel
    // Otherwise skip the syscall by returning -1

    // For now send back host index
    next_kernel_index = get_kernel_index(KMUX_DEFAULT_KERNEL_NAME);
    return next_kernel_index;
}

/* Module initialization/ termination */
static int __init syscallmux_init(void) {
    printk("Installing module: %s\n", MODULE_NAME);
    register_kern_syscall_handler(MODULE_NAME, &syscallmux_syscall_handler);
    return 0;
}

static void __exit syscallmux_exit(void) {
    printk("Uninstalling the Syscall Multiplexer kernel\n");
    unregister_kern_syscall_handler(MODULE_NAME);
    return;
}
/* ------------------------- */

module_init(syscallmux_init);
module_exit(syscallmux_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Syscall multiplexing kernel for kmux");
MODULE_LICENSE("GPL");
