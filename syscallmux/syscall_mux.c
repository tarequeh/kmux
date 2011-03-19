#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#include "../kern_mux.h"

#define MODULE_NAME "syscallmux"
#define MAX_SYSCALL 337

#define SCAN_REGEX_LENGTH 64

extern int register_kernel(char* kernel_name, kmux_kernel_syscall_handler syscall_handler, kmux_kernel_config_handler config_handler);
extern int unregister_kernel(char* kernel_name);
extern int get_kernel_index(char *kernel_name);

int syscall_kernel_register[MAX_SYSCALL + 1];

int syscallmux_syscall_handler(struct pt_regs *regs) {
    int next_kernel_index, syscall_number = (int)regs->ax;

    if (syscall_number < 0 || syscall_number > MAX_SYSCALL) {
        printk("syscallmux_syscall_handler: Encountered invalid syscall number: %lu\n", regs->ax);
    }

    next_kernel_index = syscall_kernel_register[syscall_number];

    return next_kernel_index;
}

// Config buffer contains one or more of the following structure separated by comma
// syscall_number handling_kernel_name
int syscallmux_config_handler(char *config_buffer) {
    int syscall_number, kernel_index;
    char kernel_name[MAX_KERNEL_NAME_LENGTH], scan_regex[SCAN_REGEX_LENGTH];

    memset(kernel_name, 0, MAX_KERNEL_NAME_LENGTH);

    printk("syscallmux_config_handler: Configuring kernel: %s\n", MODULE_NAME);
    // Process buffer
    if (config_buffer == NULL) {
        printk("syscallmux_config_handler: Received invalid config buffer\n");
        return -EINVAL;
    }

    if (strlen(config_buffer) == 0) {
        printk("syscallmux_config_handler: Received zero length config buffer\n");
        return -EINVAL;
    }

    memset(scan_regex, 0, SCAN_REGEX_LENGTH);
    sprintf(scan_regex, "%%d %%%d[^, ]%%*[, ]", MAX_KERNEL_NAME_LENGTH);

    while (sscanf(config_buffer, scan_regex, &syscall_number, kernel_name) > 0) {
        if (syscall_number < 0 || syscall_number > MAX_SYSCALL) {
            printk("syscallmux_config_handler: Invalid syscall number: %d specified for kernel: %s. Skipping\n", syscall_number, kernel_name);
            continue;
        }

        kernel_index = get_kernel_index(kernel_name);
        if (kernel_index < 0) {
            printk("syscallmux_config_handler: Invalid/non existent kernel: %s specified for syscall number: %d. Skipping\n", kernel_name, syscall_number);
            continue;
        }

        syscall_kernel_register[syscall_number] = kernel_index;
        printk("syscallmux_config_handler: Kernel: %s added for syscall: %d\n", kernel_name, syscall_number);
    }

    return SUCCESS;
}

/* Module initialization/ termination */
static int __init syscallmux_init(void) {
    int index;
    printk("Installing module: %s\n", MODULE_NAME);

    // As default, set all syscalls to be handled by host
    for (index = 0; index < MAX_SYSCALL + 1; index++) {
        syscall_kernel_register[index] = KMUX_HOST_KERNEL_INDEX;
    }

    register_kernel(MODULE_NAME, &syscallmux_syscall_handler, &syscallmux_config_handler);
    return 0;
}

static void __exit syscallmux_exit(void) {
    printk("Uninstalling the Syscall Multiplexer kernel\n");
    unregister_kernel(MODULE_NAME);
    return;
}
/* ------------------------- */

module_init(syscallmux_init);
module_exit(syscallmux_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Syscall multiplexing kernel for kmux");
MODULE_LICENSE("GPL");
