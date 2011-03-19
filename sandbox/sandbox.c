#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>

#include "../kern_mux.h"

#define MODULE_NAME "sandbox"
#define MAX_SYSCALL 337

#define DIRECTIVE_MAX_LENGTH 64
#define DIRECTIVE_NEXT_KERNEL "next_kernel"
#define DIRECTIVE_ALLOWED_SYSCALLS "allowed_syscalls"

#define SCAN_REGEX_LENGTH 64

extern int register_kernel(char* kernel_name, kmux_kernel_syscall_handler syscall_handler, kmux_kernel_config_handler config_handler);
extern int unregister_kernel(char* kernel_name);
extern int get_kernel_index(char* kernel_name);

int allowed_syscalls[MAX_SYSCALL + 1];
int gnext_kernel_index = KMUX_HOST_KERNEL_INDEX;

int sandbox_syscall_handler(struct pt_regs *regs) {
    int syscall_number = (int)regs->ax;

    if (syscall_number < 0 || syscall_number > MAX_SYSCALL) {
        printk("sandbox_syscall_handler: Encountered invalid syscall number: %lu\n", regs->ax);
    }

    if (allowed_syscalls[syscall_number]) {
        return gnext_kernel_index;
    } else {
        return KMUX_SYSCALL_EXIT_INDEX;
    }
}

static int set_syscall_allowed(int syscall) {
    if (syscall > MAX_SYSCALL) {
        return -EINVAL;
    }

    allowed_syscalls[syscall] = 1;
    return SUCCESS;
}

// Config buffer contains either of the following structures:
// next_kernel = next_kernel_name
// allowed_syscalls = 45, 67, 23, 178
int sandbox_config_handler(char *config_buffer) {
    char directive[DIRECTIVE_MAX_LENGTH], kernel_name[MAX_KERNEL_NAME_LENGTH], scan_regex[SCAN_REGEX_LENGTH];
    int syscall_number;

    memset(directive, 0, DIRECTIVE_MAX_LENGTH);
    memset(kernel_name, 0, MAX_KERNEL_NAME_LENGTH);

    printk("sandbox_config_handler: Configuring kernel: %s\n", MODULE_NAME);

    if (config_buffer == NULL) {
        printk("sandbox_config_handler: Received invalid config buffer\n");
        return -EINVAL;
    }

    if (strlen(config_buffer) == 0) {
        printk("sandbox_config_handler: Received zero length config buffer\n");
        return -EINVAL;
    }

    // Process buffer
    memset(scan_regex, 0, SCAN_REGEX_LENGTH);
    sprintf(scan_regex, "%%%d[^ =]%%*[ =]", DIRECTIVE_MAX_LENGTH);

    if (sscanf(config_buffer, scan_regex, directive) < 0) {
        printk("sandbox_config_handler: Error reading directive from config buffer\n");
        return -EINVAL;
    }

    if (strcmp(directive, DIRECTIVE_NEXT_KERNEL) == 0) {
        memset(scan_regex, 0, SCAN_REGEX_LENGTH);
        sprintf(scan_regex, "%%%d", MAX_KERNEL_NAME_LENGTH);

        if (sscanf(config_buffer, scan_regex, kernel_name) < 0) {
            printk("sandbox_config_handler: Error reading next kernel name config buffer\n");
            return -EINVAL;
        }
    } else if (strcmp(directive, DIRECTIVE_ALLOWED_SYSCALLS) == 0) {
        while (sscanf(config_buffer, "%d%*[ ,]", &syscall_number) > 0) {
            if (syscall_number < 0 || syscall_number > MAX_SYSCALL) {
                printk("syscallmux_config_handler: Invalid syscall number: %d specified. Skipping\n", syscall_number);
                continue;
            }

            allowed_syscalls[syscall_number] = 1;
            printk("syscallmux_config_handler: Sandbox set to allow syscall: %d\n", syscall_number);
        }
    } else {
        printk("sandbox_config_handler: Invalid directive: %s\n", directive);
        return -EINVAL;
    }

    return SUCCESS;
}

/* Module initialization/ termination */
static int __init sandbox_init(void) {
    int index;
    printk("Installing module: %s\n", MODULE_NAME);

    for (index = 0; index < MAX_SYSCALL + 1; index++) {
        allowed_syscalls[index] = 0;
    }

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
