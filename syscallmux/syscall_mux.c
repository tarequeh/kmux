#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/string.h>

#include "../kern_mux.h"
#include "../kern_utils.h"

#define MODULE_NAME "syscall_mux"

#define MIN_SYSCALL 0
#define MAX_SYSCALL 337

extern int register_kernel(char* kernel_name, kmux_kernel_syscall_handler syscall_handler, kmux_kernel_config_handler config_handler);
extern int unregister_kernel(char* kernel_name);
extern int get_kernel_index(char *kernel_name);

int syscall_kernel_register[MAX_SYSCALL + 1];

int syscallmux_syscall_handler(struct pt_regs *regs) {
    int next_kernel_index, syscall_number = (int)regs->ax;

    if (syscall_number < MIN_SYSCALL || syscall_number > MAX_SYSCALL) {
        printk("syscallmux_syscall_handler: Encountered invalid syscall number: %lu\n", regs->ax);
    }

    next_kernel_index = syscall_kernel_register[syscall_number];

    return next_kernel_index;
}

// Config buffer contains one or more of the following structure separated by comma
// (handling_kernel_name = 45, 67, 23, 178)
int syscallmux_config_handler(char *config_buffer) {
    int syscall_number, kernel_index;
    char kernel_name[MAX_KERNEL_NAME_LENGTH], safe_config_buffer[MAX_KERNEL_CONFIG_BUFFER_LENGTH];
    char *kernel_configs, *kernel_configs_tracker, *config_tokens, *config_tokens_tracker, *syscall_numbers, *syscall_numbers_tracker, *trimmed_config, *trimmed_config_token, *trimmed_syscall;

    printk("syscallmux_config_handler: Configuring kernel: %s\n", MODULE_NAME);
    // Process buffer
    if (config_buffer == NULL) {
        printk("syscallmux_config_handler: Received invalid config buffer\n");
        return -EINVAL;
    }

    if (!config_buffer || strlen(config_buffer) > MAX_KERNEL_CONFIG_BUFFER_LENGTH) {
        printk("syscallmux_config_handler: Invalid config buffer\n");
        return -EINVAL;
    }

    // strtok_r writes into buffer, so copy it into a safe location
    memset(safe_config_buffer, 0, MAX_KERNEL_CONFIG_BUFFER_LENGTH);
    strcpy(safe_config_buffer, config_buffer);

    printk("syscallmux_config_handler: Parsing config buffer: %s\n", safe_config_buffer);

    kernel_configs = strtok_r(safe_config_buffer, "()", &kernel_configs_tracker);

    while (kernel_configs != NULL) {
        trimmed_config = trim(kernel_configs, ' ');
        trimmed_config = ltrim(trimmed_config, ',');
        trimmed_config = trim(trimmed_config, ' ');

        if (strlen(trimmed_config) > 0) {
            printk("syscallmux_config_handler: Config piece: %s\n", trimmed_config);
            config_tokens = strtok_r(trimmed_config, "=", &config_tokens_tracker);

            if (config_tokens != NULL) {
                trimmed_config_token = trim(config_tokens, ' ');

                if (strlen(trimmed_config_token) > 0) {
                    memset(kernel_name, 0, MAX_KERNEL_NAME_LENGTH);
                    strcpy(kernel_name, trimmed_config_token);

                    kernel_index = get_kernel_index(kernel_name);
                    if (kernel_index >= 0) {
                        printk("syscallmux_config_handler: Kernel name: %s. Rest of config: %s\n", kernel_name, config_tokens_tracker);
                        config_tokens = strtok_r(NULL, "=", &config_tokens_tracker);

                        if (config_tokens != NULL) {
                            trimmed_config_token = trim(config_tokens, ' ');

                            if (strlen(trimmed_config_token) > 0) {
                                syscall_numbers = strtok_r(trimmed_config_token, ",", &syscall_numbers_tracker);
                                while(syscall_numbers != NULL) {
                                    trimmed_syscall = trim(syscall_numbers, ' ');
                                    if (strlen(trimmed_syscall) > 0) {
                                        syscall_number = atoi(trimmed_syscall);

                                        if (syscall_number >= MIN_SYSCALL || syscall_number <= MAX_SYSCALL) {
                                            syscall_kernel_register[syscall_number] = kernel_index;
                                            printk("syscallmux_config_handler: Kernel: %s added for syscall: %d\n", kernel_name, syscall_number);
                                        } else {
                                            printk("syscallmux_config_handler: Invalid syscall number: %d specified for kernel: %s. Skipping\n", syscall_number, kernel_name);
                                        }
                                    } else {
                                        printk("syscallmux_config_handler: Found empty syscall number. Skipping\n");
                                    }
                                    syscall_numbers = strtok_r(NULL, ",", &syscall_numbers_tracker);
                                }
                            } else {
                                printk("syscallmux_config_handler: Found empty syscall list. Skipping\n");
                            }
                        } else {
                            printk("syscallmux_config_handler: Could not read syscall list from configuration piece. Skipping\n");
                        }
                    } else {
                        printk("syscallmux_config_handler: Invalid/non existent kernel: %s. Skipping\n", kernel_name);
                    }
                } else {
                    printk("syscallmux_config_handler: Found empty kernel name. Skipping\n");
                }
            } else {
                printk("syscallmux_config_handler: Could not read kernel name from configuration piece. Skipping\n");
            }
        } else {
            printk("syscallmux_config_handler: Found blank configuration piece. Skipping\n");
        }

        kernel_configs = strtok_r(NULL, "()", &kernel_configs_tracker);
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
