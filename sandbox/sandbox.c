#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>

#include "../kern_mux.h"
#include "../kern_string.h"

#define MODULE_NAME "sandbox"

#define MIN_SYSCALL 337
#define MAX_SYSCALL 337

#define DIRECTIVE_MAX_LENGTH 64
#define DIRECTIVE_NEXT_KERNEL "next_kernel"
#define DIRECTIVE_ALLOWED_SYSCALLS "allowed_syscalls"

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
// (next_kernel = linux), (allowed_syscalls = 45, 67, 23, 178)
int sandbox_config_handler(char *config_buffer) {
    int syscall_number, kernel_index;
    char directive[DIRECTIVE_MAX_LENGTH], kernel_name[MAX_KERNEL_NAME_LENGTH], safe_config_buffer[MAX_KERNEL_CONFIG_BUFFER_LENGTH];
    char *kernel_configs, *kernel_configs_tracker, *config_tokens, *config_tokens_tracker, *syscall_numbers, *syscall_numbers_tracker, *trimmed_config, *trimmed_config_token, *trimmed_syscall;

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

    // strtok_r writes into buffer, so copy it into a safe location
    memset(safe_config_buffer, 0, MAX_KERNEL_CONFIG_BUFFER_LENGTH);
    strcpy(safe_config_buffer, config_buffer);

    printk("sandbox_config_handler: Parsing config buffer: %s\n", safe_config_buffer);

    kernel_configs = strtok_r(safe_config_buffer, "()", &kernel_configs_tracker);

    while (kernel_configs != NULL) {
        trimmed_config = trim(kernel_configs, ' ');
        trimmed_config = ltrim(trimmed_config, ',');
        trimmed_config = trim(trimmed_config, ' ');

        if (strlen(trimmed_config) > 0) {
            printk("sandbox_config_handler: Config piece: %s\n", trimmed_config);
            config_tokens = strtok_r(trimmed_config, "=", &config_tokens_tracker);

            if (config_tokens != NULL) {
                trimmed_config_token = trim(config_tokens, ' ');

                if (strlen(trimmed_config_token) > 0) {
                    memset(directive, 0, MAX_KERNEL_NAME_LENGTH);
                    strcpy(directive, trimmed_config_token);

                    printk("sandbox_config_handler: Directive: %s\n", directive);
                    config_tokens = strtok_r(NULL, "=", &config_tokens_tracker);

                    if (config_tokens != NULL) {
                        trimmed_config_token = trim(config_tokens, ' ');
                        if (strlen(trimmed_config_token) > 0) {
                            printk("sandbox_config_handler: Directive parameters: %s\n", trimmed_config_token);
                            if (strcmp(directive, DIRECTIVE_NEXT_KERNEL) == 0) {
                                kernel_index = get_kernel_index(trimmed_config_token);
                                if (kernel_index < 0) {
                                    printk("sandbox_config_handler: Invalid next kernel name: %s\n", trimmed_config_token);
                                } else {
                                    printk("sandbox_config_handler: Set next kernel to: %s\n", trimmed_config_token);
                                    gnext_kernel_index = kernel_index;
                                }
                            } else if (strcmp(directive, DIRECTIVE_ALLOWED_SYSCALLS) == 0) {
                                syscall_numbers = strtok_r(trimmed_config_token, ",", &syscall_numbers_tracker);
                                while(syscall_numbers != NULL) {
                                    trimmed_syscall = trim(syscall_numbers, ' ');
                                    if (strlen(trimmed_syscall) > 0) {
                                        syscall_number = atoi(trimmed_syscall);

                                        if (syscall_number >= MIN_SYSCALL || syscall_number <= MAX_SYSCALL) {
                                            allowed_syscalls[syscall_number] = 1;
                                            printk("sandbox_config_handler: Added syscall: %d to allowed list\n", syscall_number);
                                        } else {
                                            printk("sandbox_config_handler: Invalid syscall number: %d specified for kernel: %s. Skipping\n", syscall_number, kernel_name);
                                        }
                                    } else {
                                        printk("sandbox_config_handler: Found empty syscall number. Skipping\n");
                                    }
                                    syscall_numbers = strtok_r(NULL, ",", &syscall_numbers_tracker);
                                }
                            } else {
                                printk("sandbox_config_handler: Invalid directive in configuration piece. Skipping\n");
                            }
                        } else {
                            printk("sandbox_config_handler: Found empty directive parameters. Skipping\n");
                        }
                    } else {
                        printk("sandbox_config_handler: Could not read directive parameters from configuration piece. Skipping\n");
                    }
                } else {
                    printk("sandbox_config_handler: Found empty directive. Skipping\n");
                }
            } else {
                printk("sandbox_config_handler: Could not read directive from configuration piece. Skipping\n");
            }
        } else {
            printk("sandbox_config_handler: Found empty configuration piece. Skipping\n");
        }

        kernel_configs = strtok_r(NULL, "()", &kernel_configs_tracker);
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
