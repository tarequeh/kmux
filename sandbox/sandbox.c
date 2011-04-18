#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>

#include "../kern_mux.h"
#include "../kern_utils.h"

#define MODULE_NAME "sandbox"

#define MIN_SYSCALL 337
#define MAX_SYSCALL 337

#define MAX_PROCESS_SUPPORT 512

#define DIRECTIVE_MAX_LENGTH 64
#define DIRECTIVE_NEXT_KERNEL "next_kernel"
#define DIRECTIVE_ALLOWED_SYSCALLS "allowed_syscalls"

extern int register_kernel(char* kernel_name, kmux_kernel_syscall_handler syscall_handler, kmux_kernel_config_handler config_handler);
extern int unregister_kernel(char* kernel_name);
extern int get_kernel_index(char* kernel_name);

struct process_entry {
    int pid;
    int next_kernel_index;
    int allowed_syscalls[MAX_SYSCALL + 1];
};

typedef struct process_entry process_entry;

process_entry process_register[MAX_PROCESS_SUPPORT];

/* Hash table functions */
static int find_process_register_slot(int pid) {
    int index, hash_tracker;

    index = (int)(j32int_hash(pid) % MAX_PROCESS_SUPPORT);

    // Under no circumstance hash_tracker will exceed MAX_PROCESS_SUPPORT
    hash_tracker = 0;
    while(hash_tracker < MAX_PROCESS_SUPPORT) {
        // Return index on empty or match
        if (process_register[index].pid == -1 || process_register[index].pid == pid) {
            return index;
        }
        index = (index + 1) % MAX_PROCESS_SUPPORT;
        hash_tracker++;
    }

    return -ENOSPC;
}

static int lookup_process_entry(int pid) {
    int register_index;
    register_index = find_process_register_slot(pid);

    if (register_index < 0) {
        return register_index;
    }

    if (process_register[register_index].pid == -1) {
        // PID is not in register
        return -EFAULT;
    } else {
        // PID is in register
        return register_index;
    }
}

static int register_process(int pid, char *kernel_name, char *syscall_list) {
    int index, process_index, kernel_index, next_kernel_received = 0, syscall_received = 0;
    process_entry *process_info;

    if (!kernel_name && !syscall_list) {
        printk("register_process: Didn't receive any useful information to create a process record\n");
        return -EINVAL;
    }

    process_index = find_process_register_slot(pid);
    if (process_index < 0) {
        printk("register_process: No more space left on process register\n");
        return process_index;
    }

    process_info = kmalloc(sizeof(process_entry), GFP_KERNEL);
    if (!process_info) {
        printk("register_process: Could not allocate memory for temporary process entry\n");
        return -ENOMEM;
    }

    process_info->pid = pid;
    process_info->next_kernel_index = KMUX_HOST_KERNEL_INDEX;

    if (syscall_list) {
        int syscall_number;
        char *syscall_tokens, *trimmed_syscall_token, *syscall_tokens_tracker;
        syscall_tokens = strtok_r(syscall_list, ",", &syscall_tokens_tracker);
        while(syscall_tokens != NULL) {
            trimmed_syscall_token = trim(syscall_tokens, ' ');
            if (strlen(trimmed_syscall_token) > 0) {
                syscall_number = atoi(trimmed_syscall_token);

                if (syscall_number >= MIN_SYSCALL || syscall_number <= MAX_SYSCALL) {
                    process_info->allowed_syscalls[syscall_number] = 1;
                    syscall_received = 1;
                    printk("register_process: Added syscall: %d to allowed list for PID: %d\n", syscall_number, pid);
                } else {
                    printk("register_process: Invalid syscall number: %d specified for PID: %d. Skipping\n", syscall_number, pid);
                }
            } else {
                printk("register_process: Found empty syscall number for PID: %d. Skipping\n", pid);
            }
            syscall_tokens = strtok_r(NULL, ",", &syscall_tokens_tracker);
        }
    }

    if (kernel_name) {
        kernel_index = get_kernel_index(kernel_name);
        if (kernel_index < 0) {
            printk("register_process: Invalid next kernel name: %s for PID: %d\n", kernel_name, pid);
        } else {
            printk("register_process: Set next kernel: %s for PID: %d\n", kernel_name, pid);
            process_info->next_kernel_index = kernel_index;
            next_kernel_received = 1;
        }
    }

    if (next_kernel_received || syscall_received) {
        process_register[process_index].pid = pid;
        if (next_kernel_received) {
            process_register[process_index].next_kernel_index = process_info->next_kernel_index;
        }

        if (syscall_received) {
            for (index = 0; index < MAX_SYSCALL + 1; index++) {
                if (process_info->allowed_syscalls[index]) {
                    process_register[process_index].allowed_syscalls[index] = 1;
                }
            }
        }

        kfree(process_info);
        return SUCCESS;
    } else {
        kfree(process_info);
        return -EINVAL;
    }
}

static int unregister_process(int pid) {
    int index, register_index;

    register_index = lookup_process_entry(pid);
    if (register_index < 0) {
        return register_index;
    }

    process_register[register_index].pid = -1;
    process_register[register_index].next_kernel_index = KMUX_HOST_KERNEL_INDEX;
    for (index = 0; index < MAX_SYSCALL + 1; index++) {
        process_register[register_index].allowed_syscalls[index] = 0;
    }

    return SUCCESS;
}

int sandbox_syscall_handler(struct pt_regs *regs) {
    struct pid *pid;
    int pgid, register_index, syscall_number = (int)regs->ax;

    pid = task_pgrp(current);
    pgid = pid->numbers[0].nr;

    // Look for pid record, if not found, look for tgid (if tgid not the same as pid record), then look for pgid record
    register_index = lookup_process_entry(current->pid);
    if (register_index < 0) {
        if (current->pid != current->tgid) {
            register_index = lookup_process_entry(current->tgid);
        }

        if (register_index < 0) {
            register_index = lookup_process_entry(pgid);
        }
    }

    if (register_index) {
        if (process_register[register_index].allowed_syscalls[syscall_number]) {
            printk("Allowing system call: %d from PID (%d), PGID (%d)\n", syscall_number, current->pid, pgid);
            return process_register[register_index].next_kernel_index;
        }
    }

    printk("Blocking system call: %d from PID (%d), PGID (%d)\n", syscall_number, current->pid, pgid);
    return -EPERM;
}

// Config buffer contains either of the following structures:
// (next_kernel = 2090 - linux), (allowed_syscalls = 2090 - 45, 67, 23, 178)
int sandbox_config_handler(char *config_buffer) {
    int pid;
    char directive[DIRECTIVE_MAX_LENGTH], kernel_name[MAX_KERNEL_NAME_LENGTH], safe_config_buffer[MAX_KERNEL_CONFIG_BUFFER_LENGTH];
    char *kernel_configs, *kernel_configs_tracker, *trimmed_kernel_config;
    char *config_tokens, *config_tokens_tracker, *trimmed_config_token;
    char *parameter_tokens, *parameter_tokens_tracker, *trimmed_parameter_token;

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
        trimmed_kernel_config = trim(kernel_configs, ' ');
        trimmed_kernel_config = ltrim(trimmed_kernel_config, ',');
        trimmed_kernel_config = trim(trimmed_kernel_config, ' ');

        if (strlen(trimmed_kernel_config) > 0) {
            printk("sandbox_config_handler: Config piece: %s\n", trimmed_kernel_config);
            config_tokens = strtok_r(trimmed_kernel_config, "=", &config_tokens_tracker);

            if (config_tokens != NULL) {
                trimmed_config_token = trim(config_tokens, ' ');

                if (strlen(trimmed_config_token) > 0) {
                    memset(directive, 0, MAX_KERNEL_NAME_LENGTH);
                    strcpy(directive, trimmed_config_token);

                    printk("sandbox_config_handler: Directive: %s\n", directive);
                    if ((strcmp(directive, DIRECTIVE_NEXT_KERNEL) == 0) || (strcmp(directive, DIRECTIVE_ALLOWED_SYSCALLS) == 0)) {
                        config_tokens = strtok_r(NULL, "=", &config_tokens_tracker);

                        if (config_tokens != NULL) {
                            trimmed_config_token = trim(config_tokens, ' ');
                            if (strlen(trimmed_config_token) > 0) {
                                printk("sandbox_config_handler: Directive parameters: %s\n", trimmed_config_token);
                                parameter_tokens = strtok_r(trimmed_config_token, "-", &parameter_tokens_tracker);
                                if (parameter_tokens) {
                                    trimmed_parameter_token = trim(parameter_tokens, ' ');
                                    if (strlen(trimmed_parameter_token)) {
                                        pid = atoi(trimmed_parameter_token);
                                        if (pid > 0) {
                                            parameter_tokens = strtok_r(NULL, "-", &parameter_tokens_tracker);
                                            if (parameter_tokens) {
                                                trimmed_parameter_token = trim(parameter_tokens, ' ');
                                                if (strlen(trimmed_parameter_token)) {
                                                    if (strcmp(directive, DIRECTIVE_NEXT_KERNEL) == 0) {
                                                        register_process(pid, trimmed_parameter_token, NULL);
                                                    } else if (strcmp(directive, DIRECTIVE_ALLOWED_SYSCALLS) == 0) {
                                                        register_process(pid, NULL, trimmed_parameter_token);
                                                    }
                                                } else {
                                                    printk("sandbox_config_handler: Found empty configuration data for PID: %d in directive parameters. Skipping\n", pid);
                                                }
                                            } else {
                                                printk("sandbox_config_handler: Could not read configuration data for PID: %d from directive parameters. Skipping\n", pid);
                                            }
                                        } else {
                                            printk("sandbox_config_handler: Found invalid PID: %d in directive parameters. Skipping\n", pid);
                                        }
                                    } else {
                                        printk("sandbox_config_handler: Found empty PID in directive parameters. Skipping\n");
                                    }
                                } else {
                                    printk("sandbox_config_handler: Could not read PID from directive parameters. Skipping\n");
                                }
                            } else {
                                printk("sandbox_config_handler: Found empty directive parameters. Skipping\n");
                            }
                        } else {
                            printk("sandbox_config_handler: Could not read directive parameters from configuration piece. Skipping\n");
                        }
                    } else {
                        printk("sandbox_config_handler: Invalid directive in configuration piece. Skipping\n");
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
    int index, subindex;
    printk("Installing module: %s\n", MODULE_NAME);

    for (index = 0; index < MAX_PROCESS_SUPPORT; index++) {
        process_register[index].pid = -1;
        process_register[index].next_kernel_index = KMUX_HOST_KERNEL_INDEX;
        for (subindex = 0; subindex < MAX_SYSCALL + 1; subindex++) {
            process_register[index].allowed_syscalls[subindex] = 0;
        }
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
