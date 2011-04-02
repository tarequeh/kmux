#include <asm/uaccess.h>
#include <asm/fcntl.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/limits.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>

#include "../kern_mux.h"
#include "../kern_utils.h"

#define MODULE_NAME "filesys_filter"

#define DIRECTIVE_MAX_LENGTH 64
#define DIRECTIVE_NEXT_KERNEL "next_kernel"
#define DIRECTIVE_REGISTER_PATH "register_path"
#define DIRECTIVE_UNREGISTER_PATH "unregister_path"

#define MAX_PATH_SUPPORT 512

extern int register_kernel(char* kernel_name, kmux_kernel_syscall_handler syscall_handler, kmux_kernel_config_handler config_handler);
extern int unregister_kernel(char* kernel_name);
extern int get_kernel_index(char* kernel_name);

struct path_entry {
    int pid;
    char path[PATH_MAX];
};

typedef struct path_entry path_entry;

path_entry path_register[MAX_PATH_SUPPORT];

int gnext_kernel_index = KMUX_HOST_KERNEL_INDEX;

/*
 * Syscalls to monitor
 *
 * 3 - read
 * 4 - write
 * 5 - open
 * 6 - close
 * 8 - creat
 * 9 - link
 * 10 - unlink
 * 14 - mknod
 * 15 - chmod
 * 16 - lchown
 * 18 - stat
 * 19 - lseek
 * 21 - mount
 * 22 - umount
 * 28 - fstat
 * 39 - mkdir
 * 40 - rmdir
 * 52 - umount2
 * 55 - fcntl
 * 60 - umask
 * 61 - chroot
 * 62 - ustat
 * 63 - dup2
 * 84 - lstat
 * 85 - readlink
 * 92 - truncate
 * 93 - ftruncate
 * 94 - fchmod
 * 95 - fchown
 * 99 - statfs
 * 100 - fstatfs
 * 106 - sys_newstat
 * 107 - sys_newlstat
 * 108 - sys_newfstat
 * 115 - swapoff118 - fsync
 * 131 - quotactl
 * 133 - fchdir
 * 135 - sysfs
 * 138 - setfsuid
 * 139 - setfsgid
 * 140 - sys_llseek
 * 141 - getdents
 * 143 - flock
 * 148 - fdatasync
 * 168 - poll
 * 180 - pread
 * 181 - sys_pwrite
 * 182 - chown
 * 187 - sendfile
 *
 */

static int getpwd(char *buffer_out, int buffer_size) {
    int ret_val;
    struct path pwd;
    unsigned long len;
    char *cwd;

    read_lock(&current->fs->lock);
    pwd = current->fs->pwd;
    path_get(&pwd);
    read_unlock(&current->fs->lock);

    cwd = d_path(&pwd, buffer_out, buffer_size);

    ret_val = PTR_ERR(cwd);
    if (!IS_ERR(cwd)) {
        len = PAGE_SIZE + buffer_out - cwd;
        memcpy(buffer_out, cwd, len);
        ret_val = SUCCESS;
    }

    path_put(&pwd);
    return ret_val;
}

/* Hash table functions */
static int find_path_register_slot(int pid) {
    int index, hash_tracker;

    index = (int)(j32int_hash(pid) % MAX_PATH_SUPPORT);

    // Under no circumstance hash_tracker will exceed MAX_PATH_SUPPORT
    hash_tracker = 0;
    while(hash_tracker < MAX_PATH_SUPPORT) {
        // Return index on empty or match
        if (path_register[index].pid == -1 || path_register[index].pid) {
            return index;
        }
        index = (index + 1) % MAX_PATH_SUPPORT;
        hash_tracker++;
    }

    return -ENOSPC;
}

static char *lookup_path(int pid) {
    int index;
    index = find_path_register_slot(pid);
    if (path_register[index].pid == -1) {
        // pid is not in register
        return NULL;
    } else {
        // pid is in register
        return path_register[index].path;
    }
}

int filesys_filter_syscall_handler(struct pt_regs *regs) {
    int ret_val = gnext_kernel_index, syscall_number = regs->ax;

    if(syscall_number == 5 || syscall_number == 8) {
        char *normalized_path, *copied_file_path, *file_path, *restricted_path, *matched_path;

        file_path = (char *)regs->bx;
        copied_file_path = getname(file_path);
        normalized_path  = (char *) __get_free_page(GFP_ATOMIC);

        if (!copied_file_path || strlen(copied_file_path) == 0) {
            printk("filesys_filter_syscall_handler: Could not read user file path\n");
            ret_val = -EINVAL;
        }

        if (!normalized_path) {
            printk("filesys_filter_syscall_handler: Could not allocate memory for reading current directory\n");
            ret_val = -ENOMEM;
        }

        if (ret_val >= 0) {
            if (copied_file_path[0] != '/') {
                ret_val = getpwd(normalized_path, PAGE_SIZE);
                if (ret_val < 0){
                    printk("filesys_filter_syscall_handler: Could not read current directory. getcwd returned: %d\n", ret_val);
                    ret_val = -EFAULT;
                } else {
                    printk("filesys_filter_syscall_handler: Current directory: %s, File path: %s\n", normalized_path, copied_file_path);
                    strcat(normalized_path, copied_file_path);
                }
            } else {
                strcpy(normalized_path, copied_file_path);
            }
        }

        if (ret_val >= 0) {
            restricted_path = lookup_path(current->pid);
            if (restricted_path) {
                matched_path = strstr(normalized_path, restricted_path);
                // NOTE: If normalized path doesn't start with restricted path, return error
                if (!matched_path || matched_path != normalized_path) {
                    ret_val = -EACCES;
                }
            }
        }

        free_page((unsigned long) normalized_path);
        putname(copied_file_path);
    }

    return ret_val;
}

int register_path(int pid, char* path) {
    return SUCCESS;
}

int unregister_path(int pid) {
    return SUCCESS;
}

// Config buffer contains either of the following structures:
// (next_kernel = linux), (register_path = 3020, /tmp/firefox), (unregister_path = 3020)
int filesys_filter_config_handler(char *config_buffer) {
    int pid, kernel_index;
    char directive[DIRECTIVE_MAX_LENGTH], kernel_name[MAX_KERNEL_NAME_LENGTH], path[PATH_MAX], safe_config_buffer[MAX_KERNEL_CONFIG_BUFFER_LENGTH];
    char *kernel_configs, *kernel_configs_tracker, *config_tokens, *config_tokens_tracker, *allowed_path, *allowed_path_tracker, *trimmed_config, *trimmed_config_token, *trimmed_path;

    memset(directive, 0, DIRECTIVE_MAX_LENGTH);
    memset(kernel_name, 0, MAX_KERNEL_NAME_LENGTH);

    printk("filesys_filter_config_handler: Configuring kernel: %s\n", MODULE_NAME);

    if (config_buffer == NULL) {
        printk("filesys_filter_config_handler: Received invalid config buffer\n");
        return -EINVAL;
    }

    if (strlen(config_buffer) == 0) {
        printk("filesys_filter_config_handler: Received zero length config buffer\n");
        return -EINVAL;
    }

    // strtok_r writes into buffer, so copy it into a safe location
    memset(safe_config_buffer, 0, MAX_KERNEL_CONFIG_BUFFER_LENGTH);
    strcpy(safe_config_buffer, config_buffer);

    printk("filesys_filter_config_handler: Parsing config buffer: %s\n", safe_config_buffer);

    kernel_configs = strtok_r(safe_config_buffer, "()", &kernel_configs_tracker);

    while (kernel_configs != NULL) {
        trimmed_config = trim(kernel_configs, ' ');
        trimmed_config = ltrim(trimmed_config, ',');
        trimmed_config = trim(trimmed_config, ' ');

        if (strlen(trimmed_config) > 0) {
            printk("filesys_filter_config_handler: Config piece: %s\n", trimmed_config);
            config_tokens = strtok_r(trimmed_config, "=", &config_tokens_tracker);

            if (config_tokens != NULL) {
                trimmed_config_token = trim(config_tokens, ' ');

                if (strlen(trimmed_config_token) > 0) {
                    memset(directive, 0, MAX_KERNEL_NAME_LENGTH);
                    strcpy(directive, trimmed_config_token);

                    printk("filesys_filter_config_handler: Directive: %s\n", directive);
                    config_tokens = strtok_r(NULL, "=", &config_tokens_tracker);

                    if (config_tokens != NULL) {
                        trimmed_config_token = trim(config_tokens, ' ');
                        if (strlen(trimmed_config_token) > 0) {
                            printk("filesys_filter_config_handler: Directive parameters: %s\n", trimmed_config_token);
                            if (strcmp(directive, DIRECTIVE_NEXT_KERNEL) == 0) {
                                kernel_index = get_kernel_index(trimmed_config_token);
                                if (kernel_index < 0) {
                                    printk("filesys_filter_config_handler: Invalid next kernel name: %s\n", trimmed_config_token);
                                } else {
                                    printk("filesys_filter_config_handler: Set next kernel to: %s\n", trimmed_config_token);
                                    gnext_kernel_index = kernel_index;
                                }
                            } else if (strcmp(directive, DIRECTIVE_REGISTER_PATH) == 0) {
                                // TODO: Extract process ID and path
                                register_path(pid, path);
                            } else if (strcmp(directive, DIRECTIVE_UNREGISTER_PATH) == 0) {
                                // TODO: Extract process ID
                                unregister_path(pid);
                            } else {
                                printk("filesys_filter_config_handler: Invalid directive in configuration piece. Skipping\n");
                            }
                        } else {
                            printk("filesys_filter_config_handler: Found empty directive parameters. Skipping\n");
                        }
                    } else {
                        printk("filesys_filter_config_handler: Could not read directive parameters from configuration piece. Skipping\n");
                    }
                } else {
                    printk("filesys_filter_config_handler: Found empty directive. Skipping\n");
                }
            } else {
                printk("filesys_filter_config_handler: Could not read directive from configuration piece. Skipping\n");
            }
        } else {
            printk("filesys_filter_config_handler: Found empty configuration piece. Skipping\n");
        }

        kernel_configs = strtok_r(NULL, "()", &kernel_configs_tracker);
    }

    return SUCCESS;
}

/* Module initialization/ termination */
static int __init filesys_filter_init(void) {
    int index;
    printk("Installing module: %s\n", MODULE_NAME);

    for (index = 0; index < MAX_PATH_SUPPORT; index++) {
        path_register[index].pid = -1;
        memset(path_register[index].path, 0, PATH_MAX);
    }

    register_kernel(MODULE_NAME, &filesys_filter_syscall_handler, &filesys_filter_config_handler);
	return 0;
}

static void __exit filesys_filter_exit(void) {
	printk("Uninstalling the Filesystem Filter kernel\n");
	unregister_kernel(MODULE_NAME);
	return;
}
/* ------------------------- */

module_init(filesys_filter_init);
module_exit(filesys_filter_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Filesystem Filter kernel for kmux");
MODULE_LICENSE("GPL");
