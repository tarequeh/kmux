#include <asm/desc.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include<linux/init.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/sched.h>

#include "kern_mux.h"

#define MODULE_NAME "kernel_multiplexer"

// Needs to be replaced with semaphore
static int device_open = 0;

/* Variables global to kmux module (access protected via semaphore) */
kernel_entry kernel_entry_container[MAX_KERNEL_SUPPORT];
thread_register thread_register_container[MAX_THREAD_SUPPORT];

extern void save_syscall_environment(void);

/* ------------------------- */

int register_kern_syscall_handler(char* kernel_name, kmux_kernel_syscall_handler syscall_handler, kmux_remove_handler removal_handler, int is_direct){
	int index, is_spot_found;

	printk("Adding handler: %p for kernel: %s\n", syscall_handler, kernel_name);
	// Basic check
	if (strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -EFAULT;
	}

	// Find token spot
	printk("Checking for existing spot\n");
	is_spot_found = 0;
	for (index = 0; index < MAX_KERNEL_SUPPORT; index++) {
		if (strcmp(kernel_name, kernel_entry_container[index].kernel_name) == 0) {
			is_spot_found = 1;
			break;
		}
	}

	if (!is_spot_found) {
		// Check for empty spot
		printk("Checking for empty spot\n");
		for(index = 0; index < MAX_KERNEL_SUPPORT; index++) {
			if (strlen(kernel_entry_container[index].kernel_name) == 0) {
				printk("Found spot at %d\n", index);
				strcpy(kernel_entry_container[index].kernel_name, kernel_name);
				is_spot_found = 1;
				break;
			}
		}
	}

	// No more kernel spots available
	if (!is_spot_found) {
		return -EFAULT;
	} else {
		// Register handlers
		kernel_entry_container[index].kernel_syscall_handler = syscall_handler;
		kernel_entry_container[index].kernel_removal_handler = removal_handler;
		kernel_entry_container[index].is_direct = is_direct;
		return SUCCESS;
	}
}

int unregister_kern_syscall_handler(char* kernel_name) {
	int index, is_removed;

	// Basic check
	if (strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -EFAULT;
	}

	// Find token spot
	is_removed = 0;
	printk("Removing handler for kernel: %s\n", kernel_name);
	for(index = 0; index < MAX_KERNEL_SUPPORT; index++) {
		if (strcmp(kernel_name, kernel_entry_container[index].kernel_name) == 0) {
			// Unregister handler
			printk("Found kernel record at %d\n", index);
			memset(kernel_entry_container[index].kernel_name, MAX_KERNEL_NAME_LENGTH, 0);
			kernel_entry_container[index].kernel_syscall_handler = NULL;
			kernel_entry_container[index].kernel_removal_handler = NULL;
			kernel_entry_container[index].is_direct = -1;
			is_removed = 1;
			break;
		}
	}

	if (is_removed) {
		// Remove all registered threads
		for(index = 0; index < MAX_THREAD_SUPPORT; index++) {
			if (strcmp(kernel_name, thread_register_container[index].kernel_name) == 0) {
				// Unregister thread
				printk("Removing registered tgpid %d\n", thread_register_container[index].pgid);
				memset(thread_register_container[index].kernel_name, MAX_KERNEL_NAME_LENGTH, 0);
				thread_register_container[index].pgid = 0;
			}
		}
	}

	return is_removed ? SUCCESS:-EFAULT;
}

static int register_thread(char* kernel_name, int pgid) {
	int index, is_inserted = 0;

	// Basic check
	if (strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -EFAULT;
	}

	// Find empty spot
	printk("Registering thread: %u with kernel: %s\n", pgid, kernel_name);
	for (index = 0; index < MAX_THREAD_SUPPORT; index++) {
		if (strlen(thread_register_container[index].kernel_name) == 0) {
			// Register thread
			printk("Found thread registration spot at %d\n", index);
			strcpy(thread_register_container[index].kernel_name, kernel_name);
			thread_register_container[index].pgid = pgid;
			is_inserted = 1;
			break;
		}
	}

	return is_inserted ? SUCCESS:-EFAULT;
}

static int unregister_thread(char* kernel_name, int pgid) {
	int index, is_removed;

	// Basic check
	if (strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -1;
	}

	// Find token spot
	is_removed = 0;
	printk("De-registering thread: %u from kernel: %s\n", pgid, kernel_name);
	for(index = 0; index < MAX_THREAD_SUPPORT; index++) {
		if (strcmp(kernel_name, thread_register_container[index].kernel_name) == 0) {
			// Unregister thread
			printk("Removing kernel info at index %d\n", index);
			memset(thread_register_container[index].kernel_name, MAX_KERNEL_NAME_LENGTH, 0);
			thread_register_container[index].pgid = 0;
			is_removed = 1;
			break;
		}
	}

	return is_removed ? SUCCESS:-EFAULT;
}

static void* get_host_sysenter_address(void) {
	void* host_sysenter_addr = NULL;

	// Host kernel is always at spot 0
	host_sysenter_addr = (void *)(kernel_entry_container[0].kernel_syscall_handler);

	return host_sysenter_addr;
}

void* kmux_syscall_handler(struct pt_regs regs) {
	int index, is_direct = 1;
	char kernel_name[MAX_KERNEL_NAME_LENGTH];
	struct pid *pid = task_pgrp(current);
	int pgid = pid->numbers[0].nr;

	kmux_kernel_syscall_handler kmux_sysenter_handler = NULL;
	void *host_sysenter_address = get_host_sysenter_address();

	// If PGID is 0 then its the host kernel's process group. Skip such processes.
	if (pgid == 0) {
		kmux_sysenter_handler = host_sysenter_address;
		is_direct = 1;
	} else {
		for(index = 0; index < MAX_THREAD_SUPPORT; index++){
			if (thread_register_container[index].pgid == pgid) {
				strcpy(kernel_name, thread_register_container[index].kernel_name);
				break;
			}
		}

		if (index == MAX_THREAD_SUPPORT) {
			// Thread not registered. Host OS will handle? Or should we return -EFAULT
			kmux_sysenter_handler = host_sysenter_address;
			is_direct = 1;
		} else {
			// Thread is registered. Look up kernel
			for(index = 0; index < MAX_KERNEL_SUPPORT; index++){
				if (strcmp(kernel_name, kernel_entry_container[index].kernel_name) == 0) {
					//printk("Retrieving kernel info at index: %d\n", index);
					kmux_sysenter_handler = kernel_entry_container[index].kernel_syscall_handler;
					is_direct = kernel_entry_container[index].is_direct;
					break;
				}
			}

			if (index == MAX_KERNEL_SUPPORT) {
				// Something went wrong, thread was registered but kernel not found
				printk("Failed to locate kernel %s requested by thread %d", kernel_name, pgid);
				kmux_sysenter_handler = host_sysenter_address;
				is_direct = 1;
			}
		}
	}

	if (is_direct) {
		return (void *)kmux_sysenter_handler;
	} else {
		(*kmux_sysenter_handler)(regs);
		return get_host_sysenter_address();
	}
}

/* ------------------------- */


/* Syscall capture */
static void* hw_int_init(void) {
	void *host_sysenter_addr = NULL;
	int se_addr, trash;
	printk("Reading and saving default sysenter handler.\n");
	rdmsr(MSR_IA32_SYSENTER_EIP, se_addr, trash);
	host_sysenter_addr = (void*)se_addr;
	return host_sysenter_addr;
}

static void hw_int_override_sysenter(void *handler) {
	wrmsr(MSR_IA32_SYSENTER_EIP, (int)handler, 0);
}

static void hw_int_reset(void *host_sysenter_addr) {
	wrmsr(MSR_IA32_SYSENTER_EIP, (int)host_sysenter_addr, 0);
	printk("Restoring default sysenter handler.\n");
}
/* ------------------------- */

/* Proc Functions */

static int kmux_open(struct inode *inode, struct file *file)
{
	if (device_open)
		return -EBUSY;

	device_open++;

	try_module_get(THIS_MODULE);

	printk("kmux proc opened.\n");

	return SUCCESS;
}

static int kmux_release(struct inode *inode, struct file *file)
{
	if (!device_open)
		return -EFAULT;

	device_open--;

	module_put(THIS_MODULE);

	printk("kmux proc closed.\n");
	return SUCCESS;
}

static int kmux_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg) {
	int ret = 0;

	switch(cmd) {
		case KMUX_REGISTER_THREAD:
		{
			thread_register thread_info;
			int is_registered = 0;

			printk("Performing thread register ioctl.\n");
			if (copy_from_user(&thread_info, (void*)arg, sizeof(thread_register))) {
				printk("Error copying thread information from user space.\n");
				ret = -EFAULT;
			}

			is_registered = register_thread(thread_info.kernel_name, thread_info.pgid);
			return is_registered;
		}
		case KMUX_UNREGISTER_THREAD:
		{
			thread_register thread_info;
			int is_unregistered = 0;

			printk("Performing thread unregister ioctl.\n");
			if (copy_from_user(&thread_info, (void*)arg, sizeof(thread_register))) {
				printk("Error copying thread information from user space.\n");
				ret = -EFAULT;
			}

			is_unregistered = unregister_thread(thread_info.kernel_name, thread_info.pgid);
			return is_unregistered;
		}
		default:
			printk("Invalid kmux ioctl command: %u\n", cmd);
			return -EFAULT;
	}

	return ret;
}

static struct file_operations proc_kmux_fops = {
	.owner          = THIS_MODULE,
	.ioctl          = kmux_ioctl,
	.open           = kmux_open,
	.release        = kmux_release,
};

static int make_kmux_proc(void) {
	struct proc_dir_entry *ent;

	ent = create_proc_entry(KMUX_PROC_NAME, KMUX_PROC_NUMBER, NULL);
	if(ent == NULL){
		printk("Failed to register /proc/%s\n", KMUX_PROC_NAME);
		return -1;
	}

	ent->proc_fops = &proc_kmux_fops;

	printk("Successfully created proc device.\n");

	return SUCCESS;
}

/* ------------------------- */

/* Module initialization/ termination */
static int __init kmux_init(void) {
	void *host_sysenter_addr = NULL;
	printk("Installing module: %s\n", MODULE_NAME);

	if (make_kmux_proc()) {
		return -1;
	}

	host_sysenter_addr = hw_int_init();

	printk("Overriding sysenter handler: %p with %p\n", host_sysenter_addr, save_syscall_environment);
	hw_int_override_sysenter(save_syscall_environment);

	register_kern_syscall_handler(DEFAULT_KERNEL_NAME, host_sysenter_addr, NULL, 1);

	/*
	// Test Code
	void *fake_handler = (void *)0xf5b09cc2;
	unsigned int current_thread = (unsigned int)task_pgrp(current);
	register_kern_syscall_handler("composite", fake_handler, NULL);
	register_thread("composite", current_thread);
	kmux_sysenter_addr = NULL;
	kmux_syscall_handler();
	printk("kmux syscall handler: %p\n", kmux_sysenter_addr);
	unregister_thread("composite", current_thread);
	kmux_sysenter_addr = NULL;
	kmux_syscall_handler();
	printk("kmux syscall handler: %p\n", kmux_sysenter_addr);
	unregister_kern_syscall_handler("composite");
	*/

	return 0;
}

static void __exit kmux_exit(void) {
	void *host_sysenter_addr = get_host_sysenter_address();
	printk("Uninstalling the Kernel Multiplexer module.\n");
	printk("Retrieved host sysenter handler: %p\n", host_sysenter_addr);
	hw_int_reset(host_sysenter_addr);
	remove_proc_entry(KMUX_PROC_NAME, NULL);

	return;
}
/* ------------------------- */

module_init(kmux_init);
module_exit(kmux_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Kernel Multiplexer for Handling Sandboxed System Calls");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL_GPL(register_kern_syscall_handler);
EXPORT_SYMBOL_GPL(unregister_kern_syscall_handler);
