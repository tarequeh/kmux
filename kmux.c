#include <string.h>
#include <asm/desc.h>
#include <asm/msr.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>

#define MODULE_NAME "kernel_multiplexer"
#define MAX_KERNEL_SUPPORT 50
#define MAX_THREAD_SUPPORT 1000
#define MAX_KERNEL_NAME_LENGTH 50

static int device_open = 0;

/* Handler array definition */
typedef void (*kmux_kernel_syscall_handler)(void);
typedef void (*kmux_remove_handler)(void);

/* Data structures */
struct kernel_entry {
	char kernel_name[MAX_KERNEL_NAME_LENGTH];
	kmux_kernel_syscall_handler kernel_syscall_handler;
	kmux_remove_handler kernel_removal_handler;
};

typedef struct kernel_entry kernel_entry;

struct thread_register {
	char kernel_name[MAX_KERNEL_NAME_LENGTH];
	int thread_id;
};

typedef struct thread_register thread_register;

kernel_entry kernel_entry_container[MAX_KERNEL_SUPPORT];
thread_register thread_register_container[MAX_THREAD_SUPPORT];

// Store for host OS/ current syscall handler
void *host_sysenter_addr, *kmux_sysenter_addr;

/* ------------------------- */

int register_kern_syscall_handler(char* kernel_name, kmux_kern_syscall_handler_t *syscall_handler, kmux_remove_handler_t *removal_handler){
	// Basic check
	if (strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -1;
	}

	// Find token spot
	int index, is_spot_found = 0;
	for (index = 0; index < MAX_KERNEL_SUPPORT; index++) {
		if (strcmp(kernel_name, kernel_entry_container[index].kernel_name) == 0) {
			kernel_entry = kernel_entry_container[index];
			is_spot_found = 1;
			break;
		}
	}

	if (!is_spot_found) {
		// Check for empty spot
		for(index = 0; index < MAX_KERNEL_SUPPORT; index++) {
			if (strlen(kernel_entry_container[index].kernel_name) == 0) {
				kernel_entry = kernel_entry_container[index];
				strcpy(kernel_entry_container[empty_spot_index].kernel_name, kernel_name);
				is_spot_found = 1;
				break;
			}
		}
	}

	// No more kernel spots available
	if (!is_spot_found) {
		return -1;
	} else {
		// Register handlers
		kernel_entry.kernel_syscall_handler = syscall_handler;
		kernel_entry.kernel_removal_handler = removal_handler;
		return 0;
	}
}

int unregister_kern_syscall_handler(char* kernel_name) {
	// Basic check
	if (strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -1;
	}

	// Find token spot
	int index, is_removed = 0;
	for(index = 0; index < MAX_KERNEL_SUPPORT; index++) {
		if (strcmp(token, kernel_entry_container[index].kernel_name) == 0) {

			// Unregister handler
			memset(kernel_entry_container[index].kernel_name, MAX_KERNEL_NAME_LENGTH, 0);
			kernel_entry.kernel_syscall_handler = NULL;
			kernel_entry.kernel_removal_handler = NULL;
			is_removed = 1;
			break;
		}
	}

	return is_removed ? 0:-1;
}

int register_thread(char* kernel_name, int thread_id) {
	// Basic check
	if (strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -1;
	}

	// Find empty spot
	int index, is_inserted = 0;
	for (index = 0; index < MAX_THREAD_SUPPORT; index++) {
		if (srtlen(thread_register_container[index].kernel_name) == 0) {
			// Register thread
			strcpy(thread_register_container[index].kernel_name, kernel_name);
			thread_register_container[index].thread_id = thread_id;
			is_inserted = 1;
			break;
		}
	}

	return is_inserted ? 0:-1;
}

int unregister_thread(char* kernel_name, int thread_id) {
	// Basic check
	if (strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -1;
	}

	// Find token spot
	int index, is_removed = 0;
	for(index = 0; index < MAX_THREAD_SUPPORT; index++) {
		if (strcmp(kernel_name, thread_register_container[index].kernel_name) == 0) {

			// Unregister thread
			memset(thread_register_container[index].kernel_name, MAX_KERNEL_NAME_LENGTH, 0);
			kernel_entry.thread_id = -1;
			is_removed = 1;
			break;
		}
	}

	return is_removed ? 0:-1;
}

void kmux_syscall_handler(void) {
	// Save registers?
	int group_thread_id = task_pgrp(current);

	int index;
	char kernel_name[MAX_KERNEL_NAME_LENGTH];

	for(index = 0; index < MAX_THREAD_SUPPORT; index++){
		if (thread_register_container[index].thread_id == group_thread_id) {
			strcpy(kernel_name, thread_register_container[index].kernel_name);
			break;
		}
	}

	if (index == MAX_THREAD_SUPPORT) {
		// Thread not registered. Host OS will handle? Or should we return -EFAULT
		strcpy(kernel_name, "Host");
	}

	for(index = 0; index < MAX_KERNEL_SUPPORT; index++){
		if (strcmp(kernel_name, kernel_entry_container[index].kernel_name) == 0) {
			kmux_sysenter_addr = (void *)(kernel_entry_container[index].kernel_syscall_handler);
		}
	}
}

/* ------------------------- */


/* Syscall capture */
void hw_int_init(void) {
	int se_addr, trash;
	rdmsr(MSR_IA32_SYSENTER_EIP, se_addr, trash);
	host_sysenter_addr = (void*)se_addr;
}

void hw_int_override_sysenter(void *handler) {
	wrmsr(MSR_IA32_SYSENTER_EIP, (int)handler, 0);
	printk("Overriding sysenter handler (%p) with %p\n", host_sysenter_addr, handler);
}

void hw_int_reset(void) {
	wrmsr(MSR_IA32_SYSENTER_EIP, (int)host_sysenter_addr, 0);
}
/* ------------------------- */

/* Proc Functions */

static struct file_operations proc_kmux_fops = {
	.owner          = THIS_MODULE,
	.ioctl          = kmux_ioctl,
	.open           = kmux_open,
	.release        = kmux_release,
};

static int make_kmux_proc(void) {
	ent = create_proc_entry("kmux", 0223, NULL);
	if(ent == NULL){
		printk("Failed to register /proc/kmux\n");
		return -1;
	}

	ent->proc_fops = &proc_kmux_fops;

	return 0;
}

static int kmux_open(struct inode *inode, struct file *file)
{
	if (device_open)
		return -EBUSY;

	device_open++;

	try_module_get(THIS_MODULE);
	return SUCCESS;
}

static int kmux_open(struct inode *inode, struct file *file)
{
	if (!device_open)
		return -EFAULT;

	device_open--;

	module_put(THIS_MODULE);
	return SUCCESS;
}

static int kmux_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg) {
	int ret = 0;

	switch(cmd) {
		case KMUX_REGISTER_THREAD:
		{
			thread_register thread_info;
			int is_registered = 0;

			if (copy_from_user(&thread_info, (void*)arg, sizeof(struct thread_info))) {
				printk("Error copying thread information from user space.\n");
				return -EFAULT;
			}

			is_registered = register_thread(&(thread_info.kernel_name), thread_info.thread_id);
			return is_registered;
		}
		case KMUX_UNREGISTER_THREAD:
		{
			thread_register thread_info;

			if (copy_from_user(&thread_info, (void*)arg, sizeof(struct thread_info))) {
				printk("Error copying thread information from user space.\n");
				return -EFAULT;
			}

			is_unregistered = unregister_thread(&(thread_info.kernel_name), thread_info.thread_id);
			return is_unregistered;
		}
	}
}

/* ------------------------- */

/* Module initialization/ termination */
static int kmux_init(void) {
	printk("Installing the Kernel Multiplexer.\n");

	if (make_kmux_proc()) {
		return -1;
	}

	hw_int_init();
	hw_int_override_sysenter(save_syscall_environment);
	register_kern_syscall_handler("Host", host_sysenter_addr, NULL);

	return 0;
}

static void kmux_exit(void) {
	printk("Uninstalling the Kernel Multiplexer.\n");
	hw_int_reset();
	remove_proc_entry("kmux", NULL);

	return;
}
/* ------------------------- */

module_init(kmux_init);
module_exit(kmux_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Kernel Multiplexer for Handling Sandboxed System Calls");
MODULE_LICENSE("GPL");
