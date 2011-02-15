#include "kern_mux.h"

#include <asm/desc.h>
#include <asm/segment.h>
#include <asm/msr.h>
#include <asm/ptrace.h>
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/string.h>


#define MODULE_NAME "kernel_multiplexer"

// Needs to be replaced with semaphore
static int device_open = 0;

/* Variables global to kmux module (access protected via semaphore) */
kernel_entry kernel_register[MAX_KERNEL_SUPPORT];
thread_entry thread_register[MAX_THREAD_SUPPORT];

extern void save_syscall_environment(void);

DEFINE_PER_CPU(unsigned long, gx86_tss);
DEFINE_PER_CPU(unsigned long, gx86_tss_ip_location);

void *ghost_sysenter_addr = NULL;

int cpu_register[MAX_CPU_SUPPORT];

/* ------------------------- */

int register_kern_syscall_handler(char* kernel_name, kmux_kernel_syscall_handler syscall_handler, kmux_remove_handler removal_handler){
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
		if (strcmp(kernel_name, kernel_register[index].kernel_name) == 0) {
			is_spot_found = 1;
			break;
		}
	}

	if (!is_spot_found) {
		// Check for empty spot
		printk("Checking for empty spot\n");
		for(index = 0; index < MAX_KERNEL_SUPPORT; index++) {
			if (strlen(kernel_register[index].kernel_name) == 0) {
				printk("Found spot at %d\n", index);
				strcpy(kernel_register[index].kernel_name, kernel_name);
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
		kernel_register[index].kernel_syscall_handler = syscall_handler;
		kernel_register[index].kernel_removal_handler = removal_handler;
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
		if (strcmp(kernel_name, kernel_register[index].kernel_name) == 0) {
			// Unregister handler
			printk("Found kernel record at %d\n", index);
			memset(kernel_register[index].kernel_name, MAX_KERNEL_NAME_LENGTH, 0);
			kernel_register[index].kernel_syscall_handler = NULL;
			kernel_register[index].kernel_removal_handler = NULL;
			is_removed = 1;
			break;
		}
	}

	return is_removed ? SUCCESS:-EFAULT;
}

int register_thread(char* kernel_name, unsigned int thread_id) {
	int index, is_inserted = 0;

	// Basic check
	if (strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -EFAULT;
	}

	// Find empty spot
	printk("Registering thread: %u with kernel: %s\n", thread_id, kernel_name);
	for (index = 0; index < MAX_THREAD_SUPPORT; index++) {
		if (strlen(thread_register[index].kernel_name) == 0) {
			// Register thread
			printk("Found thread registration spot at %d\n", index);
			strcpy(thread_register[index].kernel_name, kernel_name);
			thread_register[index].thread_id = thread_id;
			is_inserted = 1;
			break;
		}
	}

	return is_inserted ? SUCCESS:-EFAULT;
}

int unregister_thread(char* kernel_name, unsigned int thread_id) {
	int index, is_removed;

	// Basic check
	if (strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -1;
	}

	// Find token spot
	is_removed = 0;
	printk("De-registering thread: %u from kernel: %s\n", thread_id, kernel_name);
	for(index = 0; index < MAX_THREAD_SUPPORT; index++) {
		if (strcmp(kernel_name, thread_register[index].kernel_name) == 0) {
			// Unregister thread
			printk("Removing kernel info at index %d\n", index);
			memset(thread_register[index].kernel_name, MAX_KERNEL_NAME_LENGTH, 0);
			thread_register[index].thread_id = 0;
			is_removed = 1;
			break;
		}
	}

	return is_removed ? SUCCESS:-EFAULT;
}

void* get_host_sysenter_address(void) {
	int index;
	char kernel_name[MAX_KERNEL_NAME_LENGTH];
	void* host_sysenter_addr = NULL;

	strcpy(kernel_name, DEFAULT_KERNEL_NAME);

	for(index = 0; index < MAX_KERNEL_SUPPORT; index++){
		if (strcmp(kernel_name, kernel_register[index].kernel_name) == 0) {
			host_sysenter_addr = (void *)(kernel_register[index].kernel_syscall_handler);
		}
	}

	return host_sysenter_addr;
}

void __attribute__((regparm(1))) kmux_syscall_handler(struct pt_regs *regs) {
	int index;
	void *kmux_sysenter_addr = NULL;
	char kernel_name[MAX_KERNEL_NAME_LENGTH];
	unsigned int group_thread_id = (unsigned int)task_pgrp(current);

	// Get TSS from higher level Linux methods
	unsigned long *cpu_x86_tss, *cpu_x86_tss_ip_location;
	unsigned long *tss_ip_location = NULL;

	for(index = 0; index < MAX_THREAD_SUPPORT; index++){
		if (thread_register[index].thread_id == group_thread_id) {
			strcpy(kernel_name, thread_register[index].kernel_name);
			break;
		}
	}

	//printk("Index: %d MAX_THREAD: %d\n", index, MAX_THREAD_SUPPORT);
	if (index == MAX_THREAD_SUPPORT) {
		// Thread not registered. Host OS will handle? Or should we return -EFAULT
		strcpy(kernel_name, DEFAULT_KERNEL_NAME);
	}

	//printk("Found matching kernel: %s\n", kernel_name);
	for(index = 0; index < MAX_KERNEL_SUPPORT; index++){
		if (strcmp(kernel_name, kernel_register[index].kernel_name) == 0) {
			//printk("Retrieving kernel info at index: %d\n", index);
			kmux_sysenter_addr = (void *)(kernel_register[index].kernel_syscall_handler);
		}
	}

	// kmux_sysenter_addr should never be NULL
	if (kmux_sysenter_addr == NULL) {
		printk("kmux handler is NULL. Investigate.");
		kmux_sysenter_addr = ghost_sysenter_addr;
	}

	cpu_x86_tss = &get_cpu_var(gx86_tss);
	cpu_x86_tss_ip_location = &get_cpu_var(gx86_tss_ip_location);

	// x86_tss (x86_hw_tss) starts sizeof(struct tss_struct) words beyond tss pointer. Add 4 to reach IP
	//tss_ip_location = (unsigned long *)((char *)gdt_tss + sizeof(struct tss_struct) + 4);
	tss_ip_location = (unsigned long *)(*cpu_x86_tss_ip_location);
	*tss_ip_location = (unsigned long)kmux_sysenter_addr;

	// In assembly we push a null value in place of orig_eax. Save the TSS location there
	//regs->orig_ax = (unsigned long)((char *)gdt_tss + sizeof(struct tss_struct));
	regs->orig_ax = *cpu_x86_tss;

	return;
}

/* ------------------------- */


/* Syscall capture */
void* hw_int_init(void) {
	void *host_sysenter_addr = NULL;
	int se_addr, trash;
	printk("Reading and saving default sysenter handler.\n");
	rdmsr(MSR_IA32_SYSENTER_EIP, se_addr, trash);
	host_sysenter_addr = (void*)se_addr;
	return host_sysenter_addr;
}

void hw_int_override_sysenter(void *handler) {
	printk("Overriding sysenter handler with %p\n", handler);
	wrmsr(MSR_IA32_SYSENTER_EIP, (int)handler, 0);
}

void hw_int_reset(void *host_sysenter_addr) {
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
			thread_entry thread_info;
			int is_registered = 0;

			printk("Performing thread register ioctl.\n");
			if (copy_from_user(&thread_info, (void*)arg, sizeof(thread_entry))) {
				printk("Error copying thread information from user space.\n");
				ret = -EFAULT;
			}

			is_registered = register_thread(thread_info.kernel_name, thread_info.thread_id);
			return is_registered;
		}
		case KMUX_UNREGISTER_THREAD:
		{
			thread_entry thread_info;
			int is_unregistered = 0;

			printk("Performing thread unregister ioctl.\n");
			if (copy_from_user(&thread_info, (void*)arg, sizeof(thread_entry))) {
				printk("Error copying thread information from user space.\n");
				ret = -EFAULT;
			}

			is_unregistered = unregister_thread(thread_info.kernel_name, thread_info.thread_id);
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

/* Per CPU functions */

static void load_cpu_tss_locations(void *info) {
	unsigned long *cpu_x86_tss, *cpu_x86_tss_ip_location;

	// Get TSS from higher level Linux methods
	unsigned long temp_gdt_tss;
	//unsigned long *tss_ip_location = NULL;
	struct tss_struct *gdt_tss = NULL;
	struct desc_struct *gdt_array = NULL;

	printk("Loading TSS locations for CPU %d\n", get_cpu());

	// Get TSS value from GDT
	gdt_array = get_cpu_gdt_table(get_cpu());
	temp_gdt_tss = get_desc_base(&gdt_array[GDT_ENTRY_TSS]);
	gdt_tss = (struct tss_struct *)temp_gdt_tss;

	// x86_tss (x86_hw_tss) starts sizeof(struct tss_struct) words beyond tss pointer. Add 4 to reach IP
	cpu_x86_tss_ip_location = &get_cpu_var(gx86_tss_ip_location);
	*cpu_x86_tss_ip_location = (unsigned long)((char *)gdt_tss + sizeof(struct tss_struct) + 4);
	put_cpu_var(gx86_tss_ip_location);

	// Save the location of tss_struct's x86_tss
	cpu_x86_tss = &get_cpu_var(gx86_tss);
	*cpu_x86_tss = (unsigned long)((char *)gdt_tss + sizeof(struct tss_struct));
	put_cpu_var(gx86_tss);
}

static void override_cpu_sysenter_handler(void *info) {
	wrmsr(MSR_IA32_SYSENTER_EIP, (int)(&save_syscall_environment), 0);
	printk("Overriding sysenter handler with: %p on CPU %d\n", (void *)(&save_syscall_environment), get_cpu());
}

static void reset_cpu_sysenter_handler(void *info) {
	wrmsr(MSR_IA32_SYSENTER_EIP, (int)ghost_sysenter_addr, 0);
	printk("Restoring sysenter handler to default: %p on CPU %d\n", (void *)ghost_sysenter_addr, get_cpu());
}

/* Module initialization/ termination */
static int kmux_init(void) {
	unsigned long *cpu_x86_tss, *cpu_x86_tss_ip_location;
	void *host_sysenter_addr = NULL;

	printk("#~~~~~~~~~~~~~~~~~~~~~ kmux DEBUG START ~~~~~~~~~~~~~~~~~~~~~#\n");
	printk("Installing module: %s\n", MODULE_NAME);
	printk("Current CPU: %d\n", get_cpu());

	if (make_kmux_proc()) {
		return -1;
	}

	host_sysenter_addr = hw_int_init();
	ghost_sysenter_addr = host_sysenter_addr;

	printk("Current host sysenter handler: %p\n", host_sysenter_addr);

	register_kern_syscall_handler(DEFAULT_KERNEL_NAME, host_sysenter_addr, NULL);

	// Load TSS locations for current CPU
	load_cpu_tss_locations(NULL);
	// Load TSS locations for all CPUs
	smp_call_function(load_cpu_tss_locations, NULL, 1);

	cpu_x86_tss = &get_cpu_var(gx86_tss);
	printk("Loaded TSS %p on CPU %d\n", (void *)(*cpu_x86_tss), get_cpu());

	cpu_x86_tss_ip_location = &get_cpu_var(gx86_tss_ip_location);
	printk("Loaded TSS IP %p on CPU %d\n", (void *)(*cpu_x86_tss_ip_location), get_cpu());

	// Override syscall handler with kmux syscall handler
	smp_call_function(override_cpu_sysenter_handler, NULL, 1);
	override_cpu_sysenter_handler(NULL);

	return 0;
}

static void kmux_exit(void) {
	// Restore syscall handler to default
	reset_cpu_sysenter_handler(NULL);
	smp_call_function(reset_cpu_sysenter_handler, NULL, 1);

	remove_proc_entry(KMUX_PROC_NAME, NULL);

	printk("Uninstalling the Kernel Multiplexer module.\n");
	printk("#~~~~~~~~~~~~~~~~~~~~~ kmux DEBUG END ~~~~~~~~~~~~~~~~~~~~~#\n");
	return;
}
/* ------------------------- */

module_init(kmux_init);
module_exit(kmux_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Kernel Multiplexer for Handling Sandboxed System Calls");
MODULE_LICENSE("GPL");
