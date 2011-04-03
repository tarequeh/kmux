#include <asm/desc.h>
#include <asm/segment.h>
#include <asm/msr.h>
#include <asm/ptrace.h>
#include <asm/uaccess.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/string.h>

#include "kern_mux.h"
#include "kern_utils.h"

#define MODULE_NAME "kernel_multiplexer"

// Needs to be replaced with semaphore
static int device_open = 0;

/* Variables global to kmux module (TODO: Protect write access via semaphore) */
kernel_entry kernel_register[MAX_KERNEL_SUPPORT];
thread_entry thread_register[MAX_THREAD_SUPPORT];
cpu_entry cpu_register[MAX_CPU_SUPPORT];

extern void save_syscall_environment(void);

DEFINE_PER_CPU(unsigned long, gx86_tss);
DEFINE_PER_CPU(unsigned long, gx86_tss_ip_location);

void *ghost_sysenter_addr = NULL;

/* Array lookup and validation functions */
int get_kernel_index(char *kernel_name) {
	int index;

	if (kernel_name[0] == 0 || strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -EINVAL;
	}

	for(index = 0; index < MAX_KERNEL_SUPPORT; index++) {
		if (strcmp(kernel_name, kernel_register[index].kernel_name) == 0) {
			return index;
		}
	}

	return -EINVAL;
}

static int validate_kernel_index(int kernel_index) {
	if (kernel_index < 0 || kernel_index >= MAX_KERNEL_SUPPORT) {
		return -EINVAL;
	}

	if (kernel_register[kernel_index].kernel_name[0] == 0 || kernel_register[kernel_index].kernel_syscall_handler == NULL) {
		return -EINVAL;
	}

	return SUCCESS;
}

static int get_cpu_binding(int kernel_index) {
    int ret_val, index;

    if((ret_val = validate_kernel_index(kernel_index)) < 0) {
        return ret_val;
    }

    for (index = 0; index < MAX_CPU_SUPPORT; index++) {
        if (cpu_register[index].kernel_index == kernel_index) {
            // TODO: Devise a way to spread process load across multiple CPUs
            return index;
        }
    }

    return 0;
}

/* Hash table functions */
static int find_thread_register_slot(int pgid) {
    int index, hash_tracker;

    index = (int)(j32int_hash(pgid) % MAX_THREAD_SUPPORT);

    // Under no circumstance hash_tracker will exceed MAX_THREAD_SUPPORT
    hash_tracker = 0;
    while(hash_tracker < MAX_THREAD_SUPPORT) {
        // Return index on empty or match
        if (thread_register[index].pgid == -1 || thread_register[index].pgid == pgid) {
            return index;
        }
        index = (index + 1) % MAX_THREAD_SUPPORT;
        hash_tracker++;
    }

    return -ENOSPC;
}

static int lookup_kernel_index(int pgid) {
    int index;
    index = find_thread_register_slot(pgid);
    if (thread_register[index].pgid == -1) {
        // pgid is not in register
        return -EINVAL;
    } else {
        // pgid is in register
        return thread_register[index].kernel_index;
    }
}

/* kmux API functions */

int register_kernel(char* kernel_name, kmux_kernel_syscall_handler syscall_handler, kmux_kernel_config_handler config_handler){
	int index;

	// Argument check
	if (kernel_name[0] == 0 || strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH || syscall_handler == NULL) {
		return -EINVAL;
	}

    printk("register_kernel: Adding syscall handler: %p for kernel: %s\n", syscall_handler, kernel_name);
    if (config_handler != NULL) {
        printk("register_kernel: Adding config handler: %p for kernel: %s\n", config_handler, kernel_name);
    }

	// Find spot by kernel name
	for (index = 0; index < MAX_KERNEL_SUPPORT; index++) {
		if (strcmp(kernel_name, kernel_register[index].kernel_name) == 0) {
			printk("register_kernel: Found existing spot at %d\n", index);
			kernel_register[index].kernel_syscall_handler = syscall_handler;
			kernel_register[index].kernel_config_handler = config_handler;
			return SUCCESS;
		}
	}

	// No existing spot. Check for empty spot
	for(index = 0; index < MAX_KERNEL_SUPPORT; index++) {
		if (kernel_register[index].kernel_name[0] == 0) {
			printk("register_kernel: Found empty spot at %d\n", index);
			strcpy(kernel_register[index].kernel_name, kernel_name);
			kernel_register[index].kernel_syscall_handler = syscall_handler;
			kernel_register[index].kernel_config_handler = config_handler;
			return SUCCESS;
		}
	}

	printk("register_kernel: Failed to register %s. Could not find existing/empty spot\n", kernel_name);
	return -ENOSPC;
}

int unregister_kernel(char* kernel_name) {
	int index, kernel_index;

	// Basic check
	if (kernel_name[0] == 0 || strlen(kernel_name) > MAX_KERNEL_NAME_LENGTH) {
		return -EINVAL;
	}

	// Find token spot
	printk("unregister_kernel: Unregistering kernel: %s\n", kernel_name);
	kernel_index = get_kernel_index(kernel_name);

	if (kernel_index >= 0) {
		// Unregister handler
		printk("unregister_kernel: Found kernel record at index: %d\n", kernel_index);
		memset(kernel_register[kernel_index].kernel_name, 0, MAX_KERNEL_NAME_LENGTH);
		kernel_register[kernel_index].kernel_syscall_handler = NULL;
		kernel_register[kernel_index].kernel_config_handler = NULL;

		// Remove all registered threads
		for(index = 0; index < MAX_THREAD_SUPPORT; index++) {
			if (thread_register[index].kernel_index == kernel_index) {
				// Unregister thread
				printk("unregister_kernel: Removing registered thread pgid %d\n", thread_register[index].pgid);
				thread_register[index].kernel_index = -1;
				thread_register[index].pgid = -1;
			}
		}

		return SUCCESS;
	}

	printk("unregister_kernel: Could not find entry for kernel: %s. Already removed?\n", kernel_name);
	return -EINVAL;
}

static int register_thread(int kernel_index, int pgid) {
	int index;

	if (validate_kernel_index(kernel_index) < 0) {
		printk("register_thread: Invalid kernel index: %d", kernel_index);
		return -EINVAL;
	}

	// Check if thread already registered
	printk("register_thread: Registering thread: %u with kernel: %s\n", pgid, kernel_register[kernel_index].kernel_name);

    index = find_thread_register_slot(pgid);
    if (index < 0) {
        printk("register_thread: Failed to register thread: %d. Registry full?\n", pgid);
        return -ENOSPC;
    }

    if (thread_register[index].pgid != -1) {
        kernel_index = thread_register[index].kernel_index;
        printk("register_thread: Thread: %d already registered with kernel: %s. Unregister first.\n", pgid, kernel_register[kernel_index].kernel_name);
        return -EINVAL;
    } else {
        printk("register_thread: Found empty thread registration spot at %d\n", index);
        thread_register[index].kernel_index = kernel_index;
        thread_register[index].pgid = pgid;
        return SUCCESS;
    }
}

static int unregister_thread(int pgid) {
    int index, kernel_index;

    // Find token spot
    printk("unregister_thread: Unregistering thread: %d\n", pgid);

    index = find_thread_register_slot(pgid);

    if ((index >= 0) && (thread_register[index].pgid != -1)) {
        kernel_index = thread_register[index].kernel_index;
        printk("unregister_thread: Unregistering thread %d from kernel %s\n", pgid, kernel_register[kernel_index].kernel_name);

        thread_register[index].kernel_index = -1;
        thread_register[index].pgid = -1;
        return SUCCESS;
    } else {
        printk("unregister_thread: Failed to unregister thread: %d. Already unregistered?\n", pgid);
        return -EINVAL;
    }
}

// TODO: Take CPU as input. Allocate if available. Return error if not
static int register_kernel_cpu(int kernel_index, int cpu) {
	if (validate_kernel_index(kernel_index) < 0) {
		printk("register_kernel_cpu: Invalid kernel index %d", kernel_index);
		return -EINVAL;
	}

	if (cpu < 0 || cpu > MAX_CPU_SUPPORT) {
		printk("register_kernel_cpu: Invalid CPU %d", cpu);
		return -EINVAL;
	}

    if (cpu_register[cpu].kernel_index != -1) {
        if (cpu_register[cpu].kernel_index == kernel_index) {
            printk("register_kernel_cpu: CPU %d is already registered with %s\n", cpu, kernel_register[kernel_index].kernel_name);
            return -EBUSY;
        } else {
            printk("register_kernel_cpu: CPU %d is not available\n", cpu);
            return -EEXIST;
        }
    }

	printk("register_kernel_cpu: Allocating CPU %d for kernel: %s\n", cpu, kernel_register[kernel_index].kernel_name);
	cpu_register[cpu].kernel_index = kernel_index;
	return SUCCESS;
}

static int unregister_kernel_cpu(int kernel_index, int cpu) {
	int index;

	if (validate_kernel_index(kernel_index) < 0) {
		printk("unregister_kernel_cpu: Invalid kernel index %d. Cleaning up.", kernel_index);
		return -EINVAL;
	}

	if (cpu < 0 || cpu > MAX_CPU_SUPPORT) {
		printk("unregister_kernel_cpu: Invalid CPU %d", cpu);
		return -EINVAL;
	}

	if (cpu == -1) { // Unregister all CPU for given kernel
		for (index = 0; index < MAX_CPU_SUPPORT; index++) {
			if (cpu_register[index].kernel_index == kernel_index) {
				printk("unregister_kernel_cpu: Unregistering CPU %d from kernel: %s\n", cpu, kernel_register[kernel_index].kernel_name);
				cpu_register[index].kernel_index = -1;
				cpu_register[index].idle_pid = -1;
			}
		}
		return SUCCESS;
	} else {
		if (cpu_register[cpu].kernel_index != kernel_index) {
			printk("unregister_kernel_cpu: CPU %d is not registered with kernel: %s", cpu, kernel_register[kernel_index].kernel_name);
			return -EINVAL;
		} else {
			printk("unregister_kernel_cpu: Unregistering CPU %d from kernel: %s\n", cpu, kernel_register[kernel_index].kernel_name);
			cpu_register[cpu].kernel_index = -1;
			cpu_register[cpu].idle_pid = -1;
			return SUCCESS;
		}
	}
}

int configure_kernel(int kernel_index, char *config_buffer) {
    kmux_kernel_config_handler kernel_config_handler;

    if (validate_kernel_index(kernel_index) < 0) {
        printk("configure_kernel: Invalid kernel index %d", kernel_index);
        return -EINVAL;
    }

    // Host kernel does not accept configuration
    if (kernel_index == KMUX_HOST_KERNEL_INDEX) {
        return -EINVAL;
    }

    kernel_config_handler = kernel_register[kernel_index].kernel_config_handler;
    if (kernel_config_handler == NULL) {
        return -EFAULT;
    } else {
        printk("configure_kernel: Sending config buffer: %s to kernel: %s\n", config_buffer, kernel_register[kernel_index].kernel_name);
        return (*kernel_config_handler)(config_buffer);
    }
}

// NOTE: No print business in this function. Critical for system performance
void __attribute__((regparm(1))) kmux_syscall_handler(struct pt_regs *regs) {
	int kernel_index, pgid;
	kmux_kernel_syscall_handler kmux_sysenter_handler;
	struct pid *pid;

	unsigned long *cpu_x86_tss, *cpu_x86_tss_ip_location;
	unsigned long *tss_ip_location = NULL;

	// Try thread registration lookup by thread pid
	if ((kernel_index = lookup_kernel_index(current->pid)) < 0) {
	    // Try thread registration lookup by thread group ID
	    if ((current->pid == current->tgid) || (kernel_index = lookup_kernel_index(current->tgid)) < 0) {
	        // Try thread registration lookup by process group ID
	        pid = task_pgrp(current);
	        pgid = pid->numbers[0].nr;
	        kernel_index = lookup_kernel_index(pgid);
	    }
	}

	if (kernel_index < 0) {
	    kernel_index = KMUX_HOST_KERNEL_INDEX;
	}

	// Call through the chain of kernels until someone wants to exit or pass control to host
	while ((kernel_index >= 0) && (kernel_index != KMUX_HOST_KERNEL_INDEX)) {
        // Validate next kernel
        if (validate_kernel_index(kernel_index) < 0) {
            // TODO: For now we pass control to host for invalid kernels, maybe we should just exit
            kernel_index = KMUX_HOST_KERNEL_INDEX;
            break;
        }

        // Load handler for next kernel
        kmux_sysenter_handler = kernel_register[kernel_index].kernel_syscall_handler;

        // Pass control to kernel and receive next kernel in chain
	    kernel_index = (*kmux_sysenter_handler)(regs);
	}

    // NOTE: Beyond this point, we will either return error on syscall or pass control to host kernel

    // Load TSS and TSS->IP locations for current CPU
    cpu_x86_tss = &get_cpu_var(gx86_tss);
    cpu_x86_tss_ip_location = &get_cpu_var(gx86_tss_ip_location);

    // In assembly we push a null value in place of orig_eax. Save the TSS location there
    regs->orig_ax = *cpu_x86_tss;

    // x86_tss (x86_hw_tss) starts sizeof(struct tss_struct) words beyond tss pointer. Add 4 to reach IP
    tss_ip_location = (unsigned long *)(*cpu_x86_tss_ip_location);

    if (kernel_index != KMUX_HOST_KERNEL_INDEX) {
        // Update stack with error value
        regs->ax = (unsigned long)kernel_index;
    }

    *tss_ip_location = (unsigned long)ghost_sysenter_addr;

    return;
}

/* ------------------------- */

/* Syscall capture */
static void hw_int_init(void) {
	int se_addr, trash;
	printk("Reading and saving default sysenter handler.\n");
	rdmsr(MSR_IA32_SYSENTER_EIP, se_addr, trash);
	ghost_sysenter_addr = (void*)se_addr;
}

static void hw_int_override_sysenter(void *handler) {
	printk("Overriding sysenter handler with %p\n", handler);
	wrmsr(MSR_IA32_SYSENTER_EIP, (int)handler, 0);
}

static void hw_int_reset(void *host_sysenter_addr) {
	printk("Restoring default sysenter handler.\n");
	wrmsr(MSR_IA32_SYSENTER_EIP, (int)host_sysenter_addr, 0);
}
/* ------------------------- */

/* Proc Functions */

static int kmux_open(struct inode *inode, struct file *file) {
	if (device_open)
		return -EBUSY;

	device_open++;

	try_module_get(THIS_MODULE);

	printk("kmux proc opened.\n");
	return SUCCESS;
}

static int kmux_release(struct inode *inode, struct file *file) {
	if (!device_open)
		return -EIO;

	device_open--;

	module_put(THIS_MODULE);

	printk("kmux proc closed.\n");
	return SUCCESS;
}

static int kmux_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg) {
	switch(cmd) {
		case KMUX_REGISTER_THREAD:
		{
			thread_entry thread_info;

			printk("Performing thread register ioctl.\n");
			if (copy_from_user(&thread_info, (void*)arg, sizeof(thread_entry))) {
				printk("Error copying thread information from user space.\n");
				return -EFAULT;
			}

			return register_thread(thread_info.kernel_index, thread_info.pgid);
		}
		case KMUX_UNREGISTER_THREAD:
		{
			thread_entry thread_info;

			printk("Performing thread unregister ioctl.\n");
			if (copy_from_user(&thread_info, (void*)arg, sizeof(thread_entry))) {
				printk("Error copying thread information from user space.\n");
				return -EFAULT;
			}

			return unregister_thread(thread_info.pgid);
		}
		case KMUX_REGISTER_KERNEL_CPU:
		{
			cpu_registration_entry cpu_registration_info;

			printk("Performing kernel cpu registration ioctl.\n");
			if (copy_from_user(&cpu_registration_info, (void*)arg, sizeof(cpu_registration_entry))) {
				printk("Error copying cpu registration information from user space.\n");
				return -EFAULT;
			}

			return register_kernel_cpu(cpu_registration_info.kernel_index, cpu_registration_info.cpu);
		}
		case KMUX_UNREGISTER_KERNEL_CPU:
		{
			cpu_registration_entry cpu_registration_info;

			printk("Performing kernel cpu unregister ioctl.\n");
			if (copy_from_user(&cpu_registration_info, (void*)arg, sizeof(cpu_registration_entry))) {
				printk("Error copying cpu registration information from user space.\n");
				return -EFAULT;
			}

			return unregister_kernel_cpu(cpu_registration_info.kernel_index, cpu_registration_info.cpu);
		}
        case KMUX_GET_KERNEL_INDEX:
        {
            char kernel_name[MAX_KERNEL_NAME_LENGTH];

            printk("Performing kernel index retrieval ioctl.\n");
            if (copy_from_user(&kernel_name, (void*)arg, MAX_KERNEL_NAME_LENGTH)) {
                printk("Error copying kernel name from user space.\n");
                return -EFAULT;
            }

            return get_kernel_index(kernel_name);
        }
        case KMUX_GET_CPU_BINDING:
        {
            int kernel_index = (int)arg;
            printk("Performing kernel CPU binding retrieval ioctl.\n");

            return get_cpu_binding(kernel_index);
        }
        case KMUX_CONFIGURE_KERNEL:
        {
            kernel_config config_info;

            printk("Performing kernel config ioctl.\n");
            if (copy_from_user(&config_info, (void*)arg, sizeof(kernel_config))) {
                printk("Error copying kernel configuration information from user space.\n");
                return -EFAULT;
            }

            return configure_kernel(config_info.kernel_index, config_info.config_buffer);
        }
        default:
		{
			printk("Invalid kmux ioctl command: %u\n", cmd);
			return -EFAULT;
		}
	}
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
		return -EFAULT;
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
// NOTE: No non-mutex access to global variable allowed outside init
static int __init kmux_init(void) {
	int index, retval;

	unsigned long *cpu_x86_tss, *cpu_x86_tss_ip_location;

	printk("#~~~~~~~~~~~~~~~~~~~~~ kmux DEBUG START ~~~~~~~~~~~~~~~~~~~~~#\n");
	printk("Installing module: %s\n", MODULE_NAME);
	printk("Current CPU: %d\n", get_cpu());

	retval = make_kmux_proc();
	if (retval < 0) {
		return retval;
	}

	// Initialize data structures with default value
	for (index = 0; index < MAX_KERNEL_SUPPORT; index++){
		memset(kernel_register[index].kernel_name, 0, MAX_KERNEL_NAME_LENGTH);
		kernel_register[index].kernel_syscall_handler = NULL;
		kernel_register[index].kernel_config_handler = NULL;
	}

	for(index = 0; index < MAX_THREAD_SUPPORT; index++) {
		thread_register[index].kernel_index = -1;
		thread_register[index].pgid = -1;
	}

	for(index = 0; index < MAX_CPU_SUPPORT; index++) {
		cpu_register[index].kernel_index = -1;
		cpu_register[index].idle_pid = -1;
	}

	hw_int_init();
	// ghost_sysenter_addr is available beyond this point

	printk("Current host sysenter handler: %p\n", ghost_sysenter_addr);

	// Default kernel has to be at KMUX_HOST_KERNEL_INDEX
	register_kernel(KMUX_DEFAULT_KERNEL_NAME, ghost_sysenter_addr, NULL);

	register_kernel_cpu(KMUX_HOST_KERNEL_INDEX, KMUX_HOST_KERNEL_CPU);

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

static void __exit kmux_exit(void) {
    // Restore syscall handler to default
    reset_cpu_sysenter_handler(NULL);
	smp_call_function(reset_cpu_sysenter_handler, NULL, 1);

	remove_proc_entry(KMUX_PROC_NAME, NULL);

	unregister_kernel_cpu(KMUX_HOST_KERNEL_INDEX, KMUX_HOST_KERNEL_CPU);
	unregister_kernel(KMUX_DEFAULT_KERNEL_NAME);

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

EXPORT_SYMBOL_GPL(register_kernel);
EXPORT_SYMBOL_GPL(unregister_kernel);
EXPORT_SYMBOL_GPL(get_kernel_index);
