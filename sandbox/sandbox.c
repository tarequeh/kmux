#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>

#include "../kern_mux.h"

#define MODULE_NAME "sandbox"

extern int register_kern_syscall_handler(char* kernel_name, kmux_kernel_syscall_handler syscall_handler);
extern int unregister_kern_syscall_handler(char* kernel_name);
extern int chain_kernel(int kernel_index, int kernel_next);
extern int get_kernel_index(char *kernel_name);
extern int get_host_sysenter_handler(void);

DEFINE_PER_CPU(unsigned long, gx86_tss);
DEFINE_PER_CPU(unsigned long, gx86_tss_ip_location);

extern void sandbox_sysenter_handler(void);

// TODO: Break down function to individually return the locations so that they are reusable
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

void __attribute__((regparm(1))) sandbox_syscall_handler(struct pt_regs *regs) {
    unsigned long *cpu_x86_tss, *cpu_x86_tss_ip_location;
    unsigned long *tss_ip_location = NULL;
    int host_sysenter_handler;

    printk("sandbox_syscall_handler: Syscall number: %lu executing on %d\n", regs->ax, get_cpu());
    // Add logic to filter system call

    cpu_x86_tss = &get_cpu_var(gx86_tss);
    cpu_x86_tss_ip_location = &get_cpu_var(gx86_tss_ip_location);

    tss_ip_location = (unsigned long *)(*cpu_x86_tss_ip_location);

    host_sysenter_handler = get_host_sysenter_handler();
    *tss_ip_location = (unsigned long)host_sysenter_handler;
}

/* Module initialization/ termination */
static int __init sandbox_init(void) {
    kmux_kernel_syscall_handler sysenter_handler;

    printk("Installing module: %s\n", MODULE_NAME);

    sysenter_handler = (kmux_kernel_syscall_handler)(&sandbox_sysenter_handler);

	// Load TSS locations for current CPU
    load_cpu_tss_locations(NULL);
    // Load TSS locations for all CPUs
    smp_call_function(load_cpu_tss_locations, NULL, 1);

	register_kern_syscall_handler(MODULE_NAME, sysenter_handler);
	chain_kernel(get_kernel_index(MODULE_NAME), KMUX_HOST_KERNEL_INDEX);
	return 0;
}

static void __exit sandbox_exit(void) {
	printk("Uninstalling the Sandbox kernel\n");
	chain_kernel(get_kernel_index(MODULE_NAME), KMUX_UNCHAINED_KERNEL);
	unregister_kern_syscall_handler(MODULE_NAME);
	return;
}
/* ------------------------- */

module_init(sandbox_init);
module_exit(sandbox_exit);

MODULE_AUTHOR("Tareque Hossain");
MODULE_DESCRIPTION("Sandbox kernel for kmux");
MODULE_LICENSE("GPL");
