#ifndef KMUL_H
#define KMUL_H

int set_cpu_affinity(pid_t pid, int cpu);

int register_thread(int proc_desc, char *kernel_name, int pgid);
int unregister_thread(int proc_desc, char *kernel_name, int pgid);
int register_kernel_cpu(int proc_desc, char *kernel_name, int cpu);
int unregister_kernel_cpu(int proc_desc, char *kernel_name, int cpu);
int configure_kernel(int proc_desc, char *kernel_name, char *config_buffer);

int switch_cpu_for_current_processes(void);

static int get_total_cpus(void);

#endif
