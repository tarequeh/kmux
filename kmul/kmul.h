#ifndef KMUL_H
#define KMUL_H

int set_cpu_affinity(pid_t pid, int cpu);

int register_thread(int proc_desc, char *kernel_name, int pgid);
int unregister_thread(int proc_desc, char *kernel_name, int pgid);
int register_kernel_cpu(int proc_desc, char *kernel_name, int cpu);
int unregister_kernel_cpu(int proc_desc, char *kernel_name, int cpu);

int switch_cpu_for_current_processes(void);

#endif
