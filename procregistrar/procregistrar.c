#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>         /* cpu_set_t  */
#include <fcntl.h>         /* open       */
#include <unistd.h>        /* exit       */
#include <sys/ioctl.h>     /* ioctl      */
#include <sys/resource.h>  /* rlimit     */

#include "../kern_mux.h"

/* ------------------------- */

/* Priority setting and idling functions */

static int call_getrlimit(int id, char *name)
{
	struct rlimit rl;

	if (sys_getrlimit(id, &rl)) {
		printk("Error getting priority limit for %s\n", name);
		return -EFAULT;
	}
	printk("rlimit for %s is %d:%d (Infinity: %d)\n", name, (int)rl.rlim_cur, (int)rl.rlim_max, (int)RLIM_INFINITY);
}

static int call_setrlimit(int id, unsigned long cur, unsigned long max) {
	struct rlimit rl;

	rl.rlim_cur = cur;
	rl.rlim_max = max;
	if (sys_setrlimit(id, &rl)) {
		printk("Error changing priority limit\n");
		return -EFAULT;
	}
}

static int set_cpu_affinity(pid_t idle_proc, int cpu) {
	int retval;
	cpu_set_t *set = (cpu_set_t *)malloc(sizeof(cpu_set_t));
	CPU_ZERO(set);
	CPU_SET(set, cpu);
	retval = sched_setaffinity(idle_proc, sizeof(cpu_set_t), set);
	if (retval < 0) {
		printf("Could not set affinity of PID: %d with CPU: %d\n", (int)pid_t, cpu);
	}
}

static pid_t spawn_idle_thread(int cpu) {
	return 0;
}

// ------------------------- */


static int register_thread(int proc_desc, thread_register *thread_info) {
	int ret_val;

	if ((ret_val = ioctl(proc_desc, KMUX_REGISTER_THREAD, thread_info)) < 0) {
		printf("Could not register thread. ioctl returned %d\n", ret_val);
		exit(-1);
	}

	printf("Performed thread register ioctl. Return value: %d\n", ret_val);
	return ret_val;
}

static int unregister_thread(int proc_desc, thread_register *thread_info) {
 	int ret_val;

	if ((ret_val = ioctl(proc_desc, KMUX_UNREGISTER_THREAD, thread_info)) < 0) {
		printf("Could not unregister thread. ioctl returned %d\n", ret_val);
		exit(-1);
	}

	printf("Performed thread unregister ioctl. Return value: %d\n", ret_val);
	return ret_val;
}

static int get_kernel_index(int proc_desc, char *kernel_name) {
	if ((ret_val = ioctl(proc_desc, KMUX_GET_KERNEL_INDEX, kernel_name)) < 0) {
		printf("Could not get kernel index. ioctl returned %d\n", ret_val);
		exit(-1);
	}

	printf("Performed kernel id retrieval ioctl. Return value: %d\n", ret_val);
	return ret_val;
}

static int get_kernel_cpu(int proc_desc, int kernel_index) {
	if ((ret_val = ioctl(proc_desc, KMUX_GET_KERNEL_CPU, kernel_index)) < 0) {
		printf("Could not get kernel cpu. ioctl returned %d\n", ret_val);
		exit(-1);
	}

	printf("Performed kernel cpu retrieval ioctl. Return value: %d\n", ret_val);
	return ret_val;
}

int main(int argc, char *argv[]) {
	char proc_path[50], kernel_name[MAX_KERNEL_NAME_LENGTH];
	int kmux_command, proc_desc, ret_val, kernel_index;
	int pgid;
	thread_register *thread_info = (thread_register*)malloc(sizeof(thread_register));

	ret_val = sprintf(proc_path, "/proc/%s", KMUX_PROC_NAME);

	// Sanitize input
	if (argc != 4) {
		printf("Usage: threadregistrar command kernel_name, pgid");
		exit(-1);
	}

	if (strlen(argv[1]) > 1) {
		printf("Invalid kmux command: %s", argv[2]);
		exit(-1);
	} else {
		kmux_command = atoi(argv[1]);
		if (!kmux_command || (kmux_command != KMUX_IOCTL_CMD_REGISTER_THREAD && kmux_command != KMUX_IOCTL_CMD_UNREGISTER_THREAD)) {
			printf("Invalid kmux command: %s", argv[1]);
			exit(-1);
		}
	}

	if (strlen(argv[2]) > 50) {
		printf("Kernel name too long: %s", argv[1]);
		exit(-1);
	} else {
		strcpy(kernel_name, argv[2]);
	}

	pgid = atol(argv[3]);
	if (!pgid) {
		printf("Invalid thread ID: %s", argv[3]);
		exit(-1);
	}

	printf("kmux command: %d\n", kmux_command);
	printf("Kernel name: %s\n", kernel_name);
	printf("PGID: %d\n", pgid);

	proc_desc = open(proc_path, O_RDONLY);
	if (proc_desc < 0) {
		printf("Can't open proc: %s\n", KMUX_PROC_NAME);
		exit(-1);
	}

	kernel_index = get_kernel_index(proc_desc, kernel_name);
	if (kernel_index < 0) {
		printf("Invalid kernel name: %s\n", kernel_name);
	}

	thread_info->kernel_index = kernel_index;
	thread_info->pgid = pgid;

	if (kmux_command == KMUX_IOCTL_CMD_REGISTER_THREAD) {
		register_thread(proc_desc, thread_info);
	} else {
		unregister_thread(proc_desc, thread_info);
	}

	close(proc_desc);

	return 0;
}
