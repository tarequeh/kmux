#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>         /* cpu_set_t  */
#include <sys/ioctl.h>     /* ioctl      */
#include <sys/resource.h>  /* rlimit     */

#include "../kern_mux.h"
#include "kmul.h"

#define MAX_BUFF 100

/* Priority setting and idling functions */

static int call_getrlimit(int id, char *name)
{
    struct rlimit rl;

    if (getrlimit(id, &rl)) {
        printf("Error getting priority limit for %s\n", name);
        return -1;
    }
    printf("rlimit for %s is %d:%d (Infinity: %d)\n", name, (int)rl.rlim_cur, (int)rl.rlim_max, (int)RLIM_INFINITY);
}

static int call_setrlimit(int id, unsigned long cur, unsigned long max) {
    struct rlimit rl;

    rl.rlim_cur = cur;
    rl.rlim_max = max;
    if (setrlimit(id, &rl)) {
        printf("Error changing priority limit\n");
        return -1;
    }
}

static int set_high_priority(pid_t pid, int is_idle) {
    struct sched_param sp;
    unsigned long max_limit = RLIM_INFINITY - is_idle;

    call_getrlimit(RLIMIT_CPU, "CPU");
#ifdef RLIMIT_RTTIME
    call_getrlimit(RLIMIT_RTTIME, "RTTIME");
#endif
    call_getrlimit(RLIMIT_RTPRIO, "RTPRIO");
    call_setrlimit(RLIMIT_RTPRIO, max_limit, max_limit);
    call_getrlimit(RLIMIT_RTPRIO, "RTPRIO");
    call_getrlimit(RLIMIT_NICE, "NICE");

    if (sched_getparam(pid, &sp) < 0) {
        printf("Error retrieving schedule parameters\n");
    }

    sp.sched_priority = sched_get_priority_max(SCHED_RR);

    if (sched_setscheduler(pid, SCHED_RR, &sp) < 0) {
        printf("Error setting scheduler mode to Round Robin\n");
        return -1;
    }

    if (sched_getparam(pid, &sp) < 0) {
        printf("Error retrieving schedule parameters\n");
    }

    if (sp.sched_priority != sched_get_priority_max(SCHED_RR)) {
        printf("Scheduler mode was not correctly set to Round Robin\n");
        return -1;
    }

    return 0;
}

int set_cpu_affinity(pid_t pid, int cpu) {
    int retval;
    cpu_set_t *set = (cpu_set_t *)malloc(sizeof(cpu_set_t));
    CPU_ZERO(set);
    CPU_SET(cpu, set);
    retval = sched_setaffinity(pid, sizeof(cpu_set_t), set);
    if (retval < 0) {
        printf("Could not set affinity of PID: %d with CPU: %d\n", pid, cpu);
    }
}

static pid_t spawn_idle_thread(int cpu) {
    pid_t idle_pid = fork();

    if (idle_pid == 0) { // Child (idle process)
        while(1);
    } else if (idle_pid < 1) {
        printf("Error spawning idle thread for CPU\n");
        return -1;
    } else { // Parent (current process)
        // Switch affinity of idle process
        set_cpu_affinity(idle_pid, cpu);
        // Set priority of idle process to max - 1
        set_high_priority(idle_pid, 1);
        // TODO: If any of these 2 funcs return -1, then kill child process, return -1
        return idle_pid;
    }
}

static int get_total_cpus(void) {
    FILE *pfile;
    char buffer[MAX_BUFF];
    int cpu_count = 0;

    if ((pfile = fopen( "/proc/cpuinfo", "r")) == NULL) {
        perror( "fopen" );
        return (-1);
    }


    while (fgets(buffer, MAX_BUFF, pfile) != NULL) {
        if (strstr(buffer, "processor") == buffer) {
            cpu_count++;
        }
    }

    fclose(pfile);
    return cpu_count;
}

/* kmux interfacing functions */

static int get_kernel_index(int proc_desc, char *kernel_name) {
    int ret_val;

    if ((ret_val = ioctl(proc_desc, KMUX_GET_KERNEL_INDEX, kernel_name)) < 0) {
        printf("Could not get kernel index. ioctl returned %d\n", ret_val);
    } else {
        printf("Performed kernel id retrieval ioctl. Return value: %d\n", ret_val);
    }

    return ret_val;
}

int register_thread(int proc_desc, char *kernel_name, int pgid) {
    int ret_val, kernel_index;
    thread_entry *thread_info;

    if ((kernel_index = get_kernel_index(proc_desc, kernel_name)) < 0) {
        printf("Invalid kernel name: %s\n", kernel_name);
        return kernel_index;
    }

    thread_info = (thread_entry *)malloc(sizeof(thread_entry));
    thread_info->kernel_index = kernel_index;
    thread_info->pgid = pgid;

    if ((ret_val = ioctl(proc_desc, KMUX_REGISTER_THREAD, thread_info)) < 0) {
        printf("Could not register thread. ioctl returned %d\n", ret_val);
    } else {
        printf("Performed thread register ioctl. Return value: %d\n", ret_val);
    }

    free(thread_info);
    return ret_val;
}

int unregister_thread(int proc_desc, char *kernel_name, int pgid) {
    int ret_val, kernel_index;
    thread_entry *thread_info;

    if ((kernel_index = get_kernel_index(proc_desc, kernel_name)) < 0) {
        printf("Invalid kernel name: %s\n", kernel_name);
        return kernel_index;
    }

    thread_info = (thread_entry *)malloc(sizeof(thread_entry));
    thread_info->kernel_index = kernel_index;
    thread_info->pgid = pgid;

    if ((ret_val = ioctl(proc_desc, KMUX_UNREGISTER_THREAD, thread_info)) < 0) {
        printf("Could not unregister thread. ioctl returned %d\n", ret_val);
    } else {
        printf("Performed thread unregister ioctl. Return value: %d\n", ret_val);
    }

    free(thread_info);
    return ret_val;
}

int register_kernel_cpu(int proc_desc, char *kernel_name, int cpu) {
    int ret_val, kernel_index;
    cpu_registration_entry * cpu_registration_info;

    if (cpu < 0 || cpu >= get_total_cpus()) {
        printf("Invalid CPU: %d\n", cpu);
        return -1;
    }

    if ((kernel_index = get_kernel_index(proc_desc, kernel_name)) < 0) {
        printf("Invalid kernel name: %s\n", kernel_name);
        return kernel_index;
    }

    cpu_registration_info = (cpu_registration_entry *)malloc(sizeof(cpu_registration_entry));
    cpu_registration_info->kernel_index = kernel_index;
    cpu_registration_info->cpu = cpu;

    if ((ret_val = ioctl(proc_desc, KMUX_REGISTER_KERNEL_CPU, cpu_registration_info)) < 0) {
        printf("Could not register kernel cpu. ioctl returned %d\n", ret_val);
    } else {
        printf("Performed kernel cpu registration ioctl. Return value: %d\n", ret_val);
    }

    free(cpu_registration_info);
    return ret_val;
}

int unregister_kernel_cpu(int proc_desc, char *kernel_name, int cpu) {
    int ret_val, kernel_index;
    cpu_registration_entry * cpu_registration_info;

    if (cpu < 0 || cpu >= get_total_cpus()) {
        printf("Invalid CPU: %d\n", cpu);
        return -1;
    }

    if ((ret_val = kernel_index = get_kernel_index(proc_desc, kernel_name)) < 0) {
        printf("Invalid kernel name: %s\n", kernel_name);
        return ret_val;
    }

    cpu_registration_info = (cpu_registration_entry *)malloc(sizeof(cpu_registration_entry));
    cpu_registration_info->kernel_index = kernel_index;
    cpu_registration_info->cpu = cpu;

    if ((ret_val = ioctl(proc_desc, KMUX_UNREGISTER_KERNEL_CPU, cpu_registration_info)) < 0) {
        printf("Could not unregister kernel cpu. ioctl returned %d\n", ret_val);
    } else {
        printf("Performed kernel cpu unregistering ioctl. Return value: %d\n", ret_val);
    }

    free(cpu_registration_info);
    return ret_val;
}

static void free_dentlist(struct dirent **dentlist, const int ndirs) {
    int index;

    for (index = 0; index < ndirs; index++)
        free(dentlist[index]);

    free(dentlist);
}

int switch_cpu_for_current_processes(void) {
    struct dirent **dentlist;
    struct dirent *dentp;
    pid_t pid;
    int ndirs, index, errno;

    errno = 0;
    ndirs = scandir("/proc", &dentlist, NULL, NULL);

    if (ndirs == -1) {
        printf("Error reading process list");
        return -1;
    }

    for (index = 0; index < ndirs; index++) {
        dentp = dentlist[index];
        if (dentp->d_name[0] == '.') {
            continue;           /* skip `.' and `..' */
        }

        errno = 0;
        pid = (pid_t)strtol(dentp->d_name, (char**)NULL, 10);
        if (pid <= 0 || errno) {
            continue;           /* not a /proc/<pid> */
        }

        set_cpu_affinity(pid, KMUX_HOST_KERNEL_CPU);
    }

    free_dentlist(dentlist, ndirs);
    return 0;
}
