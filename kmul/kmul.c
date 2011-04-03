#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>         /* cpu_set_t  */
#include <sys/ioctl.h>     /* ioctl      */
#include <sys/resource.h>  /* rlimit     */

#include "../kern_mux.h"
#include "kmul.h"

#define MAX_BUFF 100
#define PROC_PATH_LENGTH 64

/* Priority setting and idling functions */

static int call_getrlimit(int id, char *name)
{
    struct rlimit rl;

    if (getrlimit(id, &rl)) {
        printf("Error getting priority limit for %s\n", name);
        return -1;
    }
    printf("rlimit for %s is %d:%d (Infinity: %d)\n", name, (int)rl.rlim_cur, (int)rl.rlim_max, (int)RLIM_INFINITY);

    return (int)rl.rlim_cur;
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

static void maximize_available_cpu() {
    int realtime_priority = call_getrlimit(RLIMIT_RTPRIO, "RTPRIO");

    if (realtime_priority != (int)RLIM_INFINITY) {
        call_getrlimit(RLIMIT_CPU, "CPU");
        #ifdef RLIMIT_RTTIME
            call_getrlimit(RLIMIT_RTTIME, "RTTIME");
        #endif
        call_getrlimit(RLIMIT_RTPRIO, "RTPRIO");
        call_setrlimit(RLIMIT_RTPRIO, RLIM_INFINITY, RLIM_INFINITY);
        call_getrlimit(RLIMIT_RTPRIO, "RTPRIO");
        call_getrlimit(RLIMIT_NICE, "NICE");
    }
}

static int set_process_priority(pid_t pid, int priority) {
    int ret_val, process_priority, max_priority;
    struct sched_param sp;

    // Retrieve PID's scheduling parameters
    if ((ret_val = sched_getparam(pid, &sp)) < 0) {
        printf("Error retrieving schedule parameters for process: %d\n", pid);
        return ret_val;
    } else {
        sp.sched_priority = priority;

        if ((ret_val = sched_setscheduler(pid, SCHED_RR, &sp)) < 0) {
            printf("Error setting Round Robin scheduler mode for process: %d\n", pid);
            return ret_val;
        } else {
            // Test PID's scheduling to see if it was successfully set to round robin
            if ((ret_val = sched_getparam(pid, &sp)) < 0) {
                printf("Error retrieving schedule parameters for process: %d\n", pid);
                return ret_val;
            } else {
                if (sp.sched_priority != priority) {
                    printf("Error retrieving schedule parameters for process: %d\n", pid);
                    return -1;
                }
            }
        }
    }

    return SUCCESS;
}

static int maximize_process_priority(pid_t pid, int is_idle) {
    int ret_val, priority;

    priority = sched_get_priority_max(SCHED_RR) - is_idle;

    // Set realtime priority to be maximum, only need to happen once
    maximize_available_cpu();

    if((ret_val = set_process_priority(pid, priority)) < 0){
        return ret_val;
    }

    return SUCCESS;
}

static int normalize_process_priority(pid_t pid) {
    int ret_val, process_priority;
    struct sched_param sp;

    // For round robin scheduling, normal priority is 0
    if((ret_val = set_process_priority(pid, 0)) < 0){
        return ret_val;
    }

    return SUCCESS;
}

int set_cpu_affinity(pid_t pid, int cpu) {
    int retval;
    cpu_set_t *set = (cpu_set_t *)malloc(sizeof(cpu_set_t));
    CPU_ZERO(set);
    CPU_SET(cpu, set);
    retval = sched_setaffinity(pid, sizeof(cpu_set_t), set);
    if (retval < 0) {
        printf("Could not set affinity of PID: %d with CPU: %d\n", pid, cpu);
        return -1;
    }

    return SUCCESS;
}

static pid_t spawn_idle_thread(int cpu) {
    int ret_val;
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
        if ((ret_val = maximize_process_priority(idle_pid, 1)) < 0) {
            return ret_val;;
        }
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

int validate_kmul_access() {
    uid_t uid = getuid(), euid = geteuid();
    if (uid < 0 || uid != euid) {
        return -1;
    } else {
        return SUCCESS;
    }
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

static int get_cpu_binding(int proc_desc, int kernel_index) {
    int ret_val;

    if ((ret_val = ioctl(proc_desc, KMUX_GET_CPU_BINDING, kernel_index)) < 0) {
        printf("Could not get kernel CPU binding. ioctl returned %d\n", ret_val);
    } else {
        printf("Performed kernel CPU binding retrieval ioctl. Return value: %d\n", ret_val);
    }

    return ret_val;
}

int register_thread(char *kernel_name, int pgid) {
    int proc_desc, ret_val, kernel_index, cpu_binding;
    thread_entry *thread_info;
    char proc_path[PROC_PATH_LENGTH];

    ret_val = validate_kmul_access();
    if (ret_val < 0) {
        return ret_val;
    }

    sprintf(proc_path, "/proc/%s", KMUX_PROC_NAME);

    proc_desc = open(proc_path, O_RDONLY);
    if (proc_desc < 0) {
        printf("Can't open proc: %s\n", KMUX_PROC_NAME);
        return proc_desc;
    }

    if ((kernel_index = get_kernel_index(proc_desc, kernel_name)) < 0) {
        printf("Invalid kernel name: %s\n", kernel_name);
        close(proc_desc);
        return kernel_index;
    }

    if ((cpu_binding = get_cpu_binding(proc_desc, kernel_index)) < 0) {
        printf("Error retrieving CPU binding for kernel: %s\n", kernel_name);
        close(proc_desc);
        return cpu_binding;
    }

    // Bind process to CPU
    if (cpu_binding) {
        if ((ret_val = set_cpu_affinity(pgid, cpu_binding)) < 0) {
            close(proc_desc);
            return ret_val;
        }

        if (kernel_index != KMUX_HOST_KERNEL_INDEX) {
            if((ret_val = maximize_process_priority(pgid, 0)) < 0) {
                printf("Could not maximize priority for %d\n", pgid);
                close(proc_desc);
                return ret_val;
            }
        }
    }

    // Regardless of CPU binding, add process binding in KMux
    thread_info = (thread_entry *)malloc(sizeof(thread_entry));
    thread_info->kernel_index = kernel_index;
    thread_info->pgid = pgid;

    if ((ret_val = ioctl(proc_desc, KMUX_REGISTER_THREAD, thread_info)) < 0) {
        printf("Could not register thread. ioctl returned %d\n", ret_val);
    } else {
        printf("Performed thread register ioctl. Return value: %d\n", ret_val);
    }

    free(thread_info);
    close(proc_desc);

    return ret_val;
}

int unregister_thread(char *kernel_name, int pgid) {
    int proc_desc, ret_val, kernel_index;
    thread_entry *thread_info;
    char proc_path[PROC_PATH_LENGTH];

    ret_val = validate_kmul_access();
    if (ret_val < 0) {
        return ret_val;
    }

    sprintf(proc_path, "/proc/%s", KMUX_PROC_NAME);

    proc_desc = open(proc_path, O_RDONLY);
    if (proc_desc < 0) {
        printf("Can't open proc: %s\n", KMUX_PROC_NAME);
        return proc_desc;
    }

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

    if (ret_val == SUCCESS) { // Thread deregistration was successful
        if((ret_val = normalize_process_priority(pgid)) < 0) {
            printf("Could not normalize priority for %d\n", pgid);
        }
    }

    free(thread_info);
    close(proc_desc);

    return ret_val;
}

int register_kernel_cpu(char *kernel_name, int cpu) {
    int proc_desc, ret_val, kernel_index;
    cpu_registration_entry *cpu_registration_info;
    char proc_path[PROC_PATH_LENGTH];

    ret_val = validate_kmul_access();
    if (ret_val < 0) {
        return ret_val;
    }

    sprintf(proc_path, "/proc/%s", KMUX_PROC_NAME);

    proc_desc = open(proc_path, O_RDONLY);
    if (proc_desc < 0) {
        printf("Can't open proc: %s\n", KMUX_PROC_NAME);
        return proc_desc;
    }

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

    if (ret_val == 0) { // CPU registration was successful
        // Host processors do not need to have idle threads
        if (kernel_index != KMUX_HOST_KERNEL_INDEX) {
            spawn_idle_thread(cpu);
            // TODO: Save idle thread PID in cpu registry
        }
    }

    close(proc_desc);
    return ret_val;
}

int unregister_kernel_cpu(char *kernel_name, int cpu) {
    int proc_desc, ret_val, kernel_index;
    cpu_registration_entry *cpu_registration_info;

    char proc_path[PROC_PATH_LENGTH];

    ret_val = validate_kmul_access();
    if (ret_val < 0) {
        return ret_val;
    }

    sprintf(proc_path, "/proc/%s", KMUX_PROC_NAME);

    proc_desc = open(proc_path, O_RDONLY);
    if (proc_desc < 0) {
        printf("Can't open proc: %s\n", KMUX_PROC_NAME);
        return proc_desc;
    }

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

    // TODO: Create data structure that gets returned on deregistration
    // Should contain idle thread PID and all kernel bound threads
    free(cpu_registration_info);
    close(proc_desc);

    return ret_val;
}

int configure_kernel(char *kernel_name, char *config_buffer) {
    int proc_desc, ret_val, kernel_index;
    kernel_config *config_info;
    char proc_path[PROC_PATH_LENGTH];

    ret_val = validate_kmul_access();
    if (ret_val < 0) {
        return ret_val;
    }

    sprintf(proc_path, "/proc/%s", KMUX_PROC_NAME);

    proc_desc = open(proc_path, O_RDONLY);
    if (proc_desc < 0) {
        printf("Can't open proc: %s\n", KMUX_PROC_NAME);
        return proc_desc;
    }

    if ((ret_val = kernel_index = get_kernel_index(proc_desc, kernel_name)) < 0) {
        printf("Invalid kernel name: %s\n", kernel_name);
        return ret_val;
    }

    if (!config_buffer || strlen(config_buffer) > MAX_KERNEL_CONFIG_BUFFER_LENGTH) {
        printf("Invalid config buffer found\n");
        return -1;
    }

    config_info = (kernel_config *)malloc(sizeof(kernel_config));
    memset(config_info->config_buffer, 0, MAX_KERNEL_CONFIG_BUFFER_LENGTH);

    config_info->kernel_index = kernel_index;
    strcpy(config_info->config_buffer, config_buffer);

    if ((ret_val = ioctl(proc_desc, KMUX_CONFIGURE_KERNEL, config_info)) < 0) {
        printf("Could not configure kernel. ioctl returned %d\n", ret_val);
    } else {
        printf("Performed kernel configure ioctl. Return value: %d\n", ret_val);
    }

    free(config_info);
    close(proc_desc);

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
