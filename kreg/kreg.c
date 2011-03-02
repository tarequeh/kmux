#include <fcntl.h>         /* open       */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>        /* exit       */

#include "../kern_mux.h"
#include "../kmul/kmul.h"

void initialize_kreg(void) {
	// Set affinity of this utility to CPU dedicated to Linux
	pid_t kreg_pid = getpid();
	set_cpu_affinity(kreg_pid, KMUX_HOST_KERNEL_CPU);

	switch_cpu_for_current_processes();
}

// TODO: Create a loop that shows a prompt and waits for user input
// TODO: Check for unregistered kernels every time a command comes in and get rid of idle loops
int main(int argc, char *argv[]) {
    initialize_kreg();

    char proc_path[50], kernel_name[MAX_KERNEL_NAME_LENGTH];
    int kmux_command, proc_desc, ret_val;
    int pgid, cpu;

    ret_val = sprintf(proc_path, "/proc/%s", KMUX_PROC_NAME);

    // Sanitize input
    if (argc != 4) {
        printf("Usage: kreg command kernel_name, pgid/cpu");
        exit(-1);
    }

    if (strlen(argv[1]) > 1) {
        printf("Invalid kmux command: %s", argv[2]);
        exit(-1);
    } else {
        kmux_command = atoi(argv[1]);
        if (!kmux_command || kmux_command < KMUX_IOCTL_CMD_REGISTER_THREAD || kmux_command > KMUX_IOCTL_CMD_UNREGISTER_KERNEL_CPU) {
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

    printf("kmux command: %d\n", kmux_command);
    printf("Kernel name: %s\n", kernel_name);

    proc_desc = open(proc_path, O_RDONLY);
    if (proc_desc < 0) {
        printf("Can't open proc: %s\n", KMUX_PROC_NAME);
        exit(-1);
    }

    if (kmux_command == KMUX_IOCTL_CMD_REGISTER_THREAD || kmux_command == KMUX_IOCTL_CMD_UNREGISTER_THREAD) {
        pgid = atoi(argv[3]);
        if (!pgid) {
            printf("Invalid thread ID: %s", argv[3]);
            exit(-1);
        }

        printf("PGID: %d\n", pgid);

        if (kmux_command == KMUX_IOCTL_CMD_REGISTER_THREAD) {
            register_thread(proc_desc, kernel_name, pgid);
        } else {
            unregister_thread(proc_desc, kernel_name, pgid);
        }
    } else if (kmux_command == KMUX_IOCTL_CMD_REGISTER_KERNEL_CPU || kmux_command == KMUX_IOCTL_CMD_UNREGISTER_KERNEL_CPU) {
        cpu = atoi(argv[3]);
        if (!cpu) {
            printf("Invalid CPU: %s", argv[3]);
            exit(-1);
        }

        printf("CPU: %d\n", cpu);
        if (kmux_command == KMUX_IOCTL_CMD_REGISTER_KERNEL_CPU) {
            register_kernel_cpu(proc_desc, kernel_name, cpu);
        } else {
            unregister_kernel_cpu(proc_desc, kernel_name, cpu);
        }
    }

    close(proc_desc);

    return 0;
}
