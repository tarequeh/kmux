#include <fcntl.h>         /* open       */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>        /* exit       */

#include "../kern_mux.h"
#include "../kmul/kmul.h"

#define BUFFER_LENGTH 100

void initialize_kreg(void) {
	// Set affinity of this utility to CPU dedicated to Linux
	pid_t kreg_pid = getpid();
	set_cpu_affinity(kreg_pid, KMUX_HOST_KERNEL_CPU);

	switch_cpu_for_current_processes();
}

// TODO: Check for unregistered kernels every time a command comes in and get rid of idle loops
int main(void) {
    initialize_kreg();

    char proc_path[50], input_buffer[BUFFER_LENGTH], kernel_name[MAX_KERNEL_NAME_LENGTH];
    int kmux_command, proc_desc, ret_val, pgid, cpu, var_param, items_scanned;

    printf("Starting kmux registration module\n");
    ret_val = sprintf(proc_path, "/proc/%s", KMUX_PROC_NAME);

    proc_desc = open(proc_path, O_RDONLY);
    if (proc_desc < 0) {
        printf("Can't open proc: %s\n", KMUX_PROC_NAME);
        exit(-1);
    }

    while (1) {
        printf("kreg: command kernel_name pgid/cpu (command = -1 to exit)\n");
        memset(input_buffer, 0, BUFFER_LENGTH);

        fgets(input_buffer, BUFFER_LENGTH, stdin);

        items_scanned = sscanf(input_buffer, "%d %s %d", &kmux_command, kernel_name, &var_param);

        if (kmux_command == -1) {
            break;
        }

        if (items_scanned != 3) {
            printf("Items scanned %d. Invalid parameter: %s\n", items_scanned, input_buffer);
            continue;
        }

        if (!kmux_command || kmux_command < KMUX_IOCTL_CMD_REGISTER_THREAD || kmux_command > KMUX_IOCTL_CMD_UNREGISTER_KERNEL_CPU) {
            printf("Invalid kmux command: %d\n\n", kmux_command);
            continue;
        }

        printf("kmux command: %d\n", kmux_command);
        printf("Kernel name: %s\n", kernel_name);

        if (kmux_command == KMUX_IOCTL_CMD_REGISTER_THREAD || kmux_command == KMUX_IOCTL_CMD_UNREGISTER_THREAD) {
            pgid = var_param;

            printf("PGID: %d\n", pgid);

            if (kmux_command == KMUX_IOCTL_CMD_REGISTER_THREAD) {
                register_thread(proc_desc, kernel_name, pgid);
            } else {
                unregister_thread(proc_desc, kernel_name, pgid);
            }
        } else if (kmux_command == KMUX_IOCTL_CMD_REGISTER_KERNEL_CPU || kmux_command == KMUX_IOCTL_CMD_UNREGISTER_KERNEL_CPU) {
            cpu = var_param;

            printf("CPU: %d\n", cpu);
            if (kmux_command == KMUX_IOCTL_CMD_REGISTER_KERNEL_CPU) {
                register_kernel_cpu(proc_desc, kernel_name, cpu);
            } else {
                unregister_kernel_cpu(proc_desc, kernel_name, cpu);
            }
        }

        printf("\n");
    }

    close(proc_desc);

    printf("Exiting kmux registration module\n");
    return 0;
}
