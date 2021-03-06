#include <fcntl.h>         /* open       */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>        /* exit       */

#include "../kern_mux.h"
#include "../kmul/kmul.h"

#define BUFFER_LENGTH 1024
#define SCAN_REGEX_LENGTH 64

void initialize_kreg(void) {
	// Set affinity of this utility to CPU dedicated to Linux
	pid_t kreg_pid = getpid();
	set_cpu_affinity(kreg_pid, KMUX_HOST_KERNEL_CPU);

	switch_cpu_for_current_processes();
}

int main(void) {
    // Uncomment following line when experimenting with CPU binding
    //initialize_kreg();

    char input_buffer[BUFFER_LENGTH], scan_regex[SCAN_REGEX_LENGTH], kernel_name[MAX_KERNEL_NAME_LENGTH], config_buffer[MAX_KERNEL_CONFIG_BUFFER_LENGTH];
    int kmux_command, ret_val, pgid, cpu, var_param, items_scanned;

    printf("Starting kmux registration module\n");

    while (1) {
        printf("kreg: command kernel_name pgid/cpu (command = -1 to exit)\n");
        memset(input_buffer, 0, BUFFER_LENGTH);

        fgets(input_buffer, BUFFER_LENGTH, stdin);

        items_scanned = sscanf(input_buffer, "%d%*[ ]", &kmux_command);

        if (items_scanned != 1) {
            printf("Could not find command\n");
            continue;
        }

        if (kmux_command == -1) {
            break;
        }

        if (!kmux_command || kmux_command < KMUX_IOCTL_CMD_REGISTER_THREAD || kmux_command > KMUX_IOCTL_CMD_CONFIGURE_KERNEL) {
            printf("Invalid kmux command: %d\n\n", kmux_command);
            continue;
        }

        printf("kmux command: %d\n", kmux_command);

        if (kmux_command == KMUX_IOCTL_CMD_REGISTER_THREAD || kmux_command == KMUX_IOCTL_CMD_UNREGISTER_THREAD) {
            items_scanned = sscanf(input_buffer, "%*d %s %d", kernel_name, &pgid);

            if (items_scanned != 2) {
                printf("Items scanned %d. Invalid parameter(s): %s\n", items_scanned, input_buffer);
                continue;
            }

            printf("Kernel name: %s\n", kernel_name);
            printf("PGID: %d\n", pgid);

            if (kmux_command == KMUX_IOCTL_CMD_REGISTER_THREAD) {
                register_thread(kernel_name, pgid);
            } else {
                unregister_thread(kernel_name, pgid);
            }
        } else if (kmux_command == KMUX_IOCTL_CMD_REGISTER_KERNEL_CPU || kmux_command == KMUX_IOCTL_CMD_UNREGISTER_KERNEL_CPU) {
            items_scanned = sscanf(input_buffer, "%*d %s %d", kernel_name, &cpu);

            if (items_scanned != 2) {
                printf("Items scanned %d. Invalid parameter(s): %s\n", items_scanned, input_buffer);
                continue;
            }

            printf("Kernel name: %s\n", kernel_name);
            printf("CPU: %d\n", cpu);

            if (kmux_command == KMUX_IOCTL_CMD_REGISTER_KERNEL_CPU) {
                register_kernel_cpu(kernel_name, cpu);
            } else {
                unregister_kernel_cpu(kernel_name, cpu);
            }
        } else if (kmux_command == KMUX_IOCTL_CMD_CONFIGURE_KERNEL) {
            memset(scan_regex, 0, SCAN_REGEX_LENGTH);
            sprintf(scan_regex, "%%*d %%s %%%d[^\n]", MAX_KERNEL_CONFIG_BUFFER_LENGTH);
            items_scanned = sscanf(input_buffer, scan_regex, kernel_name, config_buffer);

            if (items_scanned != 2) {
                printf("Items scanned %d. Invalid parameter(s): %s\n", items_scanned, input_buffer);
                continue;
            }

            printf("Kernel name: %s\n", kernel_name);
            printf("Config buffer: %s\n", config_buffer);
            configure_kernel(kernel_name, config_buffer);
        }

        printf("-------------------\n");
    }

    printf("Exiting kmux registration module\n");
    return 0;
}
