#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>		/* open */
#include <unistd.h>		/* exit */
#include <sys/ioctl.h>		/* ioctl */

#include "../kern_mux.h"

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

int main(int argc, char *argv[]) {
	char proc_path[50], kernel_name[MAX_KERNEL_NAME_LENGTH];
	int kmux_command, proc_desc, ret_val;
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

	strcpy(thread_info->kernel_name, kernel_name);
	thread_info->pgid = pgid;

	proc_desc = open(proc_path, O_RDONLY);
	if (proc_desc < 0) {
		printf("Can't open proc: %s\n", KMUX_PROC_NAME);
		exit(-1);
	}

	if (kmux_command == KMUX_IOCTL_CMD_REGISTER_THREAD) {
		register_thread(proc_desc, thread_info);
	} else {
		unregister_thread(proc_desc, thread_info);
	}

	close(proc_desc);

	return 0;
}
