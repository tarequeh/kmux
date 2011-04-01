#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define BUFFER_LENGTH 512
#define EXIT_COMMAND "exit"

int main(void) {
    FILE * pfile;
    int items_read;

    char input_buffer[BUFFER_LENGTH];
    memset(input_buffer, 0, BUFFER_LENGTH);

    pid_t cpid = fork();

    if (cpid == 0) {
        while(1) {
            printf("Type file name/path or exit:\n");
            fgets(input_buffer, BUFFER_LENGTH, stdin);

            input_buffer[strlen(input_buffer) - 1] = '\0';

            if (strcmp(input_buffer, EXIT_COMMAND) == 0) {
                break;
            }

            printf("Opening file\n");
            pfile = fopen(input_buffer, "w+");
            if (!pfile) {
                printf("Failed to open file\n");
                continue;
            } else {
                printf("Successfully opened file: %s\n", input_buffer);
            }

            fclose(pfile);
        }
        printf("Exiting child\n");
    } else {
        printf("Scapegoat PID: %d\n", cpid);
        printf("Now waiting for child to finish\n");
        wait(NULL);
    }

    return 0;
}
