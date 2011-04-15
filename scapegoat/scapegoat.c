#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>

#define BUFFER_LENGTH 512
#define EXIT_COMMAND "exit"

int main(void) {
    FILE * pfile;
    int items_read;
    char input_buffer[BUFFER_LENGTH];
    struct timeval start, end;
    long mtime, seconds, useconds;

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
            gettimeofday(&start, NULL);
            pfile = fopen(input_buffer, "w+");
            gettimeofday(&end, NULL);

            if (!pfile) {
                printf("Failed to open file\n");
            } else {
                printf("Successfully opened file: %s\n", input_buffer);
            }

            seconds  = end.tv_sec  - start.tv_sec;
            useconds = end.tv_usec - start.tv_usec;

            mtime = ((seconds) * 1000000 + useconds) + 0.5;

            printf("Elapsed time: %ld microseconds\n", mtime);

            if (pfile) fclose(pfile);
        }
        printf("Exiting child\n");
    } else {
        printf("Scapegoat PID: %d\n", cpid);
        printf("Now waiting for child to finish\n");
        wait(NULL);
    }

    return 0;
}
