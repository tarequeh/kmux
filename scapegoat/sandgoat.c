#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>

#define BUFFER_LENGTH 512
#define EXIT_COMMAND "exit"

#define BENCHMARK_FILE_NAME "test.log"

#define BENCHMARK_LOOP_SIZE 1

#define rdtscll(val) __asm__ __volatile__("rdtsc" : "=A" (val))

int main(void) {
    FILE * pfile;
    int loop_count;
    char input_buffer[BUFFER_LENGTH];
    struct timeval test;

    char test_message[] = "This is a test.\n";
    size_t test_message_length = sizeof(test_message);

    unsigned long long start, end;

    memset(input_buffer, 0, BUFFER_LENGTH);

    pid_t cpid = fork();

    if (cpid == 0) {
        /*
        Syscall used by sandgoat child:
        -------------------------------
        4   -> write (writes to stdout)
        6   -> close (shouldn't happen if open is blocked)
        8   -> creat (create a file)
        45  -> brk (change segment size)
        78  -> gettimeofday
        252 -> exit_group (needs to exit the group since parent is waiting on it)

        Sandbox test scenario:
        -------------------------------
        Block syscall 8 and allow others

        */
        printf("Press enter to continue with test:\n");
        fgets(input_buffer, BUFFER_LENGTH, stdin);

        input_buffer[strlen(input_buffer) - 1] = '\0';

        if (strcmp(input_buffer, EXIT_COMMAND) == 0) {
            return 0;
        }

        memset(input_buffer, 0, BUFFER_LENGTH);
        sprintf(input_buffer, "rm -rf %s", BENCHMARK_FILE_NAME);
        system(input_buffer);
        fflush(stdout);

        rdtscll(start);

        while(loop_count < BENCHMARK_LOOP_SIZE) {
            pfile = fopen(BENCHMARK_FILE_NAME, "w+");

            gettimeofday(&test, NULL);

            if (!pfile) {
                printf("Failed to open file\n");
            } else {
                fwrite (test_message, 1 , test_message_length, pfile);
                fclose(pfile);
            }

            loop_count++;
        }

        rdtscll(end);

        printf("Elapsed cycles: %lld\n", end-start);
    } else {
        printf("Sandgoat PID: %d\n", cpid);
        printf("Now waiting for child to finish\n");
        wait(NULL);
    }

    return 0;
}
