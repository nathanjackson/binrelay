#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>

int foo; // Expecting 3 races: 2x Read-Write, 1x Write-Write

void *thread_body()
{
    foo += 1; // Read and Write
}

int main(int argc, char **argv)
{
    int result = 0;
    int number = 0;

    pthread_t thread;

    foo = 0;

    if (2 > argc)
    {
        printf("usage: %s <number>\n", argv[0]);
        return result;
    }

    number = atoi(argv[1]);

    pthread_create(&thread, NULL, thread_body, NULL);
    foo += number; // Read and write
    pthread_join(thread, NULL);

    return result;
}