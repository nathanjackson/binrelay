#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

int foo;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *thread_body()
{
    pthread_mutex_lock(&mutex);
    foo += 1;
    pthread_mutex_unlock(&mutex);
}

int main(int argc, char **argv)
{
    int result = 0;
    const char *password = "barbazbux";

    pthread_t thread;

    foo = 0;

    if (2 > argc)
    {
        printf("usage: %s <password>\n", argv[0]);
        return result;
    }

    if (0 == strcmp(password, argv[1]))
    {
        pthread_create(&thread, NULL, thread_body, NULL);
        for (int i = 0; i < 100; i++)
        {
            foo += 1;
        }
        pthread_join(thread, NULL);
    }

    printf("value=%d\n", foo);
    return result;
}