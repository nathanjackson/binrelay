#include <stdio.h>

#include <pthread.h>

static int x = 0; // Expecting no races thanks to mutex

static pthread_mutex_t mutex;

void *t1_body()
{
    pthread_mutex_lock(&mutex);
    x += 1; // Read and Write
    pthread_mutex_unlock(&mutex);
}

int main(int argc, char **argv)
{
    pthread_t t1;

    pthread_mutex_init(&mutex, NULL);

    pthread_create(&t1, NULL, t1_body, NULL);

    pthread_mutex_lock(&mutex);
    x += 1; // Read and Write
    pthread_mutex_unlock(&mutex);

    pthread_join(t1, NULL);

    printf("x=%d\n", x);

    return 0;
}
