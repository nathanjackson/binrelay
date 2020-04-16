#include <stdio.h>

#include <pthread.h>

static int x; // Expecting 2 races on this address\variable

void *t1_body()
{
    x = 5; // Write
}

void *t2_body()
{
    x = 7; // Write
}

int main(int argc, char **argv)
{
    pthread_t t1;
    pthread_t t2;

    pthread_create(&t1, NULL, t1_body, NULL);
    x = 3; // Write
    pthread_create(&t2, NULL, t2_body, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("x=%d\n", x);

    return 0;
}
