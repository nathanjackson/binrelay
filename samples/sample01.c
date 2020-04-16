#include <stdio.h>

#include <pthread.h>

static int x; // expecitng 1 race on this variable\address

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

    x = 3; // Write

    pthread_create(&t1, NULL, t1_body, NULL);
    pthread_create(&t2, NULL, t2_body, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("x=%d\n", x);

    return 0;
}
