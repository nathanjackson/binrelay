#include <stdio.h>

#include <pthread.h>

static int x;

void *t1_body()
{
    x = 5;
}

void *t2_body()
{
    x = 7;
}

int main(int argc, char **argv)
{
    pthread_t t1;
    pthread_t t2;

    pthread_create(&t1, NULL, t1_body, NULL);
    pthread_create(&t2, NULL, t2_body, NULL);

    x = 3;

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("x=%d\n", x);

    return 0;
}
