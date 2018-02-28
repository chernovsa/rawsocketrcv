// uloop-timer.c
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include <libubox/uloop.h>

static void timer_cb(struct uloop_timeout *timeout)
{
    static int i = 0;

        fprintf(stderr, "%d - %d\n", __LINE__, i++);

        uloop_timeout_set(timeout, 1000);
}

static struct uloop_timeout timer = {
        .cb = timer_cb,
};

int main(int argc, char **argv)
{
    uloop_init();

    uloop_timeout_set(&timer, 2000);

    uloop_run();

    uloop_done();

    return 0;
}
