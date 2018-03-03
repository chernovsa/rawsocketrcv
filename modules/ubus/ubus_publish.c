// ubus-sniffer.c

#include <unistd.h>
#include <signal.h>
#include <stdio.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

static struct ubus_context *ctx;
static struct blob_buf b;

static int value = 0;
static int packets=123;
static int bytes=456;

static void test_client_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj)
{
        fprintf(stderr, "Subscribers active: %d\n", obj->has_subscribers);
}

static void test_client_notify_cb(struct uloop_timeout *timeout);
static void createMessage(int rcv_pkts,int rcv_bytes,struct blob_buf* buf)
{
    blob_buf_init(buf, 0);
    blobmsg_add_u64(buf, "packets", packets);
    blobmsg_add_u64(buf, "bytes", bytes);
}

static int
status_handler(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    createMessage(packets,bytes,&b);
    ubus_send_reply(ctx, req, b.head);

    return 0;
}

enum {
    ADD_VALUE,
    __ADD_MAX
};

static const struct ubus_method methods[] = {
    { .name = "status" , .handler = status_handler } ,
};

static struct ubus_object_type sniffer_object_type = UBUS_OBJECT_TYPE("sniffer", methods);

static struct ubus_object smaple_object = {
    .name = "sniffer",
    .type = &sniffer_object_type ,
    .methods = methods,
    .n_methods = ARRAY_SIZE(methods),
};

static struct uloop_timeout notify_timer = {
        .cb = test_client_notify_cb,
};

static struct ubus_object test_client_object = {
        .subscribe_cb = test_client_subscribe_cb,
};

static void test_client_notify_cb(struct uloop_timeout *timeout)
{
        int err;
        struct timeval tv1, tv2;
        int max = 1000;
        long delta;
        int i = 0;

        packets++;
        bytes++;

        createMessage(packets,bytes,&b);
        gettimeofday(&tv1, NULL);
        err = ubus_notify(ctx, &test_client_object, "update", b.head, 1000);
        gettimeofday(&tv2, NULL);
        if (err)
                fprintf(stderr, "Notify failed: %s\n", ubus_strerror(err));

        delta = (tv2.tv_sec - tv1.tv_sec) * 1000000 + (tv2.tv_usec - tv1.tv_usec);
        fprintf(stderr, "Avg time per iteration: %ld usec\n", delta / max);

        uloop_timeout_set(timeout, 2000);
}

int ubus_main(int argc, char **argv)
{
    const char *ubus_socket = NULL;
    int ret;
    int ch;

    while ((ch = getopt(argc, argv, "cs:")) != -1) {
        switch (ch) {
        case 's':
            ubus_socket = optarg;
            break;
        default:
            break;
        }
    }

    argc -= optind;
    argv += optind;

    uloop_init();
    signal(SIGPIPE, SIG_IGN);

    ctx = ubus_connect(ubus_socket);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return -1;
    }

    ubus_add_uloop(ctx);

    ret = ubus_add_object(ctx, &smaple_object);
    if (ret) {
        fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
    }

    //notify
    test_client_notify_cb(&notify_timer);

    uloop_run();

    ubus_free(ctx);
    uloop_done();

    return 0;
}
#ifdef TEST_UBUS
int main(int argc, char **argv)
{
ubus_main(argc,argv);
return 0;
}
#endif
