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

static int
status_handler(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    blob_buf_init(&b, 0);
    blobmsg_add_u64(&b, "packets", packets);
    blobmsg_add_u64(&b, "bytes", bytes);

    ubus_send_reply(ctx, req, b.head);

    return 0;
}

enum {
    ADD_VALUE,
    __ADD_MAX
};

static const struct blobmsg_policy add_policy[__ADD_MAX] = {
    [ADD_VALUE] = { .name = "value", .type = BLOBMSG_TYPE_INT16 },
};

static int add_handler(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    struct blob_attr *tb[__ADD_MAX];
    int v = 0;

    blobmsg_parse(add_policy, __ADD_MAX, tb, blob_data(msg), blob_len(msg));
    if (!tb[ADD_VALUE]) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    v = blobmsg_get_u16(tb[ADD_VALUE]);
    value += v;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "result", "ok");
    blobmsg_add_u16(&b, "add", v);
    blobmsg_add_u32(&b, "value", value);
    ubus_send_reply(ctx, req, b.head);

    return 0;
}

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
