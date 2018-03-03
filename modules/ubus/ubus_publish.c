// ubus-sniffer.c

#include <unistd.h>
#include <signal.h>
#include <stdio.h>

#include <libubox/uloop.h>
#include <libubus.h>
#include "ubus_publish.h"
#define SERVICE_NAME "sniffer"
#define METHOD_NAME "status"
#define EVENT_NAME "sniffer.status"
static struct ubus_context *ctx=NULL;
static struct blob_buf b;

static SnifferData snifferData={0,0};
static ubus_sniffer_arg *sniffer_arg=NULL;


static void test_client_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj)
{
        fprintf(stderr, "Subscribers active: %d\n", obj->has_subscribers);
}

static void test_client_notify_cb(struct uloop_timeout *timeout);
static void createMessage(int rcv_pkts,int rcv_bytes,struct blob_buf* buf)
{
    blob_buf_init(buf, 0);
    blobmsg_add_u64(buf, "packets", rcv_pkts);
    blobmsg_add_u64(buf, "bytes", rcv_bytes);
}

static int
status_handler(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    createMessage(snifferData.packets,snifferData.bytes,&b);
    ubus_send_reply(ctx, req, b.head);

    return 0;
}

static const struct ubus_method methods[] = {
    { .name = METHOD_NAME , .handler = status_handler } ,
};

static struct ubus_object_type sniffer_object_type = UBUS_OBJECT_TYPE(SERVICE_NAME, methods);

static struct ubus_object smaple_object = {
    .name = SERVICE_NAME,
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
        int timer=2000;
        if (sniffer_arg)
        {
            if (sniffer_arg->handler)
                (*sniffer_arg->handler)(sniffer_arg->instance,&snifferData);
            timer=sniffer_arg->time_period;
        }
        createMessage(snifferData.packets,snifferData.bytes,&b);
        err = ubus_notify(ctx, &test_client_object, METHOD_NAME, b.head, 1000);
        if (err)
                fprintf(stderr, "Notify failed: %s\n", ubus_strerror(err));

        err=ubus_send_event(ctx,EVENT_NAME,b.head);
        if (err)
                fprintf(stderr, "Event failed: %s\n", ubus_strerror(err));

        uloop_timeout_set(timeout, timer);
}

int ubus_main(ubus_sniffer_arg *sniff_arg)
{
    sniffer_arg=sniff_arg;
    const char *ubus_socket = NULL;
    int ret;

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
ubus_sniffer_arg sniff_arg={NULL,NULL,2000};
return ubus_main(sniff_arg);
}
#endif
