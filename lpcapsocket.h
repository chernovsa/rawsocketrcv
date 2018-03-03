#ifndef LPCAPSOCKET_H
#define LPCAPSOCKET_H

#define UNUSED(x) (void)(x)
typedef void (*sniffer_data_handler)(char *, int);
typedef struct
{
    sniffer_data_handler handler;
    char* instance;
    const char* ifname;
    const char* src_ipaddr;
    const char* src_port;
} sniffer_arg;

int start_pcap(sniffer_arg *processArg);

#endif // LPCAPSOCKET_H
