#ifndef LPCAPSOCKET_H
#define LPCAPSOCKET_H

typedef void (*sniffer_data_handler)(char *, int);
typedef struct
{
    sniffer_data_handler handler;
    char* instance;
    const char* ifname;
    const char* src_ipaddr;
    const char* src_port;
} sniffer_arg;
enum {PARAM_STRING_SIZE=256};
int start_pcap(sniffer_arg *processArg);

#endif // LPCAPSOCKET_H
