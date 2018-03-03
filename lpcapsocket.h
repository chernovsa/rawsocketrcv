#ifndef LPCAPSOCKET_H
#define LPCAPSOCKET_H

typedef void (*sniffer_data_handler)(char *, int);
typedef struct
{
    sniffer_data_handler handler;
    char* instance;
} sniffer_arg;

int start_pcap(sniffer_arg *processArg);

#endif // LPCAPSOCKET_H
