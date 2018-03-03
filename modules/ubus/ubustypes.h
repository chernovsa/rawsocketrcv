#ifndef UBUSTYPES
#define UBUSTYPES
#include <stdint.h>
typedef struct{
    uint64_t packets;
    uint64_t bytes;
} SnifferData;
typedef void (*ubus_sniffer_data_handler)(char *, SnifferData*);
typedef struct
{
    ubus_sniffer_data_handler handler;
    char* instance;
    int time_period;
} ubus_sniffer_arg;

#endif // UBUSTYPES

