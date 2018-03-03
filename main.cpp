#include <iostream>
#include <thread>             // std::thread
#include "snifferdatamanager.h"
#include "lpcapsocket.h"
#include "ubus_publish.h"
using namespace std;

void pcap_process_packet(char *keeper, int bytes)
{
    if (keeper)
    {
        SnifferDataManager *k= (SnifferDataManager*)keeper;
        k->onPacketReceived(bytes);
    }
}
void ubus_process_notify(char* keeper,SnifferData *data)
{
    if (keeper)
    {
        SnifferDataManager *k= (SnifferDataManager*)keeper;
        k->populateData(data);
    }
}

int main(int argc,char **argv)
{
    UNUSED(argc);
    UNUSED(argv);
    enum {
        PCAP_THREAD,
        UBUS_THREAD,
        THREADS_SIZE
    };
    SnifferDataManager dataManager(0,0);
    sniffer_arg pcap_arg={
        &pcap_process_packet,
        (char*)&dataManager,
        "lo",
        "127.0.0.1",
        "666"
    };
    int time_period=100;
    ubus_sniffer_arg ubus_arg={&ubus_process_notify,(char*)&dataManager,time_period};
    std::thread threads[THREADS_SIZE];
    threads[PCAP_THREAD] = std::thread(start_pcap,&pcap_arg);
    threads[UBUS_THREAD] = std::thread(ubus_main,&ubus_arg);


    for (auto& th : threads) th.join();


    return 0;
}

